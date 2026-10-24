//! The IMAP side: one TLS connection to the server, read only.
//!
//! The mailbox is opened with `EXAMINE` and messages are fetched with
//! `BODY.PEEK`, so reading never changes a flag. Every value that goes into a
//! command is the plugin's own (a date it formats, UIDs the server sent, the
//! mailbox name that `async-imap` quotes), never text from a message.

use std::collections::HashSet;
use std::fmt::Display;
use std::sync::Arc;

use async_imap::{Client, Session};
use futures_util::TryStreamExt;
use rustls::pki_types::ServerName;
use seleniumbase_rs_plugin::{PluginError, Result, async_trait};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use crate::config::{ImapConfig, Secret};
use crate::mail::imap_date;
use crate::poll::{MAX_BATCH, MailSource, RawMail};

/// How much of one message is fetched. A longer one is read as far as this.
const MAX_MESSAGE_BYTES: u32 = 256 * 1024;

/// The `SINCE` search looks at whole days, in the server's time zone: start a
/// day early and let the `Date` header decide.
const SINCE_SLACK_SECS: u64 = 86_400;

/// A logged-in session on the mailbox.
pub(crate) struct ImapSource {
    session: Session<TlsStream<TcpStream>>,
}

fn failed(what: &str, error: impl Display) -> PluginError {
    PluginError::other(format!("imap: {what}: {error}"))
}

fn connector() -> Result<TlsConnector> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| failed("TLS setup failed", error))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(config)))
}

impl ImapSource {
    /// Connects over TLS, logs in and opens the mailbox read only.
    pub(crate) async fn connect(config: &ImapConfig, password: &Secret) -> Result<Self> {
        let address = format!("{}:{}", config.host, config.port);
        let tcp = TcpStream::connect((config.host.as_str(), config.port))
            .await
            .map_err(|error| failed(&format!("cannot connect to {address}"), error))?;
        let name = ServerName::try_from(config.host.clone())
            .map_err(|error| failed("bad host name", error))?;
        let tls = connector()?
            .connect(name, tcp)
            .await
            .map_err(|error| failed(&format!("TLS handshake with {address} failed"), error))?;
        let mut client = Client::new(tls);
        // The server speaks first; `Client::new` leaves its greeting unread.
        let _ = client.read_response().await;
        let mut session = client
            .login(&config.user, password.expose())
            .await
            .map_err(|(error, _)| {
                failed(
                    "login failed (check `user` and the password in `password_env`)",
                    error,
                )
            })?;
        session.examine(&config.mailbox).await.map_err(|error| {
            failed(
                &format!("cannot open the mailbox `{}`", config.mailbox),
                error,
            )
        })?;
        Ok(Self { session })
    }

    /// Says goodbye; a failure does not matter.
    pub(crate) async fn logout(mut self) {
        let _ = self.session.logout().await;
    }
}

#[async_trait]
impl MailSource for ImapSource {
    async fn fetch_new(&mut self, since_secs: u64, seen: &HashSet<u32>) -> Result<Vec<RawMail>> {
        // New mail is only announced to a session that asks.
        self.session
            .noop()
            .await
            .map_err(|error| failed("NOOP failed", error))?;
        let query = format!(
            "UNSEEN SINCE {}",
            imap_date(since_secs.saturating_sub(SINCE_SLACK_SECS))
        );
        let found = self
            .session
            .uid_search(&query)
            .await
            .map_err(|error| failed("search failed", error))?;
        let mut ids: Vec<u32> = found.into_iter().filter(|id| !seen.contains(id)).collect();
        ids.sort_unstable_by(|a, b| b.cmp(a));
        ids.truncate(MAX_BATCH);
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let set = ids.iter().map(u32::to_string).collect::<Vec<_>>().join(",");
        let mut stream = self
            .session
            .uid_fetch(&set, format!("BODY.PEEK[]<0.{MAX_MESSAGE_BYTES}>"))
            .await
            .map_err(|error| failed("fetch failed", error))?;
        let mut mails = Vec::new();
        while let Some(item) = stream
            .try_next()
            .await
            .map_err(|error| failed("fetch failed", error))?
        {
            if let (Some(id), Some(bytes)) = (item.uid, item.body()) {
                mails.push(RawMail {
                    id,
                    bytes: bytes.to_vec(),
                });
            }
        }
        mails.sort_unstable_by_key(|mail| std::cmp::Reverse(mail.id));
        Ok(mails)
    }
}
