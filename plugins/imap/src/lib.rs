//! Waits for an email in an IMAP mailbox and hands back its one-time code or
//! link, so a login that sends a code by mail can be driven end to end.
//!
//! The plugin reads one mailbox that you give it access to. It reads, it never
//! sends, deletes or marks anything: the mailbox is opened read only and the
//! messages are fetched with `BODY.PEEK`. The password is never an option:
//! `password_env` names the environment variable that holds it (an app
//! password, for providers that have them), and it is read when the task
//! starts, kept out of every error and every `Debug` output, and sent only to
//! the server, over TLS.
//!
//! ```
//! use seleniumbase_rs_plugin::PluginSet;
//! use seleniumbase_rs_plugin_imap::{Imap, ImapConfig};
//!
//! let config = ImapConfig {
//!     host: "imap.example.com".into(),
//!     user: "me@example.com".into(),
//!     password_env: "MAIL_APP_PASSWORD".into(),
//!     ..ImapConfig::default()
//! };
//! // The variable must be set, or building the plugin fails and says which one.
//! let imap = Imap::new_with(config, &|_name| Some("app password".into()))?;
//! let plugins = PluginSet::strict().with(imap)?;
//! assert_eq!(plugins.names(), ["imap"]);
//! # Ok::<(), seleniumbase_rs_plugin::PluginError>(())
//! ```
//!
//! # The task
//!
//! The plugin is a [`Task`]: `wait_for_email` with the input
//! `{"from"?, "subject_contains"?, "since_secs"?, "extract"?}` (see [`Query`])
//! looks at the mailbox every `poll_secs` for unread messages of the last
//! `since_secs` (default 600), newest first, until one matches or
//! `timeout_secs` have passed. The match is written to the sink as one line,
//! `{"from", "subject", "date", "code"?, "link"?, "text"}`.
//!
//! Messages are read as far as 256 KiB. A message is looked at once per wait.
//!
//! # Not covered
//!
//! No STARTTLS (port 143), no OAuth2 and no IDLE: the connection is IMAPS and
//! the login is `LOGIN` with a password. The capability the plugin declares is
//! `HostNet` for any address; the API has no per-host scope, so the host it
//! talks to is the `host` option and nothing else.

mod config;
mod mail;
mod poll;
mod session;

use std::time::Duration;

use seleniumbase_rs_plugin::{
    Capability, Category, Clock, Configurable, Metadata, NetScope, Plugin, Result, Task,
    TaskContext, async_trait, config::options,
};
use serde_json::{Value, json};

pub use config::{ImapConfig, MAX_POLL_SECS, MAX_TIMEOUT_SECS};
pub use mail::{
    DEFAULT_SINCE_SECS, Extract, Found, MAX_SINCE_SECS, MAX_TEXT_BYTES, Mail, Query, find_code,
    find_link, imap_date,
};
pub use poll::{MAX_BATCH, MailSource, RawMail, wait_for};

use config::Secret;
use session::ImapSource;

/// The name the plugin is enabled by.
const NAME: &str = "imap";

/// The IMAP plugin. See the [crate documentation](crate).
#[derive(Debug)]
pub struct Imap {
    config: ImapConfig,
}

impl Imap {
    /// Builds the plugin from `config`, checking that the environment variable
    /// named by `password_env` is set.
    ///
    /// # Errors
    ///
    /// [`PluginError::Config`](seleniumbase_rs_plugin::PluginError::Config)
    /// for a bad option, or for a `password_env` that names no variable (the
    /// message names it).
    pub fn new(config: ImapConfig) -> Result<Self> {
        Self::new_with(config, &|name| std::env::var(name).ok())
    }

    /// Like [`Imap::new`], with `get` in place of the process environment.
    ///
    /// # Errors
    ///
    /// As [`Imap::new`].
    pub fn new_with(config: ImapConfig, get: &dyn Fn(&str) -> Option<String>) -> Result<Self> {
        config.check()?;
        config.password_with(get)?;
        Ok(Self { config })
    }

    /// The options the plugin was built with.
    #[must_use]
    pub fn config(&self) -> &ImapConfig {
        &self.config
    }

    /// Waits for the email `query` describes: connects, then looks at the
    /// mailbox every `poll_secs` until a message matches or `timeout_secs`
    /// have passed (counted by `clock`).
    ///
    /// # Errors
    ///
    /// If the password variable is gone, the server cannot be reached or
    /// refuses the login, or nothing matched in time.
    pub async fn wait_for_email(&self, query: &Query, clock: &Clock) -> Result<Found> {
        let password: Secret = self
            .config
            .password_with(&|name| std::env::var(name).ok())?;
        let timeout = Duration::from_secs(self.config.timeout_secs);
        let mut source = clock
            .timeout(timeout, ImapSource::connect(&self.config, &password))
            .await??;
        let outcome = wait_for(
            &mut source,
            query,
            clock,
            Duration::from_secs(self.config.poll_secs),
            timeout,
        )
        .await;
        source.logout().await;
        outcome
    }
}

#[async_trait]
impl Plugin for Imap {
    fn name(&self) -> &str {
        NAME
    }

    fn metadata(&self) -> Metadata {
        Self::describe()
    }

    fn task(&self) -> Option<&dyn Task> {
        Some(self)
    }
}

#[async_trait]
impl Task for Imap {
    /// `wait_for_email`: waits for the email `{"from"?, "subject_contains"?,
    /// "since_secs"?, "extract"?}` describes and records one line,
    /// `{"from", "subject", "date", "code"?, "link"?, "text"}`. The summary
    /// says what was found: `{"matched": true, "code": bool, "link": bool}`.
    async fn run(&self, cx: &TaskContext<'_>) -> Result<Value> {
        let query = Query::parse(cx.input)?;
        let found = self.wait_for_email(&query, cx.clock).await?;
        cx.sink.record(&found.to_json())?;
        Ok(json!({
            "matched": true,
            "code": found.code.is_some(),
            "link": found.link.is_some(),
        }))
    }
}

impl Configurable for Imap {
    const NAME: &'static str = NAME;

    fn describe() -> Metadata {
        Metadata::new(Category::Core)
            .version(env!("CARGO_PKG_VERSION"))
            .summary("Waits for an email over IMAP and extracts its one-time code or link")
            .capabilities([Capability::Task, Capability::HostNet(NetScope::Any)])
    }

    /// Options: see [`ImapConfig`].
    fn configure(value: &Value) -> Result<Self> {
        Self::new(options(NAME, value)?)
    }
}
