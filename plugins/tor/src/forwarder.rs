//! A SOCKS5 forwarder between the browser and Tor.
//!
//! Chrome speaks SOCKS5 without authentication only (spike, Chrome 156: the
//! greeting is always `05 01 00`) and ignores a proxy URL that carries a user
//! name, so it cannot tell Tor which circuits it wants. The forwarder sits in
//! between: it accepts the browser's connections on a loopback port and passes
//! each CONNECT to Tor's SocksPort with the user name and password of its own
//! [`IsolationToken`]. Tor's `IsolateSOCKSAuth` puts streams with different
//! credentials on different circuits, so one forwarder per browser context
//! gives each context circuits of its own.
//!
//! The forwarder never opens a connection to the target. Names reach Tor
//! unresolved, and when Tor cannot be reached or refuses, the browser gets a
//! failure reply and nothing else happens.

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use ring::rand::{SecureRandom, SystemRandom};
use tokio::io::{AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::task::{JoinHandle, JoinSet};

use crate::socks::{self, Credentials, Error, NO_ACCEPTABLE, NO_AUTH, rep};

/// The user name sent to Tor. It starts with the `<torS0X>` marker, and the
/// `0` after it says that the password is the stream isolation parameter
/// (Tor's SOCKS extensions, proposal 351). A Tor that does not know the marker
/// reads the pair as plain credentials, which isolates just the same.
const USERNAME: &[u8] = b"<torS0X>0";

/// What tells one forwarder's streams from another's to Tor: streams with the
/// same token may share a circuit, streams with different tokens never do.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct IsolationToken([u8; 16]);

impl IsolationToken {
    /// A token with these bytes. For tests; use [`random`](Self::random).
    #[must_use]
    pub fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// A token of 128 random bits from the system's random number generator.
    ///
    /// # Errors
    ///
    /// When the system's random number generator fails.
    pub fn random() -> io::Result<Self> {
        let mut bytes = [0u8; 16];
        SystemRandom::new()
            .fill(&mut bytes)
            .map_err(|_| io::Error::other("the system random number generator failed"))?;
        Ok(Self(bytes))
    }

    /// The password sent to Tor: `sbrs-` and the token in hexadecimal.
    #[must_use]
    pub fn password(&self) -> String {
        use std::fmt::Write as _;
        self.0
            .iter()
            .fold(String::from("sbrs-"), |mut password, byte| {
                let _ = write!(password, "{byte:02x}");
                password
            })
    }

    /// The user name and password sent to Tor.
    pub(crate) fn credentials(&self) -> Credentials {
        Credentials {
            username: USERNAME.to_vec(),
            password: self.password().into_bytes(),
        }
    }
}

impl std::fmt::Debug for IsolationToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("IsolationToken(..)")
    }
}

/// How much a forwarder lets one browser ask of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Limits {
    /// How long a connection may take from its first byte to a made tunnel,
    /// Tor's side included. Default 10 seconds.
    pub handshake_timeout: Duration,
    /// How many connections are served at once; the next one is closed at
    /// once. Default 256.
    pub max_connections: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            handshake_timeout: Duration::from_secs(10),
            max_connections: 256,
        }
    }
}

impl Limits {
    /// Sets [`handshake_timeout`](Self::handshake_timeout).
    #[must_use]
    pub fn handshake_timeout(mut self, timeout: Duration) -> Self {
        self.handshake_timeout = timeout;
        self
    }

    /// Sets [`max_connections`](Self::max_connections).
    #[must_use]
    pub fn max_connections(mut self, max: usize) -> Self {
        self.max_connections = max;
        self
    }
}

/// A running forwarder. Dropping it stops it: the listener closes and so does
/// every connection it serves.
#[derive(Debug)]
pub struct Forwarder {
    address: SocketAddr,
    permits: Arc<Semaphore>,
    max_connections: usize,
    accept_loop: JoinHandle<()>,
}

impl Drop for Forwarder {
    /// Stops the accept loop. Its connections are tasks of that loop, so they
    /// stop with it and their sockets close.
    fn drop(&mut self) {
        self.accept_loop.abort();
    }
}

/// What every connection of one forwarder needs.
struct Shared {
    /// Tor's SocksPort.
    upstream: SocketAddr,
    /// The user name and password for every stream to Tor.
    credentials: Credentials,
    handshake_timeout: Duration,
}

/// Accepts connections until the task is aborted. A connection over the limit
/// is closed at once.
async fn accept_loop(listener: TcpListener, permits: Arc<Semaphore>, shared: Arc<Shared>) {
    let mut connections = JoinSet::new();
    loop {
        let client = match listener.accept().await {
            Ok((client, _)) => client,
            Err(_) => {
                // Out of descriptors, or a connection that died in the queue:
                // wait a moment and go on.
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        // Finished connections leave the set, so it does not grow.
        while connections.try_join_next().is_some() {}
        let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
            drop(client);
            continue;
        };
        let shared = Arc::clone(&shared);
        connections.spawn(async move {
            let _permit = permit;
            serve(client, &shared).await;
        });
    }
}

/// One browser connection: the handshake within the time limit, then the
/// tunnel until either side closes.
async fn serve(mut client: TcpStream, shared: &Shared) {
    let made = tokio::time::timeout(shared.handshake_timeout, negotiate(&mut client, shared)).await;
    let Ok(Some(mut upstream)) = made else {
        return;
    };
    let _ = client.set_nodelay(true);
    let _ = upstream.set_nodelay(true);
    let _ = copy_bidirectional(&mut client, &mut upstream).await;
}

/// Answers the browser's greeting and request and makes the tunnel through
/// Tor. Returns the connection to Tor, or `None` after answering the browser
/// with a failure (or after saying nothing to a peer that is not SOCKS5).
///
/// The only address this function ever connects to is `shared.upstream`.
async fn negotiate(client: &mut TcpStream, shared: &Shared) -> Option<TcpStream> {
    let methods = socks::read_greeting(client).await.ok()?;
    if !methods.contains(&NO_AUTH) {
        let _ = client.write_all(&[socks::VERSION, NO_ACCEPTABLE]).await;
        return None;
    }
    client.write_all(&[socks::VERSION, NO_AUTH]).await.ok()?;
    let target = match socks::read_request(client).await {
        Ok(target) => target,
        Err(Error::Refuse(code)) => {
            let _ = client.write_all(&socks::reply(code)).await;
            return None;
        }
        Err(Error::Io(_) | Error::Protocol(_)) => return None,
    };
    let Ok(mut upstream) = TcpStream::connect(shared.upstream).await else {
        let _ = client.write_all(&socks::reply(rep::GENERAL_FAILURE)).await;
        return None;
    };
    match socks::client_connect(&mut upstream, &shared.credentials, &target).await {
        Ok(()) => {}
        Err(Error::Refuse(code)) => {
            let _ = client.write_all(&socks::reply(code)).await;
            return None;
        }
        Err(Error::Io(_) | Error::Protocol(_)) => {
            let _ = client.write_all(&socks::reply(rep::GENERAL_FAILURE)).await;
            return None;
        }
    }
    client.write_all(&socks::reply(rep::SUCCEEDED)).await.ok()?;
    Some(upstream)
}

impl Forwarder {
    /// Starts a forwarder on a free loopback port. Its connections go to the
    /// SOCKS5 server at `upstream`, which is Tor's SocksPort.
    ///
    /// # Errors
    ///
    /// When no loopback port can be bound.
    pub async fn start(
        upstream: SocketAddr,
        token: IsolationToken,
        limits: Limits,
    ) -> io::Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let max_connections = limits.max_connections.min(Semaphore::MAX_PERMITS);
        let permits = Arc::new(Semaphore::new(max_connections));
        let shared = Arc::new(Shared {
            upstream,
            credentials: token.credentials(),
            handshake_timeout: limits.handshake_timeout,
        });
        let accept_loop = tokio::spawn(accept_loop(listener, Arc::clone(&permits), shared));
        Ok(Self {
            address,
            permits,
            max_connections,
            accept_loop,
        })
    }

    /// The loopback address the browser connects to.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.address
    }

    /// The value for the browser's `--proxy-server` switch: `socks5://` and
    /// the local address. It never carries a user name: Chrome ignores a proxy
    /// URL with one and goes direct.
    #[must_use]
    pub fn proxy_url(&self) -> String {
        format!("socks5://{}", self.address)
    }

    /// How many connections are being served now.
    #[must_use]
    pub fn active_connections(&self) -> usize {
        self.max_connections
            .saturating_sub(self.permits.available_permits())
    }
}
