//! Fakes and helpers shared by the integration tests: a SOCKS5 server that
//! stands in for Tor's SocksPort and records what it was sent, a listener that
//! counts connections, and small socket helpers.
#![allow(dead_code)]

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

/// Runs a future on a small runtime.
pub fn run<F: Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime")
        .block_on(future)
}

/// What one connection to the fake SocksPort sent.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Seen {
    /// The greeting: version, method count, methods.
    pub greeting: Vec<u8>,
    /// The RFC 1929 request: version, user name length, user name, password length, password.
    pub auth: Vec<u8>,
    /// The CONNECT request, from the version byte to the port.
    pub request: Vec<u8>,
}

/// How the fake SocksPort answers a CONNECT.
#[derive(Clone, Copy, Debug)]
pub enum Answer {
    /// Success, then echo every byte back.
    Succeed,
    /// This reply code, then close.
    Reply(u8),
    /// Refuse the user name and password.
    RefuseAuth,
    /// "No acceptable methods".
    NoAcceptableMethod,
}

/// A SOCKS5 server on a loopback port that records what it receives.
pub struct FakeSocksUpstream {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<Seen>>>,
    task: JoinHandle<()>,
}

impl FakeSocksUpstream {
    pub async fn start(answer: Answer) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("address");
        let seen: Arc<Mutex<Vec<Seen>>> = Arc::default();
        let log = Arc::clone(&seen);
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            while let Ok((stream, _)) = listener.accept().await {
                connections.spawn(serve(stream, answer, Arc::clone(&log)));
            }
        });
        Self { addr, seen, task }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn seen(&self) -> Vec<Seen> {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl Drop for FakeSocksUpstream {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn read_vec(stream: &mut TcpStream, length: usize) -> io::Result<Vec<u8>> {
    let mut bytes = vec![0u8; length];
    stream.read_exact(&mut bytes).await?;
    Ok(bytes)
}

async fn serve(mut s: TcpStream, answer: Answer, log: Arc<Mutex<Vec<Seen>>>) {
    let _ = serve_inner(&mut s, answer, &log).await;
}

async fn serve_inner(
    s: &mut TcpStream,
    answer: Answer,
    log: &Mutex<Vec<Seen>>,
) -> io::Result<()> {
    let push = |entry: Seen| log.lock().unwrap_or_else(PoisonError::into_inner).push(entry);
    let mut greeting = read_vec(s, 2).await?;
    let methods = read_vec(s, usize::from(greeting[1])).await?;
    greeting.extend_from_slice(&methods);
    let mut entry = Seen {
        greeting,
        ..Seen::default()
    };
    if matches!(answer, Answer::NoAcceptableMethod) {
        push(entry);
        return s.write_all(&[5, 0xff]).await;
    }
    if !methods.contains(&2) {
        // A probe: no authentication, and nothing more is sent.
        push(entry);
        s.write_all(&[5, 0]).await?;
        let mut rest = [0u8; 64];
        while s.read(&mut rest).await? != 0 {}
        return Ok(());
    }
    s.write_all(&[5, 2]).await?;
    let mut auth = read_vec(s, 2).await?;
    auth.extend(read_vec(s, usize::from(auth[1])).await?);
    let password_length = read_vec(s, 1).await?;
    auth.extend_from_slice(&password_length);
    auth.extend(read_vec(s, usize::from(password_length[0])).await?);
    entry.auth = auth;
    if matches!(answer, Answer::RefuseAuth) {
        push(entry);
        return s.write_all(&[1, 1]).await;
    }
    s.write_all(&[1, 0]).await?;
    let mut request = read_vec(s, 4).await?;
    match request[3] {
        1 => request.extend(read_vec(s, 4 + 2).await?),
        4 => request.extend(read_vec(s, 16 + 2).await?),
        _ => {
            let length = read_vec(s, 1).await?;
            request.extend_from_slice(&length);
            request.extend(read_vec(s, usize::from(length[0]) + 2).await?);
        }
    }
    entry.request = request;
    push(entry);
    match answer {
        Answer::Reply(code) => s.write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0]).await,
        _ => {
            s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            let mut buffer = [0u8; 1024];
            loop {
                let n = s.read(&mut buffer).await?;
                if n == 0 {
                    return Ok(());
                }
                s.write_all(&buffer[..n]).await?;
            }
        }
    }
}

/// A listener that only counts the connections it accepts: the "target".
pub struct CountingListener {
    addr: SocketAddr,
    count: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl CountingListener {
    pub async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("address");
        let count = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&count);
        let task = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                counter.fetch_add(1, Ordering::SeqCst);
                held.push(stream);
            }
        });
        Self { addr, count, task }
    }

    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    pub fn accepted(&self) -> usize {
        self.count.load(Ordering::SeqCst)
    }
}

impl Drop for CountingListener {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// A loopback address nothing listens on.
pub fn dead_address() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.local_addr().expect("address")
}

/// `05 01 00 03 <len> <host> <port>`: CONNECT to a name.
pub fn request_name(host: &str, port: u16) -> Vec<u8> {
    let length = u8::try_from(host.len()).expect("a name of at most 255 bytes");
    [
        &[5, 1, 0, 3, length][..],
        host.as_bytes(),
        &port.to_be_bytes(),
    ]
    .concat()
}

/// `05 01 00 01 <ip> <port>`: CONNECT to an IPv4 address.
pub fn request_v4(ip: [u8; 4], port: u16) -> Vec<u8> {
    [&[5, 1, 0, 1][..], &ip, &port.to_be_bytes()].concat()
}

/// Reads exactly `count` bytes, or fails the test after five seconds.
pub async fn read_n(stream: &mut TcpStream, count: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; count];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut bytes))
        .await
        .expect("timed out waiting for bytes")
        .expect("the connection ended before the bytes came");
    bytes
}

/// Reads until the peer closes, or fails the test after three seconds.
pub async fn expect_closed(stream: &mut TcpStream) {
    let mut sink = [0u8; 512];
    loop {
        match tokio::time::timeout(Duration::from_secs(3), stream.read(&mut sink)).await {
            Err(_) => panic!("the connection is still open"),
            Ok(Ok(0) | Err(_)) => return,
            Ok(Ok(_)) => {}
        }
    }
}

/// Polls `condition` every 10 ms for three seconds.
pub async fn wait_for(what: &str, mut condition: impl FnMut() -> bool) {
    for _ in 0..300 {
        if condition() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("timed out waiting for {what}");
}

/// Connects to `addr`, offers no authentication and checks the answer.
pub async fn open(addr: SocketAddr) -> TcpStream {
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    stream.write_all(&[5, 1, 0]).await.expect("greeting");
    assert_eq!(read_n(&mut stream, 2).await, [5, 0]);
    stream
}
