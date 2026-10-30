//! Against a real Tor daemon. Ignored: it needs `SB_TEST_TOR_SOCKS` to name the
//! daemon's SocksPort, and it sends one request to `check.torproject.org`
//! through Tor, so it only runs when a person asks for it:
//!
//! ```sh
//! SB_TEST_TOR_SOCKS=127.0.0.1:9050 \
//!     cargo test -p seleniumbase-rs-plugin-tor --test tor_daemon -- --ignored
//! ```

mod support;

use std::net::SocketAddr;
use std::time::Duration;

use seleniumbase_rs_plugin_tor::health::check;
use seleniumbase_rs_plugin_tor::{Forwarder, IsolationToken, Limits, TorConfig};
use support::{read_n, run};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// The SocksPort named by `SB_TEST_TOR_SOCKS`, if any.
fn daemon() -> Option<SocketAddr> {
    let value = std::env::var("SB_TEST_TOR_SOCKS").ok()?;
    Some(
        value.parse().unwrap_or_else(|error| {
            panic!("SB_TEST_TOR_SOCKS={value:?} is not an address: {error}")
        }),
    )
}

#[test]
#[ignore = "needs a real Tor daemon: set SB_TEST_TOR_SOCKS=127.0.0.1:9050"]
fn a_real_tor_daemon_passes_the_check_and_carries_a_request_through_the_forwarder() {
    let Some(socks) = daemon() else {
        eprintln!("SB_TEST_TOR_SOCKS is not set: skipped");
        return;
    };
    run(async {
        check(&TorConfig::new().socks(socks).require_bootstrapped(false))
            .await
            .expect("something answers as SOCKS5 at the SocksPort");

        let forwarder =
            Forwarder::start(socks, IsolationToken::random().unwrap(), Limits::default())
                .await
                .expect("a forwarder");
        let mut client = TcpStream::connect(forwarder.local_addr()).await.unwrap();
        client.write_all(&[5, 1, 0]).await.unwrap();
        assert_eq!(read_n(&mut client, 2).await, [5, 0]);
        let name = "check.torproject.org";
        let mut request = vec![5, 1, 0, 3, u8::try_from(name.len()).unwrap()];
        request.extend_from_slice(name.as_bytes());
        request.extend_from_slice(&80u16.to_be_bytes());
        client.write_all(&request).await.unwrap();
        let reply = tokio::time::timeout(Duration::from_secs(90), read_n(&mut client, 10))
            .await
            .expect("Tor answered the CONNECT within 90 seconds");
        assert_eq!(reply[1], 0, "Tor made the connection");

        client
            .write_all(
                b"GET /api/ip HTTP/1.0\r\nHost: check.torproject.org\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        let mut body = Vec::new();
        tokio::time::timeout(Duration::from_secs(90), client.read_to_end(&mut body))
            .await
            .expect("the answer came within 90 seconds")
            .expect("read the answer");
        let text = String::from_utf8_lossy(&body);
        assert!(text.contains("\"IsTor\":true"), "{text}");
    });
}
