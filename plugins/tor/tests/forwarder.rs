//! The forwarder against a fake Tor SocksPort: what Tor is sent, that a name
//! reaches it unresolved, that the target is never dialled, and that bad
//! input, load and shutdown are handled.

mod support;

use std::time::{Duration, Instant};

use seleniumbase_rs_plugin_tor::{Forwarder, IsolationToken, Limits};
use support::{
    Answer, CountingListener, FakeSocksUpstream, dead_address, expect_closed, open, read_n,
    request_name, request_v4, run, wait_for,
};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

const TOKEN: [u8; 16] = [0x11; 16];

async fn forwarder(upstream: std::net::SocketAddr) -> Forwarder {
    Forwarder::start(upstream, IsolationToken::new(TOKEN), Limits::default())
        .await
        .expect("a forwarder")
}

/// The RFC 1929 request for the token `bytes`: version 1, the marker user
/// name, `sbrs-` and the token in hexadecimal.
fn auth_for(bytes: [u8; 16]) -> Vec<u8> {
    let password = format!(
        "sbrs-{}",
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
    );
    let mut auth = vec![1, 9];
    auth.extend_from_slice(b"<torS0X>0");
    auth.push(u8::try_from(password.len()).expect("short"));
    auth.extend_from_slice(password.as_bytes());
    auth
}

#[test]
fn the_name_reaches_tor_unresolved_with_the_isolation_credentials() {
    run(async {
        let upstream = FakeSocksUpstream::start(Answer::Succeed).await;
        let forwarder = forwarder(upstream.addr()).await;
        let mut client = open(forwarder.local_addr()).await;
        client
            .write_all(&request_name("example.onion", 80))
            .await
            .unwrap();
        assert_eq!(
            read_n(&mut client, 10).await,
            [5, 0, 0, 1, 0, 0, 0, 0, 0, 0]
        );
        // The tunnel carries bytes both ways.
        client.write_all(b"ping").await.unwrap();
        assert_eq!(read_n(&mut client, 4).await, b"ping");

        let seen = upstream.seen();
        assert_eq!(seen.len(), 1);
        assert_eq!(
            seen[0].greeting,
            [5, 1, 2],
            "only user name and password is offered"
        );
        assert_eq!(seen[0].auth, auth_for(TOKEN));
        assert_eq!(
            seen[0].request,
            [&[5u8, 1, 0, 3, 13][..], b"example.onion", &[0, 80][..]].concat(),
            "the name goes to Tor as a name"
        );
    });
}

#[test]
fn an_address_is_forwarded_as_an_address() {
    run(async {
        let upstream = FakeSocksUpstream::start(Answer::Succeed).await;
        let forwarder = forwarder(upstream.addr()).await;
        let mut client = open(forwarder.local_addr()).await;
        client
            .write_all(&request_v4([192, 0, 2, 7], 443))
            .await
            .unwrap();
        assert_eq!(read_n(&mut client, 10).await[1], 0);
        assert_eq!(
            upstream.seen()[0].request,
            [5, 1, 0, 1, 192, 0, 2, 7, 1, 187]
        );
    });
}

#[test]
fn one_forwarder_keeps_one_token_and_two_forwarders_never_share_one() {
    run(async {
        let upstream = FakeSocksUpstream::start(Answer::Succeed).await;
        let first = Forwarder::start(
            upstream.addr(),
            IsolationToken::random().unwrap(),
            Limits::default(),
        )
        .await
        .unwrap();
        let second = Forwarder::start(
            upstream.addr(),
            IsolationToken::random().unwrap(),
            Limits::default(),
        )
        .await
        .unwrap();
        for forwarder in [&first, &first, &second] {
            let mut client = open(forwarder.local_addr()).await;
            client
                .write_all(&request_name("a.example", 80))
                .await
                .unwrap();
            assert_eq!(read_n(&mut client, 10).await[1], 0);
        }
        let seen = upstream.seen();
        assert_eq!(seen.len(), 3);
        assert_eq!(
            seen[0].auth, seen[1].auth,
            "streams of one forwarder may share circuits"
        );
        assert_ne!(seen[0].auth, seen[2].auth, "forwarders never share a token");
        assert_ne!(
            IsolationToken::random().unwrap(),
            IsolationToken::random().unwrap()
        );
    });
}

#[test]
fn with_the_upstream_down_the_target_is_never_dialled() {
    run(async {
        let target = CountingListener::start().await;
        let forwarder = forwarder(dead_address()).await;
        for request in [
            request_v4([127, 0, 0, 1], target.port()),
            request_name("localhost", target.port()),
            request_name("127.0.0.1", target.port()),
        ] {
            let mut client = open(forwarder.local_addr()).await;
            client.write_all(&request).await.unwrap();
            let reply = read_n(&mut client, 10).await;
            assert_eq!(reply[0], 5);
            assert_ne!(reply[1], 0, "the browser is told that it failed");
            expect_closed(&mut client).await;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            target.accepted(),
            0,
            "the forwarder never dials the target itself"
        );
    });
}

#[test]
fn a_refusal_from_tor_is_relayed_and_the_target_is_not_dialled() {
    run(async {
        let target = CountingListener::start().await;
        let upstream = FakeSocksUpstream::start(Answer::Reply(5)).await;
        let forwarder = forwarder(upstream.addr()).await;
        let mut client = open(forwarder.local_addr()).await;
        client
            .write_all(&request_v4([127, 0, 0, 1], target.port()))
            .await
            .unwrap();
        assert_eq!(
            read_n(&mut client, 10).await,
            [5, 5, 0, 1, 0, 0, 0, 0, 0, 0]
        );
        expect_closed(&mut client).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(target.accepted(), 0);
    });
}

#[test]
fn when_tor_refuses_the_credentials_or_the_method_the_browser_gets_a_failure() {
    run(async {
        for answer in [Answer::RefuseAuth, Answer::NoAcceptableMethod] {
            let upstream = FakeSocksUpstream::start(answer).await;
            let forwarder = forwarder(upstream.addr()).await;
            let mut client = open(forwarder.local_addr()).await;
            client
                .write_all(&request_name("a.example", 80))
                .await
                .unwrap();
            let reply = read_n(&mut client, 10).await;
            assert_eq!((reply[0], reply[1]), (5, 1), "{answer:?}");
            expect_closed(&mut client).await;
        }
    });
}

#[test]
fn bind_and_udp_associate_get_reply_7_and_tor_is_not_asked() {
    run(async {
        let upstream = FakeSocksUpstream::start(Answer::Succeed).await;
        let forwarder = forwarder(upstream.addr()).await;
        for command in [2u8, 3] {
            let mut client = open(forwarder.local_addr()).await;
            let mut request = request_name("a.example", 80);
            request[1] = command;
            client.write_all(&request).await.unwrap();
            assert_eq!(
                read_n(&mut client, 10).await,
                [5, 7, 0, 1, 0, 0, 0, 0, 0, 0]
            );
            expect_closed(&mut client).await;
        }
        assert!(upstream.seen().is_empty());
    });
}

#[test]
fn an_unknown_address_type_gets_reply_8() {
    run(async {
        let upstream = FakeSocksUpstream::start(Answer::Succeed).await;
        let forwarder = forwarder(upstream.addr()).await;
        let mut client = open(forwarder.local_addr()).await;
        client
            .write_all(&[5, 1, 0, 9, 1, 2, 3, 4, 0, 80])
            .await
            .unwrap();
        assert_eq!(
            read_n(&mut client, 10).await,
            [5, 8, 0, 1, 0, 0, 0, 0, 0, 0]
        );
        expect_closed(&mut client).await;
        assert!(upstream.seen().is_empty());
    });
}

#[test]
fn only_no_authentication_is_accepted_from_the_browser() {
    run(async {
        let upstream = FakeSocksUpstream::start(Answer::Succeed).await;
        let forwarder = forwarder(upstream.addr()).await;
        let mut client = TcpStream::connect(forwarder.local_addr()).await.unwrap();
        client.write_all(&[5, 1, 2]).await.unwrap();
        assert_eq!(read_n(&mut client, 2).await, [5, 0xff]);
        expect_closed(&mut client).await;
        assert!(upstream.seen().is_empty());
    });
}

/// Truncated, wrong and random handshakes, each followed by a close.
fn bad_handshakes() -> Vec<Vec<u8>> {
    let mut all: Vec<Vec<u8>> = vec![
        vec![],
        vec![5],
        vec![5, 2, 0],
        vec![4, 1, 0],
        vec![5, 1, 0, 5, 1, 0, 3, 200],
        vec![5, 1, 0, 5, 1, 0, 1, 1, 2],
        vec![5, 1, 0, 5, 1, 9, 1, 1, 2, 3, 4, 0, 80],
        vec![5, 1, 0, 5, 1, 0, 3, 0, 0, 80],
        b"GET / HTTP/1.1\r\nHost: example\r\n\r\n".to_vec(),
        vec![0xff; 300],
        [&[5u8, 255][..], &[7u8; 255][..]].concat(),
    ];
    let mut state = 0x2545_f491_4f6c_dd1d_u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for round in 0..120u64 {
        let length = usize::try_from(next() % 80).unwrap();
        let mut bytes: Vec<u8> = (0..length)
            .map(|_| u8::try_from(next() % 256).unwrap())
            .collect();
        if round % 3 == 0 && bytes.len() > 8 {
            bytes[..3].copy_from_slice(&[5, 1, 0]);
            bytes[3] = 5;
            bytes[4] = 1;
        }
        all.push(bytes);
    }
    all
}

#[test]
fn garbage_and_truncated_handshakes_never_stop_the_forwarder_or_leak_connections() {
    run(async {
        let upstream = FakeSocksUpstream::start(Answer::Succeed).await;
        let forwarder = forwarder(upstream.addr()).await;
        for bytes in bad_handshakes() {
            let mut client = TcpStream::connect(forwarder.local_addr()).await.unwrap();
            let _ = client.write_all(&bytes).await;
            let _ = client.shutdown().await;
            expect_closed(&mut client).await;
        }
        wait_for("every connection to be released", || {
            forwarder.active_connections() == 0
        })
        .await;

        // Still serving.
        let mut client = open(forwarder.local_addr()).await;
        client
            .write_all(&request_name("ok.example", 80))
            .await
            .unwrap();
        assert_eq!(read_n(&mut client, 10).await[1], 0);
        client.write_all(b"after").await.unwrap();
        assert_eq!(read_n(&mut client, 5).await, b"after");
    });
}

#[test]
fn a_connection_that_does_not_finish_its_handshake_is_closed() {
    run(async {
        let upstream = FakeSocksUpstream::start(Answer::Succeed).await;
        let limits = Limits::default().handshake_timeout(Duration::from_millis(200));
        let forwarder = Forwarder::start(upstream.addr(), IsolationToken::new(TOKEN), limits)
            .await
            .unwrap();

        let started = Instant::now();
        let mut silent = TcpStream::connect(forwarder.local_addr()).await.unwrap();
        expect_closed(&mut silent).await;
        assert!(started.elapsed() < Duration::from_secs(3));

        // Greeting sent, request never: the same limit applies.
        let mut stalled = open(forwarder.local_addr()).await;
        expect_closed(&mut stalled).await;
        wait_for("the connections to be released", || {
            forwarder.active_connections() == 0
        })
        .await;
    });
}

#[test]
fn the_default_limits_are_ten_seconds_and_256_connections() {
    let limits = Limits::default();
    assert_eq!(limits.handshake_timeout, Duration::from_secs(10));
    assert_eq!(limits.max_connections, 256);
}

#[test]
fn a_connection_over_the_limit_is_closed_at_once_and_a_freed_slot_is_reused() {
    run(async {
        let upstream = FakeSocksUpstream::start(Answer::Succeed).await;
        let forwarder = Forwarder::start(
            upstream.addr(),
            IsolationToken::new(TOKEN),
            Limits::default().max_connections(8),
        )
        .await
        .unwrap();
        let mut held = Vec::new();
        for _ in 0..8 {
            held.push(TcpStream::connect(forwarder.local_addr()).await.unwrap());
        }
        wait_for("eight connections", || forwarder.active_connections() == 8).await;

        let mut ninth = TcpStream::connect(forwarder.local_addr()).await.unwrap();
        expect_closed(&mut ninth).await;
        assert_eq!(forwarder.active_connections(), 8);

        // The held connections still work.
        held[0].write_all(&[5, 1, 0]).await.unwrap();
        assert_eq!(read_n(&mut held[0], 2).await, [5, 0]);

        held.pop();
        wait_for("a slot to free", || forwarder.active_connections() == 7).await;
        let _again = open(forwarder.local_addr()).await;
    });
}

#[test]
fn the_257th_connection_is_refused() {
    run(async {
        let upstream = FakeSocksUpstream::start(Answer::Succeed).await;
        let forwarder = forwarder(upstream.addr()).await;
        let mut held = Vec::new();
        for _ in 0..256 {
            held.push(TcpStream::connect(forwarder.local_addr()).await.unwrap());
        }
        wait_for("256 connections", || forwarder.active_connections() == 256).await;
        let mut extra = TcpStream::connect(forwarder.local_addr()).await.unwrap();
        expect_closed(&mut extra).await;
        assert_eq!(forwarder.active_connections(), 256);
    });
}

#[test]
fn dropping_the_forwarder_closes_its_tunnels_and_its_port() {
    run(async {
        let upstream = FakeSocksUpstream::start(Answer::Succeed).await;
        let forwarder = forwarder(upstream.addr()).await;
        let address = forwarder.local_addr();
        let mut client = open(address).await;
        client
            .write_all(&request_name("a.example", 80))
            .await
            .unwrap();
        assert_eq!(read_n(&mut client, 10).await[1], 0);

        drop(forwarder);
        expect_closed(&mut client).await;
        for _ in 0..300 {
            if TcpStream::connect(address).await.is_err() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("the port is still listening");
    });
}

#[test]
fn the_forwarder_listens_on_loopback_and_its_proxy_url_has_no_user_name() {
    run(async {
        let forwarder = forwarder(dead_address()).await;
        let address = forwarder.local_addr();
        assert!(address.ip().is_loopback());
        assert_ne!(address.port(), 0);
        assert_eq!(forwarder.proxy_url(), format!("socks5://{address}"));
        assert!(!forwarder.proxy_url().contains('@'));
    });
}
