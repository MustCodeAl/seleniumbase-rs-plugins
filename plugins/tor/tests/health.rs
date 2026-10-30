//! The start-up checks against a fake SocksPort and a fake control port.

mod support;

use std::net::SocketAddr;
use std::path::PathBuf;

use seleniumbase_rs_plugin::PluginError;
use seleniumbase_rs_plugin_tor::health::{check, check_with, no_listener_message};
use seleniumbase_rs_plugin_tor::{ControlAuth, TorConfig};
use support::control::{FakeControlPort, Script};
use support::{Answer, FakeSocksUpstream, dead_address, run};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

fn password_env(name: &str) -> Option<String> {
    (name == "TOR_CONTROL_PASSWORD").then(|| "s3cret".to_owned())
}

/// The message of the error; the check always fails with a user message.
fn message(outcome: Result<(), PluginError>) -> String {
    match outcome {
        Err(PluginError::Other(message)) => message,
        other => panic!("expected an error with a message, got {other:?}"),
    }
}

fn cookie_file(contents: &[u8]) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("a temporary folder");
    let path = dir.path().join("control.authcookie");
    std::fs::write(&path, contents).expect("write the cookie");
    (dir, path)
}

fn config(socks: SocketAddr, control: SocketAddr, auth: ControlAuth) -> TorConfig {
    TorConfig::new().socks(socks).control(control, auth)
}

#[test]
fn a_bootstrapped_tor_passes_with_the_cookie() {
    run(async {
        let socks = FakeSocksUpstream::start(Answer::Succeed).await;
        let control = FakeControlPort::start(Script::new()).await;
        let (_dir, path) = cookie_file(&[7; 32]);
        let config = config(socks.addr(), control.addr(), ControlAuth::cookie(&path));
        check_with(&config, &|_| None).await.expect("ready");

        let commands = control.commands();
        assert_eq!(commands[0], "PROTOCOLINFO 1");
        assert!(
            commands[1].starts_with("AUTHCHALLENGE SAFECOOKIE "),
            "{commands:?}"
        );
        assert!(commands[2].starts_with("AUTHENTICATE "), "{commands:?}");
        assert_eq!(commands[3], "GETINFO status/bootstrap-phase");
        assert_eq!(commands.last().map(String::as_str), Some("QUIT"));
        assert_eq!(commands.len(), 5, "nothing else is ever sent: {commands:?}");
    });
}

#[test]
fn a_password_from_the_environment_authenticates() {
    run(async {
        let socks = FakeSocksUpstream::start(Answer::Succeed).await;
        let control = FakeControlPort::start(Script::new()).await;
        let config = config(
            socks.addr(),
            control.addr(),
            ControlAuth::password_env("TOR_CONTROL_PASSWORD"),
        );
        check_with(&config, &password_env).await.expect("ready");
        let commands = control.commands();
        assert_eq!(commands[1], "AUTHENTICATE \"s3cret\"");
    });
}

#[test]
fn a_tor_that_is_still_bootstrapping_is_refused_with_its_progress() {
    run(async {
        let socks = FakeSocksUpstream::start(Answer::Succeed).await;
        let mut script = Script::new();
        script.bootstrap =
            "NOTICE BOOTSTRAP PROGRESS=45 TAG=loading_descriptors SUMMARY=\"Loading relay descriptors\""
                .to_owned();
        let control = FakeControlPort::start(script).await;
        let (_dir, path) = cookie_file(&[7; 32]);
        let config = config(socks.addr(), control.addr(), ControlAuth::cookie(path));
        let text = message(check_with(&config, &|_| None).await);
        assert!(text.contains("bootstrapping"), "{text}");
        assert!(text.contains("45"), "{text}");
        assert!(text.contains("loading_descriptors"), "{text}");
        assert!(text.contains("require_bootstrapped"), "{text}");
    });
}

#[test]
fn with_require_bootstrapped_off_the_control_port_is_never_contacted() {
    run(async {
        let socks = FakeSocksUpstream::start(Answer::Succeed).await;
        let config = config(socks.addr(), dead_address(), ControlAuth::cookie("/x"))
            .require_bootstrapped(false);
        check_with(&config, &|_| None)
            .await
            .expect("only the SOCKS listener is checked");
    });
}

#[test]
fn without_a_control_port_only_the_socks_listener_is_checked() {
    run(async {
        let socks = FakeSocksUpstream::start(Answer::Succeed).await;
        let config = TorConfig::new().socks(socks.addr());
        check_with(&config, &|_| None)
            .await
            .expect("a listener is enough");
        // The probe asked for no circuit: it sent a greeting and nothing else.
        let seen = socks.seen();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].greeting, [5, 1, 0]);
        assert!(seen[0].request.is_empty());
    });
}

#[test]
fn the_server_hash_is_checked_before_the_cookie_proof_is_sent() {
    run(async {
        let socks = FakeSocksUpstream::start(Answer::Succeed).await;
        let mut script = Script::new();
        script.bad_server_hash = true;
        let control = FakeControlPort::start(script).await;
        let (_dir, path) = cookie_file(&[7; 32]);
        let config = config(socks.addr(), control.addr(), ControlAuth::cookie(path));
        let text = message(check_with(&config, &|_| None).await);
        assert!(
            text.contains("SERVERHASH") || text.contains("prove"),
            "{text}"
        );
        assert!(
            !control.authenticate_seen(),
            "the proof was sent to a control port that failed to prove itself: {:?}",
            control.commands()
        );
    });
}

#[test]
fn a_cookie_that_is_not_the_control_ports_is_caught_by_the_server_hash() {
    run(async {
        let socks = FakeSocksUpstream::start(Answer::Succeed).await;
        let control = FakeControlPort::start(Script::new()).await;
        let (_dir, path) = cookie_file(&[9; 32]);
        let config = config(socks.addr(), control.addr(), ControlAuth::cookie(&path));
        let text = message(check_with(&config, &|_| None).await);
        assert!(text.contains("SERVERHASH"), "{text}");
        assert!(text.contains(&path.display().to_string()), "{text}");
        assert!(
            !control.authenticate_seen(),
            "no proof is sent when the server hash does not match: {:?}",
            control.commands()
        );
    });
}

#[test]
fn the_raw_cookie_is_never_sent() {
    run(async {
        let socks = FakeSocksUpstream::start(Answer::Succeed).await;
        let mut script = Script::new();
        script.methods = "COOKIE,HASHEDPASSWORD".to_owned();
        let control = FakeControlPort::start(script).await;
        let (_dir, path) = cookie_file(&[7; 32]);
        let config = config(socks.addr(), control.addr(), ControlAuth::cookie(path));
        let text = message(check_with(&config, &|_| None).await);
        assert!(text.contains("SAFECOOKIE"), "{text}");
        assert!(!control.authenticate_seen(), "{:?}", control.commands());
    });
}

#[test]
fn a_password_is_refused_when_the_control_port_does_not_offer_it() {
    run(async {
        let socks = FakeSocksUpstream::start(Answer::Succeed).await;
        let mut script = Script::new();
        script.methods = "NULL".to_owned();
        let control = FakeControlPort::start(script).await;
        let config = config(
            socks.addr(),
            control.addr(),
            ControlAuth::password_env("TOR_CONTROL_PASSWORD"),
        );
        let text = message(check_with(&config, &password_env).await);
        assert!(text.contains("HASHEDPASSWORD"), "{text}");
        assert!(!control.authenticate_seen());
    });
}

#[test]
fn a_wrong_password_is_refused_and_never_echoed() {
    run(async {
        let socks = FakeSocksUpstream::start(Answer::Succeed).await;
        let control = FakeControlPort::start(Script::new()).await;
        let config = config(
            socks.addr(),
            control.addr(),
            ControlAuth::password_env("TOR_CONTROL_PASSWORD"),
        );
        let text = message(check_with(&config, &|_| Some("hunter2".to_owned())).await);
        assert!(text.contains("515") || text.contains("refused"), "{text}");
        assert!(!text.contains("hunter2"), "{text}");
    });
}

#[test]
fn a_missing_environment_variable_is_named_and_the_control_port_is_not_contacted() {
    run(async {
        let socks = FakeSocksUpstream::start(Answer::Succeed).await;
        let control = FakeControlPort::start(Script::new()).await;
        let config = config(
            socks.addr(),
            control.addr(),
            ControlAuth::password_env("TOR_CONTROL_PASSWORD"),
        );
        let text = message(check_with(&config, &|_| None).await);
        assert!(text.contains("TOR_CONTROL_PASSWORD"), "{text}");
        assert!(control.commands().is_empty(), "{:?}", control.commands());
    });
}

#[test]
fn a_cookie_file_that_is_missing_or_not_32_bytes_is_refused() {
    run(async {
        let socks = FakeSocksUpstream::start(Answer::Succeed).await;
        let control = FakeControlPort::start(Script::new()).await;

        let missing = config(
            socks.addr(),
            control.addr(),
            ControlAuth::cookie("/nonexistent/sbrs/control.authcookie"),
        );
        let text = message(check_with(&missing, &|_| None).await);
        assert!(
            text.contains("/nonexistent/sbrs/control.authcookie"),
            "{text}"
        );

        for contents in [vec![7u8; 31], vec![7u8; 33], vec![7u8; 1 << 20], Vec::new()] {
            let (_dir, path) = cookie_file(&contents);
            let config = config(socks.addr(), control.addr(), ControlAuth::cookie(path));
            let text = message(check_with(&config, &|_| None).await);
            assert!(text.contains("32"), "{} bytes: {text}", contents.len());
        }
        assert!(!control.authenticate_seen());
    });
}

#[test]
fn no_listener_fails_closed_and_names_the_address() {
    run(async {
        let dead = dead_address();
        let config = TorConfig::new().socks(dead);
        let text = message(check(&config).await);
        assert_eq!(text, no_listener_message(dead));
        assert!(text.contains(&dead.to_string()), "{text}");
        assert!(text.contains("sbrs never installs or starts Tor"), "{text}");
    });
}

#[test]
fn something_that_is_not_a_socks_proxy_is_refused() {
    run(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let _ = stream
                    .write_all(b"HTTP/1.0 501 Tor is not an HTTP Proxy\r\n\r\n")
                    .await;
            }
        });
        let text = message(check(&TorConfig::new().socks(address)).await);
        assert!(text.contains("SOCKS5"), "{text}");
        assert!(text.contains(&address.to_string()), "{text}");
        task.abort();
    });
}

#[test]
fn a_control_port_that_is_down_is_reported_with_its_address() {
    run(async {
        let socks = FakeSocksUpstream::start(Answer::Succeed).await;
        let dead = dead_address();
        let (_dir, path) = cookie_file(&[7; 32]);
        let config = config(socks.addr(), dead, ControlAuth::cookie(path));
        let text = message(check_with(&config, &|_| None).await);
        assert!(text.contains("control port"), "{text}");
        assert!(text.contains(&dead.to_string()), "{text}");
    });
}

#[test]
fn a_control_port_that_sends_garbage_or_hangs_up_is_an_error_and_not_a_hang() {
    run(async {
        let socks = FakeSocksUpstream::start(Answer::Succeed).await;
        let (_dir, path) = cookie_file(&[7; 32]);
        let garbage: Vec<Vec<u8>> = vec![
            Vec::new(),
            b"garbage\r\n".to_vec(),
            vec![b'x'; 10_000],
            b"250-AUTH METHODS=SAFECOOKIE\r\n".to_vec(),
            b"250-PROTOCOLINFO 1\r\n250 OK\r\n".to_vec(),
            b"510 Unrecognized command\r\n".to_vec(),
        ];
        for bytes in garbage {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let sent = bytes.clone();
            let task = tokio::spawn(async move {
                if let Ok((mut stream, _)) = listener.accept().await {
                    let _ = stream.write_all(&sent).await;
                    let _ = stream.shutdown().await;
                }
            });
            let config = config(socks.addr(), address, ControlAuth::cookie(&path));
            let text = message(check_with(&config, &|_| None).await);
            assert!(!text.is_empty(), "{} bytes", bytes.len());
            task.abort();
        }
    });
}

#[test]
fn the_cookie_and_password_never_appear_in_an_error() {
    run(async {
        let socks = FakeSocksUpstream::start(Answer::Succeed).await;
        let mut script = Script::new();
        script.bad_server_hash = true;
        let control = FakeControlPort::start(script).await;
        let (_dir, path) = cookie_file(&[0x41; 32]);
        let config = config(socks.addr(), control.addr(), ControlAuth::cookie(path));
        let text = message(check_with(&config, &|_| None).await);
        assert!(!text.contains("AAAAAAAA"), "{text}");
        assert!(!text.contains(&"41".repeat(8)), "{text}");
    });
}
