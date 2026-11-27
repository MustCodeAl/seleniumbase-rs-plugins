//! A fake Tor control port that speaks enough of the control protocol
//! (PROTOCOLINFO, AUTHCHALLENGE SAFECOOKIE, AUTHENTICATE, GETINFO, QUIT) and
//! writes down every command it receives.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};

use ring::hmac;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

const SERVER_KEY: &[u8] = b"Tor safe cookie authentication server-to-controller hash";
const CLIENT_KEY: &[u8] = b"Tor safe cookie authentication controller-to-server hash";

/// What `GETINFO status/bootstrap-phase` says once Tor is ready.
pub const DONE: &str = "NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"Done\"";

/// How the fake control port behaves.
#[derive(Clone, Debug)]
pub struct Script {
    /// The `METHODS=` list of the PROTOCOLINFO reply.
    pub methods: String,
    /// The cookie the fake knows (SAFECOOKIE).
    pub cookie: Vec<u8>,
    /// The password the fake accepts (HASHEDPASSWORD).
    pub password: Option<String>,
    /// The value of `status/bootstrap-phase`.
    pub bootstrap: String,
    /// Send a SERVERHASH that is wrong.
    pub bad_server_hash: bool,
}

impl Script {
    pub fn new() -> Self {
        Self {
            methods: "COOKIE,SAFECOOKIE,HASHEDPASSWORD".to_owned(),
            cookie: vec![7; 32],
            password: Some("s3cret".to_owned()),
            bootstrap: DONE.to_owned(),
            bad_server_hash: false,
        }
    }
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn mac(key: &[u8], message: &[u8]) -> Vec<u8> {
    hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), message)
        .as_ref()
        .to_vec()
}

pub struct FakeControlPort {
    addr: SocketAddr,
    log: Arc<Mutex<Vec<String>>>,
    task: JoinHandle<()>,
}

impl FakeControlPort {
    pub async fn start(script: Script) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("address");
        let log: Arc<Mutex<Vec<String>>> = Arc::default();
        let shared = Arc::clone(&log);
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(serve(stream, script.clone(), Arc::clone(&shared)));
            }
        });
        Self { addr, log, task }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Every command line received, in order.
    pub fn commands(&self) -> Vec<String> {
        self.log
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Whether any AUTHENTICATE arrived.
    pub fn authenticate_seen(&self) -> bool {
        self.commands()
            .iter()
            .any(|line| line.starts_with("AUTHENTICATE"))
    }
}

impl Drop for FakeControlPort {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve(stream: TcpStream, script: Script, log: Arc<Mutex<Vec<String>>>) {
    let (read, mut write) = stream.into_split();
    let mut lines = BufReader::new(read).lines();
    let mut challenge: Option<Vec<u8>> = None;
    let mut authenticated = false;
    while let Ok(Some(line)) = lines.next_line().await {
        log.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(line.clone());
        let mut close = false;
        let reply = if line == "PROTOCOLINFO 1" {
            format!(
                "250-PROTOCOLINFO 1\r\n250-AUTH METHODS={} COOKIEFILE=\"/fake/control.authcookie\"\r\n\
                 250-VERSION Tor=\"0.4.8.12\"\r\n250 OK\r\n",
                script.methods
            )
        } else if let Some(client_nonce) = line.strip_prefix("AUTHCHALLENGE SAFECOOKIE ") {
            let client_nonce = unhex(client_nonce);
            let server_nonce = vec![0xab; 32];
            let message = [&script.cookie[..], &client_nonce, &server_nonce].concat();
            let mut server_hash = mac(SERVER_KEY, &message);
            if script.bad_server_hash {
                server_hash[0] ^= 0xff;
            }
            challenge = Some(message);
            format!(
                "250 AUTHCHALLENGE SERVERHASH={} SERVERNONCE={}\r\n",
                hex(&server_hash),
                hex(&server_nonce)
            )
        } else if let Some(argument) = line.strip_prefix("AUTHENTICATE") {
            let argument = argument.trim();
            let accepted = match (&challenge, &script.password) {
                (Some(message), _) => argument == hex(&mac(CLIENT_KEY, message)),
                (None, Some(password)) => {
                    argument
                        == format!(
                            "\"{}\"",
                            password.replace('\\', "\\\\").replace('"', "\\\"")
                        )
                }
                (None, None) => false,
            };
            authenticated = accepted;
            if accepted {
                "250 OK\r\n".to_owned()
            } else {
                close = true;
                "515 Authentication failed: wrong credentials.\r\n".to_owned()
            }
        } else if line == "GETINFO status/bootstrap-phase" {
            if authenticated {
                format!(
                    "250-status/bootstrap-phase={}\r\n250 OK\r\n",
                    script.bootstrap
                )
            } else {
                close = true;
                "514 Authentication required.\r\n".to_owned()
            }
        } else if line == "QUIT" {
            close = true;
            "250 closing connection\r\n".to_owned()
        } else {
            "510 Unrecognized command\r\n".to_owned()
        };
        if write.write_all(reply.as_bytes()).await.is_err() || close {
            return;
        }
    }
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).expect("hex"))
        .collect()
}
