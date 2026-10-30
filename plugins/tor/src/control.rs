//! A small client for Tor's control port (control-spec): authenticate, then
//! read `status/bootstrap-phase`. Nothing else is ever sent: the plugin does
//! not change Tor's configuration and has no new-identity call.
//!
//! Authentication is `SAFECOOKIE` (the cookie file proves itself to the control
//! port and the control port proves itself back, so a fake listener on the
//! port learns nothing) or `HASHEDPASSWORD` (the password comes from an
//! environment variable). The raw `COOKIE` method is not used: it sends the
//! cookie itself to whoever listens.

use std::io::Read as _;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use crate::config::ControlAuth;

/// The longest line read from the control port.
const MAX_LINE: u64 = 4096;
/// The most lines in one reply.
const MAX_LINES: usize = 64;
/// The most bytes in one reply.
const MAX_REPLY_BYTES: usize = 16 * 1024;
/// How long the whole conversation may take.
const CONVERSATION_TIMEOUT: Duration = Duration::from_secs(5);
/// The key of the `SERVERHASH` (control-spec, `AUTHCHALLENGE`).
const SERVER_HASH_KEY: &[u8] = b"Tor safe cookie authentication server-to-controller hash";
/// The key of the hash the controller sends in `AUTHENTICATE`.
const CLIENT_HASH_KEY: &[u8] = b"Tor safe cookie authentication controller-to-server hash";
/// Tor's authentication cookies are 32 bytes long, and a controller must not
/// use a file of another length.
const COOKIE_LENGTH: usize = 32;

/// Where a password is read from. The process environment in the plugin;
/// a closure in the tests.
pub(crate) type Env<'a> = &'a (dyn Fn(&str) -> Option<String> + Sync);

/// A reply of the control port: the status code and the text of each line,
/// without the code and the separator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Reply {
    /// The three-digit status code.
    pub(crate) status: u16,
    /// The lines of the reply. A data reply (`250+`) contributes its first
    /// line and then every data line.
    pub(crate) lines: Vec<String>,
}

/// What `GETINFO status/bootstrap-phase` says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Bootstrap {
    /// `PROGRESS`, 0 to 100.
    pub(crate) progress: u8,
    /// `TAG`, such as `done` or `loading_descriptors`.
    pub(crate) tag: String,
    /// `SUMMARY`, if there is one.
    pub(crate) summary: String,
}

/// Reads one reply: lines `250-...` until a line `250 ...`, with data
/// replies (`250+...` and lines up to a single `.`). Every read is bounded.
pub(crate) async fn read_reply<R: AsyncBufRead + Unpin>(reader: &mut R) -> Result<Reply, String> {
    let too_long = || "a reply from the control port is too long".to_owned();
    let mut lines: Vec<String> = Vec::new();
    let mut status: Option<u16> = None;
    let mut bytes = 0usize;
    loop {
        let line = read_line(reader).await?;
        bytes += line.len();
        if lines.len() >= MAX_LINES || bytes > MAX_REPLY_BYTES {
            return Err(too_long());
        }
        let (code, separator, text) = split_status(&line)
            .ok_or_else(|| "the control port sent a malformed reply line".to_owned())?;
        if *status.get_or_insert(code) != code {
            return Err(
                "the status code changed in the middle of a reply from the control port".to_owned(),
            );
        }
        lines.push(text.to_owned());
        match separator {
            b' ' => {
                return Ok(Reply {
                    status: code,
                    lines,
                });
            }
            b'+' => loop {
                let data = read_line(reader).await?;
                bytes += data.len();
                if lines.len() >= MAX_LINES || bytes > MAX_REPLY_BYTES {
                    return Err(too_long());
                }
                if data == "." {
                    break;
                }
                lines.push(data);
            },
            _ => {}
        }
    }
}

/// One line without its line end, at most [`MAX_LINE`] bytes long.
async fn read_line<R: AsyncBufRead + Unpin>(reader: &mut R) -> Result<String, String> {
    let mut bytes = Vec::new();
    let read = (&mut *reader)
        .take(MAX_LINE)
        .read_until(b'\n', &mut bytes)
        .await
        .map_err(|error| format!("reading from the control port failed: {error}"))?;
    if read == 0 {
        return Err("the control port closed the connection".to_owned());
    }
    if bytes.last() != Some(&b'\n') {
        return Err(if u64::try_from(read).is_ok_and(|read| read >= MAX_LINE) {
            "a line from the control port is too long".to_owned()
        } else {
            "the control port closed the connection in the middle of a line".to_owned()
        });
    }
    bytes.pop();
    if bytes.last() == Some(&b'\r') {
        bytes.pop();
    }
    String::from_utf8(bytes)
        .map_err(|_| "the control port sent a line that is not UTF-8".to_owned())
}

/// Splits `250-text` into the code, the separator (`-`, `+` or a space) and the text.
fn split_status(line: &str) -> Option<(u16, u8, &str)> {
    let bytes = line.as_bytes();
    if bytes.len() < 4 || !bytes[..3].iter().all(u8::is_ascii_digit) {
        return None;
    }
    let separator = bytes[3];
    if !matches!(separator, b' ' | b'-' | b'+') {
        return None;
    }
    // The first four bytes are ASCII, so these are character boundaries.
    Some((line[..3].parse().ok()?, separator, &line[4..]))
}

/// Lower-case hexadecimal.
pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}

/// The bytes of a hexadecimal string, or `None` if it is not one.
pub(crate) fn unhex(text: &str) -> Option<Vec<u8>> {
    // `is_multiple_of` is newer than the crate's minimum Rust version.
    if text.len() & 1 == 1 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).ok())
        .collect()
}

/// `password` as a control-port QuotedString: in double quotes, with `\` and
/// `"` escaped. A line break cannot be sent and is refused.
pub(crate) fn quote(password: &str) -> Result<String, String> {
    if password.contains(['\r', '\n']) {
        return Err(
            "the control password contains a line break, which the control port cannot take"
                .to_owned(),
        );
    }
    let mut quoted = String::with_capacity(password.len() + 2);
    quoted.push('"');
    for character in password.chars() {
        if matches!(character, '"' | '\\') {
            quoted.push('\\');
        }
        quoted.push(character);
    }
    quoted.push('"');
    Ok(quoted)
}

/// The methods of the `AUTH METHODS=...` line of a PROTOCOLINFO reply.
pub(crate) fn auth_methods(reply: &Reply) -> Vec<String> {
    reply
        .lines
        .iter()
        .find_map(|line| {
            let fields = line.strip_prefix("AUTH ")?;
            let methods = fields
                .split(' ')
                .find_map(|field| field.strip_prefix("METHODS="))?;
            Some(
                methods
                    .split(',')
                    .filter(|method| !method.is_empty())
                    .map(str::to_owned)
                    .collect(),
            )
        })
        .unwrap_or_default()
}

/// The fields of the value of `status/bootstrap-phase`, such as
/// `NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY="Done"`.
pub(crate) fn parse_bootstrap(value: &str) -> Option<Bootstrap> {
    let fields = fields(value);
    let get = |name: &str| {
        fields
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    };
    get("BOOTSTRAP")?;
    let progress: u8 = get("PROGRESS")?
        .parse()
        .ok()
        .filter(|progress| *progress <= 100)?;
    Some(Bootstrap {
        progress,
        tag: get("TAG").unwrap_or_default().to_owned(),
        summary: get("SUMMARY").unwrap_or_default().to_owned(),
    })
}

/// The `KEY=value` fields of a status line. A value may be a quoted string
/// with `\` escapes. A word without `=` is a field with an empty value.
fn fields(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut chars = text.chars().peekable();
    loop {
        while chars.next_if_eq(&' ').is_some() {}
        let mut key = String::new();
        while let Some(&character) = chars.peek() {
            if character == '=' || character == ' ' {
                break;
            }
            key.push(character);
            chars.next();
        }
        if key.is_empty() {
            return out;
        }
        let mut value = String::new();
        if chars.next_if_eq(&'=').is_some() {
            if chars.next_if_eq(&'"').is_some() {
                while let Some(character) = chars.next() {
                    match character {
                        '\\' => value.extend(chars.next()),
                        '"' => break,
                        other => value.push(other),
                    }
                }
            } else {
                while let Some(&character) = chars.peek() {
                    if character == ' ' {
                        break;
                    }
                    value.push(character);
                    chars.next();
                }
            }
        }
        out.push((key, value));
    }
}

/// Connects to the control port, authenticates as `auth` says and returns the
/// bootstrap phase. The whole conversation takes at most five seconds. The
/// error is a message for the user, without the password or the cookie.
pub(crate) async fn bootstrap_status(
    control: SocketAddr,
    auth: &ControlAuth,
    env: Env<'_>,
) -> Result<Bootstrap, String> {
    // The secret is read first: a missing file or variable is reported
    // without touching the port.
    let secret = Secret::load(auth, env)?;
    tokio::time::timeout(CONVERSATION_TIMEOUT, converse(control, &secret))
        .await
        .map_err(|_| {
            format!(
                "the control port at {control} did not answer within {} seconds",
                CONVERSATION_TIMEOUT.as_secs()
            )
        })?
}

/// What proves the plugin to the control port.
enum Secret {
    /// The contents of the cookie file, 32 bytes, and the file's path.
    Cookie(Vec<u8>, String),
    /// The control password.
    Password(String),
}

impl Secret {
    fn load(auth: &ControlAuth, env: Env<'_>) -> Result<Self, String> {
        match (&auth.cookie_path, &auth.password_env) {
            (Some(path), None) => Ok(Self::Cookie(read_cookie(path)?, path.display().to_string())),
            (None, Some(name)) => env(name)
                .filter(|password| !password.is_empty())
                .map(Self::Password)
                .ok_or_else(|| {
                    format!(
                        "`control_auth.password_env` names the environment variable {name}, \
                         which is not set or is empty"
                    )
                }),
            _ => Err(
                "`control_auth` must name exactly one of `cookie_path` and `password_env`"
                    .to_owned(),
            ),
        }
    }
}

/// The cookie file's contents: exactly 32 bytes, read without trusting its size.
fn read_cookie(path: &Path) -> Result<Vec<u8>, String> {
    let file = std::fs::File::open(path)
        .map_err(|error| format!("cannot read the cookie file {}: {error}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(COOKIE_LENGTH as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read the cookie file {}: {error}", path.display()))?;
    if bytes.len() != COOKIE_LENGTH {
        return Err(format!(
            "the cookie file {} must hold exactly {COOKIE_LENGTH} bytes, as Tor's authentication \
             cookie does",
            path.display()
        ));
    }
    Ok(bytes)
}

type Connection = BufReader<TcpStream>;

async fn converse(control: SocketAddr, secret: &Secret) -> Result<Bootstrap, String> {
    let stream = TcpStream::connect(control)
        .await
        .map_err(|error| format!("cannot reach the control port at {control}: {error}"))?;
    let mut connection = BufReader::new(stream);
    let info = command(&mut connection, "PROTOCOLINFO 1").await?;
    if info.status != 250 {
        return Err(refused("PROTOCOLINFO", &info));
    }
    let methods = auth_methods(&info);
    match secret {
        Secret::Cookie(cookie, path) => {
            safe_cookie(&mut connection, &methods, cookie, path, control).await?;
        }
        Secret::Password(password) => {
            password_login(&mut connection, &methods, password, control).await?;
        }
    }
    let phase = command(&mut connection, "GETINFO status/bootstrap-phase").await?;
    if phase.status != 250 {
        return Err(refused("`GETINFO status/bootstrap-phase`", &phase));
    }
    let bootstrap = phase
        .lines
        .iter()
        .find_map(|line| line.strip_prefix("status/bootstrap-phase="))
        .and_then(parse_bootstrap)
        .ok_or_else(|| {
            "the control port answered `GETINFO status/bootstrap-phase` with something that is \
             not a bootstrap status"
                .to_owned()
        })?;
    // Say goodbye and wait for the answer, so that the port sees the end of the conversation.
    let _ = command(&mut connection, "QUIT").await;
    Ok(bootstrap)
}

/// Sends one command line and reads its reply.
async fn command(connection: &mut Connection, line: &str) -> Result<Reply, String> {
    connection
        .get_mut()
        .write_all(format!("{line}\r\n").as_bytes())
        .await
        .map_err(|error| format!("writing to the control port failed: {error}"))?;
    read_reply(connection).await
}

/// The error for a command that did not get `250`.
fn refused(what: &str, reply: &Reply) -> String {
    format!(
        "the control port refused {what}: {} {}",
        reply.status,
        reply.lines.first().map_or("", String::as_str)
    )
}

/// `SAFECOOKIE`: the control port proves that it knows the cookie before the
/// plugin proves the same, so a fake listener on the port learns nothing.
async fn safe_cookie(
    connection: &mut Connection,
    methods: &[String],
    cookie: &[u8],
    path: &str,
    control: SocketAddr,
) -> Result<(), String> {
    if !methods.iter().any(|method| method == "SAFECOOKIE") {
        return Err(format!(
            "the control port at {control} does not offer SAFECOOKIE (it offers: {}); the \
             plugin never sends the raw cookie, because whatever listens on the port would keep it",
            methods.join(", ")
        ));
    }
    let mut client_nonce = [0u8; 32];
    SystemRandom::new()
        .fill(&mut client_nonce)
        .map_err(|_| "the system random number generator failed".to_owned())?;
    let challenge = command(
        connection,
        &format!("AUTHCHALLENGE SAFECOOKIE {}", hex(&client_nonce)),
    )
    .await?;
    if challenge.status != 250 {
        return Err(refused("AUTHCHALLENGE", &challenge));
    }
    let malformed = || "the control port sent a malformed AUTHCHALLENGE reply".to_owned();
    let fields = fields(
        challenge
            .lines
            .first()
            .and_then(|line| line.strip_prefix("AUTHCHALLENGE "))
            .ok_or_else(malformed)?,
    );
    let field = |name: &str| {
        fields
            .iter()
            .find(|(key, _)| key == name)
            .and_then(|(_, value)| unhex(value))
            .filter(|bytes| bytes.len() == 32)
    };
    let server_hash = field("SERVERHASH").ok_or_else(malformed)?;
    let server_nonce = field("SERVERNONCE").ok_or_else(malformed)?;

    let message = [cookie, &client_nonce, &server_nonce].concat();
    hmac::verify(
        &hmac::Key::new(hmac::HMAC_SHA256, SERVER_HASH_KEY),
        &message,
        &server_hash,
    )
    .map_err(|_| {
        format!(
            "the SERVERHASH of the control port at {control} does not match the cookie in {path}: \
             either that file is not the cookie Tor uses, or what answers on the port does not \
             know the cookie; not authenticating"
        )
    })?;
    let client_hash = hmac::sign(
        &hmac::Key::new(hmac::HMAC_SHA256, CLIENT_HASH_KEY),
        &message,
    );
    let reply = command(
        connection,
        &format!("AUTHENTICATE {}", hex(client_hash.as_ref())),
    )
    .await?;
    if reply.status == 250 {
        Ok(())
    } else {
        Err(refused("the authentication", &reply))
    }
}

/// `HASHEDPASSWORD`: the password is sent in a quoted string. It stays on this
/// machine: the control port is a loopback address.
async fn password_login(
    connection: &mut Connection,
    methods: &[String],
    password: &str,
    control: SocketAddr,
) -> Result<(), String> {
    if !methods.iter().any(|method| method == "HASHEDPASSWORD") {
        return Err(format!(
            "the control port at {control} does not offer HASHEDPASSWORD (it offers: {})",
            methods.join(", ")
        ));
    }
    let reply = command(connection, &format!("AUTHENTICATE {}", quote(password)?)).await?;
    if reply.status == 250 {
        Ok(())
    } else {
        Err(refused("the password", &reply))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::run;

    async fn reply_of(text: &[u8]) -> Result<Reply, String> {
        let mut reader = text;
        read_reply(&mut reader).await
    }

    #[test]
    fn a_reply_ends_at_the_line_with_a_space() {
        run(async {
            let reply = reply_of(b"250-first\r\n250-second\r\n250 OK\r\n")
                .await
                .unwrap();
            assert_eq!(reply.status, 250);
            assert_eq!(reply.lines, ["first", "second", "OK"]);
            let reply = reply_of(b"515 Authentication failed\r\n").await.unwrap();
            assert_eq!(reply.status, 515);
            assert_eq!(reply.lines, ["Authentication failed"]);
        });
    }

    #[test]
    fn a_data_reply_runs_to_the_lone_dot() {
        run(async {
            let reply = reply_of(b"250+info=\r\nline one\r\nline two\r\n.\r\n250 OK\r\n")
                .await
                .unwrap();
            assert_eq!(reply.lines, ["info=", "line one", "line two", "OK"]);
        });
    }

    #[test]
    fn a_lone_line_feed_ends_a_line_like_a_carriage_return_and_line_feed() {
        run(async {
            let reply = reply_of(b"250 OK\n").await.unwrap();
            assert_eq!(reply.lines, ["OK"]);
        });
    }

    #[test]
    fn replies_that_are_malformed_are_errors() {
        run(async {
            for bad in [
                &b""[..],
                b"250 OK",
                b"25\r\n",
                b"abc OK\r\n",
                b"250xOK\r\n",
                b"250-a\r\n251 b\r\n",
                b"\xff\xfe\r\n",
                b"250-no end\r\n",
            ] {
                assert!(reply_of(bad).await.is_err(), "{bad:?}");
            }
        });
    }

    #[test]
    fn a_reply_that_is_too_long_is_an_error_and_not_an_allocation() {
        run(async {
            let long_line = [b"250 ".to_vec(), vec![b'x'; 100_000], b"\r\n".to_vec()].concat();
            assert!(reply_of(&long_line).await.is_err());
            let many_lines: Vec<u8> = (0..500).flat_map(|_| b"250-x\r\n".to_vec()).collect();
            assert!(reply_of(&many_lines).await.is_err());
            let endless_data = [b"250+x\r\n".to_vec(), b"y\r\n".repeat(5_000)].concat();
            assert!(reply_of(&endless_data).await.is_err());
        });
    }

    #[test]
    fn hex_round_trips_and_rejects_what_is_not_hex() {
        assert_eq!(hex(&[0x00, 0xab, 0xff]), "00abff");
        assert_eq!(unhex("00abFF").unwrap(), [0x00, 0xab, 0xff]);
        assert_eq!(unhex("").unwrap(), Vec::<u8>::new());
        for bad in ["0", "zz", "0g", "00 ", "é"] {
            assert!(unhex(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn a_password_is_quoted_with_backslashes_and_quotes_escaped() {
        assert_eq!(quote("plain").unwrap(), "\"plain\"");
        assert_eq!(quote("a\"b\\c").unwrap(), "\"a\\\"b\\\\c\"");
        assert!(quote("two\nlines").is_err());
        assert!(quote("two\rlines").is_err());
    }

    #[test]
    fn the_methods_come_from_the_auth_line() {
        let reply = Reply {
            status: 250,
            lines: vec![
                "PROTOCOLINFO 1".into(),
                "AUTH METHODS=COOKIE,SAFECOOKIE,HASHEDPASSWORD COOKIEFILE=\"/run/tor/control.authcookie\""
                    .into(),
                "VERSION Tor=\"0.4.8.12\"".into(),
                "OK".into(),
            ],
        };
        assert_eq!(
            auth_methods(&reply),
            ["COOKIE", "SAFECOOKIE", "HASHEDPASSWORD"]
        );
        let none = Reply {
            status: 250,
            lines: vec!["PROTOCOLINFO 1".into(), "OK".into()],
        };
        assert!(auth_methods(&none).is_empty());
        let null = Reply {
            status: 250,
            lines: vec!["AUTH METHODS=NULL".into()],
        };
        assert_eq!(auth_methods(&null), ["NULL"]);
    }

    #[test]
    fn the_bootstrap_phase_is_read_from_its_fields() {
        assert_eq!(
            parse_bootstrap("NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"Done\""),
            Some(Bootstrap {
                progress: 100,
                tag: "done".into(),
                summary: "Done".into()
            })
        );
        assert_eq!(
            parse_bootstrap(
                "WARN BOOTSTRAP PROGRESS=10 TAG=conn_pt SUMMARY=\"Connecting to pluggable transport\" WARNING=\"x y\" REASON=NOROUTE"
            ),
            Some(Bootstrap {
                progress: 10,
                tag: "conn_pt".into(),
                summary: "Connecting to pluggable transport".into()
            })
        );
        assert_eq!(
            parse_bootstrap("NOTICE BOOTSTRAP PROGRESS=5 TAG=conn"),
            Some(Bootstrap {
                progress: 5,
                tag: "conn".into(),
                summary: String::new()
            })
        );
        for bad in [
            "",
            "NOTICE BOOTSTRAP TAG=done",
            "NOTICE BOOTSTRAP PROGRESS=abc TAG=done",
            "NOTICE BOOTSTRAP PROGRESS=101 TAG=done",
            "NOTICE BOOTSTRAP PROGRESS=-1",
            "garbage",
        ] {
            assert_eq!(parse_bootstrap(bad), None, "{bad:?}");
        }
    }
}
