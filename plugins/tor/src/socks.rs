//! The SOCKS5 wire format (RFC 1928, and RFC 1929 for the user name and
//! password) that the forwarder speaks to the browser and to Tor.
//!
//! Every read is bounded: a field is at most 255 bytes long, so a peer cannot
//! make a connection allocate more than a few hundred bytes.

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The protocol version byte.
pub(crate) const VERSION: u8 = 5;
/// Method: no authentication.
pub(crate) const NO_AUTH: u8 = 0x00;
/// Method: user name and password (RFC 1929).
pub(crate) const USER_PASS: u8 = 0x02;
/// Method reply: none of the offered methods is acceptable.
pub(crate) const NO_ACCEPTABLE: u8 = 0xff;
/// Command: CONNECT, the only one the forwarder serves.
pub(crate) const CMD_CONNECT: u8 = 0x01;

/// Reply codes of RFC 1928, section 6.
pub(crate) mod rep {
    /// Succeeded.
    pub(crate) const SUCCEEDED: u8 = 0x00;
    /// General SOCKS server failure.
    pub(crate) const GENERAL_FAILURE: u8 = 0x01;
    /// Command not supported (BIND, UDP ASSOCIATE).
    pub(crate) const COMMAND_NOT_SUPPORTED: u8 = 0x07;
    /// Address type not supported.
    pub(crate) const ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;
}

/// The address a client wants to reach, as it wrote it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Host {
    /// An IPv4 address.
    V4([u8; 4]),
    /// An IPv6 address.
    V6([u8; 16]),
    /// A name, 1 to 255 bytes, which the proxy resolves.
    Name(Vec<u8>),
}

/// What a CONNECT request asks for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Target {
    /// The address.
    pub(crate) host: Host,
    /// The port.
    pub(crate) port: u16,
}

/// Why a handshake step failed.
#[derive(Debug)]
pub(crate) enum Error {
    /// The stream failed or ended early. There is nobody to answer.
    Io(io::Error),
    /// The peer sent something that is not SOCKS5. Close without answering.
    Protocol(&'static str),
    /// A well-formed request that is not served: answer with this reply code,
    /// then close.
    Refuse(u8),
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// The user name and password sent to the upstream proxy (RFC 1929).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Credentials {
    /// The user name, at most 255 bytes.
    pub(crate) username: Vec<u8>,
    /// The password, at most 255 bytes.
    pub(crate) password: Vec<u8>,
}

/// Reads the client's greeting and returns the methods it offers.
pub(crate) async fn read_greeting<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>, Error> {
    let mut head = [0u8; 2];
    reader.read_exact(&mut head).await?;
    if head[0] != VERSION {
        return Err(Error::Protocol("the greeting is not SOCKS5"));
    }
    let mut methods = vec![0u8; usize::from(head[1])];
    reader.read_exact(&mut methods).await?;
    Ok(methods)
}

/// Reads a request. Only CONNECT is served: another command is read to the end
/// and refused with [`rep::COMMAND_NOT_SUPPORTED`], an address type that is
/// not known with [`rep::ADDRESS_TYPE_NOT_SUPPORTED`].
pub(crate) async fn read_request<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Target, Error> {
    let mut head = [0u8; 4];
    reader.read_exact(&mut head).await?;
    let [version, command, reserved, address_type] = head;
    if version != VERSION {
        return Err(Error::Protocol("the request is not SOCKS5"));
    }
    if reserved != 0 {
        return Err(Error::Protocol("the reserved byte of the request is not zero"));
    }
    let host = match address_type {
        0x01 => {
            let mut address = [0u8; 4];
            reader.read_exact(&mut address).await?;
            Host::V4(address)
        }
        0x03 => {
            let mut length = [0u8; 1];
            reader.read_exact(&mut length).await?;
            if length[0] == 0 {
                return Err(Error::Protocol("the request names an empty host"));
            }
            let mut name = vec![0u8; usize::from(length[0])];
            reader.read_exact(&mut name).await?;
            Host::Name(name)
        }
        0x04 => {
            let mut address = [0u8; 16];
            reader.read_exact(&mut address).await?;
            Host::V6(address)
        }
        _ => return Err(Error::Refuse(rep::ADDRESS_TYPE_NOT_SUPPORTED)),
    };
    let mut port = [0u8; 2];
    reader.read_exact(&mut port).await?;
    if command != CMD_CONNECT {
        return Err(Error::Refuse(rep::COMMAND_NOT_SUPPORTED));
    }
    Ok(Target {
        host,
        port: u16::from_be_bytes(port),
    })
}

/// The bytes of a CONNECT request for `target`.
pub(crate) fn encode_request(target: &Target) -> Vec<u8> {
    let mut out = vec![VERSION, CMD_CONNECT, 0];
    match &target.host {
        Host::V4(address) => {
            out.push(0x01);
            out.extend_from_slice(address);
        }
        Host::V6(address) => {
            out.push(0x04);
            out.extend_from_slice(address);
        }
        Host::Name(name) => {
            // A parsed name is at most 255 bytes; cut a longer one rather than lie about its length.
            let name = &name[..name.len().min(usize::from(u8::MAX))];
            out.push(0x03);
            out.push(u8::try_from(name.len()).unwrap_or(u8::MAX));
            out.extend_from_slice(name);
        }
    }
    out.extend_from_slice(&target.port.to_be_bytes());
    out
}

/// A ten-byte reply with the reply code `code` and an all-zero bound address.
pub(crate) const fn reply(code: u8) -> [u8; 10] {
    [VERSION, code, 0, 0x01, 0, 0, 0, 0, 0, 0]
}

/// Does the client side towards the upstream proxy: offers user name and
/// password only, authenticates with `credentials`, sends CONNECT for `target`
/// and reads the reply.
///
/// Returns `Ok(())` once the proxy says the connection is made; the stream is
/// then a tunnel. A refusal is `Err(Error::Refuse(code))` with the proxy's
/// reply code.
pub(crate) async fn client_connect<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    credentials: &Credentials,
    target: &Target,
) -> Result<(), Error> {
    stream.write_all(&[VERSION, 1, USER_PASS]).await?;
    let mut chosen = [0u8; 2];
    stream.read_exact(&mut chosen).await?;
    if chosen[0] != VERSION {
        return Err(Error::Protocol("the upstream proxy is not a SOCKS5 server"));
    }
    if chosen[1] != USER_PASS {
        return Err(Error::Protocol(
            "the upstream proxy does not accept user name and password authentication",
        ));
    }
    let (Ok(user_length), Ok(password_length)) = (
        u8::try_from(credentials.username.len()),
        u8::try_from(credentials.password.len()),
    ) else {
        return Err(Error::Protocol("the isolation credentials are too long"));
    };
    let mut auth = Vec::with_capacity(3 + credentials.username.len() + credentials.password.len());
    auth.push(0x01);
    auth.push(user_length);
    auth.extend_from_slice(&credentials.username);
    auth.push(password_length);
    auth.extend_from_slice(&credentials.password);
    stream.write_all(&auth).await?;
    let mut status = [0u8; 2];
    stream.read_exact(&mut status).await?;
    if status != [0x01, 0x00] {
        return Err(Error::Protocol(
            "the upstream proxy refused the isolation credentials",
        ));
    }

    stream.write_all(&encode_request(target)).await?;
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != VERSION {
        return Err(Error::Protocol("the upstream reply is not SOCKS5"));
    }
    if head[1] != rep::SUCCEEDED {
        return Err(Error::Refuse(head[1]));
    }
    // The bound address is of no use here: read it so the tunnel starts clean.
    let bound = match head[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut length = [0u8; 1];
            stream.read_exact(&mut length).await?;
            usize::from(length[0])
        }
        _ => {
            return Err(Error::Protocol(
                "the upstream reply has an unknown address type",
            ));
        }
    };
    let mut skipped = vec![0u8; bound + 2];
    stream.read_exact(&mut skipped).await?;
    Ok(())
}

/// Checks that whatever answers on `stream` speaks SOCKS5: sends a greeting
/// that offers no authentication and reads the method reply. Nothing is
/// requested, so no traffic leaves the machine.
pub(crate) async fn probe<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) -> Result<(), Error> {
    stream.write_all(&[VERSION, 1, NO_AUTH]).await?;
    let mut answer = [0u8; 2];
    stream.read_exact(&mut answer).await?;
    if answer[0] == VERSION {
        Ok(())
    } else {
        Err(Error::Protocol("the answer is not a SOCKS5 method reply"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::run;

    fn name(text: &str, port: u16) -> Target {
        Target {
            host: Host::Name(text.as_bytes().to_vec()),
            port,
        }
    }

    fn request_bytes() -> Vec<Vec<u8>> {
        let mut all = vec![
            vec![5, 1, 0, 1, 1, 2, 3, 4, 0, 80],
            {
                let mut v = vec![5, 1, 0, 4];
                v.extend_from_slice(&[0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
                v.extend_from_slice(&[0x01, 0xbb]);
                v
            },
            encode_request(&name("example.onion", 443)),
        ];
        all.push(encode_request(&name(&"a".repeat(255), 1)));
        all
    }

    /// A small deterministic generator, so the fuzz cases are the same on every run.
    struct Xorshift(u64);

    impl Xorshift {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn byte(&mut self) -> u8 {
            (self.next() >> 24) as u8
        }
    }

    #[test]
    fn a_greeting_lists_the_offered_methods() {
        run(async {
            assert_eq!(read_greeting(&mut &[5u8, 1, 0][..]).await.unwrap(), [0]);
            assert_eq!(
                read_greeting(&mut &[5u8, 2, 0, 2][..]).await.unwrap(),
                [0, 2]
            );
            assert!(
                read_greeting(&mut &[5u8, 0][..])
                    .await
                    .unwrap()
                    .is_empty()
            );
        });
    }

    #[test]
    fn a_greeting_for_another_version_or_cut_short_is_an_error() {
        run(async {
            assert!(matches!(
                read_greeting(&mut &[4u8, 1, 0][..]).await,
                Err(Error::Protocol(_))
            ));
            for cut in [&[][..], &[5][..], &[5, 2, 0][..]] {
                let mut bytes = cut;
                assert!(matches!(
                    read_greeting(&mut bytes).await,
                    Err(Error::Io(_))
                ));
            }
        });
    }

    #[test]
    fn requests_round_trip_for_every_address_type() {
        run(async {
            for target in [
                Target {
                    host: Host::V4([192, 0, 2, 1]),
                    port: 80,
                },
                Target {
                    host: Host::V6([1; 16]),
                    port: 65535,
                },
                name("example.onion", 443),
                name("x", 0),
                name(&"b".repeat(255), 8080),
            ] {
                let bytes = encode_request(&target);
                assert_eq!(read_request(&mut &bytes[..]).await.unwrap(), target);
            }
        });
    }

    #[test]
    fn the_name_reaches_the_request_unresolved() {
        let bytes = encode_request(&name("example.onion", 80));
        assert_eq!(
            bytes,
            [
                &[5u8, 1, 0, 3, 13][..],
                b"example.onion",
                &[0, 80][..]
            ]
            .concat()
        );
    }

    #[test]
    fn bind_and_udp_associate_are_refused_with_reply_7_after_the_whole_request() {
        run(async {
            for command in [2u8, 3] {
                let mut bytes: &[u8] = &[5, command, 0, 1, 1, 2, 3, 4, 0, 80, 0xaa];
                let outcome = read_request(&mut bytes).await;
                assert!(
                    matches!(outcome, Err(Error::Refuse(rep::COMMAND_NOT_SUPPORTED))),
                    "{outcome:?}"
                );
                assert_eq!(bytes, [0xaa], "the whole request was read");
            }
        });
    }

    #[test]
    fn an_unknown_address_type_is_refused_with_reply_8() {
        run(async {
            for atyp in [0u8, 2, 5, 9, 255] {
                let outcome = read_request(&mut &[5u8, 1, 0, atyp, 1, 2, 3, 4, 0, 80][..]).await;
                assert!(
                    matches!(outcome, Err(Error::Refuse(rep::ADDRESS_TYPE_NOT_SUPPORTED))),
                    "{atyp}: {outcome:?}"
                );
            }
        });
    }

    #[test]
    fn a_request_that_is_not_socks5_is_an_error_without_a_reply() {
        run(async {
            for bytes in [
                &[4u8, 1, 0, 1, 1, 2, 3, 4, 0, 80][..],
                &[5, 1, 7, 1, 1, 2, 3, 4, 0, 80][..],
                &[5, 1, 0, 3, 0, 0, 80][..],
            ] {
                let outcome = read_request(&mut &bytes[..]).await;
                assert!(matches!(outcome, Err(Error::Protocol(_))), "{outcome:?}");
            }
        });
    }

    #[test]
    fn every_truncation_of_a_request_is_an_error_and_never_a_panic() {
        run(async {
            for full in request_bytes() {
                for cut in 0..full.len() {
                    let mut bytes = &full[..cut];
                    let outcome = read_request(&mut bytes).await;
                    assert!(outcome.is_err(), "cut at {cut} of {}: {outcome:?}", full.len());
                }
            }
        });
    }

    #[test]
    fn random_bytes_never_panic_and_a_name_stays_within_bounds() {
        run(async {
            let mut rng = Xorshift(0x9e37_79b9_7f4a_7c15);
            for round in 0..4_000 {
                let length = (rng.next() % 300) as usize;
                let mut bytes: Vec<u8> = (0..length).map(|_| rng.byte()).collect();
                if round % 2 == 0 && bytes.len() >= 4 {
                    // Start like a real request so the parser gets past the header.
                    bytes[0] = 5;
                    bytes[1] = 1;
                    bytes[2] = 0;
                    bytes[3] = [1u8, 3, 4, rng.byte()][(rng.next() % 4) as usize];
                }
                if let Ok(target) = read_request(&mut &bytes[..]).await {
                    if let Host::Name(name) = &target.host {
                        assert!((1..=255).contains(&name.len()));
                    }
                }
                let _ = read_greeting(&mut &bytes[..]).await;
            }
        });
    }

    #[test]
    fn the_reply_has_the_code_and_a_zero_address() {
        assert_eq!(reply(0), [5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(reply(rep::COMMAND_NOT_SUPPORTED), [5, 7, 0, 1, 0, 0, 0, 0, 0, 0]);
    }

    /// A scripted upstream proxy on one end of an in-memory pipe. It answers
    /// the method with `method`, the credentials with `auth_status`, and the
    /// request with `reply`, and hands back every byte it read.
    async fn upstream(
        mut end: tokio::io::DuplexStream,
        method: u8,
        auth_status: u8,
        reply: Vec<u8>,
    ) -> Vec<u8> {
        let mut seen = Vec::new();
        let mut greeting = [0u8; 3];
        end.read_exact(&mut greeting).await.unwrap();
        seen.extend_from_slice(&greeting);
        end.write_all(&[5, method]).await.unwrap();
        if method != USER_PASS {
            return seen;
        }
        let mut head = [0u8; 2];
        end.read_exact(&mut head).await.unwrap();
        let mut user = vec![0u8; usize::from(head[1])];
        end.read_exact(&mut user).await.unwrap();
        let mut plen = [0u8; 1];
        end.read_exact(&mut plen).await.unwrap();
        let mut pass = vec![0u8; usize::from(plen[0])];
        end.read_exact(&mut pass).await.unwrap();
        seen.extend_from_slice(&head);
        seen.extend_from_slice(&user);
        seen.extend_from_slice(&plen);
        seen.extend_from_slice(&pass);
        end.write_all(&[1, auth_status]).await.unwrap();
        if auth_status != 0 {
            return seen;
        }
        let mut request = [0u8; 4];
        end.read_exact(&mut request).await.unwrap();
        seen.extend_from_slice(&request);
        let mut rest = Vec::new();
        match request[3] {
            1 => rest.resize(4 + 2, 0),
            4 => rest.resize(16 + 2, 0),
            _ => {
                let mut len = [0u8; 1];
                end.read_exact(&mut len).await.unwrap();
                seen.push(len[0]);
                rest.resize(usize::from(len[0]) + 2, 0);
            }
        }
        end.read_exact(&mut rest).await.unwrap();
        seen.extend_from_slice(&rest);
        end.write_all(&reply).await.unwrap();
        seen
    }

    fn credentials() -> Credentials {
        Credentials {
            username: b"user".to_vec(),
            password: b"pass".to_vec(),
        }
    }

    #[test]
    fn the_client_side_offers_user_and_password_only_and_sends_the_name() {
        run(async {
            let (mut near, far) = tokio::io::duplex(1024);
            let task = tokio::spawn(upstream(far, USER_PASS, 0, reply(rep::SUCCEEDED).to_vec()));
            client_connect(&mut near, &credentials(), &name("example.onion", 80))
                .await
                .unwrap();
            let seen = task.await.unwrap();
            assert_eq!(
                seen,
                [
                    &[5u8, 1, 2][..],
                    &[1, 4][..],
                    b"user",
                    &[4][..],
                    b"pass",
                    &[5, 1, 0, 3, 13][..],
                    b"example.onion",
                    &[0, 80][..],
                ]
                .concat()
            );
        });
    }

    #[test]
    fn the_client_side_reads_a_reply_with_a_name_or_ipv6_bound_address() {
        run(async {
            let mut with_name = vec![5, 0, 0, 3, 3];
            with_name.extend_from_slice(b"abc");
            with_name.extend_from_slice(&[0, 9]);
            let mut with_v6 = vec![5, 0, 0, 4];
            with_v6.extend_from_slice(&[0; 16]);
            with_v6.extend_from_slice(&[0, 9]);
            for reply in [with_name, with_v6] {
                let (mut near, far) = tokio::io::duplex(1024);
                let task = tokio::spawn(upstream(far, USER_PASS, 0, reply));
                client_connect(&mut near, &credentials(), &name("x", 1))
                    .await
                    .unwrap();
                task.await.unwrap();
            }
        });
    }

    #[test]
    fn the_client_side_relays_the_proxys_refusal_code() {
        run(async {
            let (mut near, far) = tokio::io::duplex(1024);
            let task = tokio::spawn(upstream(far, USER_PASS, 0, reply(4).to_vec()));
            let outcome = client_connect(&mut near, &credentials(), &name("x", 1)).await;
            assert!(matches!(outcome, Err(Error::Refuse(4))), "{outcome:?}");
            task.await.unwrap();
        });
    }

    #[test]
    fn the_client_side_stops_when_the_proxy_wants_another_method_or_refuses_the_password() {
        run(async {
            let (mut near, far) = tokio::io::duplex(1024);
            let task = tokio::spawn(upstream(far, NO_ACCEPTABLE, 0, Vec::new()));
            let outcome = client_connect(&mut near, &credentials(), &name("x", 1)).await;
            assert!(matches!(outcome, Err(Error::Protocol(_))), "{outcome:?}");
            task.await.unwrap();

            let (mut near, far) = tokio::io::duplex(1024);
            let task = tokio::spawn(upstream(far, NO_AUTH, 0, Vec::new()));
            let outcome = client_connect(&mut near, &credentials(), &name("x", 1)).await;
            assert!(matches!(outcome, Err(Error::Protocol(_))), "{outcome:?}");
            task.await.unwrap();

            let (mut near, far) = tokio::io::duplex(1024);
            let task = tokio::spawn(upstream(far, USER_PASS, 1, Vec::new()));
            let outcome = client_connect(&mut near, &credentials(), &name("x", 1)).await;
            assert!(matches!(outcome, Err(Error::Protocol(_))), "{outcome:?}");
            task.await.unwrap();
        });
    }

    #[test]
    fn the_probe_accepts_any_socks5_answer_and_nothing_else() {
        run(async {
            for answer in [[5u8, 0], [5, 2], [5, 0xff]] {
                let (mut near, mut far) = tokio::io::duplex(64);
                far.write_all(&answer).await.unwrap();
                probe(&mut near).await.unwrap();
                let mut greeting = [0u8; 3];
                far.read_exact(&mut greeting).await.unwrap();
                assert_eq!(greeting, [5, 1, 0]);
            }
            for answer in [&b"HT"[..], &[4, 0][..], &[5][..], &[][..]] {
                let (mut near, mut far) = tokio::io::duplex(64);
                far.write_all(answer).await.unwrap();
                drop(far);
                assert!(probe(&mut near).await.is_err(), "{answer:?}");
            }
        });
    }
}
