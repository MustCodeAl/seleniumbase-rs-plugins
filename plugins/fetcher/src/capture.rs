//! The log of recorded responses: a bounded queue the plugin fills from
//! `on_response` and the program reads.

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use seleniumbase_rs_plugin::{Outcome, ResponseView};
use serde::Serialize;

/// One recorded response.
///
/// The request headers are those the host handed the plugin: `Cookie`,
/// `Authorization`, `Proxy-Authorization` and `Set-Cookie` read `[redacted]`
/// unless the plugin was granted `net.sensitive`, which it does not ask for.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Captured {
    /// The address.
    pub url: String,
    /// The HTTP method.
    pub method: String,
    /// The HTTP status; `0` when there was no response.
    pub status: u16,
    /// The MIME type, such as `application/json`.
    pub mime: String,
    /// The body as text, for a text type or a body that is valid UTF-8.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// The body in base64, for anything else.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base64: Option<String>,
    /// Whether the body was cut at `max_body_bytes`.
    pub truncated: bool,
    /// How the request ended: `ok`, `failed` or `blocked`.
    pub outcome: &'static str,
    /// The request headers, with the sensitive ones redacted.
    pub headers: BTreeMap<String, String>,
    /// Milliseconds since the Unix epoch when the response arrived.
    pub at_ms: u64,
}

impl Captured {
    /// The record of `response`, taken at `at_ms`.
    pub(crate) fn of(response: &ResponseView<'_>, at_ms: u64) -> Self {
        let (text, base64) = match response.body {
            None => (None, None),
            Some(bytes) if is_textual(response.mime) => {
                (Some(String::from_utf8_lossy(bytes).into_owned()), None)
            }
            Some(bytes) => match std::str::from_utf8(bytes) {
                Ok(text) => (Some(text.to_owned()), None),
                Err(_) => (None, Some(base64(bytes))),
            },
        };
        Self {
            url: response.request.url.clone(),
            method: response.request.method.clone(),
            status: response.status,
            mime: response.mime.to_owned(),
            text,
            base64,
            truncated: response.truncated,
            outcome: match response.outcome {
                Outcome::Ok => "ok",
                Outcome::Blocked { .. } => "blocked",
                _ => "failed",
            },
            headers: response.request.headers.clone(),
            at_ms,
        }
    }
}

/// Whether bodies of this MIME type are text, whatever their bytes.
fn is_textual(mime: &str) -> bool {
    let mime = mime.to_ascii_lowercase();
    mime.starts_with("text/")
        || [
            "json",
            "xml",
            "javascript",
            "ecmascript",
            "urlencoded",
            "svg",
        ]
        .iter()
        .any(|kind| mime.contains(kind))
}

/// The log: at most `capacity` records, the oldest dropped first.
#[derive(Debug)]
pub(crate) struct CaptureLog {
    capacity: usize,
    records: Mutex<VecDeque<Captured>>,
    dropped: AtomicU64,
}

impl CaptureLog {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            capacity,
            records: Mutex::new(VecDeque::new()),
            dropped: AtomicU64::new(0),
        }
    }

    fn records(&self) -> MutexGuard<'_, VecDeque<Captured>> {
        self.records.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn push(&self, record: Captured) {
        if self.capacity == 0 {
            return;
        }
        let mut records = self.records();
        while records.len() >= self.capacity {
            records.pop_front();
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        records.push_back(record);
    }

    pub(crate) fn snapshot(&self) -> Vec<Captured> {
        self.records().iter().cloned().collect()
    }

    pub(crate) fn take(&self) -> Vec<Captured> {
        self.records().drain(..).collect()
    }

    pub(crate) fn len(&self) -> usize {
        self.records().len()
    }

    pub(crate) fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

/// Milliseconds since the Unix epoch.
pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Standard base64 with padding.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        out.push(char::from(ALPHABET[(n >> 18) as usize & 63]));
        out.push(char::from(ALPHABET[(n >> 12) as usize & 63]));
        out.push(if chunk.len() > 1 {
            char::from(ALPHABET[(n >> 6) as usize & 63])
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            char::from(ALPHABET[n as usize & 63])
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::base64;

    #[test]
    fn base64_matches_the_rfc_4648_vectors() {
        for (plain, encoded) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64(plain.as_bytes()), encoded);
        }
        assert_eq!(base64(&[0xff, 0xfe, 0x00]), "//4A");
    }
}
