//! Jobs and task input: what a URL must look like, the page script that
//! fetches it, and how the answer is read.

use std::time::Duration;

use seleniumbase_rs_plugin::{PluginError, Result};
use serde::Deserialize;
use serde_json::{Value, json};

/// The script that fetches one URL, as a function over its request.
const FETCH_JS: &str = include_str!("fetch.js");

/// The most URLs one task run accepts.
pub const MAX_URLS: usize = 10_000;

/// The longest pause between two fetches, in milliseconds.
pub const MAX_DELAY_MS: u64 = 60_000;

/// One job for [`JobRunner::run_job`](seleniumbase_rs_plugin::JobRunner::run_job).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Job {
    url: String,
    /// At most this many bytes of the body; never more than `max_body_bytes`.
    max_bytes: Option<usize>,
}

impl Job {
    pub(crate) fn parse(job: &Value) -> Result<Self> {
        serde_json::from_value(job.clone())
            .map_err(|error| PluginError::Config(format!("fetcher: bad job: {error}")))
    }

    /// The expression that fetches the URL. Both values travel as a JSON
    /// literal, so a URL cannot step out of its string.
    pub(crate) fn script(&self, max_body_bytes: usize) -> Result<String> {
        check_url(&self.url)?;
        let max = self
            .max_bytes
            .map_or(max_body_bytes, |m| m.min(max_body_bytes));
        let request = json!({ "url": self.url, "max_bytes": max });
        Ok(format!("({FETCH_JS})({request})"))
    }
}

/// What the page's `fetch` answered.
pub(crate) fn read_reply(reply: &Value) -> Result<Value> {
    let object = reply
        .as_object()
        .filter(|object| object.get("status").is_some_and(Value::is_number))
        .ok_or_else(|| {
            PluginError::other(format!("fetcher: unexpected reply from the page: {reply}"))
        })?;
    let mut out = serde_json::Map::new();
    for key in ["url", "status", "mime", "text", "truncated"] {
        out.insert(
            key.to_owned(),
            object.get(key).cloned().unwrap_or(Value::Null),
        );
    }
    Ok(Value::Object(out))
}

/// The task's input: `{"urls": [...], "delay_ms": 0, "warm_up": true}`.
#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct TaskInput {
    pub(crate) urls: Vec<String>,
    delay_ms: u64,
    pub(crate) warm_up: bool,
}

impl Default for TaskInput {
    fn default() -> Self {
        Self {
            urls: Vec::new(),
            delay_ms: 0,
            warm_up: true,
        }
    }
}

impl TaskInput {
    pub(crate) fn parse(input: &Value) -> Result<Self> {
        let parsed: Self = serde_json::from_value(input.clone())
            .map_err(|error| PluginError::Config(format!("fetcher: bad task input: {error}")))?;
        if parsed.urls.is_empty() {
            return Err(PluginError::Config(
                "fetcher: the task input needs `urls`, a list of http(s) addresses".into(),
            ));
        }
        if parsed.urls.len() > MAX_URLS {
            return Err(PluginError::Config(format!(
                "fetcher: too many urls (at most {MAX_URLS})"
            )));
        }
        if parsed.delay_ms > MAX_DELAY_MS {
            return Err(PluginError::Config(format!(
                "fetcher: `delay_ms` is at most {MAX_DELAY_MS}"
            )));
        }
        Ok(parsed)
    }

    pub(crate) fn delay(&self) -> Duration {
        Duration::from_millis(self.delay_ms)
    }
}

/// The scheme, host and port of an `http` or `https` URL, as `origin/`
/// without the slash; the error says what is wrong with the URL.
pub(crate) fn origin(url: &str) -> Result<String> {
    let bad = |why: &str| PluginError::Config(format!("fetcher: `{url}` {why}"));
    if url.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(bad("has a space or control character"));
    }
    let lower = url.to_ascii_lowercase();
    let scheme_len = if lower.starts_with("https://") {
        8
    } else if lower.starts_with("http://") {
        7
    } else {
        return Err(bad("is not an http or https address"));
    };
    let rest = &url[scheme_len..];
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.is_empty() {
        return Err(bad("has no host"));
    }
    if authority.contains('@') {
        return Err(bad("carries credentials, which are not accepted"));
    }
    Ok(format!(
        "{}{}",
        &lower[..scheme_len],
        authority.to_ascii_lowercase()
    ))
}

fn check_url(url: &str) -> Result<()> {
    origin(url).map(drop)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_keeps_scheme_host_and_port() {
        assert_eq!(
            origin("https://Example.com/a?b#c").unwrap(),
            "https://example.com"
        );
        assert_eq!(
            origin("http://localhost:8080").unwrap(),
            "http://localhost:8080"
        );
    }

    #[test]
    fn origin_refuses_what_is_not_a_plain_web_address() {
        for url in [
            "file:///etc/passwd",
            "data:text/html,x",
            "javascript:alert(1)",
            "ftp://example.com/",
            "https://",
            "https://user:pw@example.com/",
            "https://example.com/a b",
            "",
        ] {
            assert!(origin(url).is_err(), "{url}");
        }
    }
}
