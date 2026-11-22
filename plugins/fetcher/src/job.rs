//! Jobs and task input: what a URL must look like, the page script that
//! fetches it, and how the answer is read.

use std::time::Duration;

use seleniumbase_rs_plugin::{PluginError, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// The script that fetches one URL, as a function over its request.
const FETCH_JS: &str = include_str!("fetch.js");

/// The most URLs one task run accepts.
pub const MAX_URLS: usize = 10_000;

/// The longest pause between two fetches, in milliseconds.
pub const MAX_DELAY_MS: u64 = 60_000;

/// One job for [`JobRunner::run_job`](seleniumbase_rs_plugin::JobRunner::run_job).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Job {
    pub url: String,
    /// At most this many bytes of the body; never more than `max_body_bytes`.
    #[serde(default)]
    pub max_bytes: Option<usize>,
    /// Mode: `"fetch"` (default, in-page JavaScript fetch) or `"navigate"`
    /// (full browser navigation and DOM rendering).
    #[serde(default)]
    pub mode: Option<String>,
    /// Wait for a CSS selector or XPath to appear before returning (for dynamic SPAs).
    #[serde(default)]
    pub wait_for: Option<String>,
    /// Wait delay in milliseconds (e.g. for animations or network idle).
    #[serde(default)]
    pub wait_ms: Option<u64>,
    /// Auto-scroll down the page to trigger lazy loading of assets.
    #[serde(default)]
    pub scroll_y: Option<bool>,
    /// Capture screenshot of the fetched page as base64 PNG.
    #[serde(default)]
    pub screenshot: Option<bool>,
    /// Full JS execution / HTML rendering (default true in navigate mode).
    #[serde(default)]
    pub js_render: Option<bool>,
    /// Sequence of browser action steps to execute before capturing (`click`, `fill`, `wait_for`, `scroll_y`, `wait`).
    #[serde(default)]
    pub actions: Option<Vec<Value>>,
    /// Extraction schema: map of `{ "field_name": "css_selector" }`.
    #[serde(default)]
    pub extract: Option<std::collections::HashMap<String, String>>,
    /// Whether to convert rendered main content into clean Markdown.
    #[serde(default)]
    pub markdown: Option<bool>,
}

impl Job {
    pub fn parse(job: &Value) -> Result<Self> {
        serde_json::from_value(job.clone())
            .map_err(|error| PluginError::Config(format!("fetcher: bad job: {error}")))
    }

    /// Whether this job needs full browser navigation and DOM rendering rather
    /// than an in-page `fetch()`.
    #[must_use]
    pub fn is_navigate(&self) -> bool {
        self.mode.as_deref() == Some("navigate")
            || self.wait_for.is_some()
            || self.scroll_y == Some(true)
            || self.screenshot == Some(true)
            || self.actions.is_some()
            || self.extract.is_some()
            || self.markdown == Some(true)
    }

    /// The expression that fetches the URL. Both values travel as a JSON
    /// literal, so a URL cannot step out of its string.
    pub fn script(&self, max_body_bytes: usize) -> Result<String> {
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
    for key in [
        "url",
        "status",
        "mime",
        "text",
        "truncated",
        "screenshot",
        "extracted",
        "markdown",
    ] {
        if let Some(val) = object.get(key) {
            out.insert(key.to_owned(), val.clone());
        }
    }
    // Guarantee required fields
    for key in ["url", "status", "mime", "text", "truncated"] {
        out.entry(key.to_owned()).or_insert(Value::Null);
    }
    Ok(Value::Object(out))
}

/// The task's input: `{"urls": [...], "delay_ms": 0, "warm_up": true, "mode": "fetch"}`.
#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct TaskInput {
    pub(crate) urls: Vec<String>,
    delay_ms: u64,
    pub(crate) warm_up: bool,
    pub(crate) mode: Option<String>,
    pub(crate) wait_for: Option<String>,
    pub(crate) wait_ms: Option<u64>,
    pub(crate) scroll_y: Option<bool>,
    pub(crate) screenshot: Option<bool>,
    pub(crate) actions: Option<Vec<Value>>,
    pub(crate) extract: Option<std::collections::HashMap<String, String>>,
    pub(crate) markdown: Option<bool>,
}

impl Default for TaskInput {
    fn default() -> Self {
        Self {
            urls: Vec::new(),
            delay_ms: 0,
            warm_up: true,
            mode: None,
            wait_for: None,
            wait_ms: None,
            scroll_y: None,
            screenshot: None,
            actions: None,
            extract: None,
            markdown: None,
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

    /// Converts a URL in the task to a full [`Job`].
    pub(crate) fn to_job(&self, url: &str) -> Job {
        Job {
            url: url.to_owned(),
            max_bytes: None,
            mode: self.mode.clone(),
            wait_for: self.wait_for.clone(),
            wait_ms: self.wait_ms,
            scroll_y: self.scroll_y,
            screenshot: self.screenshot,
            js_render: None,
            actions: self.actions.clone(),
            extract: self.extract.clone(),
            markdown: self.markdown,
        }
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

pub(crate) fn check_url(url: &str) -> Result<()> {
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

    #[test]
    fn job_parses_navigate_mode_and_options() {
        let job = Job::parse(&json!({
            "url": "https://example.com/shop",
            "mode": "navigate",
            "wait_for": "#products",
            "scroll_y": true,
            "screenshot": true,
            "wait_ms": 500
        }))
        .unwrap();
        assert!(job.is_navigate());
        assert_eq!(job.wait_for.as_deref(), Some("#products"));
        assert_eq!(job.scroll_y, Some(true));
        assert_eq!(job.screenshot, Some(true));
        assert_eq!(job.wait_ms, Some(500));
    }
}
