//! The options of the fetcher, and the checks that make a bad one an error at
//! start-up instead of a surprise later.

use std::collections::BTreeMap;

use seleniumbase_rs_plugin::{PluginError, ResourceKind, Result};
use serde::{Deserialize, Serialize};

/// The largest `max_body_bytes` accepted: a captured body lives in memory.
pub const MAX_BODY_LIMIT: usize = 64 * 1024 * 1024;

/// The largest `max_captures` accepted.
pub const MAX_CAPTURES_LIMIT: usize = 100_000;

/// The most headers `headers` may set.
pub const MAX_HEADERS: usize = 64;

/// Header names that frame the request. Chrome ignores or refuses some of them
/// and the others would break the connection, so asking for one is an error.
const FRAMING_HEADERS: [&str; 8] = [
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "upgrade",
    "expect",
    "te",
    "trailer",
];

/// What the fetcher does, as a program or a config file states it.
///
/// ```
/// use seleniumbase_rs_plugin_fetcher::FetcherConfig;
///
/// let config: FetcherConfig = serde_json::from_value(serde_json::json!({
///     "strip": ["image", "font"],
///     "block": ["*://ads.example.com/*"],
///     "capture": ["*/api/*"],
///     "headers": { "Accept-Language": "de" },
/// }))?;
/// assert_eq!(config.max_captures, 500);
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct FetcherConfig {
    /// Kinds of resource to fail: `stylesheet`, `image`, `media`, `font`,
    /// `script`, `xhr`, `fetch`, `websocket` or `other`. Documents cannot be
    /// stripped.
    pub strip: Vec<String>,
    /// URL patterns to fail. `*` matches any run of characters, `?` one.
    pub block: Vec<String>,
    /// URL patterns whose responses are recorded.
    pub capture: Vec<String>,
    /// Request headers to add.
    pub headers: BTreeMap<String, String>,
    /// URL patterns the `headers` go to. Empty means every request, including
    /// those to third parties: give patterns when a header carries a secret.
    pub header_urls: Vec<String>,
    /// The most bytes kept of one captured body and of one fetched body.
    pub max_body_bytes: usize,
    /// The most captured responses kept; the oldest go first.
    pub max_captures: usize,
}

impl Default for FetcherConfig {
    fn default() -> Self {
        Self {
            strip: Vec::new(),
            block: Vec::new(),
            capture: Vec::new(),
            headers: BTreeMap::new(),
            header_urls: Vec::new(),
            max_body_bytes: 2 * 1024 * 1024,
            max_captures: 500,
        }
    }
}

/// An option that passed the checks, in the form the plugin uses.
#[derive(Clone, Debug)]
pub(crate) struct Checked {
    pub(crate) kinds: Vec<ResourceKind>,
}

impl FetcherConfig {
    /// Checks every option.
    pub(crate) fn check(&self) -> Result<Checked> {
        let kinds = self
            .strip
            .iter()
            .map(|name| kind(name))
            .collect::<Result<Vec<_>>>()?;
        for (option, globs) in [
            ("block", &self.block),
            ("capture", &self.capture),
            ("header_urls", &self.header_urls),
        ] {
            for glob in globs {
                check_glob(option, glob)?;
            }
        }
        check_headers(&self.headers)?;
        if self.max_body_bytes > MAX_BODY_LIMIT {
            return Err(PluginError::Config(format!(
                "fetcher: `max_body_bytes` is at most {MAX_BODY_LIMIT}"
            )));
        }
        if self.max_captures > MAX_CAPTURES_LIMIT {
            return Err(PluginError::Config(format!(
                "fetcher: `max_captures` is at most {MAX_CAPTURES_LIMIT}"
            )));
        }
        if !self.capture.is_empty() && self.max_captures == 0 {
            return Err(PluginError::Config(
                "fetcher: `capture` is set but `max_captures` is 0".into(),
            ));
        }
        Ok(Checked { kinds })
    }
}

/// The resource kind a `strip` entry names.
fn kind(name: &str) -> Result<ResourceKind> {
    match name.trim().to_ascii_lowercase().as_str() {
        "stylesheet" => Ok(ResourceKind::Stylesheet),
        "image" => Ok(ResourceKind::Image),
        "media" => Ok(ResourceKind::Media),
        "font" => Ok(ResourceKind::Font),
        "script" => Ok(ResourceKind::Script),
        "xhr" => Ok(ResourceKind::Xhr),
        "fetch" => Ok(ResourceKind::Fetch),
        "websocket" => Ok(ResourceKind::WebSocket),
        "other" => Ok(ResourceKind::Other),
        "document" => Err(PluginError::Config(
            "fetcher: `strip` cannot remove documents; use `block` with a URL pattern".into(),
        )),
        other => Err(PluginError::Config(format!(
            "fetcher: unknown resource kind `{other}` in `strip` (use stylesheet, image, media, \
             font, script, xhr, fetch, websocket or other)"
        ))),
    }
}

/// A glob is bad when it is empty or holds whitespace or a control character:
/// no URL does, so it could never match.
fn check_glob(option: &str, glob: &str) -> Result<()> {
    if glob.is_empty() || glob.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(PluginError::Config(format!(
            "fetcher: bad glob `{glob}` in `{option}`"
        )));
    }
    Ok(())
}

fn check_headers(headers: &BTreeMap<String, String>) -> Result<()> {
    if headers.len() > MAX_HEADERS {
        return Err(PluginError::Config(format!(
            "fetcher: `headers` holds at most {MAX_HEADERS} entries"
        )));
    }
    for (name, value) in headers {
        let is_token = !name.is_empty()
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b));
        if !is_token {
            return Err(PluginError::Config(format!(
                "fetcher: `{name}` is not a header name"
            )));
        }
        if FRAMING_HEADERS
            .iter()
            .any(|framing| framing.eq_ignore_ascii_case(name))
        {
            return Err(PluginError::Config(format!(
                "fetcher: the header `{name}` cannot be set"
            )));
        }
        if value.len() > 8192 || value.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0) {
            return Err(PluginError::Config(format!(
                "fetcher: the value of header `{name}` has a line break or is too long"
            )));
        }
    }
    Ok(())
}
