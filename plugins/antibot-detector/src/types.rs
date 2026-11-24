use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// The result type used throughout the `antibot-detector` crate.
pub type Result<T, E = DetectionError> = std::result::Result<T, E>;

/// Errors that can occur during detection.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DetectionError {
    /// Failed to extract or evaluate page content.
    #[error("failed to extract page content: {0}")]
    ContentExtraction(String),
    /// Script evaluation failed.
    #[error("failed to evaluate script: {0}")]
    Evaluation(String),
    /// Plugin host communication failed.
    #[cfg(feature = "plugin")]
    #[error("plugin error: {0}")]
    Plugin(#[from] seleniumbase_rs_plugin::PluginError),
    /// An unclassified error occurred.
    #[error("{0}")]
    Other(String),
}

/// Known anti-bot and bot protection vendors/technologies.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum BotProtectionKind {
    /// Cloudflare (Turnstile, Challenge platform, Bot Management, Waiting Room).
    Cloudflare,
    /// DataDome (Bot Protection, Captcha Delivery, Geetest).
    DataDome,
    /// Akamai Bot Manager & Client Reputation.
    Akamai,
    /// Kasada (Inline Protection System, KPSDK).
    Kasada,
    /// PerimeterX / HUMAN Security.
    PerimeterX,
    /// Imperva / Incapsula (WAF, Bot Protection).
    Imperva,
    /// AWS WAF (Token, Challenge, Captcha).
    AwsWaf,
    /// FingerprintJS (Browser Fingerprinting).
    FingerprintJs,
    /// Google reCAPTCHA (v2, v3, Enterprise).
    ReCaptcha,
    /// hCaptcha.
    HCaptcha,
    /// Other or unclassified protection system.
    Other,
}

impl fmt::Display for BotProtectionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cloudflare => write!(f, "Cloudflare"),
            Self::DataDome => write!(f, "DataDome"),
            Self::Akamai => write!(f, "Akamai Bot Manager"),
            Self::Kasada => write!(f, "Kasada"),
            Self::PerimeterX => write!(f, "PerimeterX / HUMAN"),
            Self::Imperva => write!(f, "Imperva / Incapsula"),
            Self::AwsWaf => write!(f, "AWS WAF"),
            Self::FingerprintJs => write!(f, "FingerprintJS"),
            Self::ReCaptcha => write!(f, "reCAPTCHA"),
            Self::HCaptcha => write!(f, "hCaptcha"),
            Self::Other => write!(f, "Other"),
        }
    }
}

/// Category of the detected protection mechanism.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ProtectionCategory {
    /// Comprehensive bot management suite.
    BotManagement,
    /// Interactive captcha or human verification challenge.
    Captcha,
    /// Web application firewall.
    Waf,
    /// Client-side browser fingerprinting or telemetry collector.
    Fingerprinting,
    /// Virtual waiting room or traffic queue.
    WaitingRoom,
}

impl fmt::Display for ProtectionCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BotManagement => write!(f, "Bot Management"),
            Self::Captcha => write!(f, "Captcha"),
            Self::Waf => write!(f, "WAF"),
            Self::Fingerprinting => write!(f, "Fingerprinting"),
            Self::WaitingRoom => write!(f, "Waiting Room"),
        }
    }
}

/// The specific source or medium where a detection signal was identified.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SignalKind {
    /// A browser cookie (e.g. `cf_clearance`, `datadome`, `_abck`).
    Cookie,
    /// An embedded iframe element (e.g. Turnstile or Captcha delivery iframe).
    Iframe,
    /// An external script URL or inline script payload.
    Script,
    /// A specific DOM element, ID, CSS class, or attribute.
    Dom,
    /// A challenge or block page text/marker (e.g. "Attention Required! | Cloudflare").
    ChallengeMarker,
    /// An HTTP response header (e.g. `cf-ray`, `x-datadome`).
    Header,
}

impl fmt::Display for SignalKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cookie => write!(f, "Cookie"),
            Self::Iframe => write!(f, "Iframe"),
            Self::Script => write!(f, "Script"),
            Self::Dom => write!(f, "DOM"),
            Self::ChallengeMarker => write!(f, "Challenge Marker"),
            Self::Header => write!(f, "Header"),
        }
    }
}

/// A specific telemetry signal or indicator that triggered a match.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DetectionSignal {
    /// The medium where the signal was detected.
    pub kind: SignalKind,
    /// Identifier or name of the matcher.
    pub name: String,
    /// The snippet, value, or pattern that was matched.
    pub matched_value: String,
    /// Confidence contribution of this signal (0 to 100).
    pub confidence: u8,
}

impl DetectionSignal {
    /// Creates a new detection signal.
    pub fn new(
        kind: SignalKind,
        name: impl Into<String>,
        matched_value: impl Into<String>,
        confidence: u8,
    ) -> Self {
        Self {
            kind,
            name: name.into(),
            matched_value: matched_value.into(),
            confidence: confidence.min(100),
        }
    }
}

/// The outcome of an anti-bot detection inspection.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct BotProtectionResult {
    /// The detected anti-bot or protection provider.
    pub provider: BotProtectionKind,
    /// The category of protection.
    pub category: ProtectionCategory,
    /// Confidence percentage (0 to 100).
    pub confidence: u8,
    /// Whether the page is currently in a challenged, blocked, or queued state.
    pub is_blocked: bool,
    /// Human-readable description of what was detected.
    pub description: String,
    /// All individual signals triggering this detection.
    pub signals: Vec<DetectionSignal>,
}

impl BotProtectionResult {
    /// The anti-bot provider.
    #[must_use]
    pub fn provider(&self) -> BotProtectionKind {
        self.provider
    }

    /// The category of protection.
    #[must_use]
    pub fn category(&self) -> ProtectionCategory {
        self.category
    }

    /// Confidence score (0 to 100).
    #[must_use]
    pub fn confidence(&self) -> u8 {
        self.confidence
    }

    /// Returns `true` if the page is actively blocking or presenting a challenge/waiting room.
    #[must_use]
    pub fn is_blocked(&self) -> bool {
        self.is_blocked
    }

    /// Human-readable summary of the detection.
    #[must_use]
    pub fn description(&self) -> &str {
        &self.description
    }

    /// The signals that contributed to this detection.
    #[must_use]
    pub fn signals(&self) -> &[DetectionSignal] {
        &self.signals
    }
}

/// A browser cookie inspected for security challenge tokens.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Cookie {
    /// The cookie name.
    pub name: String,
    /// The cookie value.
    pub value: String,
    /// The domain the cookie applies to.
    #[serde(default)]
    pub domain: Option<String>,
    /// The path the cookie applies to.
    #[serde(default)]
    pub path: Option<String>,
}

impl Cookie {
    /// Creates a new cookie with the given name and value.
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            domain: None,
            path: None,
        }
    }

    /// Sets the domain for this cookie.
    #[must_use]
    pub fn with_domain(mut self, domain: impl Into<String>) -> Self {
        self.domain = Some(domain.into());
        self
    }

    /// Sets the path for this cookie.
    #[must_use]
    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }
}

impl<N: Into<String>, V: Into<String>> From<(N, V)> for Cookie {
    fn from((name, value): (N, V)) -> Self {
        Self::new(name, value)
    }
}

/// A web page representation containing HTML source, cookies, and optional response metadata.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Page {
    /// The URL of the page, if known.
    pub url: Option<String>,
    /// The HTML source code of the page.
    pub html: String,
    /// Active cookies for the page.
    pub cookies: Vec<Cookie>,
    /// Response headers, if available.
    pub headers: HashMap<String, String>,
    /// HTTP status code, if known.
    pub status_code: Option<u16>,
}

impl Page {
    /// Creates a new `Page` from raw HTML source.
    pub fn new(html: impl Into<String>) -> Self {
        Self {
            html: html.into(),
            ..Default::default()
        }
    }

    /// Creates a new `Page` from raw HTML source.
    pub fn from_html(html: impl Into<String>) -> Self {
        Self::new(html)
    }

    /// Attaches cookies to the page.
    #[must_use]
    pub fn with_cookies(mut self, cookies: impl IntoIterator<Item = Cookie>) -> Self {
        self.cookies = cookies.into_iter().collect();
        self
    }

    /// Sets the URL of the page.
    #[must_use]
    pub fn with_url(mut self, url: impl Into<String>) -> Self {
        self.url = Some(url.into());
        self
    }

    /// Sets HTTP response headers.
    #[must_use]
    pub fn with_headers(mut self, headers: HashMap<String, String>) -> Self {
        self.headers = headers;
        self
    }

    /// Sets the HTTP status code.
    #[must_use]
    pub fn with_status_code(mut self, status: u16) -> Self {
        self.status_code = Some(status);
        self
    }

    /// Extracts page data from a live `seleniumbase-rs-plugin` [`PageHandle`].
    ///
    /// # Errors
    ///
    /// Returns a [`DetectionError`] if the page handle fails to evaluate or return content.
    #[cfg(feature = "plugin")]
    pub async fn from_handle(
        handle: &dyn seleniumbase_rs_plugin::PageHandle,
    ) -> Result<Self, DetectionError> {
        let html_expr = "document.documentElement ? document.documentElement.outerHTML : ''";
        let html = match handle.evaluate(html_expr).await {
            Ok(serde_json::Value::String(s)) => s,
            Ok(other) => other.to_string(),
            Err(e) => return Err(DetectionError::ContentExtraction(e.to_string())),
        };

        let url = handle.url().await.ok();

        let mut cookies = Vec::new();
        if let Ok(serde_json::Value::String(cookie_str)) = handle.evaluate("document.cookie").await
        {
            for pair in cookie_str.split(';') {
                let trimmed = pair.trim();
                if let Some((k, v)) = trimmed.split_once('=') {
                    cookies.push(Cookie::new(k.trim(), v.trim()));
                }
            }
        }

        Ok(Self {
            url,
            html,
            cookies,
            headers: HashMap::new(),
            status_code: None,
        })
    }
}
