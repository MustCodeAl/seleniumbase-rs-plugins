//! Passive cookie and `Set-Cookie` security posture checks.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::auditors::jwt;
use crate::error::{OwaspError, Result};
use crate::types::{AuditorKind, Finding, OwaspCategory, Severity, url_host};

const SESSION_COOKIE_HINTS: &[&str] = &[
    "session",
    "sess",
    "sid",
    "jsessionid",
    "phpsessid",
    "asp.net_sessionid",
    "aspsessionid",
    "connect.sid",
    "auth",
    "token",
    "jwt",
    "access_token",
    "refresh_token",
    "id_token",
    "remember",
];

const CSRF_COOKIE_HINTS: &[&str] = &["csrf", "xsrf", "xsrf-token", "csrf-token"];

/// Parsed `SameSite` attribute of an HTTP cookie.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum SameSite {
    /// `SameSite=Strict`.
    Strict,
    /// `SameSite=Lax`.
    Lax,
    /// `SameSite=None`.
    None,
}

impl SameSite {
    /// Canonical lowercase string representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Strict => "Strict",
            Self::Lax => "Lax",
            Self::None => "None",
        }
    }
}

impl fmt::Display for SameSite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SameSite {
    type Err = OwaspError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "strict" => Ok(Self::Strict),
            "lax" => Ok(Self::Lax),
            "none" => Ok(Self::None),
            other => Err(OwaspError::InvalidHeader(format!(
                "unknown SameSite value `{other}`"
            ))),
        }
    }
}

/// Parsed HTTP `Set-Cookie` header value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SetCookie {
    /// Cookie name.
    pub name: String,
    /// Cookie value (kept private in reports via redaction).
    pub value: String,
    /// Whether `HttpOnly` is set.
    pub http_only: bool,
    /// Whether `Secure` is set.
    pub secure: bool,
    /// Parsed `SameSite` policy, if present.
    pub same_site: Option<SameSite>,
    /// `Domain` attribute, if present.
    pub domain: Option<String>,
    /// `Path` attribute, if present.
    pub path: Option<String>,
    /// `Max-Age` attribute in seconds, if present and valid integer.
    pub max_age: Option<i64>,
    /// Raw `Expires` attribute, if present.
    pub expires: Option<String>,
    /// Whether `Partitioned` (CHIPS) is set.
    pub partitioned: bool,
    /// Unrecognized `SameSite` value if malformed.
    pub invalid_same_site: Option<String>,
}

impl SetCookie {
    /// Parses a raw `Set-Cookie` header value.
    ///
    /// # Errors
    ///
    /// Returns [`OwaspError::InvalidHeader`] when `name=value` is missing or cookie name is empty.
    pub fn parse(raw: &str) -> Result<Self> {
        let mut parts = raw.split(';');
        let first = parts
            .next()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| OwaspError::InvalidHeader("empty Set-Cookie header".to_owned()))?;

        let (name, value) = first.split_once('=').ok_or_else(|| {
            OwaspError::InvalidHeader("Set-Cookie missing `name=value` pair".to_owned())
        })?;
        let name = name.trim();
        if name.is_empty() {
            return Err(OwaspError::InvalidHeader(
                "Set-Cookie has an empty cookie name".to_owned(),
            ));
        }

        let mut cookie = Self {
            name: name.to_owned(),
            value: value.trim().to_owned(),
            http_only: false,
            secure: false,
            same_site: None,
            domain: None,
            path: None,
            max_age: None,
            expires: None,
            partitioned: false,
            invalid_same_site: None,
        };

        for attr in parts {
            let trimmed = attr.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Some((k, v)) = trimmed.split_once('=') {
                let key = k.trim().to_ascii_lowercase();
                let val = v.trim();
                match key.as_str() {
                    "samesite" => match SameSite::from_str(val) {
                        Ok(ss) => cookie.same_site = Some(ss),
                        Err(_) => cookie.invalid_same_site = Some(val.to_owned()),
                    },
                    "domain" if !val.is_empty() => cookie.domain = Some(val.to_owned()),
                    "path" if !val.is_empty() => cookie.path = Some(val.to_owned()),
                    "max-age" => cookie.max_age = val.parse::<i64>().ok(),
                    "expires" if !val.is_empty() => cookie.expires = Some(val.to_owned()),
                    _ => {}
                }
            } else {
                match trimmed.to_ascii_lowercase().as_str() {
                    "httponly" => cookie.http_only = true,
                    "secure" => cookie.secure = true,
                    "partitioned" => cookie.partitioned = true,
                    _ => {}
                }
            }
        }

        Ok(cookie)
    }

    /// Formats cookie attributes without exposing the raw cookie value.
    #[must_use]
    pub fn redacted_attributes(&self) -> String {
        let mut attrs = Vec::new();
        if self.http_only {
            attrs.push("HttpOnly".to_owned());
        }
        if self.secure {
            attrs.push("Secure".to_owned());
        }
        if let Some(ss) = self.same_site {
            attrs.push(format!("SameSite={ss}"));
        }
        if let Some(domain) = &self.domain {
            attrs.push(format!("Domain={domain}"));
        }
        if let Some(path) = &self.path {
            attrs.push(format!("Path={path}"));
        }
        if attrs.is_empty() {
            format!("{}=[redacted] (no attributes)", self.name)
        } else {
            format!("{}=[redacted]; {}", self.name, attrs.join("; "))
        }
    }
}

/// Cookie metadata supplied by runtime/DOM inspection (e.g. `document.cookie` or CDP cookies).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct CookieInput {
    /// Cookie name.
    pub name: String,
    /// Cookie value (kept redacted in findings).
    pub value: String,
    /// `HttpOnly` flag when known (`false` for `document.cookie`).
    pub http_only: bool,
    /// `Secure` flag when known.
    pub secure: bool,
    /// `SameSite` policy when known.
    pub same_site: Option<SameSite>,
    /// `Domain` when known.
    pub domain: Option<String>,
    /// `Path` when known.
    pub path: Option<String>,
    /// True when the cookie was read from `document.cookie` rather than `Set-Cookie`.
    pub from_document_cookie: bool,
}

impl CookieInput {
    /// Creates a runtime cookie observed from `document.cookie` (inherently non-`HttpOnly`).
    #[must_use]
    pub fn from_document_cookie(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            http_only: false,
            secure: false,
            same_site: None,
            domain: None,
            path: None,
            from_document_cookie: true,
        }
    }
}

/// Context for auditing cookies against the origin URL scheme and host.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct CookieAuditContext {
    /// Target URL where the cookie was observed.
    pub url: Option<String>,
    /// Whether the target URL is `https://`.
    pub is_https: bool,
    /// Hostname of the target URL, if known.
    pub host: Option<String>,
}

impl CookieAuditContext {
    /// Builds context from an optional URL.
    #[must_use]
    pub fn from_url(url: Option<&str>) -> Self {
        match url {
            Some(raw) => {
                let is_https = raw.trim().to_ascii_lowercase().starts_with("https://");
                let host = url_host(raw);
                Self {
                    url: Some(raw.to_owned()),
                    is_https,
                    host,
                }
            }
            None => Self::default(),
        }
    }
}

/// Returns `true` when the cookie name follows common session/authentication naming heuristics.
#[must_use]
pub fn is_session_cookie_name(name: &str) -> bool {
    let lower = name.trim().to_ascii_lowercase();
    if is_csrf_cookie_name(&lower) {
        return false;
    }
    SESSION_COOKIE_HINTS.iter().any(|hint| lower.contains(hint))
}

fn is_csrf_cookie_name(lower_name: &str) -> bool {
    CSRF_COOKIE_HINTS
        .iter()
        .any(|hint| lower_name.contains(hint))
}

/// Audits a raw `Set-Cookie` header string. Handles `[redacted]` placeholders cleanly when
/// the plugin does not hold `net.sensitive`.
#[must_use]
pub fn audit_set_cookie(raw: &str, ctx: &CookieAuditContext) -> Vec<Finding> {
    let trimmed = raw.trim();
    if trimmed == "[redacted]" {
        return vec![
            Finding::new(
                "OWASP-COOKIE-REDACTED",
                "Set-Cookie header redacted without `net.sensitive` capability",
                Severity::Info,
                OwaspCategory::A05SecurityMisconfiguration,
                AuditorKind::Cookies,
            )
            .wstg("WSTG-SESS-02")
            .location(ctx.url.as_deref().unwrap_or("Set-Cookie"))
            .description(
                "The plugin host redacted `Set-Cookie` because `net.sensitive` is not granted; cookie attributes could not be inspected from network events.",
            )
            .remediation(
                "Grant `net.sensitive` to inspect `Set-Cookie` attributes passively during network observation.",
            ),
        ];
    }

    let mut findings = Vec::new();
    let parsed = match SetCookie::parse(trimmed) {
        Ok(c) => c,
        Err(err) => {
            findings.push(
                Finding::new(
                    "OWASP-COOKIE-MALFORMED",
                    "Malformed `Set-Cookie` header observed",
                    Severity::Low,
                    OwaspCategory::A05SecurityMisconfiguration,
                    AuditorKind::Cookies,
                )
                .cwe(16)
                .wstg("WSTG-SESS-02")
                .location(ctx.url.as_deref().unwrap_or("Set-Cookie"))
                .evidence(err.to_string())
                .description(
                    "Response sent a `Set-Cookie` header that failed RFC 6265 syntax checks.",
                )
                .remediation(
                    "Ensure `Set-Cookie` headers emit valid `name=value; Attributes` syntax.",
                ),
            );
            return findings;
        }
    };

    let loc = match &ctx.url {
        Some(url) => format!("{url} [cookie:{}]", parsed.name),
        None => format!("cookie:{}", parsed.name),
    };
    let evidence = parsed.redacted_attributes();
    let is_session = is_session_cookie_name(&parsed.name);
    let is_csrf = is_csrf_cookie_name(&parsed.name.to_ascii_lowercase());

    // 1. Cookie prefix rules (RFC 6265bis)
    if parsed.name.starts_with("__Host-") {
        let mut violations = Vec::new();
        if !parsed.secure {
            violations.push("missing `Secure` attribute");
        }
        if parsed.domain.is_some() {
            violations.push("must not set `Domain` attribute");
        }
        if parsed.path.as_deref() != Some("/") {
            violations.push("must set `Path=/`");
        }
        if ctx.url.is_some() && !ctx.is_https {
            violations.push("set over non-HTTPS scheme");
        }
        if !violations.is_empty() {
            findings.push(
                Finding::new(
                    "OWASP-COOKIE-HOST-PREFIX-VIOLATION",
                    "Cookie uses `__Host-` prefix but violates RFC 6265bis constraints",
                    Severity::High,
                    OwaspCategory::A05SecurityMisconfiguration,
                    AuditorKind::Cookies,
                )
                .cwe(565)
                .wstg("WSTG-SESS-02")
                .location(loc.clone())
                .evidence(format!("{evidence} ({})", violations.join(", ")))
                .description(
                    "`__Host-` cookies are ignored by compliant browsers unless `Secure` is set, `Domain` is omitted, `Path=/` is specified, and the origin is HTTPS.",
                )
                .remediation(
                    "Set `Secure; Path=/`, omit `Domain`, and deliver `__Host-` cookies strictly over HTTPS.",
                ),
            );
        }
    } else if parsed.name.starts_with("__Secure-")
        && (!parsed.secure || (ctx.url.is_some() && !ctx.is_https))
    {
        findings.push(
            Finding::new(
                "OWASP-COOKIE-SECURE-PREFIX-VIOLATION",
                "Cookie uses `__Secure-` prefix without `Secure` or HTTPS origin",
                Severity::High,
                OwaspCategory::A05SecurityMisconfiguration,
                AuditorKind::Cookies,
            )
            .cwe(614)
            .wstg("WSTG-SESS-02")
            .location(loc.clone())
            .evidence(evidence.clone())
            .description(
                "`__Secure-` prefixed cookies require the `Secure` flag and an HTTPS origin.",
            )
            .remediation("Add the `Secure` attribute and set `__Secure-` cookies over HTTPS only."),
        );
    }

    // 2. HttpOnly check (double-submit CSRF cookies legitimately omit HttpOnly for SPA access)
    if !parsed.http_only && !is_csrf {
        let severity = if is_session {
            Severity::High
        } else {
            Severity::Medium
        };
        findings.push(
            Finding::new(
                "OWASP-COOKIE-NO-HTTPONLY",
                "Cookie set without `HttpOnly` attribute",
                severity,
                OwaspCategory::A05SecurityMisconfiguration,
                AuditorKind::Cookies,
            )
            .cwe(1004)
            .wstg("WSTG-SESS-02")
            .location(loc.clone())
            .evidence(evidence.clone())
            .description(
                "Cookies without `HttpOnly` are readable via `document.cookie` if any script executes on the origin.",
            )
            .remediation("Add the `HttpOnly` flag to session, authentication, and sensitive cookies."),
        );
    }

    // 3. Secure flag check
    if !parsed.secure {
        let severity = if is_session || ctx.is_https {
            Severity::High
        } else {
            Severity::Medium
        };
        findings.push(
            Finding::new(
                "OWASP-COOKIE-NO-SECURE",
                "Cookie set without `Secure` attribute",
                severity,
                OwaspCategory::A02CryptographicFailures,
                AuditorKind::Cookies,
            )
            .cwe(614)
            .wstg("WSTG-SESS-02")
            .location(loc.clone())
            .evidence(evidence.clone())
            .description(
                "Cookies without `Secure` may be transmitted over unencrypted HTTP requests on downgrade or mixed-scheme paths.",
            )
            .remediation("Always add the `Secure` attribute and serve cookies strictly over HTTPS."),
        );
    }

    // 4. SameSite checks
    if let Some(bad) = &parsed.invalid_same_site {
        findings.push(
            Finding::new(
                "OWASP-COOKIE-INVALID-SAMESITE",
                "Cookie sets unrecognized `SameSite` attribute value",
                Severity::Medium,
                OwaspCategory::A05SecurityMisconfiguration,
                AuditorKind::Cookies,
            )
            .cwe(1275)
            .wstg("WSTG-SESS-02")
            .location(loc.clone())
            .evidence(format!("{evidence}; invalid SameSite={bad}"))
            .description("Unrecognized `SameSite` values fall back inconsistently across browsers.")
            .remediation("Set `SameSite=Strict` or `SameSite=Lax` (or `SameSite=None; Secure` when required)."),
        );
    } else {
        match parsed.same_site {
            None => {
                findings.push(
                    Finding::new(
                        "OWASP-COOKIE-NO-SAMESITE",
                        "Cookie set without explicit `SameSite` attribute",
                        if is_session { Severity::Medium } else { Severity::Low },
                        OwaspCategory::A01BrokenAccessControl,
                        AuditorKind::Cookies,
                    )
                    .cwe(1275)
                    .wstg("WSTG-SESS-02")
                    .location(loc.clone())
                    .evidence(evidence.clone())
                    .description(
                        "Omitting `SameSite` leaves CSRF cookie transmission behavior dependent on browser defaults.",
                    )
                    .remediation("Explicitly specify `SameSite=Lax` or `SameSite=Strict` on session cookies."),
                );
            }
            Some(SameSite::None) if !parsed.secure => {
                findings.push(
                    Finding::new(
                        "OWASP-COOKIE-SAMESITE-NONE-INSECURE",
                        "Cookie specifies `SameSite=None` without `Secure`",
                        Severity::High,
                        OwaspCategory::A05SecurityMisconfiguration,
                        AuditorKind::Cookies,
                    )
                    .cwe(614)
                    .wstg("WSTG-SESS-02")
                    .location(loc.clone())
                    .evidence(evidence.clone())
                    .description("Modern browsers reject `SameSite=None` cookies that omit `Secure`.")
                    .remediation("Add `Secure` when `SameSite=None` is necessary, or switch to `SameSite=Lax`/`Strict`."),
                );
            }
            Some(SameSite::None) if is_session => {
                findings.push(
                    Finding::new(
                        "OWASP-COOKIE-SAMESITE-NONE-SESSION",
                        "Session-like cookie allows cross-site requests via `SameSite=None`",
                        Severity::Low,
                        OwaspCategory::A01BrokenAccessControl,
                        AuditorKind::Cookies,
                    )
                    .cwe(1275)
                    .wstg("WSTG-SESS-02")
                    .location(loc.clone())
                    .evidence(evidence.clone())
                    .description("`SameSite=None` permits the cookie on cross-site requests, increasing CSRF exposure.")
                    .remediation("Prefer `SameSite=Lax` or `SameSite=Strict` for session cookies unless cross-site SSO/embed requires `None`."),
                );
            }
            Some(_) => {}
        }
    }

    // 5. Over-broad Domain / Path checks
    if let Some(domain) = &parsed.domain
        && is_overly_broad_domain(domain, ctx.host.as_deref())
    {
        findings.push(
            Finding::new(
                "OWASP-COOKIE-BROAD-DOMAIN",
                "Cookie sets overly broad `Domain` scope",
                if is_session { Severity::Medium } else { Severity::Low },
                OwaspCategory::A05SecurityMisconfiguration,
                AuditorKind::Cookies,
            )
            .cwe(200)
            .wstg("WSTG-SESS-02")
            .location(loc.clone())
            .evidence(format!("Domain={domain}"))
            .description(
                "Setting `Domain` shares the cookie with all subdomains, expanding blast radius if any subdomain is compromised.",
            )
            .remediation("Omit the `Domain` attribute (host-only cookie) unless cross-subdomain sharing is explicitly required."),
        );
    }

    if is_session && parsed.path.is_none() {
        findings.push(
            Finding::new(
                "OWASP-COOKIE-MISSING-PATH",
                "Session cookie omits explicit `Path` attribute",
                Severity::Info,
                OwaspCategory::A05SecurityMisconfiguration,
                AuditorKind::Cookies,
            )
            .cwe(16)
            .wstg("WSTG-SESS-02")
            .location(loc.clone())
            .evidence(evidence.clone())
            .description("Session cookies without an explicit `Path` inherit the directory path of the request URL.")
            .remediation("Set `Path=/` (or the narrowest application base path) explicitly."),
        );
    }

    // 6. Inspect cookie value passively if it looks like a JWT
    if parsed.value.starts_with("eyJ")
        && parsed.value.matches('.').count() == 2
        && let Ok(jwt_res) = jwt::audit_jwt(&parsed.value, Some(&loc), None)
    {
        findings.extend(jwt_res.findings);
    }

    findings
}

/// Audits runtime-observed cookies (e.g. from `document.cookie`).
#[must_use]
pub fn audit_cookies(cookies: &[CookieInput], ctx: &CookieAuditContext) -> Vec<Finding> {
    let mut findings = Vec::new();
    for cookie in cookies {
        if cookie.value == "[redacted]" {
            continue;
        }
        let loc = match &ctx.url {
            Some(url) => format!("{url} [cookie:{}]", cookie.name),
            None => format!("cookie:{}", cookie.name),
        };
        let is_session = is_session_cookie_name(&cookie.name);
        let is_csrf = is_csrf_cookie_name(&cookie.name.to_ascii_lowercase());

        if cookie.from_document_cookie && is_session && !is_csrf {
            findings.push(
                Finding::new(
                    "OWASP-COOKIE-JS-ACCESSIBLE-SESSION",
                    "Session-like cookie is accessible to JavaScript (`document.cookie`)",
                    Severity::High,
                    OwaspCategory::A05SecurityMisconfiguration,
                    AuditorKind::Cookies,
                )
                .cwe(1004)
                .wstg("WSTG-SESS-02")
                .location(loc.clone())
                .evidence(format!("{}=[redacted] (visible in document.cookie)", cookie.name))
                .description(
                    "Any cookie readable in `document.cookie` does not carry `HttpOnly` and can be read by client scripts.",
                )
                .remediation("Set `HttpOnly` on session and authentication cookies via `Set-Cookie`."),
            );
        }

        if cookie.value.starts_with("eyJ")
            && cookie.value.matches('.').count() == 2
            && let Ok(jwt_res) = jwt::audit_jwt(&cookie.value, Some(&loc), None)
        {
            findings.extend(jwt_res.findings);
        }
    }
    findings
}

fn is_overly_broad_domain(domain_attr: &str, request_host: Option<&str>) -> bool {
    let cleaned = domain_attr
        .trim()
        .trim_start_matches('.')
        .to_ascii_lowercase();
    if cleaned.is_empty() {
        return false;
    }
    if domain_attr.trim().starts_with('.') {
        return true;
    }
    if let Some(host) = request_host {
        let host_lower = host.to_ascii_lowercase();
        if host_lower != cleaned && host_lower.ends_with(&format!(".{cleaned}")) {
            return true;
        }
    }
    false
}
