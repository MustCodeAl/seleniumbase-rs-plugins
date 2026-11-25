//! Passive HTTP response header, CSP AST, CORS, and server banner auditor.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::auditors::cookies::{CookieAuditContext, audit_set_cookie};
use crate::auditors::jwt;
use crate::types::{AuditorKind, Finding, OwaspCategory, Severity, redact_secret};

const ONE_YEAR_SECS: u64 = 31_536_000;

const SENSITIVE_PERMISSIONS: &[&str] = &["camera", "microphone", "geolocation", "payment", "usb"];

/// Parsed CSP source expression inside a directive.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum CspSource {
    /// `'none'`
    None,
    /// `'self'`
    SelfOrigin,
    /// `'unsafe-inline'`
    UnsafeInline,
    /// `'unsafe-eval'`
    UnsafeEval,
    /// `'wasm-unsafe-eval'`
    WasmUnsafeEval,
    /// `'unsafe-hashes'`
    UnsafeHashes,
    /// `'strict-dynamic'`
    StrictDynamic,
    /// `'report-sample'`
    ReportSample,
    /// Wildcard `*`
    Wildcard,
    /// Scheme source (for example `data:`, `http:`, `https:`, `blob:`).
    Scheme(String),
    /// Nonce source (`'nonce-...'`).
    Nonce(String),
    /// Hash source (`'sha256-...'`, `'sha384-...'`, `'sha512-...'`).
    Hash(String),
    /// Host or path source expression.
    Host(String),
}

impl CspSource {
    /// Parses a single CSP source token.
    #[must_use]
    pub fn parse(token: &str) -> Self {
        let trimmed = token.trim();
        let lower = trimmed.to_ascii_lowercase();
        match lower.as_str() {
            "'none'" => Self::None,
            "'self'" => Self::SelfOrigin,
            "'unsafe-inline'" => Self::UnsafeInline,
            "'unsafe-eval'" => Self::UnsafeEval,
            "'wasm-unsafe-eval'" => Self::WasmUnsafeEval,
            "'unsafe-hashes'" => Self::UnsafeHashes,
            "'strict-dynamic'" => Self::StrictDynamic,
            "'report-sample'" => Self::ReportSample,
            "*" => Self::Wildcard,
            _ if lower.starts_with("'nonce-") && lower.ends_with('\'') => {
                Self::Nonce(trimmed.to_owned())
            }
            _ if (lower.starts_with("'sha256-")
                || lower.starts_with("'sha384-")
                || lower.starts_with("'sha512-"))
                && lower.ends_with('\'') =>
            {
                Self::Hash(trimmed.to_owned())
            }
            _ if lower.ends_with(':') && !lower.contains('/') => Self::Scheme(lower),
            _ => Self::Host(trimmed.to_owned()),
        }
    }

    /// Returns `true` if this source matches a given scheme prefix such as `data:` or `http:`.
    #[must_use]
    pub fn is_scheme(&self, scheme: &str) -> bool {
        match self {
            Self::Scheme(s) => s.eq_ignore_ascii_case(scheme),
            Self::Host(h) => h
                .to_ascii_lowercase()
                .starts_with(&scheme.to_ascii_lowercase()),
            _ => false,
        }
    }
}

/// Single directive inside a parsed [`CspPolicy`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct CspDirective {
    /// Lowercase CSP directive name (for example `script-src`, `default-src`).
    pub name: String,
    /// Parsed source expressions for this directive.
    pub sources: Vec<CspSource>,
    /// Original raw source tokens.
    pub raw_tokens: Vec<String>,
}

/// AST representation of a `Content-Security-Policy` header value.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct CspPolicy {
    /// Effective directives in policy order (per CSP3, duplicate directive names are ignored after the first).
    pub directives: Vec<CspDirective>,
    /// Duplicate directive names encountered in the header.
    pub duplicate_directives: Vec<String>,
}

impl CspPolicy {
    /// Parses a raw `Content-Security-Policy` header string into a [`CspPolicy`] AST.
    #[must_use]
    pub fn parse(raw: &str) -> Self {
        let mut policy = Self::default();
        for segment in raw.split(';') {
            let trimmed = segment.trim();
            if trimmed.is_empty() {
                continue;
            }
            let mut tokens = trimmed.split_ascii_whitespace();
            let Some(name_raw) = tokens.next() else {
                continue;
            };
            let name = name_raw.to_ascii_lowercase();
            if policy.directives.iter().any(|d| d.name == name) {
                policy.duplicate_directives.push(name);
                continue;
            }
            let raw_tokens: Vec<String> = tokens.map(str::to_owned).collect();
            let sources = raw_tokens.iter().map(|t| CspSource::parse(t)).collect();
            policy.directives.push(CspDirective {
                name,
                sources,
                raw_tokens,
            });
        }
        policy
    }

    /// Returns the directive with `name` (case-insensitive), if present.
    #[must_use]
    pub fn directive(&self, name: &str) -> Option<&CspDirective> {
        self.directives
            .iter()
            .find(|d| d.name.eq_ignore_ascii_case(name))
    }

    /// Returns `true` when `name` is present in the policy.
    #[must_use]
    pub fn has_directive(&self, name: &str) -> bool {
        self.directive(name).is_some()
    }
}

/// Context passed into the HTTP header auditor.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct HeaderAuditContext<'a> {
    /// Target URL of the HTTP response.
    pub url: &'a str,
    /// HTTP response status code (`0` if blocked/failed before receiving a response).
    pub status: u16,
    /// Response MIME type (for example `text/html`, `application/json`).
    pub mime: &'a str,
    /// Whether this resource is a top-level/frame document navigation.
    pub is_document: bool,
    /// Header pairs `(name, value)` preserving multi-value headers such as `Set-Cookie` and `CSP`.
    pub headers: &'a [(String, String)],
    /// Optional request `Origin` header for reflected-CORS correlation.
    pub request_origin: Option<&'a str>,
}

impl<'a> HeaderAuditContext<'a> {
    /// Creates a new header audit context for an HTTP response.
    #[must_use]
    pub const fn new(
        url: &'a str,
        status: u16,
        mime: &'a str,
        headers: &'a [(String, String)],
    ) -> Self {
        Self {
            url,
            status,
            mime,
            is_document: false,
            headers,
            request_origin: None,
        }
    }

    /// Marks whether the response is a top-level/frame document navigation.
    #[must_use]
    pub const fn document(mut self, is_document: bool) -> Self {
        self.is_document = is_document;
        self
    }

    /// Supplies the request `Origin` header for reflected-CORS correlation.
    #[must_use]
    pub const fn request_origin(mut self, origin: Option<&'a str>) -> Self {
        self.request_origin = origin;
        self
    }
}

/// Convenience helper for auditing a `BTreeMap<String, String>` header map.
#[must_use]
pub fn audit_headers_map(
    url: &str,
    status: u16,
    mime: &str,
    is_document: bool,
    headers: &BTreeMap<String, String>,
) -> Vec<Finding> {
    let pairs: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let request_origin = find_first_header(&pairs, "origin").map(str::to_owned);
    audit_headers(&HeaderAuditContext {
        url,
        status,
        mime,
        is_document,
        headers: &pairs,
        request_origin: request_origin.as_deref(),
    })
}

/// Audits HTTP response headers, CSP policies, CORS posture, HSTS, banners, and `Set-Cookie`.
#[must_use]
pub fn audit_headers(ctx: &HeaderAuditContext<'_>) -> Vec<Finding> {
    let mut findings = Vec::new();
    let url_lower = ctx.url.trim().to_ascii_lowercase();
    let is_https = url_lower.starts_with("https://");
    let is_http = url_lower.starts_with("http://");
    let is_html = ctx.is_document || ctx.mime.to_ascii_lowercase().contains("html");

    if ctx.status == 0 {
        return findings;
    }

    // 1. Plaintext HTTP transport check
    if is_http && !is_loopback_http(&url_lower) {
        findings.push(
            Finding::new(
                "OWASP-HDR-CLEARTEXT-HTTP",
                "Response served over unencrypted HTTP",
                Severity::Medium,
                OwaspCategory::A02CryptographicFailures,
                AuditorKind::Headers,
            )
            .cwe(319)
            .wstg("WSTG-CRYP-03")
            .location(ctx.url)
            .evidence(format!("scheme=http, status={}", ctx.status))
            .description("Traffic served over `http://` exposes headers, cookies, and payloads to interception.")
            .remediation("Serve all endpoints over HTTPS and redirect HTTP requests with 301/308 to HTTPS."),
        );
    }

    // 2. HSTS (Strict-Transport-Security)
    let hsts_values = find_all_headers(ctx.headers, "strict-transport-security");
    if is_https {
        if hsts_values.is_empty() {
            if ctx.is_document {
                findings.push(
                    Finding::new(
                        "OWASP-HDR-HSTS-MISSING",
                        "Missing `Strict-Transport-Security` (HSTS) header",
                        Severity::Medium,
                        OwaspCategory::A05SecurityMisconfiguration,
                        AuditorKind::Headers,
                    )
                    .cwe(523)
                    .wstg("WSTG-CONF-07")
                    .location(ctx.url)
                    .description("HTTPS response omits HSTS, leaving users vulnerable to initial HTTP downgrade attacks.")
                    .remediation("Set `Strict-Transport-Security: max-age=31536000; includeSubDomains`."),
                );
            }
        } else {
            for val in &hsts_values {
                audit_hsts(ctx.url, val, &mut findings);
            }
        }
    } else if is_http && !hsts_values.is_empty() {
        findings.push(
            Finding::new(
                "OWASP-HDR-HSTS-OVER-HTTP",
                "`Strict-Transport-Security` sent over insecure HTTP",
                Severity::Info,
                OwaspCategory::A05SecurityMisconfiguration,
                AuditorKind::Headers,
            )
            .cwe(523)
            .wstg("WSTG-CONF-07")
            .location(ctx.url)
            .evidence(hsts_values[0].clone())
            .description(
                "Per RFC 6797, user agents ignore HSTS headers received over plaintext HTTP.",
            )
            .remediation("Emit HSTS exclusively on HTTPS responses."),
        );
    }

    // 3. Content-Security-Policy (AST parser)
    let csp_headers = find_all_headers(ctx.headers, "content-security-policy");
    let csp_ro_headers = find_all_headers(ctx.headers, "content-security-policy-report-only");
    let mut csp_has_frame_ancestors = false;

    if is_html {
        if csp_headers.is_empty() {
            if !csp_ro_headers.is_empty() {
                findings.push(
                    Finding::new(
                        "OWASP-CSP-REPORT-ONLY-WITHOUT-ENFORCING",
                        "Only `Content-Security-Policy-Report-Only` is configured",
                        Severity::Low,
                        OwaspCategory::A05SecurityMisconfiguration,
                        AuditorKind::Headers,
                    )
                    .cwe(693)
                    .wstg("WSTG-CONF-12")
                    .location(ctx.url)
                    .description("A report-only CSP observes violations without enforcing script or framing restrictions.")
                    .remediation("Promote the validated policy to an enforcing `Content-Security-Policy` header."),
                );
            } else {
                findings.push(
                    Finding::new(
                        "OWASP-CSP-MISSING",
                        "Missing `Content-Security-Policy` header",
                        Severity::Medium,
                        OwaspCategory::A05SecurityMisconfiguration,
                        AuditorKind::Headers,
                    )
                    .cwe(693)
                    .wstg("WSTG-CONF-12")
                    .location(ctx.url)
                    .description("Document lacks a Content-Security-Policy to mitigate XSS and unauthorized script injection.")
                    .remediation("Define a restrictive `Content-Security-Policy` with `default-src 'self'`, `object-src 'none'`, `base-uri 'self'`, and `frame-ancestors`."),
                );
            }
        } else {
            for raw_csp in &csp_headers {
                let policy = CspPolicy::parse(raw_csp);
                if policy.has_directive("frame-ancestors") {
                    csp_has_frame_ancestors = true;
                }
                audit_csp_policy(ctx.url, &policy, &mut findings);
            }
        }
    }

    // 4. Clickjacking (`X-Frame-Options` & `frame-ancestors`)
    let xfo = find_first_header(ctx.headers, "x-frame-options");
    if is_html {
        match xfo {
            None if !csp_has_frame_ancestors => {
                findings.push(
                    Finding::new(
                        "OWASP-HDR-CLICKJACKING-MISSING",
                        "Missing clickjacking protection (`X-Frame-Options` / CSP `frame-ancestors`)",
                        Severity::Medium,
                        OwaspCategory::A05SecurityMisconfiguration,
                        AuditorKind::Headers,
                    )
                    .cwe(1021)
                    .wstg("WSTG-CLNT-09")
                    .location(ctx.url)
                    .description("Neither `X-Frame-Options` nor CSP `frame-ancestors` prevents cross-origin framing.")
                    .remediation("Set `Content-Security-Policy: frame-ancestors 'none'` (or `'self'`) and `X-Frame-Options: DENY` / `SAMEORIGIN`."),
                );
            }
            Some(val) => {
                let upper = val.trim().to_ascii_uppercase();
                if upper != "DENY" && upper != "SAMEORIGIN" {
                    findings.push(
                        Finding::new(
                            "OWASP-HDR-XFO-WEAK",
                            "Weak or deprecated `X-Frame-Options` value",
                            Severity::Low,
                            OwaspCategory::A05SecurityMisconfiguration,
                            AuditorKind::Headers,
                        )
                        .cwe(1021)
                        .wstg("WSTG-CLNT-09")
                        .location(ctx.url)
                        .evidence(format!("X-Frame-Options: {val}"))
                        .description("Modern browsers ignore `ALLOW-FROM` or malformed `X-Frame-Options` values.")
                        .remediation("Use `X-Frame-Options: DENY` or `SAMEORIGIN` alongside CSP `frame-ancestors`."),
                    );
                }
            }
            _ => {}
        }
    }

    // 5. X-Content-Type-Options
    match find_first_header(ctx.headers, "x-content-type-options") {
        None if ctx.is_document => {
            findings.push(
                Finding::new(
                    "OWASP-HDR-XCTO-MISSING",
                    "Missing `X-Content-Type-Options: nosniff` header",
                    Severity::Low,
                    OwaspCategory::A05SecurityMisconfiguration,
                    AuditorKind::Headers,
                )
                .cwe(16)
                .wstg("WSTG-CONF-07")
                .location(ctx.url)
                .description("Without `nosniff`, browsers may MIME-sniff non-script responses into executable types.")
                .remediation("Send `X-Content-Type-Options: nosniff` on all responses."),
            );
        }
        Some(val) if !val.trim().eq_ignore_ascii_case("nosniff") => {
            findings.push(
                Finding::new(
                    "OWASP-HDR-XCTO-INVALID",
                    "Non-standard `X-Content-Type-Options` value",
                    Severity::Low,
                    OwaspCategory::A05SecurityMisconfiguration,
                    AuditorKind::Headers,
                )
                .cwe(16)
                .wstg("WSTG-CONF-07")
                .location(ctx.url)
                .evidence(format!("X-Content-Type-Options: {val}"))
                .description(
                    "`X-Content-Type-Options` must be set to `nosniff` to disable MIME sniffing.",
                )
                .remediation("Set `X-Content-Type-Options: nosniff`."),
            );
        }
        _ => {}
    }

    // 6. Referrer-Policy
    if ctx.is_document {
        match find_first_header(ctx.headers, "referrer-policy") {
            None => {
                findings.push(
                    Finding::new(
                        "OWASP-HDR-REFERRER-POLICY-MISSING",
                        "Missing `Referrer-Policy` header",
                        Severity::Low,
                        OwaspCategory::A05SecurityMisconfiguration,
                        AuditorKind::Headers,
                    )
                    .cwe(200)
                    .wstg("WSTG-CONF-07")
                    .location(ctx.url)
                    .description("No `Referrer-Policy` header was observed; full path/query URLs may leak to third parties depending on defaults.")
                    .remediation("Set `Referrer-Policy: strict-origin-when-cross-origin` or `no-referrer`."),
                );
            }
            Some(val) => {
                let lower = val.trim().to_ascii_lowercase();
                if lower == "unsafe-url"
                    || lower == "no-referrer-when-downgrade"
                    || lower == "origin"
                {
                    let sev = if lower == "unsafe-url" {
                        Severity::Medium
                    } else {
                        Severity::Low
                    };
                    findings.push(
                        Finding::new(
                            "OWASP-HDR-REFERRER-POLICY-WEAK",
                            "Permissive `Referrer-Policy` may leak URL paths or query parameters",
                            sev,
                            OwaspCategory::A05SecurityMisconfiguration,
                            AuditorKind::Headers,
                        )
                        .cwe(200)
                        .wstg("WSTG-CONF-07")
                        .location(ctx.url)
                        .evidence(format!("Referrer-Policy: {val}"))
                        .description("Permissive referrer policies can expose sensitive query parameters or paths cross-origin.")
                        .remediation("Use `strict-origin-when-cross-origin`, `same-origin`, or `no-referrer`."),
                    );
                }
            }
        }
    }

    // 7. Permissions-Policy
    if is_html {
        match find_first_header(ctx.headers, "permissions-policy") {
            None => {
                findings.push(
                    Finding::new(
                        "OWASP-HDR-PERMISSIONS-POLICY-MISSING",
                        "Missing `Permissions-Policy` header",
                        Severity::Info,
                        OwaspCategory::A05SecurityMisconfiguration,
                        AuditorKind::Headers,
                    )
                    .cwe(16)
                    .wstg("WSTG-CONF-07")
                    .location(ctx.url)
                    .description("Document does not explicitly restrict powerful browser APIs (camera, microphone, geolocation).")
                    .remediation("Send `Permissions-Policy: camera=(), microphone=(), geolocation=()`."),
                );
            }
            Some(val) => audit_permissions_policy(ctx.url, val, &mut findings),
        }
    }

    // 8. Cross-Origin Isolation headers (COOP / COEP / CORP)
    if is_html {
        if find_first_header(ctx.headers, "cross-origin-opener-policy").is_none() {
            findings.push(
                Finding::new(
                    "OWASP-HDR-COOP-MISSING",
                    "Missing `Cross-Origin-Opener-Policy` (COOP) header",
                    Severity::Info,
                    OwaspCategory::A05SecurityMisconfiguration,
                    AuditorKind::Headers,
                )
                .cwe(346)
                .wstg("WSTG-CONF-07")
                .location(ctx.url)
                .description("Without COOP (`same-origin`), cross-origin popups may share a browsing context group.")
                .remediation("Set `Cross-Origin-Opener-Policy: same-origin` when cross-origin popup communication is unnecessary."),
            );
        }
        if find_first_header(ctx.headers, "cross-origin-embedder-policy").is_none() {
            findings.push(
                Finding::new(
                    "OWASP-HDR-COEP-MISSING",
                    "Missing `Cross-Origin-Embedder-Policy` (COEP) header",
                    Severity::Info,
                    OwaspCategory::A05SecurityMisconfiguration,
                    AuditorKind::Headers,
                )
                .cwe(346)
                .wstg("WSTG-CONF-07")
                .location(ctx.url)
                .description("COEP prevents documents from loading non-CORP/CORS cross-origin resources.")
                .remediation("Consider `Cross-Origin-Embedder-Policy: require-corp` or `credentialless` for cross-origin isolation."),
            );
        }
        if find_first_header(ctx.headers, "cross-origin-resource-policy").is_none() {
            findings.push(
                Finding::new(
                    "OWASP-HDR-CORP-MISSING",
                    "Missing `Cross-Origin-Resource-Policy` (CORP) header",
                    Severity::Info,
                    OwaspCategory::A05SecurityMisconfiguration,
                    AuditorKind::Headers,
                )
                .cwe(346)
                .wstg("WSTG-CONF-07")
                .location(ctx.url)
                .description("Without CORP, cross-origin embeds may attempt speculative/no-cors reads of resources.")
                .remediation("Set `Cross-Origin-Resource-Policy: same-origin` (or `same-site`)."),
            );
        }
    }

    // 9. Server / stack banner leaks
    for banner_header in [
        "server",
        "x-powered-by",
        "x-aspnet-version",
        "x-aspnetmvc-version",
        "x-generator",
    ] {
        if let Some(val) = find_first_header(ctx.headers, banner_header)
            && is_informative_banner(banner_header, val)
        {
            findings.push(
                Finding::new(
                    "OWASP-HDR-BANNER-LEAK",
                    format!("Server technology banner disclosed via `{banner_header}`"),
                    Severity::Low,
                    OwaspCategory::A05SecurityMisconfiguration,
                    AuditorKind::Headers,
                )
                .cwe(200)
                .wstg("WSTG-INFO-02")
                .location(ctx.url)
                .evidence(format!("{banner_header}: {val}"))
                .description("Technology and version banners help fingerprint server stacks and patch levels.")
                .remediation("Suppress or strip `Server` version details and `X-Powered-By` / `X-AspNet-Version` headers."),
            );
        }
    }

    // 10. CORS posture checks
    audit_cors(ctx, &mut findings);

    // 11. Set-Cookie headers
    let cookie_ctx = CookieAuditContext::from_url(Some(ctx.url));
    for set_cookie in find_all_headers(ctx.headers, "set-cookie") {
        findings.extend(audit_set_cookie(&set_cookie, &cookie_ctx));
    }

    // 12. Passive JWT detection in Authorization header (when unredacted)
    if let Some(auth) = find_first_header(ctx.headers, "authorization")
        && auth != "[redacted]"
    {
        for token in jwt::find_jwts_in_text(auth) {
            if let Ok(res) =
                jwt::audit_jwt(&token, Some(&format!("{} [Authorization]", ctx.url)), None)
            {
                findings.extend(res.findings);
            }
        }
        if auth.to_ascii_lowercase().starts_with("basic ") {
            findings.push(
                Finding::new(
                    "OWASP-HDR-BASIC-AUTH-EXPOSED",
                    "HTTP Basic authentication credential observed in request header",
                    if is_https { Severity::Info } else { Severity::High },
                    OwaspCategory::A07IdentificationAndAuthenticationFailures,
                    AuditorKind::Headers,
                )
                .cwe(522)
                .wstg("WSTG-ATHN-01")
                .location(ctx.url)
                .evidence(format!("Authorization: Basic {}", redact_secret(auth)))
                .description("HTTP Basic authentication sends static encoded credentials on every request.")
                .remediation("Prefer short-lived bearer/session tokens over HTTPS rather than HTTP Basic credentials."),
            );
        }
    }

    findings
}

fn audit_hsts(url: &str, raw: &str, findings: &mut Vec<Finding>) {
    let mut max_age: Option<u64> = None;
    let mut include_subdomains = false;

    for part in raw.split(';') {
        let trimmed = part.trim();
        if trimmed.eq_ignore_ascii_case("includesubdomains") {
            include_subdomains = true;
        } else if let Some((k, v)) = trimmed.split_once('=')
            && k.trim().eq_ignore_ascii_case("max-age")
        {
            let clean = v.trim().trim_matches('"');
            max_age = clean.parse::<u64>().ok();
        }
    }

    match max_age {
        None => {
            findings.push(
                Finding::new(
                    "OWASP-HDR-HSTS-NO-MAX-AGE",
                    "HSTS header missing valid `max-age` directive",
                    Severity::Medium,
                    OwaspCategory::A05SecurityMisconfiguration,
                    AuditorKind::Headers,
                )
                .cwe(523)
                .wstg("WSTG-CONF-07")
                .location(url)
                .evidence(format!("Strict-Transport-Security: {raw}"))
                .description("An HSTS header without `max-age` is ignored by browsers.")
                .remediation(
                    "Set `Strict-Transport-Security: max-age=31536000; includeSubDomains`.",
                ),
            );
        }
        Some(0) => {
            findings.push(
                Finding::new(
                    "OWASP-HDR-HSTS-DISABLED",
                    "HSTS disabled with `max-age=0`",
                    Severity::High,
                    OwaspCategory::A05SecurityMisconfiguration,
                    AuditorKind::Headers,
                )
                .cwe(523)
                .wstg("WSTG-CONF-07")
                .location(url)
                .evidence(format!("Strict-Transport-Security: {raw}"))
                .description(
                    "`max-age=0` instructs browsers to immediately delete the stored HSTS policy.",
                )
                .remediation("Set `max-age` to at least `31536000` (1 year)."),
            );
        }
        Some(age) if age < ONE_YEAR_SECS => {
            findings.push(
                Finding::new(
                    "OWASP-HDR-HSTS-SHORT-MAX-AGE",
                    "HSTS `max-age` is shorter than 1 year (31,536,000 s)",
                    Severity::Low,
                    OwaspCategory::A05SecurityMisconfiguration,
                    AuditorKind::Headers,
                )
                .cwe(523)
                .wstg("WSTG-CONF-07")
                .location(url)
                .evidence(format!("Strict-Transport-Security: {raw}"))
                .description("Short HSTS lifetimes reduce protection between infrequent visits.")
                .remediation("Increase `max-age` to at least `31536000` seconds."),
            );
        }
        Some(_) => {}
    }

    if !include_subdomains && max_age.is_some_and(|a| a > 0) {
        findings.push(
            Finding::new(
                "OWASP-HDR-HSTS-NO-SUBDOMAINS",
                "HSTS omits `includeSubDomains` directive",
                Severity::Info,
                OwaspCategory::A05SecurityMisconfiguration,
                AuditorKind::Headers,
            )
            .cwe(523)
            .wstg("WSTG-CONF-07")
            .location(url)
            .evidence(format!("Strict-Transport-Security: {raw}"))
            .description("Without `includeSubDomains`, sibling or sub-hosts remain exposed to plaintext downgrade.")
            .remediation("Include `includeSubDomains` once all subdomains serve valid HTTPS."),
        );
    }
}

fn audit_csp_policy(url: &str, policy: &CspPolicy, findings: &mut Vec<Finding>) {
    if !policy.duplicate_directives.is_empty() {
        findings.push(
            Finding::new(
                "OWASP-CSP-DUPLICATE-DIRECTIVE",
                "CSP contains duplicate directives (subsequent copies ignored)",
                Severity::Low,
                OwaspCategory::A05SecurityMisconfiguration,
                AuditorKind::Headers,
            )
            .cwe(693)
            .wstg("WSTG-CONF-12")
            .location(url)
            .evidence(format!(
                "duplicates={}",
                policy.duplicate_directives.join(", ")
            ))
            .description(
                "Per CSP Level 3, browsers ignore duplicate directives after the first occurrence.",
            )
            .remediation("Merge duplicate directive source lists into a single directive."),
        );
    }

    let script_dir = policy
        .directive("script-src")
        .or_else(|| policy.directive("script-src-elem"))
        .or_else(|| policy.directive("default-src"));

    match script_dir {
        None => {
            findings.push(
                Finding::new(
                    "OWASP-CSP-MISSING-SCRIPT-SRC",
                    "CSP defines neither `script-src` nor `default-src`",
                    Severity::High,
                    OwaspCategory::A05SecurityMisconfiguration,
                    AuditorKind::Headers,
                )
                .cwe(693)
                .wstg("WSTG-CLNT-03")
                .location(url)
                .description("Without `script-src` or `default-src`, inline and external scripts run unrestricted.")
                .remediation("Add `default-src 'self'` and a strict `script-src` policy."),
            );
        }
        Some(dir) => {
            let has_nonce_or_hash = dir
                .sources
                .iter()
                .any(|s| matches!(s, CspSource::Nonce(_) | CspSource::Hash(_)));
            let has_strict_dynamic = dir.sources.contains(&CspSource::StrictDynamic);

            if dir.sources.contains(&CspSource::UnsafeInline) {
                let (sev, desc) = if has_nonce_or_hash || has_strict_dynamic {
                    (
                        Severity::Low,
                        "CSP includes `'unsafe-inline'` alongside a nonce/hash; modern CSP2+ browsers ignore `'unsafe-inline'`, though legacy clients still permit inline execution.",
                    )
                } else {
                    (
                        Severity::High,
                        "CSP allows `'unsafe-inline'` in scripts without nonces/hashes, permitting arbitrary inline script execution.",
                    )
                };
                findings.push(
                    Finding::new(
                        "OWASP-CSP-UNSAFE-INLINE",
                        format!("CSP `{}` permits `'unsafe-inline'`", dir.name),
                        sev,
                        OwaspCategory::A03Injection,
                        AuditorKind::Headers,
                    )
                    .cwe(79)
                    .wstg("WSTG-CLNT-03")
                    .location(url)
                    .evidence(format!("{} {}", dir.name, dir.raw_tokens.join(" ")))
                    .description(desc)
                    .remediation("Remove `'unsafe-inline'` and adopt per-request cryptographic nonces or SRI hashes."),
                );
            }

            if dir.sources.contains(&CspSource::UnsafeEval) {
                findings.push(
                    Finding::new(
                        "OWASP-CSP-UNSAFE-EVAL",
                        format!("CSP `{}` permits `'unsafe-eval'`", dir.name),
                        Severity::Medium,
                        OwaspCategory::A03Injection,
                        AuditorKind::Headers,
                    )
                    .cwe(95)
                    .wstg("WSTG-CLNT-03")
                    .location(url)
                    .evidence(format!("{} {}", dir.name, dir.raw_tokens.join(" ")))
                    .description("`'unsafe-eval'` permits dynamic code evaluation via `eval()`, `Function()`, and string timers.")
                    .remediation("Eliminate `eval()`/`new Function()` calls and remove `'unsafe-eval'` from CSP."),
                );
            }

            if dir.sources.contains(&CspSource::Wildcard) {
                findings.push(
                    Finding::new(
                        "OWASP-CSP-WILDCARD-SCRIPT",
                        format!("CSP `{}` allows wildcard `*` script origin", dir.name),
                        Severity::High,
                        OwaspCategory::A05SecurityMisconfiguration,
                        AuditorKind::Headers,
                    )
                    .cwe(693)
                    .wstg("WSTG-CLNT-03")
                    .location(url)
                    .evidence(format!("{} {}", dir.name, dir.raw_tokens.join(" ")))
                    .description("Wildcard `*` allows scripts to be loaded from any arbitrary network host.")
                    .remediation("Replace `*` with explicit trusted origins or `'strict-dynamic'` with nonces."),
                );
            }

            if dir.sources.iter().any(|s| s.is_scheme("data:")) {
                findings.push(
                    Finding::new(
                        "OWASP-CSP-DATA-SCRIPT",
                        format!("CSP `{}` permits `data:` URIs for scripts", dir.name),
                        Severity::High,
                        OwaspCategory::A03Injection,
                        AuditorKind::Headers,
                    )
                    .cwe(79)
                    .wstg("WSTG-CLNT-03")
                    .location(url)
                    .evidence(format!("{} {}", dir.name, dir.raw_tokens.join(" ")))
                    .description("Allowing `data:` in `script-src` lets attackers inject executable JavaScript via data URLs.")
                    .remediation("Remove `data:` from `script-src` / `default-src`."),
                );
            }

            if dir.sources.iter().any(|s| s.is_scheme("http:")) {
                findings.push(
                    Finding::new(
                        "OWASP-CSP-HTTP-SCRIPT",
                        format!("CSP `{}` permits plaintext `http:` script sources", dir.name),
                        Severity::High,
                        OwaspCategory::A02CryptographicFailures,
                        AuditorKind::Headers,
                    )
                    .cwe(345)
                    .wstg("WSTG-CRYP-03")
                    .location(url)
                    .evidence(format!("{} {}", dir.name, dir.raw_tokens.join(" ")))
                    .description("Allowing `http:` script sources permits network modification of executable scripts.")
                    .remediation("Restrict script origins strictly to HTTPS (`https:` or explicit `https://` hosts)."),
                );
            }
        }
    }

    // Wildcard checks across other sensitive directives
    for check_dir in [
        "default-src",
        "connect-src",
        "frame-ancestors",
        "object-src",
    ] {
        if let Some(dir) = policy.directive(check_dir)
            && dir.sources.contains(&CspSource::Wildcard)
            && script_dir.is_none_or(|s| s.name != check_dir)
        {
            findings.push(
                Finding::new(
                    "OWASP-CSP-WILDCARD-DIRECTIVE",
                    format!("CSP `{check_dir}` uses overly permissive `*` wildcard"),
                    Severity::Medium,
                    OwaspCategory::A05SecurityMisconfiguration,
                    AuditorKind::Headers,
                )
                .cwe(693)
                .wstg("WSTG-CONF-12")
                .location(url)
                .evidence(format!("{check_dir} {}", dir.raw_tokens.join(" ")))
                .description(format!(
                    "`{check_dir} *` weakens origin isolation for that resource class."
                ))
                .remediation(format!(
                    "Restrict `{check_dir}` to `'none'`, `'self'`, or explicit allowlisted origins."
                )),
            );
        }
    }

    let default_is_none = policy
        .directive("default-src")
        .is_some_and(|d| d.sources == [CspSource::None]);
    if !policy.has_directive("object-src") && !default_is_none {
        findings.push(
            Finding::new(
                "OWASP-CSP-MISSING-OBJECT-SRC",
                "CSP omits `object-src` directive",
                Severity::Medium,
                OwaspCategory::A05SecurityMisconfiguration,
                AuditorKind::Headers,
            )
            .cwe(693)
            .wstg("WSTG-CONF-12")
            .location(url)
            .description("Without `object-src 'none'`, legacy `<object>` / `<embed>` plugin contexts may bypass script restrictions.")
            .remediation("Add `object-src 'none'` to the Content-Security-Policy."),
        );
    }

    if !policy.has_directive("base-uri") {
        findings.push(
            Finding::new(
                "OWASP-CSP-MISSING-BASE-URI",
                "CSP omits `base-uri` directive",
                Severity::Medium,
                OwaspCategory::A05SecurityMisconfiguration,
                AuditorKind::Headers,
            )
            .cwe(693)
            .wstg("WSTG-CONF-12")
            .location(url)
            .description("`base-uri` does not inherit from `default-src`; omitting it can permit `<base>` tag injection hijacking relative script URLs.")
            .remediation("Add `base-uri 'none'` or `base-uri 'self'` to the Content-Security-Policy."),
        );
    }

    if !policy.has_directive("frame-ancestors") {
        findings.push(
            Finding::new(
                "OWASP-CSP-MISSING-FRAME-ANCESTORS",
                "CSP omits `frame-ancestors` directive",
                Severity::Low,
                OwaspCategory::A05SecurityMisconfiguration,
                AuditorKind::Headers,
            )
            .cwe(1021)
            .wstg("WSTG-CLNT-09")
            .location(url)
            .description("`frame-ancestors` supersedes `X-Frame-Options` and does not fall back to `default-src`.")
            .remediation("Add `frame-ancestors 'none'` or `'self'` to the Content-Security-Policy."),
        );
    }
}

fn audit_permissions_policy(url: &str, raw: &str, findings: &mut Vec<Finding>) {
    let lower = raw.to_ascii_lowercase();
    for feature in SENSITIVE_PERMISSIONS {
        let wildcard_a = format!("{feature}=*");
        let wildcard_b = format!("{feature}=(*)");
        if lower.contains(&wildcard_a) || lower.contains(&wildcard_b) {
            findings.push(
                Finding::new(
                    "OWASP-HDR-PERMISSIONS-WILDCARD",
                    format!("`Permissions-Policy` allows wildcard `*` access to `{feature}`"),
                    Severity::Medium,
                    OwaspCategory::A05SecurityMisconfiguration,
                    AuditorKind::Headers,
                )
                .cwe(16)
                .wstg("WSTG-CONF-07")
                .location(url)
                .evidence(format!("Permissions-Policy: {raw}"))
                .description(format!("Granting `{feature}=*` allows any embedded third-party iframe to request `{feature}` permissions."))
                .remediation(format!("Restrict `{feature}=()` or `{feature}=(self)` in `Permissions-Policy`.")),
            );
        }
    }
}

fn audit_cors(ctx: &HeaderAuditContext<'_>, findings: &mut Vec<Finding>) {
    let Some(acao) = find_first_header(ctx.headers, "access-control-allow-origin") else {
        return;
    };
    let acao_trimmed = acao.trim();
    let allow_creds = find_first_header(ctx.headers, "access-control-allow-credentials")
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("true"));

    if acao_trimmed == "*" && allow_creds {
        findings.push(
            Finding::new(
                "OWASP-CORS-WILDCARD-CREDENTIALS",
                "CORS combines `Access-Control-Allow-Origin: *` with `Allow-Credentials: true`",
                Severity::Critical,
                OwaspCategory::A01BrokenAccessControl,
                AuditorKind::Headers,
            )
            .cwe(942)
            .wstg("WSTG-CLNT-07")
            .location(ctx.url)
            .evidence("Access-Control-Allow-Origin: *, Access-Control-Allow-Credentials: true")
            .description(
                "Combining wildcard ACAO with credentials violates the CORS specification and indicates overly permissive cross-origin policy logic.",
            )
            .remediation(
                "Never emit `*` alongside `Access-Control-Allow-Credentials: true`; validate against a strict explicit origin allowlist.",
            ),
        );
    } else if acao_trimmed.eq_ignore_ascii_case("null") {
        let sev = if allow_creds {
            Severity::High
        } else {
            Severity::Medium
        };
        findings.push(
            Finding::new(
                "OWASP-CORS-NULL-ORIGIN",
                "CORS allows untrusted `null` origin",
                sev,
                OwaspCategory::A01BrokenAccessControl,
                AuditorKind::Headers,
            )
            .cwe(942)
            .wstg("WSTG-CLNT-07")
            .location(ctx.url)
            .evidence(format!(
                "Access-Control-Allow-Origin: {acao_trimmed}, Allow-Credentials: {allow_creds}"
            ))
            .description(
                "Sandboxed iframes (`sandbox=\"allow-scripts\"`) and `file:`/`data:` contexts send `Origin: null`, bypassing origin restrictions.",
            )
            .remediation("Never allowlist the `null` origin in `Access-Control-Allow-Origin`."),
        );
    } else if acao_trimmed == "*" {
        findings.push(
            Finding::new(
                "OWASP-CORS-WILDCARD",
                "CORS permits wildcard cross-origin reads (`Access-Control-Allow-Origin: *`)",
                Severity::Low,
                OwaspCategory::A05SecurityMisconfiguration,
                AuditorKind::Headers,
            )
            .cwe(942)
            .wstg("WSTG-CLNT-07")
            .location(ctx.url)
            .evidence("Access-Control-Allow-Origin: *")
            .description("Wildcard CORS allows any website to read unauthenticated responses from this endpoint.")
            .remediation("Verify this endpoint carries only public data, or restrict ACAO to specific trusted origins."),
        );
    } else {
        if let Some(req_origin) = ctx.request_origin
            && acao_trimmed.eq_ignore_ascii_case(req_origin.trim())
        {
            let sev = if allow_creds {
                Severity::High
            } else {
                Severity::Medium
            };
            findings.push(
                Finding::new(
                    "OWASP-CORS-REFLECTED-ORIGIN",
                    "CORS `Access-Control-Allow-Origin` reflects request `Origin` header",
                    sev,
                    OwaspCategory::A01BrokenAccessControl,
                    AuditorKind::Headers,
                )
                .cwe(942)
                .wstg("WSTG-CLNT-07")
                .location(ctx.url)
                .evidence(format!(
                    "Origin={req_origin}, ACAO={acao_trimmed}, Allow-Credentials={allow_creds}"
                ))
                .description(
                    "The response echoes the request's `Origin` header into `Access-Control-Allow-Origin`; ensure only strictly allowlisted origins are reflected.",
                )
                .remediation(
                    "Verify the reflected origin matches a static server-side allowlist (not substring/regex suffix matches) before echoing.",
                ),
            );
        }

        let has_vary_origin = find_all_headers(ctx.headers, "vary").iter().any(|v| {
            v.split(',')
                .any(|item| item.trim().eq_ignore_ascii_case("origin"))
        });
        if !has_vary_origin {
            findings.push(
                Finding::new(
                    "OWASP-CORS-MISSING-VARY-ORIGIN",
                    "Dynamic `Access-Control-Allow-Origin` omits `Vary: Origin`",
                    Severity::Low,
                    OwaspCategory::A05SecurityMisconfiguration,
                    AuditorKind::Headers,
                )
                .cwe(942)
                .wstg("WSTG-CLNT-07")
                .location(ctx.url)
                .evidence(format!("Access-Control-Allow-Origin: {acao_trimmed}"))
                .description("Without `Vary: Origin`, shared caches may serve an origin-specific CORS header to unintended origins.")
                .remediation("Add `Vary: Origin` whenever `Access-Control-Allow-Origin` varies per request."),
            );
        }
    }
}

fn find_first_header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn find_all_headers(headers: &[(String, String)], name: &str) -> Vec<String> {
    headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.clone())
        .collect()
}

fn is_loopback_http(url_lower: &str) -> bool {
    url_lower.starts_with("http://localhost")
        || url_lower.starts_with("http://127.0.0.1")
        || url_lower.starts_with("http://[::1]")
}

fn is_informative_banner(header_name: &str, value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return false;
    }
    if header_name != "server" {
        return true;
    }
    // Generic CDN labels without versions (e.g. `cloudflare`) are less informative than `nginx/1.18.0`.
    trimmed.contains('/')
        || trimmed.bytes().any(|b| b.is_ascii_digit())
        || trimmed.to_ascii_lowercase().contains("apache")
        || trimmed.to_ascii_lowercase().contains("nginx")
        || trimmed.to_ascii_lowercase().contains("microsoft-iis")
        || trimmed.to_ascii_lowercase().contains("jetty")
}
