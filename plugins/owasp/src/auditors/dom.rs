//! Passive DOM, mixed-content, SRI, tabnabbing, storage secret, and `postMessage` auditor.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::auditors::jwt;
use crate::types::{AuditorKind, Finding, OwaspCategory, Severity, redact_secret, url_host};

const SENSITIVE_STORAGE_KEY_HINTS: &[&str] = &[
    "token",
    "jwt",
    "auth",
    "secret",
    "api_key",
    "apikey",
    "password",
    "passwd",
    "private_key",
    "access_token",
    "refresh_token",
    "id_token",
    "session",
    "bearer",
    "credential",
];

const DEBUG_COMMENT_HINTS: &[&str] = &[
    "todo",
    "fixme",
    "hack",
    "staging",
    "internal",
    "debug",
    "jdbc:",
    "mongodb://",
    "postgres://",
    "mysql://",
    "stack trace",
];

/// Script element observed in DOM or HTML.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ScriptElement {
    /// External `src` URL, if present.
    pub src: Option<String>,
    /// Subresource Integrity `integrity` attribute, if present.
    pub integrity: Option<String>,
    /// `crossorigin` attribute, if present.
    pub crossorigin: Option<String>,
    /// Inline JavaScript body when `src` is absent.
    pub inline_code: Option<String>,
}

/// Stylesheet `<link>` element observed in DOM or HTML.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct StylesheetElement {
    /// Stylesheet `href` URL.
    pub href: String,
    /// Subresource Integrity `integrity` attribute, if present.
    pub integrity: Option<String>,
    /// `crossorigin` attribute, if present.
    pub crossorigin: Option<String>,
}

/// Anchor or area link observed in DOM or HTML.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AnchorElement {
    /// Link `href` URL.
    pub href: String,
    /// Link `target` attribute (for example `_blank`).
    pub target: Option<String>,
    /// Link `rel` attribute.
    pub rel: Option<String>,
}

/// Generic resource reference (`iframe`, `object`, `embed`, `form`, `img`, `media`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ResourceRef {
    /// Lowercase tag name.
    pub tag: String,
    /// Attribute holding the URL (`src`, `href`, `data`, `action`).
    pub attr: String,
    /// Referenced URL string.
    pub url: String,
}

/// Password input observed on the page.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PasswordField {
    /// Enclosing form `action` URL, if any.
    pub form_action: Option<String>,
    /// `autocomplete` attribute value, if any.
    pub autocomplete: Option<String>,
}

/// Client-side runtime library versions detected via JS globals or DOM markers.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct JsGlobals {
    /// `jQuery.fn.jquery` / `$.fn.jquery`
    pub jquery_version: Option<String>,
    /// `angular.version.full` (AngularJS 1.x)
    pub angular_version: Option<String>,
    /// `[ng-version]` attribute (Angular 2+)
    pub ng_version: Option<String>,
    /// `React.version`
    pub react_version: Option<String>,
    /// `_.VERSION` (Lodash)
    pub lodash_version: Option<String>,
    /// `bootstrap.Tooltip.VERSION` / `$.fn.tooltip.Constructor.VERSION`
    pub bootstrap_version: Option<String>,
    /// `Vue.version`
    pub vue_version: Option<String>,
}

impl JsGlobals {
    /// Creates an empty runtime JS globals snapshot.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets detected `jQuery` version.
    #[must_use]
    pub fn jquery(mut self, version: impl Into<String>) -> Self {
        self.jquery_version = Some(version.into());
        self
    }

    /// Sets detected `AngularJS` 1.x version.
    #[must_use]
    pub fn angular(mut self, version: impl Into<String>) -> Self {
        self.angular_version = Some(version.into());
        self
    }

    /// Sets detected Angular 2+ `[ng-version]`.
    #[must_use]
    pub fn ng_version(mut self, version: impl Into<String>) -> Self {
        self.ng_version = Some(version.into());
        self
    }

    /// Sets detected `React.version`.
    #[must_use]
    pub fn react(mut self, version: impl Into<String>) -> Self {
        self.react_version = Some(version.into());
        self
    }

    /// Sets detected Lodash `_.VERSION`.
    #[must_use]
    pub fn lodash(mut self, version: impl Into<String>) -> Self {
        self.lodash_version = Some(version.into());
        self
    }

    /// Sets detected Bootstrap version.
    #[must_use]
    pub fn bootstrap(mut self, version: impl Into<String>) -> Self {
        self.bootstrap_version = Some(version.into());
        self
    }

    /// Sets detected `Vue.version`.
    #[must_use]
    pub fn vue(mut self, version: impl Into<String>) -> Self {
        self.vue_version = Some(version.into());
        self
    }
}

/// Snapshot of a page's passive DOM, inline scripts, HTML comments, and browser storage.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DomSnapshot {
    /// Current page URL.
    pub url: String,
    /// Raw HTML source, if captured.
    pub html: String,
    /// Script tags on the page.
    pub scripts: Vec<ScriptElement>,
    /// Stylesheet `<link>` tags on the page.
    pub stylesheets: Vec<StylesheetElement>,
    /// `<a>` / `<area>` links on the page.
    pub links: Vec<AnchorElement>,
    /// Active resource elements (`iframe`, `object`, `embed`, `form`).
    pub active_elements: Vec<ResourceRef>,
    /// Passive resource elements (`img`, `audio`, `video`, `source`).
    pub passive_elements: Vec<ResourceRef>,
    /// Password inputs observed on the page.
    pub password_inputs: Vec<PasswordField>,
    /// Snapshot of `window.localStorage` key/value pairs.
    pub local_storage: BTreeMap<String, String>,
    /// Snapshot of `window.sessionStorage` key/value pairs.
    pub session_storage: BTreeMap<String, String>,
    /// Extracted HTML comments (`<!-- ... -->`).
    pub comments: Vec<String>,
    /// Detected client-side library globals.
    pub globals: JsGlobals,
}

impl DomSnapshot {
    /// Creates an empty snapshot for `url`.
    #[must_use]
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            ..Self::default()
        }
    }

    /// Parses raw HTML into a structured [`DomSnapshot`] without executing any script.
    #[must_use]
    pub fn from_html(url: impl Into<String>, html: impl Into<String>) -> Self {
        let url_str = url.into();
        let html_str = html.into();
        let mut snap = Self {
            url: url_str,
            html: html_str.clone(),
            ..Self::default()
        };
        parse_html_into_snapshot(&html_str, &mut snap);
        snap
    }

    /// Attaches a `localStorage` entry.
    #[must_use]
    pub fn local_storage_entry(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.local_storage.insert(key.into(), value.into());
        self
    }

    /// Attaches a `sessionStorage` entry.
    #[must_use]
    pub fn session_storage_entry(
        mut self,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        self.session_storage.insert(key.into(), value.into());
        self
    }

    /// Attaches JS globals metadata.
    #[must_use]
    pub fn globals(mut self, globals: JsGlobals) -> Self {
        self.globals = globals;
        self
    }

    /// Builds a [`DomSnapshot`] from a JSON object returned by `PageHandle::evaluate`.
    #[must_use]
    pub fn from_value(fallback_url: &str, value: &Value) -> Self {
        let url = value
            .get("url")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .unwrap_or(fallback_url)
            .to_owned();
        let html = value
            .get("html")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();

        let mut snap = if html.is_empty() {
            Self::new(url)
        } else {
            Self::from_html(url, html)
        };

        if let Some(arr) = value.get("scripts").and_then(Value::as_array) {
            for item in arr {
                let src = item
                    .get("src")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned);
                let integrity = item
                    .get("integrity")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned);
                let crossorigin = item
                    .get("crossorigin")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned);
                let inline_code = item
                    .get("inline")
                    .or_else(|| item.get("inline_code"))
                    .and_then(Value::as_str)
                    .filter(|s| !s.trim().is_empty())
                    .map(str::to_owned);
                if src.is_some() || inline_code.is_some() {
                    let exists = src
                        .as_ref()
                        .is_some_and(|s| snap.scripts.iter().any(|e| e.src.as_deref() == Some(s)));
                    if !exists {
                        snap.scripts.push(ScriptElement {
                            src,
                            integrity,
                            crossorigin,
                            inline_code,
                        });
                    }
                }
            }
        }

        if let Some(arr) = value.get("stylesheets").and_then(Value::as_array) {
            for item in arr {
                if let Some(href) = item
                    .get("href")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                    && !snap.stylesheets.iter().any(|s| s.href == href)
                {
                    snap.stylesheets.push(StylesheetElement {
                        href: href.to_owned(),
                        integrity: item
                            .get("integrity")
                            .and_then(Value::as_str)
                            .filter(|s| !s.is_empty())
                            .map(str::to_owned),
                        crossorigin: item
                            .get("crossorigin")
                            .and_then(Value::as_str)
                            .filter(|s| !s.is_empty())
                            .map(str::to_owned),
                    });
                }
            }
        }

        if let Some(arr) = value.get("links").and_then(Value::as_array) {
            for item in arr {
                if let Some(href) = item.get("href").and_then(Value::as_str) {
                    let target = item
                        .get("target")
                        .and_then(Value::as_str)
                        .filter(|s| !s.is_empty())
                        .map(str::to_owned);
                    let rel = item
                        .get("rel")
                        .and_then(Value::as_str)
                        .filter(|s| !s.is_empty())
                        .map(str::to_owned);
                    if !snap
                        .links
                        .iter()
                        .any(|l| l.href == href && l.target == target && l.rel == rel)
                    {
                        snap.links.push(AnchorElement {
                            href: href.to_owned(),
                            target,
                            rel,
                        });
                    }
                }
            }
        }

        if let Some(arr) = value.get("active_elements").and_then(Value::as_array) {
            for item in arr {
                if let (Some(tag), Some(attr), Some(res_url)) = (
                    item.get("tag").and_then(Value::as_str),
                    item.get("attr").and_then(Value::as_str),
                    item.get("url").and_then(Value::as_str),
                ) {
                    snap.active_elements.push(ResourceRef {
                        tag: tag.to_owned(),
                        attr: attr.to_owned(),
                        url: res_url.to_owned(),
                    });
                }
            }
        }

        if let Some(arr) = value.get("passive_elements").and_then(Value::as_array) {
            for item in arr {
                if let (Some(tag), Some(attr), Some(res_url)) = (
                    item.get("tag").and_then(Value::as_str),
                    item.get("attr").and_then(Value::as_str),
                    item.get("url").and_then(Value::as_str),
                ) {
                    snap.passive_elements.push(ResourceRef {
                        tag: tag.to_owned(),
                        attr: attr.to_owned(),
                        url: res_url.to_owned(),
                    });
                }
            }
        }

        if let Some(obj) = value.get("localStorage").and_then(Value::as_object) {
            for (k, v) in obj {
                if let Some(s) = v.as_str() {
                    snap.local_storage.insert(k.clone(), s.to_owned());
                } else if !v.is_null() {
                    snap.local_storage.insert(k.clone(), v.to_string());
                }
            }
        }

        if let Some(obj) = value.get("sessionStorage").and_then(Value::as_object) {
            for (k, v) in obj {
                if let Some(s) = v.as_str() {
                    snap.session_storage.insert(k.clone(), s.to_owned());
                } else if !v.is_null() {
                    snap.session_storage.insert(k.clone(), v.to_string());
                }
            }
        }

        if let Some(arr) = value.get("comments").and_then(Value::as_array) {
            for item in arr {
                if let Some(c) = item.as_str()
                    && !snap.comments.iter().any(|existing| existing == c)
                {
                    snap.comments.push(c.to_owned());
                }
            }
        }

        if let Some(g) = value.get("globals").and_then(Value::as_object) {
            let pick = |k: &str| {
                g.get(k)
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
            };
            snap.globals.jquery_version = pick("jquery").or(snap.globals.jquery_version);
            snap.globals.angular_version = pick("angular").or(snap.globals.angular_version);
            snap.globals.ng_version = pick("ng_version").or(snap.globals.ng_version);
            snap.globals.react_version = pick("react").or(snap.globals.react_version);
            snap.globals.lodash_version = pick("lodash").or(snap.globals.lodash_version);
            snap.globals.bootstrap_version = pick("bootstrap").or(snap.globals.bootstrap_version);
            snap.globals.vue_version = pick("vue").or(snap.globals.vue_version);
        }

        snap
    }
}

/// Options controlling optional DOM passive heuristics.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct DomAuditOptions {
    /// Emit informational inventory findings for DOM sink patterns (`innerHTML`, `eval`).
    pub inventory_dom_sinks: bool,
    /// Check `localStorage` and `sessionStorage` for JWTs and exposed secrets.
    pub audit_storage: bool,
}

impl Default for DomAuditOptions {
    fn default() -> Self {
        Self {
            inventory_dom_sinks: true,
            audit_storage: true,
        }
    }
}

/// Audits a [`DomSnapshot`] passively for mixed content, missing SRI, tabnabbing,
/// storage/comment secret exposure, insecure password forms, and `postMessage('*')` sinks.
#[must_use]
pub fn audit_dom(snapshot: &DomSnapshot, options: &DomAuditOptions) -> Vec<Finding> {
    let mut findings = Vec::new();
    let page_is_https = snapshot
        .url
        .trim()
        .to_ascii_lowercase()
        .starts_with("https://");
    let page_host = url_host(&snapshot.url);

    // 1. Mixed active & passive content on HTTPS pages
    if page_is_https {
        for script in &snapshot.scripts {
            if let Some(src) = &script.src
                && is_plaintext_http_url(src)
            {
                findings.push(mixed_active_finding(&snapshot.url, "script", "src", src));
            }
        }
        for sheet in &snapshot.stylesheets {
            if is_plaintext_http_url(&sheet.href) {
                findings.push(mixed_active_finding(
                    &snapshot.url,
                    "link",
                    "href",
                    &sheet.href,
                ));
            }
        }
        for elem in &snapshot.active_elements {
            if is_plaintext_http_url(&elem.url) {
                findings.push(mixed_active_finding(
                    &snapshot.url,
                    &elem.tag,
                    &elem.attr,
                    &elem.url,
                ));
            }
        }
        for elem in &snapshot.passive_elements {
            if is_plaintext_http_url(&elem.url) {
                findings.push(
                    Finding::new(
                        "OWASP-DOM-MIXED-PASSIVE",
                        format!("Mixed passive `http://` {} resource on HTTPS page", elem.tag),
                        Severity::Low,
                        OwaspCategory::A02CryptographicFailures,
                        AuditorKind::Dom,
                    )
                    .cwe(319)
                    .wstg("WSTG-CRYP-03")
                    .location(snapshot.url.clone())
                    .evidence(format!("<{} {}=\"{}\">", elem.tag, elem.attr, elem.url))
                    .description("Loading passive media over `http://` on an HTTPS page triggers mixed-content degradation.")
                    .remediation("Serve all subresources over HTTPS."),
                );
            }
        }
    }

    // 2. Third-party scripts and stylesheets missing SRI `integrity`
    for script in &snapshot.scripts {
        if let Some(src) = &script.src
            && is_third_party_resource(src, page_host.as_deref())
            && script.integrity.as_deref().is_none_or(str::is_empty)
        {
            findings.push(
                Finding::new(
                    "OWASP-DOM-MISSING-SRI",
                    "Third-party `<script>` loaded without Subresource Integrity (`integrity`)",
                    Severity::Medium,
                    OwaspCategory::A08SoftwareAndDataIntegrityFailures,
                    AuditorKind::Dom,
                )
                .cwe(353)
                .wstg("WSTG-CONF-07")
                .location(snapshot.url.clone())
                .evidence(format!("<script src=\"{src}\">"))
                .description(
                    "External scripts without an `integrity` hash run arbitrary code if the third-party CDN is compromised or tampered with.",
                )
                .remediation(
                    "Add `integrity=\"sha384-...\"` and `crossorigin=\"anonymous\"` to third-party script tags, or self-host pinned assets.",
                ),
            );
        }
    }

    for sheet in &snapshot.stylesheets {
        if is_third_party_resource(&sheet.href, page_host.as_deref())
            && sheet.integrity.as_deref().is_none_or(str::is_empty)
        {
            findings.push(
                Finding::new(
                    "OWASP-DOM-STYLESHEET-MISSING-SRI",
                    "Third-party `<link rel=\"stylesheet\">` missing `integrity` attribute",
                    Severity::Low,
                    OwaspCategory::A08SoftwareAndDataIntegrityFailures,
                    AuditorKind::Dom,
                )
                .cwe(353)
                .wstg("WSTG-CONF-07")
                .location(snapshot.url.clone())
                .evidence(format!("<link rel=\"stylesheet\" href=\"{}\">", sheet.href))
                .description("External stylesheets without Subresource Integrity are trusted blindly from remote hosts.")
                .remediation("Add SRI `integrity` and `crossorigin=\"anonymous\"` attributes to external stylesheets."),
            );
        }
    }

    // 3. `target="_blank"` missing `rel="noopener noreferrer"`
    for link in &snapshot.links {
        if link
            .target
            .as_deref()
            .is_some_and(|t| t.trim().eq_ignore_ascii_case("_blank"))
        {
            let rel_tokens: Vec<String> = link
                .rel
                .as_deref()
                .unwrap_or_default()
                .split_ascii_whitespace()
                .map(str::to_ascii_lowercase)
                .collect();
            let has_noopener = rel_tokens.iter().any(|t| t == "noopener");
            let has_noreferrer = rel_tokens.iter().any(|t| t == "noreferrer");
            if !has_noopener || !has_noreferrer {
                let sev = if !has_noopener && !has_noreferrer {
                    Severity::Low
                } else {
                    Severity::Info
                };
                findings.push(
                    Finding::new(
                        "OWASP-DOM-TABNABBING",
                        "`target=\"_blank\"` link missing `rel=\"noopener noreferrer\"`",
                        sev,
                        OwaspCategory::A05SecurityMisconfiguration,
                        AuditorKind::Dom,
                    )
                    .cwe(1022)
                    .wstg("WSTG-CLNT-04")
                    .location(snapshot.url.clone())
                    .evidence(format!(
                        "<a href=\"{}\" target=\"_blank\" rel=\"{}\">",
                        link.href,
                        link.rel.as_deref().unwrap_or("")
                    ))
                    .description(
                        "Opening links with `target=\"_blank\"` without `noopener noreferrer` risks reverse tabnabbing on older browsers and leaks referrer headers.",
                    )
                    .remediation("Add `rel=\"noopener noreferrer\"` to every `target=\"_blank\"` link."),
                );
            }
        }
    }

    // 4. Password fields on insecure HTTP pages or targeting HTTP actions
    for pwd in &snapshot.password_inputs {
        let insecure_page = snapshot
            .url
            .trim()
            .to_ascii_lowercase()
            .starts_with("http://");
        let insecure_action = pwd
            .form_action
            .as_deref()
            .is_some_and(is_plaintext_http_url);
        if insecure_page || insecure_action {
            findings.push(
                Finding::new(
                    "OWASP-DOM-INSECURE-PASSWORD-FORM",
                    "Password input submitted or hosted over unencrypted `http://`",
                    Severity::High,
                    OwaspCategory::A02CryptographicFailures,
                    AuditorKind::Dom,
                )
                .cwe(319)
                .wstg("WSTG-CRYP-03")
                .location(snapshot.url.clone())
                .evidence(format!(
                    "page_url={}, form_action={}",
                    snapshot.url,
                    pwd.form_action.as_deref().unwrap_or("(same-page)")
                ))
                .description("Credentials entered into password forms over `http://` can be intercepted in transit.")
                .remediation("Host authentication pages and form `action` targets strictly over HTTPS."),
            );
        }
    }

    // 5. Storage secret/token/JWT exposure checks
    if options.audit_storage {
        audit_storage_map(
            &snapshot.url,
            "localStorage",
            &snapshot.local_storage,
            &mut findings,
        );
        audit_storage_map(
            &snapshot.url,
            "sessionStorage",
            &snapshot.session_storage,
            &mut findings,
        );
    }

    // 6. HTML comments secret/debug leak checks
    for comment in &snapshot.comments {
        if let Some((pattern_name, snippet)) = detect_secret_pattern(comment) {
            findings.push(
                Finding::new(
                    "OWASP-DOM-SECRET-IN-COMMENT",
                    format!("Potential secret or credential ({pattern_name}) exposed in HTML comment"),
                    Severity::High,
                    OwaspCategory::A02CryptographicFailures,
                    AuditorKind::Dom,
                )
                .cwe(615)
                .wstg("WSTG-INFO-05")
                .location(snapshot.url.clone())
                .evidence(format!("<!-- {snippet} -->"))
                .description("HTML comments are shipped to every client and inspected passively by browsers and proxies.")
                .remediation("Remove credentials, API keys, and internal secrets from HTML templates and comments."),
            );
        } else {
            let lower = comment.to_ascii_lowercase();
            if let Some(hint) = DEBUG_COMMENT_HINTS.iter().find(|h| lower.contains(*h)) {
                let preview: String = comment.trim().chars().take(80).collect();
                findings.push(
                    Finding::new(
                        "OWASP-DOM-DEBUG-COMMENT",
                        "Internal debug or environment note found in HTML comment",
                        Severity::Info,
                        OwaspCategory::A05SecurityMisconfiguration,
                        AuditorKind::Dom,
                    )
                    .cwe(615)
                    .wstg("WSTG-INFO-05")
                    .location(snapshot.url.clone())
                    .evidence(format!("matched={hint}, comment=<!-- {preview} -->"))
                    .description("HTML comments containing internal URLs, connection strings, or developer notes aid reconnaissance.")
                    .remediation("Strip developer and build comments before deploying HTML to production."),
                );
            }
        }
    }

    // 7. Passive `postMessage('*')` and DOM sink inventory in inline scripts
    for (idx, script) in snapshot.scripts.iter().enumerate() {
        let Some(code) = &script.inline_code else {
            continue;
        };
        if contains_postmessage_wildcard(code) {
            findings.push(
                Finding::new(
                    "OWASP-DOM-POSTMESSAGE-WILDCARD",
                    "Inline script invokes `postMessage(..., '*')` with wildcard targetOrigin",
                    Severity::Medium,
                    OwaspCategory::A01BrokenAccessControl,
                    AuditorKind::Dom,
                )
                .cwe(346)
                .wstg("WSTG-CLNT-11")
                .location(format!("{} [inline-script#{idx}]", snapshot.url))
                .evidence("postMessage(..., '*')")
                .description(
                    "Using wildcard `*` as `targetOrigin` in `window.postMessage` allows any malicious embedding or popup origin to receive the message.",
                )
                .remediation(
                    "Specify an explicit `https://` origin in `postMessage(payload, expectedOrigin)`.",
                ),
            );
        }

        if has_message_listener_without_origin(code) {
            findings.push(
                Finding::new(
                    "OWASP-DOM-POSTMESSAGE-NO-ORIGIN-CHECK",
                    "`message` event listener appears to omit `event.origin` validation",
                    Severity::Low,
                    OwaspCategory::A01BrokenAccessControl,
                    AuditorKind::Dom,
                )
                .cwe(346)
                .wstg("WSTG-CLNT-11")
                .location(format!("{} [inline-script#{idx}]", snapshot.url))
                .evidence("message listener without `.origin` reference")
                .description(
                    "Web messaging listeners that fail to check `event.origin` against an allowlist may accept messages from untrusted origins.",
                )
                .remediation(
                    "Validate `event.origin` strictly against a known allowlist before processing `event.data`.",
                ),
            );
        }

        if options.inventory_dom_sinks {
            let sinks = find_passive_dom_sinks(code);
            if !sinks.is_empty() {
                findings.push(
                    Finding::new(
                        "OWASP-DOM-PASSIVE-SINK-INVENTORY",
                        "Inline script references DOM execution/HTML sink APIs",
                        Severity::Info,
                        OwaspCategory::A03Injection,
                        AuditorKind::Dom,
                    )
                    .cwe(79)
                    .wstg("WSTG-CLNT-01")
                    .location(format!("{} [inline-script#{idx}]", snapshot.url))
                    .evidence(format!("sinks=[{}]", sinks.join(", ")))
                    .description(
                        "Passive inventory of DOM sinks (`innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval`) requiring safe sanitization when fed user-controlled inputs.",
                    )
                    .remediation(
                        "Prefer `textContent` / `createElement` over raw HTML sinks, or sanitize with a strict library such as DOMPurify.",
                    ),
                );
            }
        }
    }

    findings
}

fn mixed_active_finding(page_url: &str, tag: &str, attr: &str, resource_url: &str) -> Finding {
    Finding::new(
        "OWASP-DOM-MIXED-ACTIVE",
        format!("Mixed active `http://` <{tag}> resource on HTTPS page"),
        Severity::High,
        OwaspCategory::A02CryptographicFailures,
        AuditorKind::Dom,
    )
    .cwe(319)
    .wstg("WSTG-CRYP-03")
    .location(page_url)
    .evidence(format!("<{tag} {attr}=\"{resource_url}\">"))
    .description("Active resources loaded over plaintext `http://` on an HTTPS origin can be tampered with in transit.")
    .remediation("Upgrade all script, stylesheet, iframe, form, and object URLs to `https://`.")
}

fn audit_storage_map(
    page_url: &str,
    storage_name: &str,
    entries: &BTreeMap<String, String>,
    findings: &mut Vec<Finding>,
) {
    for (key, value) in entries {
        let loc = format!("{page_url} [{storage_name}:{key}]");
        // 1. Check JWTs inside storage values
        let jwts = jwt::find_jwts_in_text(value);
        for token in &jwts {
            findings.push(
                Finding::new(
                    "OWASP-DOM-JWT-IN-STORAGE",
                    format!("JWT stored in browser `{storage_name}`"),
                    Severity::Medium,
                    OwaspCategory::A04InsecureDesign,
                    AuditorKind::Dom,
                )
                .cwe(922)
                .wstg("WSTG-CLNT-12")
                .location(loc.clone())
                .evidence(format!("{storage_name}[{key}]={}", redact_secret(token)))
                .description(
                    "Tokens stored in Web Storage (`localStorage`/`sessionStorage`) are readable by any JavaScript running on the origin.",
                )
                .remediation(
                    "Store sensitive session/bearer tokens in `HttpOnly; Secure; SameSite=Lax` cookies instead of Web Storage.",
                ),
            );
            if let Ok(jwt_res) = jwt::audit_jwt(token, Some(&loc), None) {
                findings.extend(jwt_res.findings);
            }
        }

        // 2. Check known secret token/key prefixes
        if let Some((pattern_name, masked)) = detect_secret_pattern(value) {
            findings.push(
                Finding::new(
                    "OWASP-DOM-SECRET-IN-STORAGE",
                    format!("Exposed secret pattern ({pattern_name}) in `{storage_name}`"),
                    Severity::High,
                    OwaspCategory::A02CryptographicFailures,
                    AuditorKind::Dom,
                )
                .cwe(922)
                .wstg("WSTG-CLNT-12")
                .location(loc)
                .evidence(format!("{storage_name}[{key}]={masked}"))
                .description("Sensitive keys or credentials persisted in Web Storage can be exfiltrated via any XSS flaw or third-party script.")
                .remediation("Remove long-lived API keys/secrets from client storage and keep secrets server-side."),
            );
            continue;
        }

        // 3. Check sensitive key names when no JWT/pattern already flagged
        let lower_key = key.to_ascii_lowercase();
        if jwts.is_empty()
            && !value.trim().is_empty()
            && SENSITIVE_STORAGE_KEY_HINTS
                .iter()
                .any(|hint| lower_key.contains(hint))
        {
            findings.push(
                Finding::new(
                    "OWASP-DOM-SENSITIVE-STORAGE-KEY",
                    format!("Sensitive credential-named entry `{key}` in `{storage_name}`"),
                    Severity::Medium,
                    OwaspCategory::A04InsecureDesign,
                    AuditorKind::Dom,
                )
                .cwe(922)
                .wstg("WSTG-CLNT-12")
                .location(loc)
                .evidence(format!("{storage_name}[{key}]={}", redact_secret(value)))
                .description("Authentication or session artifacts stored in Web Storage lack `HttpOnly` protection.")
                .remediation("Move sensitive session/auth tokens into `HttpOnly` server cookies."),
            );
        }
    }
}

fn detect_secret_pattern(text: &str) -> Option<(&'static str, String)> {
    if let Some(pos) = text.find("-----BEGIN ")
        && text[pos..].contains("PRIVATE KEY-----")
    {
        return Some(("PEM Private Key", redact_secret(&text[pos..])));
    }
    for (prefix, label, min_len) in [
        ("AKIA", "AWS Access Key ID", 20),
        ("ghp_", "GitHub Personal Access Token", 20),
        ("github_pat_", "GitHub Fine-Grained Token", 24),
        ("sk_live_", "Stripe Live Secret Key", 20),
        ("AIza", "Google API Key", 30),
    ] {
        if let Some(pos) = text.find(prefix) {
            let token: String = text[pos..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
                .collect();
            if token.len() >= min_len {
                return Some((label, redact_secret(&token)));
            }
        }
    }

    let lower = text.to_ascii_lowercase();
    for kw in ["password", "api_key", "apikey", "client_secret", "secret"] {
        if let Some(pos) = lower.find(kw) {
            let after = &text[pos + kw.len()..];
            let trimmed = after.trim_start();
            if let Some(rest) = trimmed
                .strip_prefix('=')
                .or_else(|| trimmed.strip_prefix(':'))
            {
                let val = rest.trim_start().trim_matches(|c| c == '"' || c == '\'');
                let token: String = val
                    .chars()
                    .take_while(|c| !c.is_whitespace() && *c != '"' && *c != '\'' && *c != ';')
                    .collect();
                if token.len() >= 4 {
                    return Some((
                        "Hardcoded Credential",
                        format!("{kw}={}", redact_secret(&token)),
                    ));
                }
            }
        }
    }
    None
}

fn is_plaintext_http_url(url: &str) -> bool {
    url.trim().to_ascii_lowercase().starts_with("http://")
}

fn is_third_party_resource(resource_url: &str, page_host: Option<&str>) -> bool {
    let trimmed = resource_url.trim();
    let normalized = if trimmed.starts_with("//") {
        format!("https:{trimmed}")
    } else {
        trimmed.to_owned()
    };
    let lower = normalized.to_ascii_lowercase();
    if !lower.starts_with("https://") && !lower.starts_with("http://") {
        return false;
    }
    let Some(res_host) = url_host(&normalized) else {
        return false;
    };
    match page_host {
        Some(host) => !res_host.eq_ignore_ascii_case(host),
        None => true,
    }
}

fn contains_postmessage_wildcard(code: &str) -> bool {
    let mut search_from = 0;
    while let Some(rel) = code[search_from..].find("postMessage(") {
        let open_paren = search_from + rel + "postMessage(".len();
        if let Some(args) = slice_until_matching_paren(&code[open_paren..]) {
            let trimmed = args.trim_end();
            if trimmed.ends_with("'*'") || trimmed.ends_with("\"*\"") {
                return true;
            }
            if let Some(comma_idx) = find_top_level_comma(args) {
                let rest = args[comma_idx + 1..].trim();
                if rest.starts_with("'*'") || rest.starts_with("\"*\"") {
                    return true;
                }
            }
        }
        search_from = open_paren;
    }
    false
}

fn slice_until_matching_paren(s: &str) -> Option<&str> {
    let mut depth = 1_usize;
    let mut in_quote: Option<char> = None;
    let mut escaped = false;
    for (idx, ch) in s.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if let Some(q) = in_quote {
            if ch == '\\' {
                escaped = true;
            } else if ch == q {
                in_quote = None;
            }
            continue;
        }
        match ch {
            '\'' | '"' | '`' => in_quote = Some(ch),
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&s[..idx]);
                }
            }
            _ => {}
        }
    }
    None
}

fn find_top_level_comma(s: &str) -> Option<usize> {
    let mut depth = 0_usize;
    let mut in_quote: Option<char> = None;
    let mut escaped = false;
    for (idx, ch) in s.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if let Some(q) = in_quote {
            if ch == '\\' {
                escaped = true;
            } else if ch == q {
                in_quote = None;
            }
            continue;
        }
        match ch {
            '\'' | '"' | '`' => in_quote = Some(ch),
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => return Some(idx),
            _ => {}
        }
    }
    None
}

fn has_message_listener_without_origin(code: &str) -> bool {
    let has_listener = code.contains("addEventListener('message'")
        || code.contains("addEventListener(\"message\"")
        || code.contains(".onmessage");
    has_listener && !code.contains(".origin")
}

fn find_passive_dom_sinks(code: &str) -> Vec<&'static str> {
    let mut found = Vec::new();
    for (pattern, label) in [
        (".innerHTML", "innerHTML"),
        (".outerHTML", "outerHTML"),
        (".insertAdjacentHTML(", "insertAdjacentHTML"),
        ("document.write(", "document.write"),
        ("eval(", "eval"),
    ] {
        if code.contains(pattern) {
            found.push(label);
        }
    }
    found
}

/// Lightweight deterministic HTML tag/comment/script extractor for offline HTML auditing.
fn parse_html_into_snapshot(html: &str, snap: &mut DomSnapshot) {
    let lower = html.to_ascii_lowercase();
    let mut pos = 0;

    while pos < html.len() {
        let Some(rel_lt) = html[pos..].find('<') else {
            break;
        };
        let lt = pos + rel_lt;

        // HTML comment
        if html[lt..].starts_with("<!--") {
            let start = lt + 4;
            if let Some(rel_end) = html[start..].find("-->") {
                snap.comments.push(html[start..start + rel_end].to_owned());
                pos = start + rel_end + 3;
                continue;
            }
            break;
        }

        let Some(rel_gt) = html[lt..].find('>') else {
            break;
        };
        let gt = lt + rel_gt;
        let tag_body = &html[lt + 1..gt];
        let trimmed = tag_body.trim();
        if trimmed.starts_with('/') || trimmed.starts_with('!') {
            pos = gt + 1;
            continue;
        }

        let tag_name_end = trimmed
            .find(|c: char| c.is_ascii_whitespace() || c == '/')
            .unwrap_or(trimmed.len());
        let tag_name = trimmed[..tag_name_end].to_ascii_lowercase();
        let attrs_slice = &trimmed[tag_name_end..];
        let attrs = parse_attributes(attrs_slice);

        match tag_name.as_str() {
            "script" => {
                let src = attr_val(&attrs, "src").filter(|s| !s.is_empty());
                let integrity = attr_val(&attrs, "integrity").filter(|s| !s.is_empty());
                let crossorigin = attr_val(&attrs, "crossorigin");
                let mut inline_code = None;
                let next_pos = if trimmed.ends_with('/') {
                    gt + 1
                } else if let Some(rel_close) = lower[gt + 1..].find("</script") {
                    let body = html[gt + 1..gt + 1 + rel_close].trim();
                    if src.is_none() && !body.is_empty() {
                        inline_code = Some(body.to_owned());
                    }
                    lower[gt + 1 + rel_close..]
                        .find('>')
                        .map_or(html.len(), |i| gt + 1 + rel_close + i + 1)
                } else {
                    gt + 1
                };
                snap.scripts.push(ScriptElement {
                    src,
                    integrity,
                    crossorigin,
                    inline_code,
                });
                pos = next_pos;
                continue;
            }
            "link" => {
                if let Some(rel) = attr_val(&attrs, "rel")
                    && rel
                        .split_ascii_whitespace()
                        .any(|t| t.eq_ignore_ascii_case("stylesheet"))
                    && let Some(href) = attr_val(&attrs, "href").filter(|s| !s.is_empty())
                {
                    snap.stylesheets.push(StylesheetElement {
                        href,
                        integrity: attr_val(&attrs, "integrity").filter(|s| !s.is_empty()),
                        crossorigin: attr_val(&attrs, "crossorigin"),
                    });
                }
            }
            "a" | "area" => {
                let href = attr_val(&attrs, "href").unwrap_or_default();
                let target = attr_val(&attrs, "target");
                let rel = attr_val(&attrs, "rel");
                snap.links.push(AnchorElement { href, target, rel });
            }
            "iframe" | "embed" => {
                if let Some(src) = attr_val(&attrs, "src").filter(|s| !s.is_empty()) {
                    snap.active_elements.push(ResourceRef {
                        tag: tag_name,
                        attr: "src".to_owned(),
                        url: src,
                    });
                }
            }
            "object" => {
                if let Some(data) = attr_val(&attrs, "data").filter(|s| !s.is_empty()) {
                    snap.active_elements.push(ResourceRef {
                        tag: tag_name,
                        attr: "data".to_owned(),
                        url: data,
                    });
                }
            }
            "form" => {
                if let Some(action) = attr_val(&attrs, "action").filter(|s| !s.is_empty()) {
                    snap.active_elements.push(ResourceRef {
                        tag: tag_name,
                        attr: "action".to_owned(),
                        url: action,
                    });
                }
            }
            "input" => {
                if attr_val(&attrs, "type")
                    .is_some_and(|t| t.trim().eq_ignore_ascii_case("password"))
                {
                    let form_action = snap
                        .active_elements
                        .iter()
                        .rev()
                        .find(|r| r.tag == "form")
                        .map(|r| r.url.clone());
                    snap.password_inputs.push(PasswordField {
                        form_action,
                        autocomplete: attr_val(&attrs, "autocomplete"),
                    });
                }
            }
            "img" | "audio" | "video" | "source" => {
                if let Some(src) = attr_val(&attrs, "src").filter(|s| !s.is_empty()) {
                    snap.passive_elements.push(ResourceRef {
                        tag: tag_name,
                        attr: "src".to_owned(),
                        url: src,
                    });
                }
            }
            _ => {}
        }

        if let Some(ng) = attr_val(&attrs, "ng-version").filter(|s| !s.is_empty())
            && snap.globals.ng_version.is_none()
        {
            snap.globals.ng_version = Some(ng);
        }

        pos = gt + 1;
    }
}

fn parse_attributes(input: &str) -> Vec<(String, String)> {
    let mut attrs = Vec::new();
    let bytes = input.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        while i < bytes.len() && (bytes[i].is_ascii_whitespace() || bytes[i] == b'/') {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let name_start = i;
        while i < bytes.len()
            && !bytes[i].is_ascii_whitespace()
            && bytes[i] != b'='
            && bytes[i] != b'/'
        {
            i += 1;
        }
        let name = input[name_start..i].to_ascii_lowercase();
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i < bytes.len() && bytes[i] == b'=' {
            i += 1;
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            if i < bytes.len() && (bytes[i] == b'"' || bytes[i] == b'\'') {
                let quote = bytes[i];
                i += 1;
                let val_start = i;
                while i < bytes.len() && bytes[i] != quote {
                    i += 1;
                }
                let val = input[val_start..i].to_owned();
                if i < bytes.len() {
                    i += 1;
                }
                attrs.push((name, val));
            } else {
                let val_start = i;
                while i < bytes.len() && !bytes[i].is_ascii_whitespace() && bytes[i] != b'>' {
                    i += 1;
                }
                let val = input[val_start..i].to_owned();
                attrs.push((name, val));
            }
        } else if !name.is_empty() {
            attrs.push((name, String::new()));
        }
    }

    attrs
}

fn attr_val(attrs: &[(String, String)], key: &str) -> Option<String> {
    attrs.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone())
}
