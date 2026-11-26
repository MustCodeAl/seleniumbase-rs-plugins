//! Defensive OWASP passive security auditing and OWASP Pentest-Kit (`PTK`) integration
//! plugin for [seleniumbase-rs](https://github.com/MustCodeAl/seleniumbase-rs).
//!
//! Strictly defensive and passive: inspects HTTP headers, CSP ASTs, CORS posture, cookies,
//! Base64URL JWT structures, DOM/storage exposure, `postMessage('*')` sinks, and client-side
//! library versions without generating exploit payloads, fuzzing, or altering network traffic.
//!
//! # Example
//!
//! ```
//! use seleniumbase_rs_plugin_owasp::{
//!     HeaderAuditContext, OwaspAuditReport, audit_headers,
//! };
//!
//! let headers = vec![
//!     ("Server".to_owned(), "nginx/1.18.0".to_owned()),
//!     ("Access-Control-Allow-Origin".to_owned(), "*".to_owned()),
//! ];
//! let findings = audit_headers(
//!     &HeaderAuditContext::new("https://app.example.com/", 200, "text/html", &headers)
//!         .document(true),
//! );
//! let report = OwaspAuditReport::from_parts(
//!     Some("https://app.example.com/".to_owned()),
//!     findings,
//!     Vec::new(),
//!     1,
//!     0,
//!     None,
//!     true,
//! );
//! assert!(report.summary.total > 0);
//! assert_eq!(report.to_sarif()["version"], "2.1.0");
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod auditors;
pub mod error;
#[cfg(feature = "plugin")]
pub mod plugin;
pub mod ptk;
pub mod report;
pub mod types;

pub use auditors::{
    AnchorElement, ComponentStatus, CookieAuditContext, CookieInput, CspDirective, CspPolicy,
    CspSource, DecodedJwt, DetectedComponent, DomAuditOptions, DomSnapshot, FormInfo,
    FormInputInfo, HeaderAuditContext, JsGlobals, JwtAuditResult, PasswordField, ResourceRef,
    SameSite, ScaResult, ScriptElement, SemVer, SetCookie, StylesheetElement, audit_cookies,
    audit_dom, audit_forms, audit_headers, audit_headers_map, audit_jwt, audit_sca,
    audit_set_cookie, decode_jwt, find_jwts_in_text, parse_forms_from_value,
};
pub use error::{OwaspError, Result};
#[cfg(feature = "plugin")]
pub use plugin::{
    AuditSession, DEFAULT_MAX_FINDINGS, DEFAULT_MAX_OBSERVED_RESPONSES, NAME, ObservedResponse,
    OwaspConfig, OwaspPlugin,
};
pub use ptk::{
    PackedArchiveFormat, PtkAgentSnapshot, PtkEngine, PtkExtensionConfig, PtkExtensionStatus,
    PtkFinding, PtkManifestInfo, PtkModule, PtkModuleCatalog, PtkModuleMetadata, PtkRuleDefinition,
    PtkScanResult, PtkStats, normalize_cwe_string, parse_cwe_number,
};
pub use report::{OwaspAuditReport, SARIF_SCHEMA_URL, SeveritySummary};
pub use types::{
    AuditorKind, Finding, OwaspCategory, Severity, redact_secret, url_host, url_origin,
};
