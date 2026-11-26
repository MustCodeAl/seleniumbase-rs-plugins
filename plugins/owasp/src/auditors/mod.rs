//! Passive security auditors for HTTP headers, cookies, JWTs, DOM/storage, and client-side SCA.

pub mod cookies;
pub mod dom;
pub mod forms;
pub mod headers;
pub mod jwt;
pub mod sca;

pub use cookies::{
    CookieAuditContext, CookieInput, SameSite, SetCookie, audit_cookies, audit_set_cookie,
};
pub use dom::{
    AnchorElement, DomAuditOptions, DomSnapshot, JsGlobals, PasswordField, ResourceRef,
    ScriptElement, StylesheetElement, audit_dom,
};
pub use forms::{FormInfo, FormInputInfo, audit_forms, parse_forms_from_value};
pub use headers::{
    CspDirective, CspPolicy, CspSource, HeaderAuditContext, audit_headers, audit_headers_map,
};
pub use jwt::{DecodedJwt, JwtAuditResult, audit_jwt, decode_jwt, find_jwts_in_text};
pub use sca::{ComponentStatus, DetectedComponent, ScaResult, SemVer, audit_sca};
