//! Passive `<form>` and `<input>` security posture auditor.
//!
//! Strictly defensive and read-only: inspects form `action`, `method`, hidden CSRF
//! token presence, and `autocomplete` attributes on password/sensitive inputs without
//! submitting forms or generating attack payloads.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::types::{AuditorKind, Finding, OwaspCategory, Severity};

const CSRF_TOKEN_HINTS: &[&str] = &[
    "csrf",
    "xsrf",
    "_token",
    "authenticity_token",
    "__requestverificationtoken",
    "antiforgery",
    "nonce",
];

const SENSITIVE_INPUT_HINTS: &[&str] = &[
    "password", "passwd", "passcode", "secret", "token", "pin", "otp", "totp", "cvv", "cvc", "ssn",
];

/// Passive metadata for an `<input>` or `<textarea>` inside a `<form>`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct FormInputInfo {
    /// Lowercase `type` attribute (defaults to `"text"`).
    pub input_type: String,
    /// `name` attribute, if present.
    pub name: Option<String>,
    /// `id` attribute, if present.
    pub id: Option<String>,
    /// `autocomplete` attribute, if present.
    pub autocomplete: Option<String>,
}

/// Passive metadata for a `<form>` element collected from the DOM.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct FormInfo {
    /// Resolved or raw `action` attribute, if present.
    pub action: Option<String>,
    /// Uppercase HTTP method (`"GET"` or `"POST"`, defaulting to `"GET"`).
    pub method: String,
    /// Form `id` attribute, if present.
    pub id: Option<String>,
    /// Form `name` attribute, if present.
    pub name: Option<String>,
    /// Inputs contained within this form.
    pub inputs: Vec<FormInputInfo>,
}

/// Parses `forms` array from `PAGE_AUDIT_JS` evaluation output.
#[must_use]
pub fn parse_forms_from_value(value: &Value) -> Vec<FormInfo> {
    let Some(arr) = value.get("forms").and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut forms = Vec::with_capacity(arr.len());
    for item in arr {
        let Some(obj) = item.as_object() else {
            continue;
        };
        let action = obj
            .get("action")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned);
        let method = obj
            .get("method")
            .and_then(Value::as_str)
            .map(|m| m.trim().to_ascii_uppercase())
            .filter(|m| !m.is_empty())
            .unwrap_or_else(|| "GET".to_owned());
        let id = obj
            .get("id")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_owned);
        let name = obj
            .get("name")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_owned);

        let mut inputs = Vec::new();
        if let Some(in_arr) = obj.get("inputs").and_then(Value::as_array) {
            for in_item in in_arr {
                let Some(in_obj) = in_item.as_object() else {
                    continue;
                };
                let input_type = in_obj
                    .get("type")
                    .or_else(|| in_obj.get("input_type"))
                    .and_then(Value::as_str)
                    .map(|s| s.trim().to_ascii_lowercase())
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "text".to_owned());
                inputs.push(FormInputInfo {
                    input_type,
                    name: in_obj
                        .get("name")
                        .and_then(Value::as_str)
                        .filter(|s| !s.is_empty())
                        .map(str::to_owned),
                    id: in_obj
                        .get("id")
                        .and_then(Value::as_str)
                        .filter(|s| !s.is_empty())
                        .map(str::to_owned),
                    autocomplete: in_obj
                        .get("autocomplete")
                        .and_then(Value::as_str)
                        .filter(|s| !s.is_empty())
                        .map(str::to_owned),
                });
            }
        }

        forms.push(FormInfo {
            action,
            method,
            id,
            name,
            inputs,
        });
    }
    forms
}

/// Audits `<form>` and `<input>` metadata passively for transport, method, CSRF token,
/// and `autocomplete` posture weaknesses.
#[must_use]
pub fn audit_forms(page_url: &str, forms: &[FormInfo]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let page_lower = page_url.trim().to_ascii_lowercase();
    let page_is_https = page_lower.starts_with("https://");
    let page_is_http = page_lower.starts_with("http://");

    for (idx, form) in forms.iter().enumerate() {
        let form_label = form
            .id
            .as_deref()
            .or(form.name.as_deref())
            .map_or_else(|| format!("form#{idx}"), str::to_owned);
        let method = if form.method.is_empty() {
            "GET"
        } else {
            form.method.as_str()
        };
        let is_post = method.eq_ignore_ascii_case("POST");
        let is_get = method.eq_ignore_ascii_case("GET");
        let action_is_http = form
            .action
            .as_deref()
            .is_some_and(|a| a.trim().to_ascii_lowercase().starts_with("http://"));

        if page_is_https && action_is_http {
            findings.push(
                Finding::new(
                    "OWASP-FORM-INSECURE-ACTION",
                    "HTTPS page submits `<form>` to plaintext `http://` action URL",
                    Severity::High,
                    OwaspCategory::A02CryptographicFailures,
                    AuditorKind::Dom,
                )
                .cwe(319)
                .wstg("WSTG-CRYP-03")
                .location(page_url.to_owned())
                .evidence(format!(
                    "form={form_label}, action={}",
                    form.action.as_deref().unwrap_or("")
                ))
                .description("Submitting form data from an HTTPS page to an `http://` endpoint exposes user inputs in cleartext.")
                .remediation("Update the form `action` attribute to use `https://`."),
            );
        }

        let has_password = form.inputs.iter().any(|i| i.input_type == "password");
        if has_password && (page_is_http || is_get) {
            findings.push(
                Finding::new(
                    "OWASP-FORM-PASSWORD-GET-OR-HTTP",
                    "Password input hosted on `http://` or submitted via `method=\"GET\"`",
                    Severity::High,
                    OwaspCategory::A07IdentificationAndAuthenticationFailures,
                    AuditorKind::Dom,
                )
                .cwe(598)
                .wstg("WSTG-ATHN-01")
                .location(page_url.to_owned())
                .evidence(format!("form={form_label}, method={method}"))
                .description("Password fields on `http://` pages or `GET` forms leak credentials in transit, URLs, browser history, and server logs.")
                .remediation("Serve authentication forms over HTTPS and use `method=\"POST\"`."),
            );
        }

        if is_post {
            let has_csrf_hidden = form.inputs.iter().any(|input| {
                if input.input_type != "hidden" {
                    return false;
                }
                let combined = format!(
                    "{} {}",
                    input
                        .name
                        .as_deref()
                        .unwrap_or_default()
                        .to_ascii_lowercase(),
                    input.id.as_deref().unwrap_or_default().to_ascii_lowercase()
                );
                CSRF_TOKEN_HINTS.iter().any(|hint| combined.contains(hint))
            });
            if !has_csrf_hidden {
                findings.push(
                    Finding::new(
                        "OWASP-FORM-POST-MISSING-CSRF-TOKEN",
                        "`POST` form lacks a hidden CSRF token field",
                        Severity::Medium,
                        OwaspCategory::A01BrokenAccessControl,
                        AuditorKind::Dom,
                    )
                    .cwe(352)
                    .wstg("WSTG-SESS-05")
                    .location(page_url.to_owned())
                    .evidence(format!("form={form_label}, method=POST"))
                    .description("State-changing `POST` forms without an anti-CSRF token field may be vulnerable to Cross-Site Request Forgery if SameSite cookies are not strictly enforced.")
                    .remediation("Include an unpredictable server-validated CSRF token in a hidden input or custom request header."),
                );
            }
        }

        for input in &form.inputs {
            let name_id = format!(
                "{} {}",
                input
                    .name
                    .as_deref()
                    .unwrap_or_default()
                    .to_ascii_lowercase(),
                input.id.as_deref().unwrap_or_default().to_ascii_lowercase()
            );
            let is_sensitive = input.input_type == "password"
                || SENSITIVE_INPUT_HINTS.iter().any(|h| name_id.contains(h));
            if is_sensitive
                && input
                    .autocomplete
                    .as_deref()
                    .is_none_or(|a| a.trim().is_empty())
            {
                findings.push(
                    Finding::new(
                        "OWASP-FORM-SENSITIVE-MISSING-AUTOCOMPLETE",
                        "Password or sensitive input missing explicit `autocomplete` attribute",
                        Severity::Info,
                        OwaspCategory::A05SecurityMisconfiguration,
                        AuditorKind::Dom,
                    )
                    .cwe(522)
                    .wstg("WSTG-ATHN-06")
                    .location(page_url.to_owned())
                    .evidence(format!(
                        "form={form_label}, input_type={}, name={}",
                        input.input_type,
                        input.name.as_deref().unwrap_or("(unnamed)")
                    ))
                    .description("Sensitive inputs without an explicit `autocomplete` attribute may be cached or autofilled unexpectedly.")
                    .remediation("Set `autocomplete=\"off\"`, `current-password`, or `new-password` explicitly on sensitive inputs."),
                );
            }
        }
    }

    findings
}
