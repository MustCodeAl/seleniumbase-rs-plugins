//! Passive Base64URL JWT header and claims decoder (no signing, cracking, or brute-forcing).

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::error::{OwaspError, Result};
use crate::types::{AuditorKind, Finding, OwaspCategory, Severity, redact_secret};

const THIRTY_DAYS_SECS: i64 = 30 * 24 * 60 * 60;

const CREDENTIAL_CLAIM_KEYS: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "secret",
    "client_secret",
    "api_key",
    "apikey",
    "private_key",
    "credit_card",
    "card_number",
    "cvv",
    "cvc",
    "ssn",
    "pin",
];

const PII_CLAIM_KEYS: &[&str] = &[
    "email",
    "email_address",
    "phone",
    "phone_number",
    "mobile",
    "address",
    "street_address",
    "dob",
    "birth_date",
    "date_of_birth",
    "national_id",
    "passport",
];

/// Passively decoded JWT header and payload claims without signature verification or secrets.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DecodedJwt {
    /// Header `alg` field, if present.
    pub alg: Option<String>,
    /// Header `typ` field, if present.
    pub typ: Option<String>,
    /// Header `kid` field, if present.
    pub kid: Option<String>,
    /// Header `jku` field (remote JWK Set URL), if present.
    pub jku: Option<String>,
    /// Header `x5u` field (remote X.509 certificate URL), if present.
    pub x5u: Option<String>,
    /// Raw parsed JSON header object.
    pub header: Map<String, Value>,
    /// Raw parsed JSON claims object.
    pub claims: Map<String, Value>,
    /// Whether the third segment (signature) is non-empty.
    pub has_signature: bool,
    /// Claims `iss` field, if present.
    pub iss: Option<String>,
    /// Claims `sub` field, if present.
    pub sub: Option<String>,
    /// Claims `aud` strings, if present.
    pub aud: Vec<String>,
    /// Claims `exp` (Unix epoch seconds), if numeric.
    pub exp: Option<i64>,
    /// Claims `nbf` (Unix epoch seconds), if numeric.
    pub nbf: Option<i64>,
    /// Claims `iat` (Unix epoch seconds), if numeric.
    pub iat: Option<i64>,
}

/// Result of passively decoding and auditing a JWT string.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct JwtAuditResult {
    /// Decoded metadata and claims structure.
    pub decoded: DecodedJwt,
    /// Defensive findings emitted for weak header parameters, expiry, or sensitive claims.
    pub findings: Vec<Finding>,
}

/// Passively decodes a JWT (`header.payload.signature`) from Base64URL without modifying
/// or verifying any cryptographic signature.
///
/// # Errors
///
/// Returns [`OwaspError::InvalidJwt`] if the token does not have three dot-separated
/// segments, contains invalid Base64URL bytes, or header/payload are not JSON objects.
pub fn decode_jwt(token: &str) -> Result<DecodedJwt> {
    let trimmed = token.trim();
    let raw = trimmed
        .strip_prefix("Bearer ")
        .or_else(|| trimmed.strip_prefix("bearer "))
        .unwrap_or(trimmed)
        .trim();

    let mut parts = raw.split('.');
    let header_b64 = parts
        .next()
        .ok_or_else(|| OwaspError::InvalidJwt("missing header segment".to_owned()))?;
    let claims_b64 = parts
        .next()
        .ok_or_else(|| OwaspError::InvalidJwt("missing payload segment".to_owned()))?;
    let sig_b64 = parts
        .next()
        .ok_or_else(|| OwaspError::InvalidJwt("missing signature segment".to_owned()))?;
    if parts.next().is_some() {
        return Err(OwaspError::InvalidJwt(
            "expected exactly 3 dot-separated JWT segments (JWS)".to_owned(),
        ));
    }

    let header_bytes = decode_base64url(header_b64)?;
    let claims_bytes = decode_base64url(claims_b64)?;

    let header_val: Value = serde_json::from_slice(&header_bytes)
        .map_err(|err| OwaspError::InvalidJwt(format!("JWT header is not valid JSON: {err}")))?;
    let claims_val: Value = serde_json::from_slice(&claims_bytes)
        .map_err(|err| OwaspError::InvalidJwt(format!("JWT payload is not valid JSON: {err}")))?;

    let header = header_val
        .as_object()
        .ok_or_else(|| OwaspError::InvalidJwt("JWT header must be a JSON object".to_owned()))?
        .clone();
    let claims = claims_val
        .as_object()
        .ok_or_else(|| OwaspError::InvalidJwt("JWT payload must be a JSON object".to_owned()))?
        .clone();

    let aud = match claims.get("aud") {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(arr)) => arr
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
        _ => Vec::new(),
    };

    Ok(DecodedJwt {
        alg: header.get("alg").and_then(Value::as_str).map(str::to_owned),
        typ: header.get("typ").and_then(Value::as_str).map(str::to_owned),
        kid: header.get("kid").and_then(Value::as_str).map(str::to_owned),
        jku: header.get("jku").and_then(Value::as_str).map(str::to_owned),
        x5u: header.get("x5u").and_then(Value::as_str).map(str::to_owned),
        header,
        claims: claims.clone(),
        has_signature: !sig_b64.trim().is_empty(),
        iss: claims.get("iss").and_then(Value::as_str).map(str::to_owned),
        sub: claims.get("sub").and_then(Value::as_str).map(str::to_owned),
        aud,
        exp: claims.get("exp").and_then(Value::as_i64),
        nbf: claims.get("nbf").and_then(Value::as_i64),
        iat: claims.get("iat").and_then(Value::as_i64),
    })
}

/// Passively inspects a JWT for `alg: none`, unpinned remote key headers (`jku`/`x5u`),
/// missing or excessive expiration (`exp`), and sensitive credential/PII claims.
///
/// # Errors
///
/// Returns [`OwaspError::InvalidJwt`] if the token cannot be decoded.
pub fn audit_jwt(
    token: &str,
    location: Option<&str>,
    now_unix_secs: Option<i64>,
) -> Result<JwtAuditResult> {
    let decoded = decode_jwt(token)?;
    let mut findings = Vec::new();
    let loc = location.unwrap_or("jwt");
    let masked = redact_secret(token);

    match decoded.alg.as_deref() {
        Some(alg) if alg.eq_ignore_ascii_case("none") => {
            findings.push(
                Finding::new(
                    "OWASP-JWT-ALG-NONE",
                    "JWT uses insecure `alg: none`",
                    Severity::Critical,
                    OwaspCategory::A02CryptographicFailures,
                    AuditorKind::Jwt,
                )
                .cwe(347)
                .wstg("WSTG-SESS-10")
                .location(loc)
                .evidence(format!("alg={alg}, token={masked}"))
                .description(
                    "The observed JWT specifies `alg: none`, indicating an unsigned token accepted without cryptographic signature integrity.",
                )
                .remediation(
                    "Reject `alg: none` server-side and strictly enforce an explicit allowlist of strong asymmetric/MAC algorithms (such as RS256, ES256, or EdDSA).",
                ),
            );
        }
        None => {
            findings.push(
                Finding::new(
                    "OWASP-JWT-MISSING-ALG",
                    "JWT header is missing `alg` parameter",
                    Severity::High,
                    OwaspCategory::A07IdentificationAndAuthenticationFailures,
                    AuditorKind::Jwt,
                )
                .cwe(347)
                .wstg("WSTG-SESS-10")
                .location(loc)
                .evidence(format!("token={masked}"))
                .description(
                    "The JWT header lacks an `alg` claim specifying the signing algorithm.",
                )
                .remediation(
                    "Always require and validate a trusted `alg` parameter in JWT headers.",
                ),
            );
        }
        Some(_) if !decoded.has_signature => {
            findings.push(
                Finding::new(
                    "OWASP-JWT-EMPTY-SIGNATURE",
                    "JWT carries an empty signature segment",
                    Severity::Critical,
                    OwaspCategory::A02CryptographicFailures,
                    AuditorKind::Jwt,
                )
                .cwe(347)
                .wstg("WSTG-SESS-10")
                .location(loc)
                .evidence(format!(
                    "alg={}, token={masked}",
                    decoded.alg.as_deref().unwrap_or("unknown")
                ))
                .description("The JWT has a blank third segment despite declaring a signing algorithm.")
                .remediation("Ensure all tokens carry valid cryptographic signatures verified on the server."),
            );
        }
        Some(_) => {}
    }

    if let Some(jku) = &decoded.jku {
        findings.push(
            Finding::new(
                "OWASP-JWT-JKU-HEADER",
                "JWT header specifies remote `jku` key URL",
                Severity::High,
                OwaspCategory::A08SoftwareAndDataIntegrityFailures,
                AuditorKind::Jwt,
            )
            .cwe(347)
            .wstg("WSTG-SESS-10")
            .location(loc)
            .evidence(format!("jku={jku}"))
            .description(
                "The JWT header includes a `jku` (JWK Set URL). If servers fetch unvalidated `jku` URLs, it can enable key substitution or SSRF.",
            )
            .remediation(
                "Ignore untrusted `jku` header URLs and resolve verification keys strictly from a server-pinned JWK store.",
            ),
        );
    }

    if let Some(x5u) = &decoded.x5u {
        findings.push(
            Finding::new(
                "OWASP-JWT-X5U-HEADER",
                "JWT header specifies remote `x5u` certificate URL",
                Severity::High,
                OwaspCategory::A08SoftwareAndDataIntegrityFailures,
                AuditorKind::Jwt,
            )
            .cwe(347)
            .wstg("WSTG-SESS-10")
            .location(loc)
            .evidence(format!("x5u={x5u}"))
            .description(
                "The JWT header includes an `x5u` remote X.509 URL, which poses key-confusion and SSRF risks unless strictly ignored or pinned.",
            )
            .remediation(
                "Do not fetch verification certificates from `x5u` token headers; verify against server-pinned public keys.",
            ),
        );
    }

    match decoded.exp {
        None => {
            findings.push(
                Finding::new(
                    "OWASP-JWT-MISSING-EXP",
                    "JWT payload lacks `exp` expiration claim",
                    Severity::Medium,
                    OwaspCategory::A07IdentificationAndAuthenticationFailures,
                    AuditorKind::Jwt,
                )
                .cwe(613)
                .wstg("WSTG-SESS-07")
                .location(loc)
                .evidence(format!(
                    "alg={}, claims_keys={}",
                    decoded.alg.as_deref().unwrap_or("unknown"),
                    decoded.claims.keys().cloned().collect::<Vec<_>>().join(",")
                ))
                .description(
                    "The observed JWT has no `exp` claim, allowing tokens to remain valid indefinitely unless explicitly revoked.",
                )
                .remediation(
                    "Include a short-lived `exp` (expiration time) claim on all session and access tokens.",
                ),
            );
        }
        Some(exp) => {
            if let Some(now) = now_unix_secs
                && exp < now
            {
                findings.push(
                    Finding::new(
                        "OWASP-JWT-EXPIRED",
                        "Expired JWT observed in client context",
                        Severity::Info,
                        OwaspCategory::A07IdentificationAndAuthenticationFailures,
                        AuditorKind::Jwt,
                    )
                    .cwe(613)
                    .wstg("WSTG-SESS-07")
                    .location(loc)
                    .evidence(format!("exp={exp}, observed_at={now}"))
                    .description(
                        "An already-expired JWT remains stored or transmitted in the browser.",
                    )
                    .remediation("Clear expired tokens from client storage upon logout or expiry."),
                );
            }
            if let Some(iat) = decoded.iat
                && exp.saturating_sub(iat) > THIRTY_DAYS_SECS
            {
                findings.push(
                    Finding::new(
                        "OWASP-JWT-LONG-EXPIRY",
                        "JWT has excessive expiration lifetime (> 30 days)",
                        Severity::Low,
                        OwaspCategory::A07IdentificationAndAuthenticationFailures,
                        AuditorKind::Jwt,
                    )
                    .cwe(613)
                    .wstg("WSTG-SESS-07")
                    .location(loc)
                    .evidence(format!("ttl_seconds={}", exp.saturating_sub(iat)))
                    .description("Long-lived JWTs enlarge the replay window if a token is exposed.")
                    .remediation(
                        "Use short-lived access tokens paired with rotating refresh tokens stored in HttpOnly cookies.",
                    ),
                );
            }
        }
    }

    let mut cred_keys = BTreeSet::new();
    let mut pii_keys = BTreeSet::new();
    collect_sensitive_claim_keys(&decoded.claims, "", &mut cred_keys, &mut pii_keys);

    if !cred_keys.is_empty() {
        let joined = cred_keys.into_iter().collect::<Vec<_>>().join(", ");
        findings.push(
            Finding::new(
                "OWASP-JWT-SENSITIVE-CREDENTIAL-CLAIM",
                "JWT payload contains credential/secret claim keys",
                Severity::High,
                OwaspCategory::A02CryptographicFailures,
                AuditorKind::Jwt,
            )
            .cwe(312)
            .wstg("WSTG-ATHN-06")
            .location(loc)
            .evidence(format!("claim_keys=[{joined}]"))
            .description(
                "Standard JWS payloads are only Base64URL-encoded, not encrypted. Secret or credential claims are readable by any holder.",
            )
            .remediation(
                "Remove passwords, secrets, API keys, and financial identifiers from JWT claims, or use JWE when confidentiality is required.",
            ),
        );
    }

    if !pii_keys.is_empty() {
        let joined = pii_keys.into_iter().collect::<Vec<_>>().join(", ");
        findings.push(
            Finding::new(
                "OWASP-JWT-PII-CLAIM",
                "JWT payload exposes unencrypted PII claim keys",
                Severity::Low,
                OwaspCategory::A02CryptographicFailures,
                AuditorKind::Jwt,
            )
            .cwe(200)
            .wstg("WSTG-SESS-10")
            .location(loc)
            .evidence(format!("pii_claim_keys=[{joined}]"))
            .description(
                "JWT claims are readable client-side via Base64URL decoding; storing PII in tokens increases exposure in logs and browser storage.",
            )
            .remediation(
                "Minimize PII embedded in JWT payloads and prefer opaque subject identifiers (`sub`).",
            ),
        );
    }

    Ok(JwtAuditResult { decoded, findings })
}

fn collect_sensitive_claim_keys(
    map: &Map<String, Value>,
    prefix: &str,
    creds: &mut BTreeSet<String>,
    pii: &mut BTreeSet<String>,
) {
    for (key, val) in map {
        let full = if prefix.is_empty() {
            key.clone()
        } else {
            format!("{prefix}.{key}")
        };
        let lower = key.to_ascii_lowercase();
        let non_empty =
            !matches!(val, Value::Null) && val.as_str().is_none_or(|s| !s.trim().is_empty());
        if non_empty {
            if CREDENTIAL_CLAIM_KEYS
                .iter()
                .any(|pat| lower == *pat || lower.ends_with(pat))
            {
                creds.insert(full.clone());
            } else if PII_CLAIM_KEYS.iter().any(|pat| lower == *pat) {
                pii.insert(full.clone());
            }
        }
        match val {
            Value::Object(nested) => collect_sensitive_claim_keys(nested, &full, creds, pii),
            Value::Array(items) => {
                for item in items {
                    if let Value::Object(nested) = item {
                        collect_sensitive_claim_keys(nested, &full, creds, pii);
                    }
                }
            }
            _ => {}
        }
    }
}

/// Scans arbitrary text passively for JWT-shaped `eyJ...` strings.
#[must_use]
pub fn find_jwts_in_text(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while i + 3 < bytes.len() {
        if &bytes[i..i + 3] == b"eyJ" && (i == 0 || !is_jwt_char(bytes[i - 1])) {
            let mut end = i;
            let mut dots = 0_usize;
            while end < bytes.len() && (is_jwt_char(bytes[end]) || bytes[end] == b'.') {
                if bytes[end] == b'.' {
                    dots += 1;
                    if dots > 2 {
                        break;
                    }
                }
                end += 1;
            }
            let candidate = &text[i..end];
            if candidate.matches('.').count() == 2 {
                let mut parts = candidate.split('.');
                if let (Some(h), Some(p), Some(_)) = (parts.next(), parts.next(), parts.next())
                    && h.len() >= 8
                    && p.starts_with("eyJ")
                    && !found.iter().any(|existing| existing == candidate)
                {
                    found.push(candidate.to_owned());
                }
            }
            i = end;
            continue;
        }
        i += 1;
    }
    found
}

const fn is_jwt_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'='
}

/// Decodes RFC 4648 Base64URL (padded or unpadded) into bytes.
fn decode_base64url(input: &str) -> Result<Vec<u8>> {
    let stripped = input.trim().trim_end_matches('=');
    if stripped.is_empty() {
        return Err(OwaspError::InvalidJwt("empty Base64URL segment".to_owned()));
    }
    if stripped.len() % 4 == 1 {
        return Err(OwaspError::InvalidJwt(
            "invalid Base64URL segment length".to_owned(),
        ));
    }

    let mut out = Vec::with_capacity((stripped.len() * 3) / 4);
    let mut buf: u32 = 0;
    let mut bits: u8 = 0;

    for b in stripped.bytes() {
        let val = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => {
                return Err(OwaspError::InvalidJwt(format!(
                    "invalid Base64URL byte `{}`",
                    char::from(b)
                )));
            }
        };
        buf = (buf << 6) | u32::from(val);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xFF) as u8);
        }
    }
    Ok(out)
}
