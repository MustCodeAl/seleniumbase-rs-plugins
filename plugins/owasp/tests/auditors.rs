//! Comprehensive offline tests for passive OWASP auditors (headers, CSP, CORS,
//! cookies, JWT, DOM/storage/postMessage, and client-side SCA).

use std::collections::BTreeMap;

use seleniumbase_rs_plugin_owasp::{
    AuditorKind, ComponentStatus, CookieAuditContext, CookieInput, CspPolicy, CspSource,
    DomAuditOptions, DomSnapshot, HeaderAuditContext, JsGlobals, OwaspCategory, SameSite, SemVer,
    SetCookie, Severity, audit_cookies, audit_dom, audit_headers, audit_headers_map, audit_jwt,
    audit_sca, audit_set_cookie, decode_jwt, find_jwts_in_text,
};

fn b64url_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(*chunk.get(1).unwrap_or(&0));
        let b2 = u32::from(*chunk.get(2).unwrap_or(&0));
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(char::from(TABLE[((n >> 18) & 0x3F) as usize]));
        out.push(char::from(TABLE[((n >> 12) & 0x3F) as usize]));
        if chunk.len() > 1 {
            out.push(char::from(TABLE[((n >> 6) & 0x3F) as usize]));
        }
        if chunk.len() > 2 {
            out.push(char::from(TABLE[(n & 0x3F) as usize]));
        }
    }
    out
}

fn make_test_jwt(header_json: &str, claims_json: &str, sig: &str) -> String {
    format!(
        "{}.{}.{}",
        b64url_encode(header_json.as_bytes()),
        b64url_encode(claims_json.as_bytes()),
        sig
    )
}

#[test]
fn headers_detect_missing_security_controls_and_banner_leaks() {
    let headers = vec![
        ("Server".to_owned(), "nginx/1.18.0".to_owned()),
        ("X-Powered-By".to_owned(), "Express".to_owned()),
        ("Referrer-Policy".to_owned(), "unsafe-url".to_owned()),
        (
            "Permissions-Policy".to_owned(),
            "camera=(*), geolocation=()".to_owned(),
        ),
    ];
    let findings = audit_headers(
        &HeaderAuditContext::new(
            "https://app.example.com/login",
            200,
            "text/html; charset=utf-8",
            &headers,
        )
        .document(true),
    );

    let rule_ids: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
    for expected in [
        "OWASP-HDR-HSTS-MISSING",
        "OWASP-CSP-MISSING",
        "OWASP-HDR-CLICKJACKING-MISSING",
        "OWASP-HDR-XCTO-MISSING",
        "OWASP-HDR-REFERRER-POLICY-WEAK",
        "OWASP-HDR-PERMISSIONS-WILDCARD",
        "OWASP-HDR-COOP-MISSING",
        "OWASP-HDR-COEP-MISSING",
        "OWASP-HDR-CORP-MISSING",
        "OWASP-HDR-BANNER-LEAK",
    ] {
        assert!(
            rule_ids.contains(&expected),
            "missing {expected} in {rule_ids:?}"
        );
    }
}

#[test]
fn headers_hardened_https_document_passes_cleanly() {
    let mut headers = BTreeMap::new();
    headers.insert(
        "Strict-Transport-Security".to_owned(),
        "max-age=31536000; includeSubDomains; preload".to_owned(),
    );
    headers.insert(
        "Content-Security-Policy".to_owned(),
        "default-src 'none'; script-src 'self' 'nonce-r4nd0m'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'".to_owned(),
    );
    headers.insert("X-Frame-Options".to_owned(), "DENY".to_owned());
    headers.insert("X-Content-Type-Options".to_owned(), "nosniff".to_owned());
    headers.insert(
        "Referrer-Policy".to_owned(),
        "strict-origin-when-cross-origin".to_owned(),
    );
    headers.insert(
        "Permissions-Policy".to_owned(),
        "camera=(), microphone=(), geolocation=()".to_owned(),
    );
    headers.insert(
        "Cross-Origin-Opener-Policy".to_owned(),
        "same-origin".to_owned(),
    );
    headers.insert(
        "Cross-Origin-Embedder-Policy".to_owned(),
        "require-corp".to_owned(),
    );
    headers.insert(
        "Cross-Origin-Resource-Policy".to_owned(),
        "same-origin".to_owned(),
    );

    let findings = audit_headers_map(
        "https://secure.example.com/",
        200,
        "text/html",
        true,
        &headers,
    );
    assert!(
        findings.is_empty(),
        "expected zero findings, got {findings:?}"
    );
}

#[test]
fn csp_ast_flags_unsafe_directives_and_missing_protections() {
    let raw = "default-src *; script-src 'self' 'unsafe-inline' 'unsafe-eval' data: http://cdn.bad.test; script-src 'none'";
    let ast = CspPolicy::parse(raw);
    assert_eq!(ast.duplicate_directives, ["script-src"]);
    let script_src = ast.directive("script-src").expect("script-src present");
    assert!(script_src.sources.contains(&CspSource::UnsafeInline));
    assert!(script_src.sources.contains(&CspSource::UnsafeEval));
    assert!(script_src.sources.iter().any(|s| s.is_scheme("data:")));
    assert!(script_src.sources.iter().any(|s| s.is_scheme("http:")));

    let headers = vec![("Content-Security-Policy".to_owned(), raw.to_owned())];
    let findings = audit_headers(
        &HeaderAuditContext::new("https://app.example.com/", 200, "text/html", &headers)
            .document(true),
    );
    let ids: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
    for expected in [
        "OWASP-CSP-DUPLICATE-DIRECTIVE",
        "OWASP-CSP-UNSAFE-INLINE",
        "OWASP-CSP-UNSAFE-EVAL",
        "OWASP-CSP-DATA-SCRIPT",
        "OWASP-CSP-HTTP-SCRIPT",
        "OWASP-CSP-WILDCARD-DIRECTIVE",
        "OWASP-CSP-MISSING-OBJECT-SRC",
        "OWASP-CSP-MISSING-BASE-URI",
        "OWASP-CSP-MISSING-FRAME-ANCESTORS",
    ] {
        assert!(ids.contains(&expected), "missing {expected} in {ids:?}");
    }
}

#[test]
fn cors_auditor_flags_wildcard_with_credentials_null_and_reflected_origin() {
    let combo = vec![
        ("Access-Control-Allow-Origin".to_owned(), "*".to_owned()),
        (
            "Access-Control-Allow-Credentials".to_owned(),
            "true".to_owned(),
        ),
    ];
    let combo_findings = audit_headers(&HeaderAuditContext::new(
        "https://api.example.com/me",
        200,
        "application/json",
        &combo,
    ));
    assert!(combo_findings.iter().any(|f| {
        f.rule_id == "OWASP-CORS-WILDCARD-CREDENTIALS"
            && f.severity == Severity::Critical
            && f.category == OwaspCategory::A01BrokenAccessControl
    }));

    let reflected = vec![
        (
            "Access-Control-Allow-Origin".to_owned(),
            "https://evil.example".to_owned(),
        ),
        (
            "Access-Control-Allow-Credentials".to_owned(),
            "true".to_owned(),
        ),
    ];
    let refl_findings = audit_headers(
        &HeaderAuditContext::new(
            "https://api.example.com/profile",
            200,
            "application/json",
            &reflected,
        )
        .request_origin(Some("https://evil.example")),
    );
    let refl_ids: Vec<&str> = refl_findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(refl_ids.contains(&"OWASP-CORS-REFLECTED-ORIGIN"));
    assert!(refl_ids.contains(&"OWASP-CORS-MISSING-VARY-ORIGIN"));

    let null_cors = vec![("Access-Control-Allow-Origin".to_owned(), "null".to_owned())];
    let null_findings = audit_headers(&HeaderAuditContext::new(
        "https://api.example.com/data",
        200,
        "application/json",
        &null_cors,
    ));
    assert!(
        null_findings
            .iter()
            .any(|f| f.rule_id == "OWASP-CORS-NULL-ORIGIN")
    );
}

#[test]
fn cookie_auditor_checks_flags_prefixes_broad_domain_and_redaction() {
    let parsed =
        SetCookie::parse("JSESSIONID=secret123; Path=/; SameSite=None; Domain=.example.com")
            .unwrap();
    assert_eq!(parsed.name, "JSESSIONID");
    assert_eq!(parsed.same_site, Some(SameSite::None));
    assert!(!parsed.http_only);
    assert!(!parsed.secure);

    let ctx = CookieAuditContext::from_url(Some("https://app.example.com/dashboard"));
    let findings = audit_set_cookie(
        "JSESSIONID=secret123; Path=/; SameSite=None; Domain=.example.com",
        &ctx,
    );
    let ids: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
    for expected in [
        "OWASP-COOKIE-NO-HTTPONLY",
        "OWASP-COOKIE-NO-SECURE",
        "OWASP-COOKIE-SAMESITE-NONE-INSECURE",
        "OWASP-COOKIE-BROAD-DOMAIN",
    ] {
        assert!(ids.contains(&expected), "missing {expected} in {ids:?}");
    }
    // Raw cookie value must never leak into evidence.
    assert!(findings.iter().all(|f| {
        f.evidence
            .as_deref()
            .is_none_or(|ev| !ev.contains("secret123"))
    }));

    // __Host- prefix violation
    let host_findings = audit_set_cookie(
        "__Host-sid=abc; Secure; Domain=example.com; Path=/app",
        &ctx,
    );
    assert!(
        host_findings
            .iter()
            .any(|f| f.rule_id == "OWASP-COOKIE-HOST-PREFIX-VIOLATION"
                && f.severity == Severity::High)
    );

    // Valid hardened __Host- cookie produces zero findings
    let ok = audit_set_cookie(
        "__Host-session=xyz; Secure; HttpOnly; SameSite=Strict; Path=/",
        &ctx,
    );
    assert!(ok.is_empty(), "expected clean __Host- cookie, got {ok:?}");

    // Redacted placeholder handled gracefully
    let redacted = audit_set_cookie("[redacted]", &ctx);
    assert_eq!(redacted.len(), 1);
    assert_eq!(redacted[0].rule_id, "OWASP-COOKIE-REDACTED");

    // JS-accessible document.cookie check
    let doc_cookies = vec![CookieInput::from_document_cookie("auth_session", "tok123")];
    let js_findings = audit_cookies(&doc_cookies, &ctx);
    assert!(
        js_findings
            .iter()
            .any(|f| f.rule_id == "OWASP-COOKIE-JS-ACCESSIBLE-SESSION")
    );
}

#[test]
fn jwt_auditor_decodes_passively_and_flags_alg_none_missing_exp_and_pii() {
    let insecure_jwt = make_test_jwt(
        r#"{"alg":"none","typ":"JWT","jku":"https://untrusted.example/jwks.json"}"#,
        r#"{"sub":"42","email":"alice@example.com","password":"supersecretvalue"}"#,
        "sig",
    );
    let res = audit_jwt(
        &insecure_jwt,
        Some("localStorage:auth"),
        Some(1_700_000_000),
    )
    .unwrap();
    assert_eq!(res.decoded.alg.as_deref(), Some("none"));
    let ids: Vec<&str> = res.findings.iter().map(|f| f.rule_id.as_str()).collect();
    for expected in [
        "OWASP-JWT-ALG-NONE",
        "OWASP-JWT-JKU-HEADER",
        "OWASP-JWT-MISSING-EXP",
        "OWASP-JWT-SENSITIVE-CREDENTIAL-CLAIM",
        "OWASP-JWT-PII-CLAIM",
    ] {
        assert!(ids.contains(&expected), "missing {expected} in {ids:?}");
    }
    // Raw credential values must never be echoed in evidence.
    assert!(res.findings.iter().all(|f| {
        f.evidence
            .as_deref()
            .is_none_or(|ev| !ev.contains("supersecretvalue"))
    }));

    // Clean RS256 token with valid exp
    let valid_jwt = make_test_jwt(
        r#"{"alg":"RS256","typ":"JWT","kid":"k1"}"#,
        r#"{"iss":"https://auth.example.com","sub":"user-99","aud":"api","iat":1700000000,"exp":1700003600}"#,
        "c2lnbmF0dXJl",
    );
    let ok = audit_jwt(&valid_jwt, Some("Authorization"), Some(1_700_000_100)).unwrap();
    assert!(
        ok.findings.is_empty(),
        "expected clean JWT, got {:?}",
        ok.findings
    );

    // Invalid JWT format produces typed error
    assert!(decode_jwt("not.a.valid.jwt.token").is_err());

    // Text scanner locates JWTs inside storage/headers
    let text = format!("Bearer {valid_jwt}");
    assert_eq!(find_jwts_in_text(&text), vec![valid_jwt]);
}

#[test]
fn dom_auditor_flags_mixed_content_sri_tabnabbing_storage_secrets_and_postmessage() {
    let html = r#"
    <!doctype html>
    <html>
      <head>
        <script src="http://insecure.example.com/mixed.js"></script>
        <script src="https://cdn.thirdparty.test/widget.js"></script>
        <script src="https://cdn.thirdparty.test/safe.js" integrity="sha384-abc" crossorigin="anonymous"></script>
        <script src="/static/local.js"></script>
      </head>
      <body>
        <!-- TODO: internal staging password=MySecretPass123 -->
        <a href="https://external.example/" target="_blank">External</a>
        <a href="https://safe.example/" target="_blank" rel="noopener noreferrer">Safe</a>
        <img src="http://media.example.com/logo.png">
        <script>
          window.parent.postMessage({ ok: true }, '*');
          window.addEventListener('message', function(ev) {
            document.getElementById('out').innerHTML = ev.data;
          });
        </script>
      </body>
    </html>
    "#;

    let jwt = make_test_jwt(
        r#"{"alg":"HS256","typ":"JWT"}"#,
        r#"{"sub":"u1"}"#,
        "sig123",
    );
    let snap = DomSnapshot::from_html("https://app.example.com/home", html)
        .local_storage_entry("auth_jwt", jwt)
        .session_storage_entry("aws_key", "AKIAIOSFODNN7EXAMPLE12");

    let findings = audit_dom(&snap, &DomAuditOptions::default());
    let ids: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
    for expected in [
        "OWASP-DOM-MIXED-ACTIVE",
        "OWASP-DOM-MIXED-PASSIVE",
        "OWASP-DOM-MISSING-SRI",
        "OWASP-DOM-TABNABBING",
        "OWASP-DOM-SECRET-IN-COMMENT",
        "OWASP-DOM-JWT-IN-STORAGE",
        "OWASP-JWT-MISSING-EXP",
        "OWASP-DOM-SECRET-IN-STORAGE",
        "OWASP-DOM-POSTMESSAGE-WILDCARD",
        "OWASP-DOM-POSTMESSAGE-NO-ORIGIN-CHECK",
        "OWASP-DOM-PASSIVE-SINK-INVENTORY",
    ] {
        assert!(ids.contains(&expected), "missing {expected} in {ids:?}");
    }

    // Ensure safe scripts/links were NOT falsely flagged
    assert!(!findings.iter().any(|f| {
        f.rule_id == "OWASP-DOM-MISSING-SRI"
            && f.evidence
                .as_deref()
                .is_some_and(|e| e.contains("safe.js") || e.contains("local.js"))
    }));
    // Ensure raw secrets are masked in evidence
    assert!(findings.iter().all(|f| {
        f.evidence.as_deref().is_none_or(|ev| {
            !ev.contains("MySecretPass123") && !ev.contains("AKIAIOSFODNN7EXAMPLE12")
        })
    }));
}

#[test]
fn sca_auditor_identifies_eol_and_current_client_libraries() {
    assert_eq!(SemVer::parse("v4.17.15"), Some(SemVer::new(4, 17, 15)));

    let html = r#"
    <html>
      <head>
        <script src="https://code.jquery.com/jquery-3.4.1.min.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/lodash@4.17.15/lodash.min.js"></script>
        <script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.8.2/angular.min.js"></script>
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@3.3.7/dist/css/bootstrap.min.css">
      </head>
    </html>
    "#;
    let globals = JsGlobals::new().react("18.3.1").vue("2.6.14");
    let snap = DomSnapshot::from_html("https://app.example.com/", html).globals(globals);
    let sca = audit_sca(&snap, &[]);

    let names: Vec<&str> = sca.components.iter().map(|c| c.name.as_str()).collect();
    for lib in ["jquery", "lodash", "angularjs", "bootstrap", "react", "vue"] {
        assert!(names.contains(&lib), "missing {lib} in {names:?}");
    }

    let react = sca.components.iter().find(|c| c.name == "react").unwrap();
    assert_eq!(react.status, ComponentStatus::Current);

    let lodash = sca.components.iter().find(|c| c.name == "lodash").unwrap();
    assert_eq!(lodash.status, ComponentStatus::VulnerableOrEol);

    assert!(sca.findings.iter().all(|f| {
        f.category == OwaspCategory::A06VulnerableAndOutdatedComponents
            && f.auditor == AuditorKind::Sca
    }));
}
