//! Offline tests for PTK extension validation, `modules.json` parsing,
//! bidirectional PTK scan reports, Markdown summaries, and SARIF v2.1.0 schema export.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use seleniumbase_rs_plugin_owasp::{
    AuditorKind, Finding, OwaspAuditReport, OwaspCategory, PackedArchiveFormat, PtkAgentSnapshot,
    PtkEngine, PtkExtensionConfig, PtkModuleCatalog, PtkScanResult, SARIF_SCHEMA_URL, Severity,
};

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(prefix: &str) -> Self {
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "sbrs-owasp-test-{prefix}-{}-{id}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("create temp test dir");
        Self { path }
    }

    fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[test]
fn ptk_extension_config_validates_mv3_unpacked_and_chromium_unpacked_layout() {
    let tmp = TempDir::new("mv3");
    let unpacked = tmp.path().join("chromium-unpacked");
    let modules_dir = unpacked.join("ptk/background/sast/modules");
    fs::create_dir_all(&modules_dir).unwrap();
    fs::write(
        unpacked.join("manifest.json"),
        r#"{
            "manifest_version": 3,
            "name": "OWASP Penetration Testing Kit",
            "version": "10.1.0",
            "description": "OWASP PTK security extension",
            "background": { "service_worker": "ptk/background.js" },
            "permissions": ["storage", "tabs"]
        }"#,
    )
    .unwrap();
    fs::write(
        unpacked.join("dev.local.json"),
        r#"{"automationEnabled": true}"#,
    )
    .unwrap();
    fs::write(
        modules_dir.join("modules.json"),
        r#"[
            {
                "id": "no-inner-outer-html",
                "name": "Unsafe DOM HTML Assignment",
                "type": "sast",
                "metadata": {
                    "taxonomy": {
                        "severity": "medium",
                        "owasp": "A03:2021",
                        "cwe": "https://cwe.mitre.org/data/definitions/79.html",
                        "wstg": "WSTG-CLNT-01"
                    },
                    "description": "Passive DOM sink detection",
                    "remediation": "Use textContent instead of innerHTML"
                },
                "rules": [
                    { "id": "inner-html-rule", "name": "innerHTML sink", "mode": "passive" }
                ]
            },
            {
                "id": "active-fuzzer",
                "name": "Active Probe Module",
                "mode": "active",
                "rules": [
                    { "id": "active-probe-1", "name": "Active probe", "mode": "active" }
                ]
            }
        ]"#,
    )
    .unwrap();

    // Point at the artifact root containing `chromium-unpacked`
    let cfg = PtkExtensionConfig::new()
        .extension_dir(tmp.path())
        .require_ptk_manifest(true);
    let status = cfg.validate_for_launch().unwrap();
    assert_eq!(
        status.extension_dir,
        Some(fs::canonicalize(&unpacked).unwrap())
    );
    assert_eq!(status.automation_enabled, Some(true));
    let manifest = status.manifest.as_ref().unwrap();
    assert_eq!(manifest.manifest_version, 3);
    assert!(manifest.is_ptk());

    let catalog = status.catalog.as_ref().unwrap();
    assert_eq!(catalog.modules.len(), 2);
    // Active modules must be excluded from passive catalog queries.
    let passive_mods = catalog.passive_modules();
    assert_eq!(passive_mods.len(), 1);
    assert_eq!(passive_mods[0].id, "no-inner-outer-html");
    assert_eq!(passive_mods[0].metadata.cwe.as_deref(), Some("CWE-79"));
    assert_eq!(catalog.passive_rules().len(), 1);
}

#[test]
fn ptk_extension_rejects_mv2_missing_manifest_and_bad_archives() {
    let tmp = TempDir::new("invalid-ext");
    fs::write(
        tmp.path().join("manifest.json"),
        r#"{"manifest_version": 2, "name": "Legacy", "version": "1.0"}"#,
    )
    .unwrap();
    let err = PtkExtensionConfig::new()
        .extension_dir(tmp.path())
        .validate()
        .unwrap_err();
    assert!(err.to_string().contains("Manifest V3"), "{err}");

    let zip_path = tmp.path().join("ptk-latest-chromium.zip");
    fs::write(&zip_path, b"PK\x03\x04dummy-zip-payload").unwrap();
    let zip_status = PtkExtensionConfig::new()
        .extension_archive(&zip_path)
        .validate()
        .unwrap();
    assert_eq!(zip_status.archive_format, Some(PackedArchiveFormat::Zip));
    // Launch requires unpacked extension_dir
    assert!(
        PtkExtensionConfig::new()
            .extension_archive(&zip_path)
            .validate_for_launch()
            .is_err()
    );

    let crx_path = tmp.path().join("ptk-latest.crx");
    let mut crx_bytes = Vec::from(&b"Cr24"[..]);
    crx_bytes.extend_from_slice(&3u32.to_le_bytes());
    crx_bytes.extend_from_slice(&0u32.to_le_bytes());
    let mut crx_ok = crx_bytes;
    crx_ok.extend_from_slice(b"PK\x03\x04");
    fs::write(&crx_path, crx_ok).unwrap();
    let crx_status = PtkExtensionConfig::new()
        .extension_archive(&crx_path)
        .validate()
        .unwrap();
    assert_eq!(crx_status.archive_format, Some(PackedArchiveFormat::Crx3));
}

#[test]
fn ptk_catalog_parses_object_root_modules_json() {
    let json = r#"{
        "version": "10.0.0",
        "modules": [
            {
                "id": "passive-headers",
                "name": "Security Headers Passive Check",
                "engine": "dast_passive",
                "passive": true,
                "metadata": {
                    "severity": "medium",
                    "owasp": "A05:2021",
                    "cwe": "693",
                    "wstg": "WSTG-CONF-07"
                },
                "rules": [
                    { "id": "missing-hsts", "name": "Missing HSTS" }
                ]
            }
        ]
    }"#;
    let cat = PtkModuleCatalog::from_json_str(json).unwrap();
    assert_eq!(cat.version.as_deref(), Some("10.0.0"));
    assert_eq!(cat.passive_modules().len(), 1);
    assert_eq!(cat.passive_modules()[0].engine, PtkEngine::DastPassive);
    assert_eq!(
        cat.passive_modules()[0].metadata.cwe.as_deref(),
        Some("CWE-693")
    );
}

#[test]
fn ptk_bidirectional_report_and_sarif_v2_1_0_schema_compliance() {
    let findings = vec![
        Finding::new(
            "OWASP-JWT-ALG-NONE",
            "JWT uses insecure `alg: none`",
            Severity::Critical,
            OwaspCategory::A02CryptographicFailures,
            AuditorKind::Jwt,
        )
        .cwe(347)
        .wstg("WSTG-SESS-10")
        .location("https://app.example.com/api")
        .evidence("alg=none")
        .description("Unsigned JWT token accepted without cryptographic integrity.")
        .remediation("Enforce RS256/ES256 server-side."),
        Finding::new(
            "OWASP-HDR-HSTS-MISSING",
            "Missing HSTS header",
            Severity::Medium,
            OwaspCategory::A05SecurityMisconfiguration,
            AuditorKind::Headers,
        )
        .cwe(523)
        .wstg("WSTG-CONF-07")
        .location("https://app.example.com/")
        .description("HTTPS response omits HSTS.")
        .remediation("Set Strict-Transport-Security header."),
    ];

    let report = OwaspAuditReport::from_parts(
        Some("https://app.example.com/".to_owned()),
        findings,
        Vec::new(),
        2,
        1,
        None,
        true,
    );
    assert_eq!(report.summary.critical, 1);
    assert_eq!(report.summary.medium, 1);
    assert_eq!(report.summary.total, 2);
    assert_eq!(
        report.wstg_references(),
        vec!["WSTG-CONF-07".to_owned(), "WSTG-SESS-10".to_owned()]
    );

    // Markdown output
    let md = report.to_markdown();
    assert!(md.contains("# OWASP Passive Security Audit Report"));
    assert!(md.contains("OWASP-JWT-ALG-NONE"));
    assert!(md.contains("WSTG-SESS-10"));

    // Bidirectional PTK round-trip
    let ptk_json = report.to_ptk_json_pretty().unwrap();
    let imported = PtkScanResult::from_json_str(&ptk_json).unwrap();
    assert_eq!(imported.scan_mode, "passive");
    assert_eq!(imported.stats.critical, 1);
    assert_eq!(imported.stats.medium, 1);
    assert_eq!(imported.effective_severity(), Some(Severity::Critical));
    let roundtrip_findings = imported.to_findings();
    assert_eq!(roundtrip_findings.len(), 2);
    assert_eq!(roundtrip_findings[0].cwe, Some(347));
    assert_eq!(roundtrip_findings[0].wstg.as_deref(), Some("WSTG-SESS-10"));

    // Import upstream camelCase PTK export envelope
    let upstream = r#"{
        "target": "https://portal.example.org",
        "scanEngine": "sast_passive",
        "groups": [
            {
                "findings": [
                    {
                        "ruleId": "ptk-sast-dom-sink",
                        "title": "DOM sink observed",
                        "severity": "high",
                        "effectiveSeverity": "medium",
                        "owasp": "A03:2021",
                        "cwe": "https://cwe.mitre.org/data/definitions/79.html",
                        "wstg": "WSTG-CLNT-01",
                        "url": "https://portal.example.org/app.js",
                        "remediation": "Use safe DOM APIs"
                    }
                ]
            }
        ]
    }"#;
    let parsed_upstream = PtkScanResult::from_json_str(upstream).unwrap();
    assert_eq!(parsed_upstream.findings.len(), 1);
    assert_eq!(
        parsed_upstream.findings[0].effective_severity,
        Severity::Medium
    );
    assert_eq!(parsed_upstream.findings[0].cwe.as_deref(), Some("CWE-79"));

    // Parse window.PTK_AGENT bridge payload
    let bridge_json = serde_json::json!({
        "scanStatus": { "ok": true, "sessionId": "sess-1", "status": "completed" },
        "findingsResponse": {
            "ok": true,
            "truncated": false,
            "findings": [
                {
                    "id": "ptk-passive-1",
                    "name": "Missing CSP",
                    "engine": "dast_passive",
                    "severity": "medium",
                    "owasp": "A05:2021",
                    "cwe": "CWE-693",
                    "wstg": "WSTG-CONF-12"
                },
                {
                    "id": "ptk-active-skip",
                    "name": "Active Probe",
                    "mode": "active",
                    "severity": "high"
                }
            ]
        }
    });
    let agent = PtkAgentSnapshot::from_value(&bridge_json).unwrap();
    assert!(agent.ok);
    assert_eq!(agent.status.as_deref(), Some("completed"));
    assert_eq!(agent.findings.len(), 1);
    assert_eq!(agent.findings[0].id, "ptk-passive-1");

    // SARIF v2.1.0 schema verification
    let sarif = report.to_sarif();
    assert_eq!(sarif["$schema"], SARIF_SCHEMA_URL);
    assert_eq!(sarif["version"], "2.1.0");
    let run = &sarif["runs"][0];
    assert_eq!(
        run["tool"]["driver"]["name"],
        "seleniumbase-rs-plugin-owasp"
    );
    assert_eq!(run["invocations"][0]["executionSuccessful"], true);

    let rules = run["tool"]["driver"]["rules"].as_array().unwrap();
    let results = run["results"].as_array().unwrap();
    assert_eq!(rules.len(), 2);
    assert_eq!(results.len(), 2);
    for result in results {
        let idx = result["ruleIndex"].as_u64().unwrap() as usize;
        assert_eq!(rules[idx]["id"], result["ruleId"]);
        assert!(matches!(
            result["level"].as_str(),
            Some("error" | "warning" | "note")
        ));
        assert!(
            result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                .as_str()
                .is_some()
        );
        assert!(
            result["partialFingerprints"]["primaryLocationLineHash"]
                .as_str()
                .is_some_and(|h| h.len() == 16)
        );
    }
}
