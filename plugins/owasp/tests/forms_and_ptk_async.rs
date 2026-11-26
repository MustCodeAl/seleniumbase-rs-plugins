//! Tests for passive `<form>`/`<input>` posture auditing, async `window.PTK_AGENT`
//! bridge ingestion (including `exportPlan`), and `target_url` `Task::run`.

use std::sync::Arc;

use seleniumbase_rs_plugin::{Clock, NoPrompt, PluginSet, TaskContext};
use seleniumbase_rs_plugin_owasp::{
    NAME, OwaspAuditReport, OwaspConfig, OwaspPlugin, PtkAgentSnapshot, audit_forms,
    parse_forms_from_value,
};
use seleniumbase_rs_plugin_testing::{
    Call, ManualTimer, RecordingBrowser, RecordingPage, VecSink, block_on,
};
use serde_json::{Value, json};

#[test]
fn forms_auditor_flags_insecure_action_get_password_missing_csrf_and_autocomplete() {
    let payload = json!({
        "forms": [
            {
                "id": "login-form",
                "action": "http://auth.example.com/login",
                "method": "GET",
                "inputs": [
                    { "type": "text", "name": "username" },
                    { "type": "password", "name": "password" }
                ]
            },
            {
                "id": "profile-form",
                "action": "https://app.example.com/profile",
                "method": "POST",
                "inputs": [
                    { "type": "text", "name": "display_name" }
                ]
            },
            {
                "id": "safe-form",
                "action": "https://app.example.com/update",
                "method": "POST",
                "inputs": [
                    { "type": "hidden", "name": "_csrf_token" },
                    { "type": "password", "name": "new_pass", "autocomplete": "new-password" }
                ]
            }
        ]
    });

    let forms = parse_forms_from_value(&payload);
    assert_eq!(forms.len(), 3);

    let findings = audit_forms("https://app.example.com/account", &forms);
    let rules: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();

    assert!(rules.contains(&"OWASP-FORM-INSECURE-ACTION"), "{rules:?}");
    assert!(
        rules.contains(&"OWASP-FORM-PASSWORD-GET-OR-HTTP"),
        "{rules:?}"
    );
    assert!(
        rules.contains(&"OWASP-FORM-POST-MISSING-CSRF-TOKEN"),
        "{rules:?}"
    );
    assert!(
        rules.contains(&"OWASP-FORM-SENSITIVE-MISSING-AUTOCOMPLETE"),
        "{rules:?}"
    );
}

#[test]
fn async_ptk_agent_export_plan_and_target_url_task_run() {
    let page = RecordingPage::new().at("about:blank").evaluating(
        "__sbrs_owasp_audit__",
        json!({
            "url": "https://portal.example.com/login",
            "forms": [
                {
                    "id": "auth",
                    "action": "https://portal.example.com/login",
                    "method": "POST",
                    "inputs": [
                        { "type": "password", "name": "pw" }
                    ]
                }
            ],
            "ptkAgent": {
                "scanStatus": { "ok": true, "sessionId": "s-42", "status": "completed" },
                "findingsResponse": {
                    "ok": true,
                    "truncated": false,
                    "findings": [
                        {
                            "id": "ptk-async-1",
                            "name": "Async PTK Finding",
                            "engine": "dast_passive",
                            "severity": "medium",
                            "owasp": "A05:2021"
                        }
                    ]
                },
                "exportPlan": {
                    "ok": true,
                    "mode": "retrieval-plan",
                    "scans": [{ "engine": "DAST", "exportId": "exp-1" }]
                }
            }
        }),
    );

    let plugin = OwaspPlugin::new(OwaspConfig::default()).unwrap();
    let report = block_on(plugin.audit_page(&page)).unwrap();
    assert!(
        page.calls()
            .iter()
            .any(|c| matches!(c, Call::Evaluate(js) if js.contains("(async () =>") && js.contains("exportFullReport")))
    );
    assert!(report.findings.iter().any(|f| f.rule_id == "ptk-async-1"));
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.rule_id == "OWASP-FORM-POST-MISSING-CSRF-TOKEN")
    );
    let agent: PtkAgentSnapshot = report.ptk_agent.expect("ptk_agent snapshot");
    assert_eq!(agent.session_id.as_deref(), Some("s-42"));
    assert_eq!(
        agent
            .export_plan
            .as_ref()
            .and_then(|v| v.get("mode"))
            .and_then(Value::as_str),
        Some("retrieval-plan")
    );

    // Verify `target_url` alias works in Task::run
    let set = PluginSet::strict().with(plugin).unwrap();
    let browser = RecordingBrowser::builder().contexts().build();
    let sink = VecSink::new();
    let clock = Clock::new(Arc::new(ManualTimer::new()));
    let input = json!({ "target_url": "https://portal.example.com/login" });
    let cx = TaskContext::new(&browser, &input, &sink, &set, &clock, &NoPrompt);
    let out = block_on(set.task(NAME).unwrap().run(&cx)).unwrap();
    let task_report: OwaspAuditReport = serde_json::from_value(out).unwrap();
    assert_eq!(
        task_report.target_url.as_deref(),
        Some("https://portal.example.com/login")
    );
    assert_eq!(browser.live_pages(), 0);
}
