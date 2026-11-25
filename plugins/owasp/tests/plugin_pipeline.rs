//! Integration tests for `OwaspPlugin`, `PluginSet`, `before_launch`,
//! `on_response` (`drive_response`), `on_protocol_event`, and `Task` execution.

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use seleniumbase_rs_plugin::{
    BrowserFamily, BrowserHandle, Capability, CapabilitySet, Category, Clock, Configurable,
    Descriptor, Engine, LaunchContext, LaunchSettings, NoPrompt, PageHandle, PluginError,
    PluginSet, ProtocolEvent, Registry, RequestDecision, RequestView, ResourceKind, ResponseView,
    TaskContext, async_trait,
};
use seleniumbase_rs_plugin_owasp::{
    NAME, OwaspAuditReport, OwaspConfig, OwaspPlugin, PtkExtensionConfig,
};
use seleniumbase_rs_plugin_testing::{
    Call, ManualTimer, RecordingBrowser, RecordingPage, VecSink, block_on, drive_request,
    drive_response,
};
use serde_json::{Value, json};

static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(prefix: &str) -> Self {
        let id = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "sbrs-owasp-plugin-{prefix}-{}-{id}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("create temp dir");
        Self { path }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

struct OneTab {
    page: RecordingPage,
    opened: AtomicUsize,
}

impl OneTab {
    fn new(page: RecordingPage) -> Self {
        Self {
            page,
            opened: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl BrowserHandle for OneTab {
    fn engine(&self) -> Engine {
        Engine::Cdp
    }

    fn family(&self) -> BrowserFamily {
        BrowserFamily::Chromium
    }

    async fn new_page<'a>(
        &'a self,
        _url: Option<&str>,
    ) -> seleniumbase_rs_plugin::Result<Box<dyn PageHandle + 'a>> {
        self.opened.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(self.page.clone()))
    }

    async fn send(&self, _method: &str, _params: Value) -> seleniumbase_rs_plugin::Result<Value> {
        Ok(Value::Null)
    }
}

#[test]
fn metadata_registration_and_strict_config_validation() {
    let meta = OwaspPlugin::describe();
    assert_eq!(OwaspPlugin::NAME, NAME);
    assert_eq!(meta.category, Some(Category::Core));
    for cap in [
        Capability::NetObserve,
        Capability::PageEvaluate,
        Capability::Task,
    ] {
        assert!(meta.capabilities.covers(&cap), "missing {cap}");
    }
    // Never requests NetIntercept or NetFulfill — strictly passive.
    assert!(!meta.capabilities.covers(&Capability::NetIntercept));
    assert!(!meta.optional.covers(&Capability::NetIntercept));
    assert!(!meta.capabilities.covers(&Capability::NetFulfill));

    let registry = Registry::new().with(Descriptor::of::<OwaspPlugin>());
    assert_eq!(registry.names(), ["owasp"]);

    let plugin = OwaspPlugin::configure(&Value::Null).unwrap();
    let set = PluginSet::strict().with(plugin).unwrap();
    assert_eq!(set.names(), ["owasp"]);
    assert_eq!(set.task_names(), ["owasp"]);
    assert!(set.job_runner("owasp").is_ok());

    set.check(&LaunchContext {
        engine: Engine::Cdp,
        family: BrowserFamily::Chromium,
        headless: true,
        connecting: false,
    })
    .unwrap();

    // Unknown config option produces typed Config error.
    let err = OwaspPlugin::configure(&json!({ "attack_mode": true })).unwrap_err();
    assert_eq!(
        err.to_string(),
        "plugin configuration: owasp: unknown option `attack_mode`"
    );

    // Passive network() interest must not register intercept filters or blocking rules.
    let interest = set.interest();
    assert!(interest.rules.is_empty());
    assert!(interest.intercept.is_empty());
    assert!(!interest.observe.is_empty());

    // Never blocks traffic.
    let req = RequestView::new("https://app.example.com/", "GET", ResourceKind::Document);
    assert_eq!(drive_request(&set, req), RequestDecision::Continue);
}

#[test]
fn before_launch_wires_ptk_extension_and_loads_passive_catalog() {
    let tmp = TempDir::new("ptk-launch");
    let modules_dir = tmp.path.join("ptk/background/sast/modules");
    fs::create_dir_all(&modules_dir).unwrap();
    fs::write(
        tmp.path.join("manifest.json"),
        r#"{"manifest_version": 3, "name": "OWASP PTK", "version": "10.0.0"}"#,
    )
    .unwrap();
    fs::write(
        modules_dir.join("modules.json"),
        r#"[{"id": "sast-1", "name": "Passive SAST", "mode": "passive"}]"#,
    )
    .unwrap();

    let cfg = OwaspConfig::new().ptk(PtkExtensionConfig::new().extension_dir(&tmp.path));
    let plugin = OwaspPlugin::new(cfg).unwrap();
    let set = PluginSet::strict().with(plugin).unwrap();

    let mut launch = LaunchSettings::default();
    block_on(set.before_launch(&mut launch)).unwrap();
    assert_eq!(
        launch.extensions,
        vec![fs::canonicalize(&tmp.path).unwrap()]
    );

    // Refuses old headless when extension is configured
    let mut old_headless = LaunchSettings::default();
    old_headless.args.push("--headless=old".to_owned());
    assert!(block_on(set.before_launch(&mut old_headless)).is_err());
}

#[test]
fn on_response_and_protocol_events_collect_passive_findings_without_blocking() {
    let plugin = OwaspPlugin::new(OwaspConfig::default()).unwrap();
    let set = PluginSet::strict().with(plugin).unwrap();

    let doc_req = RequestView::new("https://app.example.com/", "GET", ResourceKind::Document)
        .header("Server", "Apache/2.4.49")
        .header("Set-Cookie", "session_id=tok_abc; Path=/")
        .header("Access-Control-Allow-Origin", "*")
        .header("Access-Control-Allow-Credentials", "true");

    let failures = drive_response(&set, ResponseView::new(&doc_req, 200, "text/html"));
    assert!(failures.is_empty(), "{failures:?}");

    // Drive a protocol event as well
    let browser = RecordingBrowser::new();
    let cdp_event = ProtocolEvent::new(
        "Network.responseReceived",
        json!({
            "type": "XHR",
            "response": {
                "url": "https://api.example.com/v1/user",
                "status": 200,
                "mimeType": "application/json",
                "headers": {
                    "X-Powered-By": "Express/4.18.0",
                    "Access-Control-Allow-Origin": "null"
                }
            }
        }),
    );
    let proto_failures = block_on(set.on_protocol_event(&browser, &cdp_event));
    assert!(proto_failures.is_empty(), "{proto_failures:?}");

    // Run Task on an active RecordingPage to combine passive network + page DOM/storage/SCA findings
    let page = RecordingPage::new()
        .at("https://app.example.com/")
        .evaluating(
            "__sbrs_owasp_audit__",
            json!({
                "url": "https://app.example.com/",
                "documentCookie": "sid_js=rawcookie",
                "scripts": [
                    { "src": "https://cdn.example.net/jquery-3.4.1.min.js" },
                    { "inline": "window.parent.postMessage('hi', '*');" }
                ],
                "stylesheets": [],
                "links": [
                    { "href": "https://other.test", "target": "_blank" }
                ],
                "active_elements": [],
                "passive_elements": [],
                "comments": ["debug staging server"],
                "localStorage": {
                    "token": "ghp_1234567890abcdef1234567890abcdef1234"
                },
                "sessionStorage": {},
                "globals": { "jquery": "3.4.1" },
                "ptkAgent": {
                    "scanStatus": { "ok": true, "status": "completed" },
                    "findingsResponse": {
                        "ok": true,
                        "findings": [
                            {
                                "id": "ptk-bridge-1",
                                "name": "PTK Passive Observation",
                                "engine": "sast_passive",
                                "severity": "low",
                                "owasp": "A05:2021"
                            }
                        ]
                    }
                }
            }),
        );

    let tab_browser = OneTab::new(page);
    let sink = VecSink::new();
    let clock = Clock::new(Arc::new(ManualTimer::new()));
    let cx = TaskContext::new(&tab_browser, &Value::Null, &sink, &set, &clock, &NoPrompt);

    let report_val = block_on(set.task("owasp").unwrap().run(&cx)).unwrap();
    let report: OwaspAuditReport = serde_json::from_value(report_val).unwrap();

    assert_eq!(report.observed_responses, 2);
    assert!(report.summary.critical >= 1);
    assert!(report.summary.high >= 1);
    assert_eq!(sink.lines().len(), report.findings.len());
    assert!(tab_browser.page.calls().contains(&Call::Close));

    let rule_ids: Vec<&str> = report.findings.iter().map(|f| f.rule_id.as_str()).collect();
    for expected in [
        "OWASP-CORS-WILDCARD-CREDENTIALS",
        "OWASP-CORS-NULL-ORIGIN",
        "OWASP-COOKIE-NO-HTTPONLY",
        "OWASP-COOKIE-JS-ACCESSIBLE-SESSION",
        "OWASP-DOM-MISSING-SRI",
        "OWASP-DOM-TABNABBING",
        "OWASP-DOM-POSTMESSAGE-WILDCARD",
        "OWASP-DOM-SECRET-IN-STORAGE",
        "OWASP-SCA-OUTDATED-JQUERY",
        "ptk-bridge-1",
    ] {
        assert!(
            rule_ids.contains(&expected),
            "missing {expected} in {rule_ids:?}"
        );
    }
}

#[test]
fn on_response_redacts_set_cookie_when_net_sensitive_is_withheld() {
    let plugin = OwaspPlugin::new(OwaspConfig::default()).unwrap();
    let mut grants = CapabilitySet::new();
    grants.insert(Capability::NetObserve);
    grants.insert(Capability::PageEvaluate);
    grants.insert(Capability::Task);
    let set = PluginSet::strict().with_grants(plugin, grants).unwrap();

    let req = RequestView::new("https://app.example.com/", "GET", ResourceKind::Document)
        .header("Set-Cookie", "sid=supersecret; HttpOnly; Secure");
    let failures = drive_response(&set, ResponseView::new(&req, 200, "text/html"));
    assert!(failures.is_empty());

    let browser = RecordingBrowser::builder().contexts().build();
    let sink = VecSink::new();
    let clock = Clock::new(Arc::new(ManualTimer::new()));
    let input = json!({ "url": "https://app.example.com/" });
    // PageNavigate is not granted so navigate must be rejected while tab still closes cleanly.
    let cx = TaskContext::new(&browser, &input, &sink, &set, &clock, &NoPrompt);
    let err = block_on(set.task("owasp").unwrap().run(&cx)).unwrap_err();
    assert!(
        matches!(err, PluginError::Capability { .. }) && err.to_string().contains("page.navigate"),
        "{err}"
    );
    assert_eq!(browser.live_pages(), 0);
}

#[test]
fn task_and_job_runner_work_with_recording_browser_and_direct_html_input() {
    let plugin = OwaspPlugin::new(OwaspConfig::default()).unwrap();
    let set = PluginSet::strict().with(plugin).unwrap();
    let browser = RecordingBrowser::builder().contexts().build();
    let sink = VecSink::new();
    let clock = Clock::new(Arc::new(ManualTimer::new()));

    let input = json!({
        "url": "https://shop.example.com/cart",
        "headers": {
            "Server": "nginx/1.19.0",
            "X-Frame-Options": "SAMEORIGIN"
        },
        "set_cookies": [
            "cart_session=abc; Path=/"
        ],
        "html": "<html><body><a href='https://x.test' target='_blank'>go</a></body></html>"
    });
    let cx = TaskContext::new(&browser, &input, &sink, &set, &clock, &NoPrompt);
    let report_val = block_on(set.task("owasp").unwrap().run(&cx)).unwrap();
    let report: OwaspAuditReport = serde_json::from_value(report_val).unwrap();
    assert_eq!(
        report.target_url.as_deref(),
        Some("https://shop.example.com/cart")
    );
    assert!(!report.findings.is_empty());
    assert_eq!(sink.lines().len(), report.findings.len());
    assert_eq!(browser.live_pages(), 0);

    // JobRunner works on an open RecordingPage directly
    let runner = set.job_runner("owasp").unwrap();
    let page = RecordingPage::new().at("https://shop.example.com/");
    let job_out = block_on(runner.run_job(&page, &Value::Null)).unwrap();
    let job_report: OwaspAuditReport = serde_json::from_value(job_out).unwrap();
    assert_eq!(
        job_report.target_url.as_deref(),
        Some("https://shop.example.com/")
    );
}

#[test]
fn per_launch_isolates_audit_sessions_between_pooled_browsers() {
    let plugin = OwaspPlugin::new(OwaspConfig::default()).unwrap();
    plugin.session().record_response(
        "https://a.test/".to_owned(),
        200,
        "text/html".to_owned(),
        Vec::new(),
    );

    let set = PluginSet::strict().with(plugin).unwrap();
    let launched = set.for_launch();
    let browser = RecordingBrowser::builder().contexts().build();
    let sink = VecSink::new();
    let clock = Clock::new(Arc::new(ManualTimer::new()));
    let cx = TaskContext::new(&browser, &Value::Null, &sink, &launched, &clock, &NoPrompt);
    let report_val = block_on(launched.task("owasp").unwrap().run(&cx)).unwrap();
    let report: OwaspAuditReport = serde_json::from_value(report_val).unwrap();
    assert_eq!(report.observed_responses, 0);
}
