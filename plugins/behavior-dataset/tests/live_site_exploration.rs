//! Live-site DOM discovery, CDP Input.* dispatch, WebDriver JS fallback,
//! multi-page link traversal, safety filtering, and Task telemetry tests.
#![cfg(feature = "plugin")]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use seleniumbase_rs_plugin::{
    BrowserFamily, BrowserHandle, Capability, CapabilitySet, Clock, Engine, NoPrompt, PageHandle,
    PluginError, PluginSet, TaskContext, async_trait,
};
use seleniumbase_rs_plugin_behavior_dataset::{
    BehaviorDatasetPlugin, DatasetConfig, DatasetSample, ElementRole, EventKind, NAME, PersonaKind,
    SiteExplorer, reconstruct_field_texts,
};
use seleniumbase_rs_plugin_testing::{Call, ManualTimer, RecordingPage, VecSink, block_on};
use serde_json::{Value, json};

struct SingleTabBrowser {
    page: RecordingPage,
    closed: AtomicBool,
}

impl SingleTabBrowser {
    fn new(page: RecordingPage) -> Self {
        Self {
            page,
            closed: AtomicBool::new(false),
        }
    }
}

#[async_trait]
impl BrowserHandle for SingleTabBrowser {
    fn engine(&self) -> Engine {
        self.page.engine()
    }

    fn family(&self) -> BrowserFamily {
        BrowserFamily::Chromium
    }

    async fn new_page<'a>(
        &'a self,
        _url: Option<&str>,
    ) -> seleniumbase_rs_plugin::Result<Box<dyn PageHandle + 'a>> {
        Ok(Box::new(TrackedPage {
            inner: self.page.clone(),
            closed: &self.closed,
        }))
    }

    async fn send(&self, _method: &str, _params: Value) -> seleniumbase_rs_plugin::Result<Value> {
        Ok(Value::Null)
    }
}

struct TrackedPage<'a> {
    inner: RecordingPage,
    closed: &'a AtomicBool,
}

#[async_trait]
impl PageHandle for TrackedPage<'_> {
    fn engine(&self) -> Engine {
        self.inner.engine()
    }

    async fn send(&self, method: &str, params: Value) -> seleniumbase_rs_plugin::Result<Value> {
        self.inner.send(method, params).await
    }

    async fn add_init_script(&self, source: &str) -> seleniumbase_rs_plugin::Result<()> {
        self.inner.add_init_script(source).await
    }

    async fn evaluate(&self, expression: &str) -> seleniumbase_rs_plugin::Result<Value> {
        self.inner.evaluate(expression).await
    }

    async fn url(&self) -> seleniumbase_rs_plugin::Result<String> {
        self.inner.url().await
    }

    async fn navigate(&self, url: &str) -> seleniumbase_rs_plugin::Result<()> {
        self.inner.navigate(url).await
    }

    async fn close(&self) -> seleniumbase_rs_plugin::Result<()> {
        self.closed.store(true, Ordering::SeqCst);
        self.inner.close().await
    }
}

fn home_dom_snapshot() -> Value {
    json!({
        "marker": "__sbrs_discover_site_elements__",
        "url": "https://docs.example.com/",
        "title": "Docs Home",
        "viewportWidth": 1440.0,
        "viewportHeight": 900.0,
        "scrollHeight": 2200.0,
        "elements": [
            {
                "selector": "#intro-copy",
                "role": "readable_block",
                "tag": "p",
                "x": 120.0,
                "y": 90.0,
                "width": 680.0,
                "height": 72.0,
                "sameOrigin": false,
                "wordCount": 28,
                "label": "Welcome to the developer documentation portal for browser automation."
            },
            {
                "selector": "#search-docs",
                "role": "text_input",
                "tag": "input",
                "inputType": "search",
                "x": 180.0,
                "y": 42.0,
                "width": 320.0,
                "height": 38.0,
                "sameOrigin": false,
                "wordCount": 0,
                "label": "Search documentation"
            },
            {
                "selector": "#login-password",
                "role": "text_input",
                "tag": "input",
                "inputType": "password",
                "x": 920.0,
                "y": 42.0,
                "width": 180.0,
                "height": 36.0,
                "sameOrigin": false,
                "wordCount": 0,
                "label": "Password"
            },
            {
                "selector": "#delete-workspace",
                "role": "button",
                "tag": "button",
                "x": 1120.0,
                "y": 42.0,
                "width": 140.0,
                "height": 36.0,
                "sameOrigin": false,
                "wordCount": 2,
                "label": "Delete workspace"
            },
            {
                "selector": "#theme-toggle",
                "role": "button",
                "tag": "button",
                "x": 860.0,
                "y": 42.0,
                "width": 96.0,
                "height": 36.0,
                "sameOrigin": false,
                "wordCount": 2,
                "label": "Toggle theme"
            },
            {
                "selector": "a[data-testid=\"external-blog\"]",
                "role": "link",
                "tag": "a",
                "x": 180.0,
                "y": 300.0,
                "width": 160.0,
                "height": 28.0,
                "href": "https://external.other.org/post",
                "sameOrigin": false,
                "wordCount": 2,
                "label": "External blog"
            },
            {
                "selector": "#nav-pricing",
                "role": "link",
                "tag": "a",
                "x": 380.0,
                "y": 44.0,
                "width": 110.0,
                "height": 32.0,
                "href": "https://docs.example.com/pricing",
                "sameOrigin": true,
                "wordCount": 1,
                "label": "Pricing"
            }
        ]
    })
}

fn pricing_dom_snapshot() -> Value {
    json!({
        "marker": "__sbrs_discover_site_elements__",
        "url": "https://docs.example.com/pricing",
        "title": "Pricing Plans",
        "viewportWidth": 1440.0,
        "viewportHeight": 900.0,
        "scrollHeight": 1600.0,
        "elements": [
            {
                "selector": "#pricing-overview",
                "role": "readable_block",
                "tag": "article",
                "x": 140.0,
                "y": 120.0,
                "width": 720.0,
                "height": 110.0,
                "sameOrigin": false,
                "wordCount": 36,
                "label": "Compare developer and team tiers with transparent usage quotas."
            },
            {
                "selector": "#billing-tab",
                "role": "interactive_control",
                "tag": "div",
                "x": 260.0,
                "y": 280.0,
                "width": 150.0,
                "height": 40.0,
                "sameOrigin": false,
                "wordCount": 2,
                "label": "Annual billing"
            }
        ]
    })
}

#[test]
fn parse_discovery_filters_unsafe_password_and_destructive_controls() {
    let parsed = SiteExplorer::parse_discovery("https://docs.example.com/", &home_dom_snapshot());
    let selectors: Vec<&str> = parsed.iter().map(|e| e.selector.as_str()).collect();

    assert!(selectors.contains(&"#intro-copy"));
    assert!(selectors.contains(&"#search-docs"));
    assert!(selectors.contains(&"#theme-toggle"));
    assert!(selectors.contains(&"#nav-pricing"));
    assert!(!selectors.contains(&"#login-password"));
    assert!(!selectors.contains(&"#delete-workspace"));
}

#[test]
fn explore_page_dispatches_cdp_mouse_wheel_key_events_and_traverses_same_origin_links() {
    let page = RecordingPage::new()
        .at("https://docs.example.com/")
        .evaluating(
            "url=https://docs.example.com/pricing",
            pricing_dom_snapshot(),
        )
        .evaluating("url=https://docs.example.com/", home_dom_snapshot());

    let config = DatasetConfig {
        url: Some("https://docs.example.com/".to_owned()),
        base_seed: 2026,
        personas: vec![PersonaKind::AverageDesktop],
        max_steps: 10,
        max_pages: 2,
        same_origin_only: true,
        dispatch_live_inputs: true,
        typing_samples: vec!["getting started".to_owned()],
        ..DatasetConfig::default()
    };
    let plugin = BehaviorDatasetPlugin::new(config.clone()).unwrap();

    let report = block_on(plugin.explore_page(&page, &config)).unwrap();

    assert_eq!(report.start_url, "https://docs.example.com/");
    assert_eq!(
        report.visited_urls,
        vec![
            "https://docs.example.com/".to_owned(),
            "https://docs.example.com/pricing".to_owned()
        ]
    );
    assert_eq!(report.visits.len(), 2);
    assert!(report.cdp_input_dispatched);
    assert!(!report.steps.is_empty());
    assert!(report.steps.len() <= 10);

    // Verify unsafe selectors were never targeted, while benign search input and pricing link were.
    assert!(report.target_selectors.contains(&"#search-docs".to_owned()));
    assert!(report.target_selectors.contains(&"#nav-pricing".to_owned()));
    assert!(
        !report
            .target_selectors
            .contains(&"#login-password".to_owned())
    );
    assert!(
        !report
            .target_selectors
            .contains(&"#delete-workspace".to_owned())
    );
    assert!(
        !report
            .visited_urls
            .contains(&"https://external.other.org/post".to_owned())
    );

    // Verify reconstructed typed text matches the configured benign sample even if typos occurred.
    assert_eq!(
        reconstruct_field_texts(&report.sample.events),
        vec!["getting started".to_owned()]
    );
    assert!(report.sample.features.pointer_event_count > 4);
    assert!(report.sample.features.key_event_count >= "getting started".len());
    assert!(report.sample.features.scroll_event_count > 0);
    assert!(report.sample.features.tremor_high_freq_energy > 0.0);
    assert_eq!(
        report.sample.page_url.as_deref(),
        Some("https://docs.example.com/")
    );
    assert_eq!(report.sample.action_path, report.action_path);
    assert_eq!(report.sample.target_selectors, report.target_selectors);

    // Verify real CDP Input.dispatchMouseEvent (move, press, release, wheel) and Input.dispatchKeyEvent calls.
    let calls = page.calls();
    let mut saw_mouse_move = false;
    let mut saw_mouse_press = false;
    let mut saw_mouse_wheel = false;
    let mut saw_key_down = false;
    let mut saw_navigate = false;

    for call in &calls {
        match call {
            Call::Send(method, params) if method == "Input.dispatchMouseEvent" => {
                match params.get("type").and_then(Value::as_str) {
                    Some("mouseMoved") => saw_mouse_move = true,
                    Some("mousePressed") => saw_mouse_press = true,
                    Some("mouseWheel") => saw_mouse_wheel = true,
                    _ => {}
                }
            }
            Call::Send(method, params) if method == "Input.dispatchKeyEvent" => {
                if params.get("type").and_then(Value::as_str) == Some("keyDown") {
                    saw_key_down = true;
                }
            }
            Call::Navigate(dest) if dest == "https://docs.example.com/pricing" => {
                saw_navigate = true;
            }
            _ => {}
        }
    }

    assert!(saw_mouse_move, "expected CDP mouseMoved events");
    assert!(saw_mouse_press, "expected CDP mousePressed events");
    assert!(saw_mouse_wheel, "expected CDP mouseWheel events");
    assert!(saw_key_down, "expected CDP keyDown events");
    assert!(saw_navigate, "expected same-origin link navigation");
}

#[test]
fn explore_page_falls_back_cleanly_on_webdriver_non_cdp_pages() {
    let page = RecordingPage::on(Engine::WebDriver)
        .at("https://docs.example.com/")
        .evaluating("__sbrs_discover_site_elements__", home_dom_snapshot());

    let config = DatasetConfig {
        url: Some("https://docs.example.com/".to_owned()),
        base_seed: 99,
        max_steps: 5,
        max_pages: 1,
        dispatch_live_inputs: true,
        typing_samples: vec!["pricing".to_owned()],
        ..DatasetConfig::default()
    };
    let explorer = SiteExplorer::new(config).unwrap();
    let report = block_on(explorer.explore_page(&page)).unwrap();

    assert!(!report.cdp_input_dispatched);
    assert!(
        report
            .sample
            .events
            .iter()
            .any(|e| e.kind == EventKind::KeyPress)
    );
    assert!(
        report
            .steps
            .iter()
            .any(|s| s.target_role == Some(ElementRole::TextInput))
    );

    // No CDP Send calls should be emitted on a WebDriver page; JS evaluate fallbacks are used instead.
    assert!(
        !page.calls().iter().any(|c| matches!(c, Call::Send(_, _))),
        "unexpected CDP calls on WebDriver handle: {:?}",
        page.calls()
    );
}

#[test]
fn live_task_opens_tab_navigates_records_telemetry_to_sink_and_closes_tab() {
    let page = RecordingPage::new()
        .at("about:blank")
        .evaluating(
            "url=https://docs.example.com/pricing",
            pricing_dom_snapshot(),
        )
        .evaluating("url=https://docs.example.com/", home_dom_snapshot());
    let browser = SingleTabBrowser::new(page);

    let plugin = BehaviorDatasetPlugin::default();
    let set = PluginSet::strict().with(plugin).unwrap();

    let sink = VecSink::new();
    let clock = Clock::new(Arc::new(ManualTimer::new()));
    let input = json!({
        "url": "https://docs.example.com/",
        "base_seed": 77,
        "personas": ["careful_reader"],
        "max_steps": 8,
        "max_pages": 2,
        "include_baseline_negatives": true,
        "typing_samples": ["documentation"],
        "export_format": "csv_features",
        "include_export": true
    });
    let cx = TaskContext::new(&browser, &input, &sink, &set, &clock, &NoPrompt);

    let summary = block_on(set.task(NAME).unwrap().run(&cx)).unwrap();
    assert!(browser.closed.load(Ordering::SeqCst));

    assert_eq!(summary["mode"], "live");
    assert_eq!(summary["total_samples"], 2);
    assert_eq!(summary["human_samples"], 1);
    assert_eq!(summary["baseline_samples"], 1);
    assert_eq!(
        summary["site_journey"]["start_url"],
        "https://docs.example.com/"
    );
    assert_eq!(summary["site_journey"]["pages_visited"], 2);
    assert_eq!(summary["site_journey"]["cdp_input_dispatched"], true);
    assert!(summary["exported"].as_str().unwrap().lines().count() == 3);

    let lines = sink.lines();
    assert_eq!(lines.len(), 2);
    let live_sample: DatasetSample = serde_json::from_value(lines[0].clone()).unwrap();
    assert!(live_sample.summary.is_human);
    assert_eq!(
        live_sample.page_url.as_deref(),
        Some("https://docs.example.com/")
    );
    assert!(!live_sample.action_path.is_empty());
    assert!(!live_sample.target_selectors.is_empty());

    // Capability enforcement: withholding cdp:Input rejects live CDP dispatch while still closing the tab.
    let page2 = RecordingPage::new()
        .at("about:blank")
        .evaluating("__sbrs_discover_site_elements__", home_dom_snapshot());
    let browser2 = SingleTabBrowser::new(page2);
    let mut limited_grants = CapabilitySet::new();
    limited_grants.insert(Capability::Task);
    limited_grants.insert(Capability::PageEvaluate);
    limited_grants.insert(Capability::PageNavigate);
    let restricted_set = PluginSet::strict()
        .with_grants(BehaviorDatasetPlugin::default(), limited_grants)
        .unwrap();
    let sink2 = VecSink::new();
    let input2 = json!({ "url": "https://docs.example.com/" });
    let cx2 = TaskContext::new(
        &browser2,
        &input2,
        &sink2,
        &restricted_set,
        &clock,
        &NoPrompt,
    );
    let err = block_on(restricted_set.task(NAME).unwrap().run(&cx2)).unwrap_err();
    assert!(matches!(err, PluginError::Capability { .. }), "{err:?}");
    assert!(browser2.closed.load(Ordering::SeqCst));
}
