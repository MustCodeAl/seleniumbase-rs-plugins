//! The fetcher against the plugin API's fakes: no browser.

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use seleniumbase_rs_plugin::{
    BrowserFamily, BrowserHandle, Capability, CapabilitySet, Clock, Configurable, Descriptor,
    Engine, JobRunner, LaunchContext, NoPrompt, Outcome, PageHandle, PluginError, PluginSet,
    PluginSpec, Registry, RequestDecision, RequestView, ResourceKind, ResponseView, RuleAction,
    TaskContext, async_trait,
};
use seleniumbase_rs_plugin_fetcher::{Fetcher, FetcherConfig};
use seleniumbase_rs_plugin_testing::{
    Call, ManualTimer, RecordingPage, VecSink, block_on, drive_request, drive_response,
};
use serde_json::{Value, json};

fn fetcher(config: Value) -> Fetcher {
    Fetcher::configure(&config).unwrap()
}

fn set_with(fetcher: Fetcher) -> PluginSet {
    PluginSet::strict().with(fetcher).unwrap()
}

fn config_error(config: Value) -> String {
    match Fetcher::configure(&config) {
        Err(PluginError::Config(message)) => message,
        other => panic!("expected a configuration error, got {other:?}"),
    }
}

// ---- options ----------------------------------------------------------------

#[test]
fn no_options_means_the_defaults_and_no_interest() {
    let plugin = Fetcher::configure(&Value::Null).unwrap();
    assert_eq!(*plugin.config(), FetcherConfig::default());
    assert_eq!(plugin.config().max_body_bytes, 2 * 1024 * 1024);
    assert_eq!(plugin.config().max_captures, 500);
    assert!(set_with(plugin).interest().is_empty());
}

#[test]
fn a_misspelt_option_names_the_plugin_and_the_option() {
    assert_eq!(
        config_error(json!({ "captrue": ["*"] })),
        "fetcher: unknown option `captrue`"
    );
}

#[test]
fn a_bad_glob_is_an_error_that_names_it() {
    assert_eq!(
        config_error(json!({ "block": ["*.png", ""] })),
        "fetcher: bad glob `` in `block`"
    );
    assert_eq!(
        config_error(json!({ "capture": ["a b"] })),
        "fetcher: bad glob `a b` in `capture`"
    );
    assert!(config_error(json!({ "header_urls": ["x\ny"] })).contains("bad glob"));
}

#[test]
fn strip_takes_kinds_but_never_documents() {
    assert!(config_error(json!({ "strip": ["document"] })).contains("cannot remove documents"));
    assert!(config_error(json!({ "strip": ["pictures"] })).contains("unknown resource kind"));
    Fetcher::configure(&json!({ "strip": ["Image", " font ", "xhr"] })).unwrap();
}

#[test]
fn headers_that_could_split_or_frame_a_request_are_refused() {
    assert!(config_error(json!({ "headers": { "X-A": "1\r\nX-B: 2" } })).contains("line break"));
    assert!(config_error(json!({ "headers": { "Host": "evil.test" } })).contains("cannot be set"));
    assert!(config_error(json!({ "headers": { "bad name": "1" } })).contains("not a header name"));
    assert!(config_error(json!({ "headers": { "": "1" } })).contains("not a header name"));
}

#[test]
fn limits_are_bounded() {
    assert!(config_error(json!({ "max_body_bytes": 70_000_000 })).contains("max_body_bytes"));
    assert!(config_error(json!({ "max_captures": 100_001 })).contains("max_captures"));
    assert!(config_error(json!({ "capture": ["*"], "max_captures": 0 })).contains("max_captures"));
}

#[test]
fn it_declares_its_category_and_capabilities() {
    let meta = Fetcher::describe();
    for needed in [
        Capability::NetIntercept,
        Capability::NetObserve,
        Capability::Task,
        Capability::PageEvaluate,
        Capability::PageNavigate,
    ] {
        assert!(meta.capabilities.covers(&needed), "{needed}");
    }
    assert!(meta.optional.covers(&Capability::NetBodies));
    assert!(!meta.capabilities.covers(&Capability::NetSensitive));
    assert!(!meta.capabilities.covers(&Capability::CookiesRead));
}

#[test]
fn it_registers_and_runs_on_chromium_over_cdp_only() {
    let registry = Registry::new().with(Descriptor::of::<Fetcher>());
    assert_eq!(registry.names(), ["fetcher"]);
    let set = registry.plugin_set(&[PluginSpec::new("fetcher")]).unwrap();
    let cdp = LaunchContext {
        engine: Engine::Cdp,
        family: BrowserFamily::Chromium,
        headless: true,
        connecting: false,
    };
    set.check(&cdp).unwrap();
    let firefox = LaunchContext {
        family: BrowserFamily::Firefox,
        ..cdp
    };
    assert!(set.check(&firefox).is_err());
}

// ---- rules -------------------------------------------------------------------

#[test]
fn blocking_rules_come_first_and_cover_kinds_and_patterns() {
    let set = set_with(fetcher(json!({
        "strip": ["image", "font"],
        "block": ["*://ads.example.com/*"],
        "headers": { "Accept-Language": "de" },
    })));
    let interest = set.interest();
    assert_eq!(interest.rules.len(), 3);
    assert!(matches!(interest.rules[0].action, RuleAction::Block));
    assert!(matches!(interest.rules[1].action, RuleAction::Block));
    assert!(matches!(
        interest.rules[2].action,
        RuleAction::SetHeaders(_)
    ));
    assert!(interest.observe.is_empty());
    assert!(interest.intercept.is_empty());
}

#[test]
fn strip_and_block_fail_matching_requests_and_name_the_plugin() {
    let set = set_with(fetcher(json!({
        "strip": ["image"],
        "block": ["*://ads.example.com/*"],
    })));
    let image = RequestView::new("https://a.test/logo.png", "GET", ResourceKind::Image);
    let ad = RequestView::new("https://ads.example.com/x.js", "GET", ResourceKind::Script);
    let page = RequestView::new("https://a.test/", "GET", ResourceKind::Document);
    for blocked in [image, ad] {
        match drive_request(&set, blocked) {
            RequestDecision::Block(reason) => assert!(reason.starts_with("fetcher:"), "{reason}"),
            other => panic!("expected a block, got {other:?}"),
        }
    }
    assert_eq!(drive_request(&set, page), RequestDecision::Continue);
}

#[test]
fn headers_go_to_every_request_or_only_to_the_patterns() {
    let everywhere = set_with(fetcher(json!({ "headers": { "X-Test": "1" } })));
    let request = RequestView::new("https://a.test/x", "GET", ResourceKind::Fetch);
    assert_eq!(everywhere.extra_headers(&request)["X-Test"], "1");

    let scoped = set_with(fetcher(json!({
        "headers": { "X-Hint": "x" },
        "header_urls": ["https://api.a.test/*"],
    })));
    let inside = RequestView::new("https://api.a.test/v1", "GET", ResourceKind::Fetch);
    assert_eq!(scoped.extra_headers(&inside)["X-Hint"], "x");
    assert!(scoped.extra_headers(&request).is_empty());
}

// ---- records -----------------------------------------------------------------

fn feed(set: &PluginSet, response: ResponseView<'_>) {
    let errors = drive_response(set, response);
    assert!(errors.is_empty(), "{errors:?}");
}

fn respond(set: &PluginSet, url: &str, mime: &str, body: Option<&[u8]>) {
    let request = RequestView::new(url, "GET", ResourceKind::Fetch)
        .header("Cookie", "session=secret")
        .header("Accept", "application/json");
    let mut response = ResponseView::new(&request, 200, mime);
    if let Some(body) = body {
        response = response.body(body);
    }
    feed(set, response);
}

fn shared(config: Value) -> (Arc<Fetcher>, PluginSet) {
    let plugin = Arc::new(Fetcher::configure(&config).unwrap());
    let set = PluginSet::strict().with_shared(plugin.clone()).unwrap();
    (plugin, set)
}

#[test]
fn matching_responses_are_recorded_with_their_body_as_text() {
    let (plugin, set) = shared(json!({ "capture": ["*/api/*"] }));
    respond(
        &set,
        "https://a.test/api/items",
        "application/json",
        Some(br#"{"a":1}"#),
    );
    respond(&set, "https://a.test/other", "text/html", Some(b"<p>"));
    let captured = plugin.captured();
    assert_eq!(captured.len(), 1);
    let first = &captured[0];
    assert_eq!(first.url, "https://a.test/api/items");
    assert_eq!(first.method, "GET");
    assert_eq!(first.status, 200);
    assert_eq!(first.mime, "application/json");
    assert_eq!(first.text.as_deref(), Some(r#"{"a":1}"#));
    assert_eq!(first.base64, None);
    assert!(!first.truncated);
    assert_eq!(first.outcome, "ok");
    assert!(first.at_ms > 0);
}

#[test]
fn a_binary_body_is_recorded_in_base64_and_take_empties_the_log() {
    let (plugin, set) = shared(json!({ "capture": ["*"] }));
    respond(
        &set,
        "https://a.test/x.bin",
        "application/octet-stream",
        Some(&[0xff, 0xfe, 0x00]),
    );
    let captured = plugin.take_captured();
    assert_eq!(captured[0].base64.as_deref(), Some("//4A"));
    assert_eq!(captured[0].text, None);
    assert_eq!(plugin.captured_len(), 0);
}

#[test]
fn a_body_is_cut_to_max_body_bytes_and_says_so() {
    let (plugin, set) = shared(json!({ "capture": ["*"], "max_body_bytes": 4 }));
    respond(
        &set,
        "https://a.test/big",
        "text/plain",
        Some(b"0123456789"),
    );
    let captured = plugin.captured();
    assert_eq!(captured[0].text.as_deref(), Some("0123"));
    assert!(captured[0].truncated);
}

#[test]
fn max_body_bytes_zero_records_no_body() {
    let (plugin, set) = shared(json!({ "capture": ["*"], "max_body_bytes": 0 }));
    respond(&set, "https://a.test/x", "text/plain", Some(b"secret body"));
    let captured = plugin.captured();
    assert_eq!(captured[0].text, None);
    assert_eq!(captured[0].base64, None);
}

#[test]
fn the_log_never_holds_more_than_max_captures_and_drops_the_oldest() {
    let (plugin, set) = shared(json!({ "capture": ["*"], "max_captures": 3 }));
    for n in 0..10 {
        respond(&set, &format!("https://a.test/{n}"), "text/plain", None);
        assert!(plugin.captured_len() <= 3);
    }
    let urls: Vec<_> = plugin.captured().into_iter().map(|c| c.url).collect();
    assert_eq!(
        urls,
        ["https://a.test/7", "https://a.test/8", "https://a.test/9"]
    );
    assert_eq!(plugin.dropped(), 7);
}

#[test]
fn cookies_and_authorization_are_redacted_in_a_record() {
    let (plugin, set) = shared(json!({ "capture": ["*"] }));
    let request = RequestView::new("https://a.test/me", "GET", ResourceKind::Fetch)
        .header("Cookie", "session=secret")
        .header("Authorization", "Bearer t0ken")
        .header("Set-Cookie", "a=b")
        .header("Accept", "text/html");
    feed(&set, ResponseView::new(&request, 200, "text/html"));
    let headers = &plugin.captured()[0].headers;
    for name in ["Cookie", "Authorization", "Set-Cookie"] {
        assert_eq!(headers[name], "[redacted]", "{name}");
    }
    assert_eq!(headers["Accept"], "text/html");
    let dump = serde_json::to_string(&plugin.captured()).unwrap();
    assert!(
        !dump.contains("secret") && !dump.contains("t0ken"),
        "{dump}"
    );
}

#[test]
fn a_failed_or_blocked_request_is_recorded_with_its_outcome() {
    let (plugin, set) = shared(json!({ "capture": ["*"] }));
    let request = RequestView::new("https://a.test/x", "GET", ResourceKind::Fetch);
    feed(
        &set,
        ResponseView::new(&request, 0, "").outcome(Outcome::Failed),
    );
    feed(
        &set,
        ResponseView::new(&request, 0, "").outcome(Outcome::Blocked {
            by: "shield".into(),
        }),
    );
    let outcomes: Vec<_> = plugin.captured().iter().map(|c| c.outcome).collect();
    assert_eq!(outcomes, ["failed", "blocked"]);
}

#[test]
fn without_the_bodies_capability_a_record_has_no_body() {
    let plugin = Arc::new(fetcher(json!({ "capture": ["*"] })));
    let mut grants = CapabilitySet::new();
    grants.insert(Capability::NetObserve);
    let set = PluginSet::strict()
        .with_grants_shared(plugin.clone(), grants)
        .unwrap();
    respond(&set, "https://a.test/x", "text/plain", Some(b"hello"));
    assert_eq!(plugin.captured()[0].text, None);
    assert_eq!(plugin.captured()[0].status, 200);
}

// ---- the job runner -----------------------------------------------------------

fn page_reply() -> Value {
    json!({
        "url": "https://a.test/data",
        "status": 200,
        "mime": "application/json",
        "text": "{\"ok\":true}",
        "truncated": false,
        "extra": "dropped",
    })
}

fn scripts(page: &RecordingPage) -> Vec<String> {
    page.calls()
        .into_iter()
        .filter_map(|call| match call {
            Call::Evaluate(script) => Some(script),
            _ => None,
        })
        .collect()
}

#[test]
fn a_job_fetches_in_the_page_and_returns_status_mime_and_text() {
    let page = RecordingPage::new().evaluating("fetch(", page_reply());
    let plugin = fetcher(json!({}));
    let out = block_on(plugin.run_job(&page, &json!({ "url": "https://a.test/data" }))).unwrap();
    assert_eq!(
        out,
        json!({
            "url": "https://a.test/data",
            "status": 200,
            "mime": "application/json",
            "text": "{\"ok\":true}",
            "truncated": false,
        })
    );
    let scripts = scripts(&page);
    assert_eq!(scripts.len(), 1);
    assert!(
        scripts[0].contains("credentials: \"include\""),
        "{}",
        scripts[0]
    );
    assert!(
        scripts[0].contains("\"max_bytes\":2097152"),
        "{}",
        scripts[0]
    );
}

#[test]
fn the_url_travels_as_a_json_literal_and_cannot_leave_its_string() {
    let page = RecordingPage::new().evaluating("fetch(", page_reply());
    let url = "https://a.test/\"));alert(1);//?q=`${x}`</script>";
    block_on(fetcher(json!({})).run_job(&page, &json!({ "url": url }))).unwrap();
    let script = &scripts(&page)[0];
    let literal = serde_json::to_string(url).unwrap();
    assert!(script.contains(&literal), "{script}");
    assert!(
        !script.replace(&literal, "").contains("alert(1);//?q"),
        "an unescaped copy of the URL is in the script"
    );
}

#[test]
fn a_job_can_ask_for_less_than_max_body_bytes_never_more() {
    let page = RecordingPage::new().evaluating("fetch(", page_reply());
    let plugin = fetcher(json!({ "max_body_bytes": 1000 }));
    block_on(plugin.run_job(&page, &json!({ "url": "https://a.test/", "max_bytes": 10 }))).unwrap();
    block_on(plugin.run_job(
        &page,
        &json!({ "url": "https://a.test/", "max_bytes": 99999 }),
    ))
    .unwrap();
    let scripts = scripts(&page);
    assert!(scripts[0].contains("\"max_bytes\":10,") || scripts[0].contains("\"max_bytes\":10}"));
    assert!(scripts[1].contains("\"max_bytes\":1000"), "{}", scripts[1]);
}

#[test]
fn a_job_with_a_bad_url_or_field_fails_before_the_page_is_touched() {
    let page = RecordingPage::new().evaluating("fetch(", page_reply());
    let plugin = fetcher(json!({}));
    for job in [
        json!({ "url": "file:///etc/passwd" }),
        json!({ "url": "javascript:alert(1)" }),
        json!({ "url": "https://user:pw@a.test/" }),
        json!({}),
        json!({ "url": "https://a.test/", "cookies": true }),
        json!("https://a.test/"),
    ] {
        let error = block_on(plugin.run_job(&page, &job)).unwrap_err();
        assert!(matches!(error, PluginError::Config(_)), "{job}: {error}");
    }
    assert!(page.calls().is_empty(), "{:?}", page.calls());
}

#[test]
fn an_odd_reply_from_the_page_is_an_error_not_a_panic() {
    let page = RecordingPage::new().evaluating("fetch(", json!("nonsense"));
    let error = block_on(fetcher(json!({})).run_job(&page, &json!({ "url": "https://a.test/" })))
        .unwrap_err();
    assert!(error.to_string().contains("unexpected reply"), "{error}");
}

#[test]
fn a_page_that_fails_to_evaluate_fails_the_job() {
    let page = RecordingPage::new().failing("evaluate");
    let result = block_on(fetcher(json!({})).run_job(&page, &json!({ "url": "https://a.test/" })));
    assert!(result.is_err());
}

// ---- the task -----------------------------------------------------------------

/// A browser that hands out one prepared tab and counts how often it is asked.
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

fn answer(url: &str, text: &str) -> Value {
    json!({ "url": url, "status": 200, "mime": "text/plain", "text": text, "truncated": false })
}

fn task_page() -> RecordingPage {
    RecordingPage::new()
        .evaluating("https://a.test/1", answer("https://a.test/1", "one"))
        .evaluating("https://a.test/2", answer("https://a.test/2", "two"))
        .evaluating(
            "https://b.test:8443/3",
            answer("https://b.test:8443/3", "three"),
        )
}

fn navigations(page: &RecordingPage) -> Vec<String> {
    page.calls()
        .into_iter()
        .filter_map(|call| match call {
            Call::Navigate(url) => Some(url),
            _ => None,
        })
        .collect()
}

#[test]
fn the_task_fetches_each_url_in_one_tab_and_goes_to_a_site_once() {
    let set = set_with(fetcher(json!({})));
    let browser = OneTab::new(task_page());
    let sink = VecSink::new();
    let clock = Clock::new(Arc::new(ManualTimer::new()));
    let input = json!({ "urls": [
        "https://a.test/1", "https://a.test/2", "https://b.test:8443/3", "ftp://c.test/4",
        "https://a.test/9",
    ]});
    let cx = TaskContext::new(&browser, &input, &sink, &set, &clock, &NoPrompt);
    let summary = block_on(set.task("fetcher").unwrap().run(&cx)).unwrap();
    assert_eq!(
        summary,
        json!({ "total": 5, "ok": 3, "failed": 2, "captured": 0 })
    );

    let lines = sink.lines();
    assert_eq!(lines.len(), 5);
    assert_eq!(lines[0]["index"], 0);
    assert_eq!(lines[0]["url"], "https://a.test/1");
    assert_eq!(lines[0]["status"], 200);
    assert_eq!(lines[0]["text"], "one");
    assert_eq!(lines[2]["text"], "three");
    assert!(
        lines[3]["error"]
            .as_str()
            .unwrap()
            .contains("not an http or https address")
    );
    assert!(lines[3].get("status").is_none());
    // The page had no answer for the last URL: a failure, and the task went on.
    assert!(
        lines[4]["error"]
            .as_str()
            .unwrap()
            .contains("unexpected reply"),
        "{}",
        lines[4]
    );

    assert_eq!(
        browser.opened.load(Ordering::SeqCst),
        1,
        "one tab for the whole task"
    );
    // a.test once, then b.test; the return to a.test is a second visit.
    assert_eq!(
        navigations(&browser.page),
        ["https://a.test/", "https://b.test:8443/", "https://a.test/"]
    );
    assert!(
        browser.page.calls().contains(&Call::Close),
        "the tab is closed"
    );
}

#[test]
fn warm_up_false_fetches_from_wherever_the_tab_is() {
    let set = set_with(fetcher(json!({})));
    let browser = OneTab::new(task_page());
    let sink = VecSink::new();
    let clock = Clock::new(Arc::new(ManualTimer::new()));
    let input = json!({ "urls": ["https://a.test/1"], "warm_up": false });
    let cx = TaskContext::new(&browser, &input, &sink, &set, &clock, &NoPrompt);
    block_on(set.task("fetcher").unwrap().run(&cx)).unwrap();
    assert!(navigations(&browser.page).is_empty());
    assert_eq!(sink.lines()[0]["text"], "one");
}

#[test]
fn the_task_input_is_checked_before_a_tab_is_opened() {
    let set = set_with(fetcher(json!({})));
    let many: Vec<String> = (0..10_001).map(|n| format!("https://a.test/{n}")).collect();
    for input in [
        json!({}),
        json!({ "urls": [] }),
        json!({ "urls": ["https://a.test/"], "delay_ms": 3_600_000 }),
        json!({ "urls": ["https://a.test/"], "proxy": "x" }),
        json!({ "urls": "https://a.test/" }),
        json!({ "urls": many }),
    ] {
        let browser = OneTab::new(RecordingPage::new());
        let sink = VecSink::new();
        let clock = Clock::new(Arc::new(ManualTimer::new()));
        let cx = TaskContext::new(&browser, &input, &sink, &set, &clock, &NoPrompt);
        let result = block_on(set.task("fetcher").unwrap().run(&cx));
        assert!(
            matches!(result, Err(PluginError::Config(_))),
            "{:?}: {result:?}",
            input.to_string().chars().take(60).collect::<String>()
        );
        assert_eq!(browser.opened.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn the_task_stops_when_a_capability_is_missing_and_still_closes_its_tab() {
    // The plugin is in the set without `page.navigate`.
    let mut grants = CapabilitySet::new();
    grants.insert(Capability::Task);
    grants.insert(Capability::PageEvaluate);
    let set = PluginSet::strict()
        .with_grants(fetcher(json!({})), grants)
        .unwrap();
    let browser = OneTab::new(task_page());
    let sink = VecSink::new();
    let clock = Clock::new(Arc::new(ManualTimer::new()));
    let input = json!({ "urls": ["https://a.test/1", "https://a.test/2"] });
    let cx = TaskContext::new(&browser, &input, &sink, &set, &clock, &NoPrompt);
    let error = block_on(set.task("fetcher").unwrap().run(&cx)).unwrap_err();
    assert!(
        matches!(error, PluginError::Capability { .. })
            && error.to_string().contains("page.navigate"),
        "{error}"
    );
    assert!(sink.lines().is_empty(), "{:?}", sink.lines());
    assert!(navigations(&browser.page).is_empty());
    assert!(browser.page.calls().contains(&Call::Close));
}

#[test]
fn the_task_pauses_between_fetches_by_the_clock() {
    let set = set_with(fetcher(json!({})));
    let browser = OneTab::new(task_page());
    let sink = VecSink::new();
    let timer = Arc::new(ManualTimer::new());
    let clock = Clock::new(timer.clone());
    let input = json!({ "urls": ["https://a.test/1", "https://a.test/2"], "delay_ms": 500, "warm_up": false });
    let cx = TaskContext::new(&browser, &input, &sink, &set, &clock, &NoPrompt);
    let mut future = Box::pin(set.task("fetcher").unwrap().run(&cx));
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    // It records the first line, then waits for the timer.
    assert!(future.as_mut().poll(&mut context).is_pending());
    assert_eq!(sink.lines().len(), 1);
    timer.advance(Duration::from_millis(500));
    assert!(future.as_mut().poll(&mut context).is_ready());
    assert_eq!(sink.lines().len(), 2);
}

#[test]
fn it_offers_a_task_and_a_job_runner_by_name() {
    let set = set_with(fetcher(json!({})));
    assert_eq!(set.task_names(), ["fetcher"]);
    assert!(set.job_runner("fetcher").is_ok());
    assert!(set.job_runner("nothing").is_err());
}

#[test]
fn a_future_that_is_not_polled_does_nothing() {
    // `Task::run` is lazy: dropping the future before the first poll opens no tab.
    let set = set_with(fetcher(json!({})));
    let browser = OneTab::new(task_page());
    let sink = VecSink::new();
    let clock = Clock::new(Arc::new(ManualTimer::new()));
    let input = json!({ "urls": ["https://a.test/1"] });
    let cx = TaskContext::new(&browser, &input, &sink, &set, &clock, &NoPrompt);
    let future = set.task("fetcher").unwrap().run(&cx);
    drop(future);
    assert_eq!(browser.opened.load(Ordering::SeqCst), 0);
}
