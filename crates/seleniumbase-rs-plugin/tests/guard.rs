//! A plugin cannot take the host down: its panics are caught, its hooks have
//! time limits, and the handles it gets refuse what the host owns.

use std::future::Future;
use std::pin::{Pin, pin};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use seleniumbase_rs_plugin::{
    BrowserHandle, Budgets, Capability, Category, LaunchSettings, Metadata, NavOutcome, Navigation,
    NetworkInterest, PageHandle, Plugin, PluginError, PluginSet, RequestDecision, RequestFilter,
    RequestView, ResourceKind, Result, TestInfo, TestOutcome, TestVerdict, async_trait,
};
use seleniumbase_rs_plugin::{
    ContextHandle, ContextSettings, HostScope, PathScope, RawKind, Seals, cdp_policy,
};
use seleniumbase_rs_plugin_testing::Call;
use seleniumbase_rs_plugin_testing::{ManualTimer, RecordingBrowser, RecordingPage, block_on};
use serde_json::{Value, json};

type Log = Arc<Mutex<Vec<String>>>;

/// What a hook of a [`Probe`] does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    /// Returns at once.
    Quiet,
    /// Panics.
    Panic,
    /// Never finishes.
    Hang,
}

/// A plugin whose hooks all behave the same way.
struct Probe {
    name: &'static str,
    mode: Mode,
    caps: Vec<Capability>,
    budgets: Budgets,
    verdict: Option<&'static str>,
    log: Log,
}

impl Probe {
    fn new(name: &'static str, mode: Mode, log: &Log) -> Self {
        Self {
            name,
            mode,
            caps: Vec::new(),
            budgets: Budgets::default(),
            verdict: None,
            log: Arc::clone(log),
        }
    }

    fn with(mut self, capability: Capability) -> Self {
        self.caps.push(capability);
        self
    }

    fn budgets(mut self, budgets: Budgets) -> Self {
        self.budgets = budgets;
        self
    }

    fn failing_tests(mut self, message: &'static str) -> Self {
        self.verdict = Some(message);
        self
    }

    async fn act(&self, hook: &str) {
        self.log
            .lock()
            .unwrap()
            .push(format!("{}:{hook}", self.name));
        match self.mode {
            Mode::Quiet => {}
            Mode::Panic => panic!("{hook} of {} panics (the test expects it)", self.name),
            Mode::Hang => std::future::pending::<()>().await,
        }
    }
}

#[async_trait]
impl Plugin for Probe {
    fn name(&self) -> &str {
        self.name
    }

    fn metadata(&self) -> Metadata {
        Metadata::new(Category::Core)
            .capabilities(self.caps.clone())
            .budget(self.budgets)
    }

    fn network(&self) -> NetworkInterest {
        NetworkInterest::none().intercept(RequestFilter::any())
    }

    async fn before_launch(&self, _launch: &mut LaunchSettings) -> Result<()> {
        self.act("before_launch").await;
        Ok(())
    }

    async fn on_browser(&self, _browser: &dyn BrowserHandle) -> Result<()> {
        self.act("on_browser").await;
        Ok(())
    }

    async fn on_page_created(&self, _page: &dyn PageHandle) -> Result<()> {
        self.act("on_page_created").await;
        Ok(())
    }

    async fn before_navigate(
        &self,
        _page: &dyn PageHandle,
        _navigation: &Navigation,
    ) -> Result<seleniumbase_rs_plugin::NavDecision> {
        self.act("before_navigate").await;
        Ok(seleniumbase_rs_plugin::NavDecision::Continue)
    }

    async fn after_navigate(&self, _page: &dyn PageHandle, _outcome: &NavOutcome) -> Result<()> {
        self.act("after_navigate").await;
        Ok(())
    }

    async fn on_request(&self, _request: &RequestView) -> Result<RequestDecision> {
        self.act("on_request").await;
        Ok(RequestDecision::Continue)
    }

    async fn on_test_end(
        &self,
        _test: &TestInfo,
        _outcome: &TestOutcome,
        _page: Option<&dyn PageHandle>,
    ) -> Result<TestVerdict> {
        self.act("on_test_end").await;
        Ok(self.verdict.map_or(TestVerdict::Keep, |message| {
            TestVerdict::Fail(message.into())
        }))
    }

    async fn before_close(&self, _browser: &dyn BrowserHandle) -> Result<()> {
        self.act("before_close").await;
        Ok(())
    }

    async fn on_close(&self) -> Result<()> {
        self.act("on_close").await;
        Ok(())
    }
}

fn log() -> Log {
    Log::default()
}

fn entries(log: &Log) -> Vec<String> {
    log.lock().unwrap().clone()
}

fn request() -> RequestView {
    RequestView::new("https://a.test/", "GET", ResourceKind::Document)
}

/// Polls once with a waker that does nothing, so a test can move a manual
/// timer between polls.
fn poll<F: Future>(future: &mut Pin<&mut F>) -> Poll<F::Output> {
    future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
}

fn set_of(probes: impl IntoIterator<Item = Probe>) -> PluginSet {
    probes
        .into_iter()
        .fold(PluginSet::new(), |set, probe| set.with(probe).unwrap())
}

// Panics.

#[test]
fn a_panic_in_a_hook_becomes_panicked_and_names_the_plugin_and_the_hook() {
    let log = log();
    let set = set_of([Probe::new("boomer", Mode::Panic, &log)]);
    let page = RecordingPage::new();

    let error = block_on(set.on_page_created(&page)).unwrap_err();

    assert!(
        matches!(&error, PluginError::Panicked { plugin, hook }
            if plugin == "boomer" && *hook == "on_page_created"),
        "{error:?}"
    );
    assert_eq!(
        error.to_string(),
        "plugin `boomer` panicked in `on_page_created`"
    );
}

#[test]
fn a_panic_stops_the_launch_hooks_like_any_error() {
    let log = log();
    let set = set_of([
        Probe::new("boomer", Mode::Panic, &log),
        Probe::new("after", Mode::Quiet, &log),
    ]);

    let launch = block_on(set.before_launch(&mut LaunchSettings::default())).unwrap_err();
    let browser = block_on(set.on_browser(&RecordingBrowser::new())).unwrap_err();

    assert!(matches!(
        launch,
        PluginError::Panicked {
            hook: "before_launch",
            ..
        }
    ));
    assert!(matches!(
        browser,
        PluginError::Panicked {
            hook: "on_browser",
            ..
        }
    ));
    assert_eq!(
        entries(&log),
        ["boomer:before_launch", "boomer:on_browser"],
        "the plugin after the panic did not run"
    );
}

#[test]
fn a_panic_in_before_navigate_cancels_the_navigation() {
    let log = log();
    let set = set_of([Probe::new("boomer", Mode::Panic, &log)]);

    let error = block_on(set.before_navigate(
        &RecordingPage::new(),
        &Navigation::program("https://a.test/"),
    ))
    .unwrap_err();

    assert!(matches!(
        error,
        PluginError::Panicked {
            hook: "before_navigate",
            ..
        }
    ));
}

#[test]
fn a_panic_in_on_request_blocks_the_request() {
    let log = log();
    let set = set_of([Probe::new("boomer", Mode::Panic, &log).with(Capability::NetIntercept)]);

    let decision = block_on(set.on_request(&request()));

    let RequestDecision::Block(reason) = decision else {
        panic!("a request must not pass a plugin that panicked: {decision:?}");
    };
    assert!(
        reason.contains("boomer") && reason.contains("panicked"),
        "{reason}"
    );
}

#[test]
fn hooks_whose_errors_are_collected_survive_a_panic_and_run_the_others() {
    let log = log();
    let set = set_of([
        Probe::new("boomer", Mode::Panic, &log),
        Probe::new("steady", Mode::Quiet, &log),
    ]);
    let browser = RecordingBrowser::new();

    let closing = block_on(set.before_close(&browser));
    let closed = block_on(set.on_close());

    assert!(
        matches!(closing.as_slice(), [PluginError::Panicked { plugin, hook: "before_close" }] if plugin == "boomer")
    );
    assert!(
        matches!(closed.as_slice(), [PluginError::Panicked { plugin, hook: "on_close" }] if plugin == "boomer")
    );
    assert_eq!(
        entries(&log),
        [
            "boomer:before_close",
            "steady:before_close",
            "boomer:on_close",
            "steady:on_close"
        ]
    );
}

#[test]
fn a_panic_in_on_test_end_does_not_change_the_verdict_of_the_others() {
    let log = log();
    let set = set_of([
        Probe::new("boomer", Mode::Panic, &log).with(Capability::TestHooks),
        Probe::new("judge", Mode::Quiet, &log)
            .with(Capability::TestHooks)
            .failing_tests("too slow"),
    ]);

    let (verdict, failures) =
        block_on(set.on_test_end(&TestInfo::new("t"), &TestOutcome::Passed, None));

    assert_eq!(verdict, TestVerdict::Fail("too slow".into()));
    assert!(matches!(
        failures.as_slice(),
        [PluginError::Panicked {
            hook: "on_test_end",
            ..
        }]
    ));
}

#[test]
fn a_panic_is_caught_when_the_set_has_a_timer_too() {
    let log = log();
    let set =
        set_of([Probe::new("boomer", Mode::Panic, &log)]).with_timer(Arc::new(ManualTimer::new()));

    let error = block_on(set.on_page_created(&RecordingPage::new())).unwrap_err();

    assert!(matches!(error, PluginError::Panicked { .. }), "{error:?}");
}

// Guarded handles.

type Seen = Arc<Mutex<Vec<Result<Value>>>>;

/// What an [`Actor`] tries with the handle a hook gives it.
#[derive(Clone)]
enum Act {
    Nothing,
    PageSend(&'static str, Value),
    BrowserSend(&'static str, Value),
    Navigate(&'static str),
    Evaluate,
    InitScript,
    BlockUrls,
    NewContext,
    NewPage,
    /// Opens a context, a tab in it, and sends `Fetch.enable` to that tab.
    ContextThenFetch,
}

/// A plugin that tries one thing with the handle of each hook and writes down
/// whether it was allowed.
struct Actor {
    name: &'static str,
    caps: Vec<Capability>,
    seals: Seals,
    act: Act,
    seen: Seen,
}

impl Actor {
    fn new(name: &'static str, act: Act, seen: &Seen) -> Self {
        Self {
            name,
            caps: Vec::new(),
            seals: Seals::empty(),
            act,
            seen: Arc::clone(seen),
        }
    }

    fn with(mut self, capability: Capability) -> Self {
        self.caps.push(capability);
        self
    }

    fn sealing_context_proxies(mut self) -> Self {
        self.seals = Seals::CONTEXT_PROXY;
        self
    }

    fn note(&self, result: Result<Value>) {
        self.seen.lock().unwrap().push(result);
    }

    async fn act_on_page(&self, page: &dyn PageHandle) {
        let result = match &self.act {
            Act::PageSend(method, params) => page.send(method, params.clone()).await,
            Act::Navigate(url) => page.navigate(url).await.map(|()| Value::Null),
            Act::Evaluate => page.evaluate("1 + 1").await,
            Act::InitScript => page
                .add_init_script("window.x = 1")
                .await
                .map(|()| Value::Null),
            Act::BlockUrls => page
                .block_urls(&["*.gif".to_owned()])
                .await
                .map(|()| Value::Null),
            _ => return,
        };
        self.note(result);
    }

    async fn act_on_browser(&self, browser: &dyn BrowserHandle) {
        let result = match &self.act {
            Act::BrowserSend(method, params) => browser.send(method, params.clone()).await,
            Act::NewContext => browser
                .new_context(ContextSettings::new())
                .await
                .map(|_| Value::Null),
            Act::NewPage => browser.new_page(None).await.map(|_| Value::Null),
            Act::ContextThenFetch => match browser.new_context(ContextSettings::new()).await {
                Ok(context) => match context.new_page(None).await {
                    Ok(page) => page.send("Fetch.enable", json!({})).await,
                    Err(error) => Err(error),
                },
                Err(error) => Err(error),
            },
            _ => return,
        };
        self.note(result);
    }

    async fn act_on_context(&self, context: &dyn ContextHandle) {
        if matches!(self.act, Act::NewPage) {
            self.note(context.new_page(None).await.map(|_| Value::Null));
        }
    }
}

#[async_trait]
impl Plugin for Actor {
    fn name(&self) -> &str {
        self.name
    }

    fn metadata(&self) -> Metadata {
        Metadata::new(Category::Core)
            .capabilities(self.caps.clone())
            .seal(self.seals)
    }

    async fn on_browser(&self, browser: &dyn BrowserHandle) -> Result<()> {
        self.act_on_browser(browser).await;
        Ok(())
    }

    async fn on_page_created(&self, page: &dyn PageHandle) -> Result<()> {
        self.act_on_page(page).await;
        Ok(())
    }

    async fn before_navigate(
        &self,
        page: &dyn PageHandle,
        _navigation: &Navigation,
    ) -> Result<seleniumbase_rs_plugin::NavDecision> {
        self.act_on_page(page).await;
        Ok(seleniumbase_rs_plugin::NavDecision::Continue)
    }

    async fn on_context_created(&self, context: &dyn ContextHandle) -> Result<()> {
        self.act_on_context(context).await;
        Ok(())
    }

    async fn before_close(&self, browser: &dyn BrowserHandle) -> Result<()> {
        self.act_on_browser(browser).await;
        Ok(())
    }

    async fn on_test_end(
        &self,
        _test: &TestInfo,
        _outcome: &TestOutcome,
        page: Option<&dyn PageHandle>,
    ) -> Result<TestVerdict> {
        if let Some(page) = page {
            self.act_on_page(page).await;
        }
        Ok(TestVerdict::Keep)
    }
}

fn one(actor: Actor) -> PluginSet {
    PluginSet::new().with(actor).unwrap()
}

fn raw_cdp(actor: Actor) -> PluginSet {
    PluginSet::new()
        .with_trusted(actor, &[Capability::Raw(RawKind::Cdp)])
        .unwrap()
}

/// The one attempt an actor made.
fn attempt(seen: &Seen) -> Result<Value> {
    let mut all = std::mem::take(&mut *seen.lock().unwrap());
    assert_eq!(all.len(), 1, "the actor should have tried once");
    all.remove(0)
}

fn is_refusal(error: &PluginError, plugin: &str, what: &str) -> bool {
    matches!(error, PluginError::Capability { plugin: p, capability, .. }
        if p == plugin && capability == what)
}

#[test]
fn the_commands_the_host_owns_are_refused_even_to_a_plugin_with_raw_cdp() {
    for method in [
        "Fetch.enable",
        "Fetch.fulfillRequest",
        "fetch.disable",
        "Target.setAutoAttach",
        "Browser.close",
        "Browser.crash",
        "Browser.crashGpuProcess",
    ] {
        let seen = Seen::default();
        let page = RecordingPage::new();
        let set = raw_cdp(Actor::new("raw", Act::PageSend(method, json!({})), &seen));
        block_on(set.on_page_created(&page)).unwrap();
        let error = attempt(&seen).unwrap_err();
        assert!(is_refusal(&error, "raw", method), "{method}: {error:?}");
        assert!(page.calls().is_empty(), "{method} reached the tab");

        let browser = RecordingBrowser::new();
        let set = raw_cdp(Actor::new(
            "raw",
            Act::BrowserSend(method, json!({})),
            &seen,
        ));
        block_on(set.on_browser(&browser)).unwrap();
        let error = attempt(&seen).unwrap_err();
        assert!(is_refusal(&error, "raw", method), "{method}: {error:?}");
        assert!(browser.calls().is_empty(), "{method} reached the browser");
    }
}

#[test]
fn a_command_needs_the_capability_the_table_names() {
    let network = Capability::Cdp("Network".into());
    let cases: [(&str, Value, Vec<Capability>, Option<&str>); 9] = [
        ("Network.enable", json!({}), vec![network.clone()], None),
        (
            "Network.getAllCookies",
            json!({}),
            vec![network.clone()],
            Some("cookies.read"),
        ),
        (
            "Network.getAllCookies",
            json!({}),
            vec![Capability::CookiesRead],
            None,
        ),
        (
            "DOM.getDocument",
            json!({}),
            vec![network.clone()],
            Some("cdp:DOM"),
        ),
        ("Unknown.thing", json!({}), vec![network], Some("raw:cdp")),
        (
            "Runtime.evaluate",
            json!({"expression": "1"}),
            Vec::new(),
            Some("page.evaluate"),
        ),
        (
            "Runtime.evaluate",
            json!({"expression": "1"}),
            vec![Capability::PageEvaluate],
            None,
        ),
        (
            "Network.clearBrowserCache",
            json!({}),
            Vec::new(),
            Some("storage.clear"),
        ),
        (
            "Network.getResponseBody",
            json!({}),
            Vec::new(),
            Some("net.bodies"),
        ),
    ];
    for (method, params, caps, refused) in cases {
        let seen = Seen::default();
        let mut actor = Actor::new("p", Act::PageSend(method, params), &seen);
        for capability in caps {
            actor = actor.with(capability);
        }
        let page = RecordingPage::new();
        block_on(one(actor).on_page_created(&page)).unwrap();
        match (attempt(&seen), refused) {
            (Ok(_), None) => assert_eq!(page.calls().len(), 1, "{method} was not sent"),
            (Err(error), Some(what)) => {
                assert!(is_refusal(&error, "p", what), "{method}: {error:?}");
                assert!(page.calls().is_empty(), "{method} was sent");
            }
            (other, expected) => panic!("{method}: {other:?}, expected refusal {expected:?}"),
        }
    }
}

#[test]
fn a_plugin_with_raw_cdp_may_send_what_the_table_would_refuse_others() {
    for method in ["Network.getAllCookies", "Unknown.thing", "Runtime.evaluate"] {
        let seen = Seen::default();
        let page = RecordingPage::new();
        let set = raw_cdp(Actor::new("raw", Act::PageSend(method, json!({})), &seen));
        block_on(set.on_page_created(&page)).unwrap();
        attempt(&seen).unwrap();
        assert_eq!(page.calls(), [Call::Send(method.into(), json!({}))]);
    }
}

#[test]
fn a_raw_set_blocked_urls_becomes_block_urls() {
    let seen = Seen::default();
    let page = RecordingPage::new();
    let set = one(Actor::new(
        "blocker",
        Act::PageSend(
            "Network.setBlockedURLs",
            json!({"urls": ["*.png", "*.gif"]}),
        ),
        &seen,
    )
    .with(Capability::Cdp("Network".into())));

    block_on(set.on_page_created(&page)).unwrap();

    assert_eq!(attempt(&seen).unwrap(), json!({}));
    assert_eq!(
        page.calls(),
        [Call::BlockUrls(vec!["*.png".into(), "*.gif".into()])],
        "the command itself was not sent"
    );
}

#[test]
fn a_malformed_set_blocked_urls_is_an_error_and_sends_nothing() {
    let seen = Seen::default();
    let page = RecordingPage::new();
    let set = one(Actor::new(
        "blocker",
        Act::PageSend("Network.setBlockedURLs", json!({"urls": [1, 2]})),
        &seen,
    )
    .with(Capability::Cdp("Network".into())));

    block_on(set.on_page_created(&page)).unwrap();

    let error = attempt(&seen).unwrap_err();
    assert!(
        error.to_string().contains("`urls` array of strings"),
        "{error}"
    );
    assert!(page.calls().is_empty());
}

/// A tab of an older host: it offers `send` and nothing that is new.
#[derive(Default)]
struct PlainPage {
    sent: Mutex<Vec<(String, Value)>>,
}

#[async_trait]
impl PageHandle for PlainPage {
    fn engine(&self) -> seleniumbase_rs_plugin::Engine {
        seleniumbase_rs_plugin::Engine::Cdp
    }
    async fn send(&self, method: &str, params: Value) -> Result<Value> {
        self.sent.lock().unwrap().push((method.to_owned(), params));
        Ok(Value::Null)
    }
    async fn add_init_script(&self, _source: &str) -> Result<()> {
        Ok(())
    }
    async fn evaluate(&self, _expression: &str) -> Result<Value> {
        Ok(Value::Null)
    }
}

#[test]
fn a_tab_without_block_urls_gets_the_command_as_before() {
    let seen = Seen::default();
    let page = PlainPage::default();
    let params = json!({"urls": ["*.png"]});
    let set = one(Actor::new(
        "blocker",
        Act::PageSend("Network.setBlockedURLs", params.clone()),
        &seen,
    )
    .with(Capability::Cdp("Network".into())));

    block_on(set.on_page_created(&page)).unwrap();

    attempt(&seen).unwrap();
    assert_eq!(
        *page.sent.lock().unwrap(),
        [("Network.setBlockedURLs".to_owned(), params)]
    );
}

#[test]
fn the_typed_page_methods_need_their_capabilities() {
    let cases: [(Act, Option<Capability>, &str); 8] = [
        (
            Act::Evaluate,
            Some(Capability::PageEvaluate),
            "page.evaluate",
        ),
        (
            Act::InitScript,
            Some(Capability::PageScript(HostScope::Everywhere)),
            "page.script:*",
        ),
        (
            Act::InitScript,
            Some(Capability::PageScript(HostScope::Hosts(vec![
                "a.test".into(),
            ]))),
            "page.script:*",
        ),
        (
            Act::Navigate("https://a.test/"),
            Some(Capability::PageNavigate),
            "page.navigate",
        ),
        (
            Act::BlockUrls,
            Some(Capability::NetIntercept),
            "net.intercept",
        ),
        (
            Act::BlockUrls,
            Some(Capability::Cdp("Network".into())),
            "net.intercept",
        ),
        (
            Act::BlockUrls,
            Some(Capability::CookiesRead),
            "net.intercept",
        ),
        (Act::Evaluate, None, "page.evaluate"),
    ];
    let allowed = [true, true, false, true, true, true, false, false];
    for ((act, capability, what), allowed) in cases.into_iter().zip(allowed) {
        let seen = Seen::default();
        let mut actor = Actor::new("typed", act, &seen);
        if let Some(capability) = capability.clone() {
            actor = actor.with(capability);
        }
        let page = RecordingPage::new();
        block_on(one(actor).on_page_created(&page)).unwrap();
        let result = attempt(&seen);
        if allowed {
            result.unwrap_or_else(|error| panic!("{capability:?}: {error:?}"));
            assert_eq!(
                page.calls().len(),
                1,
                "{capability:?} did not reach the tab"
            );
        } else {
            let error = result.unwrap_err();
            assert!(
                is_refusal(&error, "typed", what),
                "{capability:?}: {error:?}"
            );
            assert!(page.calls().is_empty());
        }
    }
}

#[test]
fn navigate_inside_before_navigate_is_reentrant_and_nothing_is_sent() {
    for act in [
        Act::Navigate("https://b.test/"),
        Act::PageSend("Page.navigate", json!({"url": "https://b.test/"})),
    ] {
        let operation = match &act {
            Act::Navigate(_) => "navigate",
            _ => "Page.navigate",
        };
        let seen = Seen::default();
        let page = RecordingPage::new();
        let set = one(Actor::new("nav", act, &seen).with(Capability::PageNavigate));

        let navigation =
            block_on(set.before_navigate(&page, &Navigation::program("https://a.test/"))).unwrap();

        assert_eq!(navigation.url, "https://a.test/");
        let error = attempt(&seen).unwrap_err();
        assert!(
            matches!(&error, PluginError::Reentrant { plugin, operation: found, hook }
                if plugin == "nav" && *found == operation && *hook == "before_navigate"),
            "{error:?}"
        );
        assert!(page.calls().is_empty(), "the navigation reached the tab");
    }
}

#[test]
fn navigate_is_fine_in_a_hook_that_does_not_run_before_navigate() {
    let seen = Seen::default();
    let page = RecordingPage::new();
    let set =
        one(Actor::new("nav", Act::Navigate("https://b.test/"), &seen)
            .with(Capability::PageNavigate));

    block_on(set.on_page_created(&page)).unwrap();

    attempt(&seen).unwrap();
    assert_eq!(page.calls(), [Call::Navigate("https://b.test/".into())]);
}

#[test]
fn opening_a_tab_inside_a_context_hook_is_reentrant() {
    let seen = Seen::default();
    let browser = RecordingBrowser::new().with_contexts();
    let context = block_on(browser.new_context(ContextSettings::new())).unwrap();
    let set = one(Actor::new("opener", Act::NewPage, &seen).with(Capability::Contexts));

    block_on(set.on_context_created(&*context)).unwrap();

    let error = attempt(&seen).unwrap_err();
    assert!(
        matches!(&error, PluginError::Reentrant { plugin, operation: "new_page", hook }
            if plugin == "opener" && *hook == "on_context_created"),
        "{error:?}"
    );
    assert_eq!(browser.pages_made(), 0);
}

#[test]
fn a_browser_hook_may_open_contexts_with_the_capability_and_not_without() {
    for (granted, expected) in [(true, 1), (false, 0)] {
        let seen = Seen::default();
        let browser = RecordingBrowser::new().with_contexts();
        let mut actor = Actor::new("opener", Act::NewContext, &seen);
        if granted {
            actor = actor.with(Capability::Contexts);
        }

        block_on(one(actor).on_browser(&browser)).unwrap();

        match attempt(&seen) {
            Ok(_) => assert!(granted),
            Err(error) => assert!(is_refusal(&error, "opener", "contexts"), "{error:?}"),
        }
        assert_eq!(browser.contexts_made(), expected);
    }
}

#[test]
fn a_raw_context_with_a_proxy_needs_launch_proxy_and_yields_to_a_seal() {
    let proxied = json!({"proxyServer": "socks5://127.0.0.1:9050"});
    let actor = |seen: &Seen, with_proxy: bool| {
        let actor = Actor::new(
            "creator",
            Act::BrowserSend("Target.createBrowserContext", proxied.clone()),
            seen,
        )
        .with(Capability::Contexts);
        if with_proxy {
            actor.with(Capability::LaunchProxy)
        } else {
            actor
        }
    };

    // Without launch.proxy.
    let seen = Seen::default();
    let browser = RecordingBrowser::new();
    block_on(one(actor(&seen, false)).on_browser(&browser)).unwrap();
    assert!(is_refusal(
        &attempt(&seen).unwrap_err(),
        "creator",
        "launch.proxy"
    ));

    // With it, and no seal.
    block_on(one(actor(&seen, true)).on_browser(&browser)).unwrap();
    attempt(&seen).unwrap();
    assert_eq!(browser.calls().len(), 1);

    // With it, while another plugin sealed the proxy of new contexts.
    let sealer = Actor::new("tor", Act::Nothing, &seen).sealing_context_proxies();
    let set = PluginSet::new()
        .with(sealer)
        .unwrap()
        .with(actor(&seen, true))
        .unwrap();
    let browser = RecordingBrowser::new();
    block_on(set.on_browser(&browser)).unwrap();
    let error = attempt(&seen).unwrap_err();
    assert!(
        matches!(&error, PluginError::Sealed { field: "context.proxy", a, b }
            if a == "tor" && b == "creator"),
        "{error:?}"
    );
    assert!(browser.calls().is_empty());
}

#[test]
fn what_a_guarded_handle_opens_is_guarded_too() {
    let seen = Seen::default();
    let browser = RecordingBrowser::new().with_contexts();
    let set = one(Actor::new("deep", Act::ContextThenFetch, &seen).with(Capability::Contexts));

    block_on(set.on_browser(&browser)).unwrap();

    let error = attempt(&seen).unwrap_err();
    assert!(is_refusal(&error, "deep", "Fetch.enable"), "{error:?}");
    assert_eq!(browser.contexts_made(), 1);
    assert!(
        browser.contexts()[0].pages()[0].calls().is_empty(),
        "Fetch.enable reached the tab"
    );
}

#[test]
fn the_page_of_on_test_end_and_the_browser_of_before_close_are_guarded() {
    let seen = Seen::default();
    let page = RecordingPage::new();
    let set = one(
        Actor::new("late", Act::PageSend("Fetch.enable", json!({})), &seen)
            .with(Capability::TestHooks),
    );
    let (verdict, failures) =
        block_on(set.on_test_end(&TestInfo::new("t"), &TestOutcome::Passed, Some(&page)));
    assert_eq!(verdict, TestVerdict::Keep);
    assert!(failures.is_empty());
    assert!(is_refusal(
        &attempt(&seen).unwrap_err(),
        "late",
        "Fetch.enable"
    ));
    assert!(page.calls().is_empty());

    let browser = RecordingBrowser::new();
    let set = one(Actor::new(
        "late",
        Act::BrowserSend("Browser.close", json!({})),
        &seen,
    ));
    assert!(block_on(set.before_close(&browser)).is_empty());
    assert!(is_refusal(
        &attempt(&seen).unwrap_err(),
        "late",
        "Browser.close"
    ));
    assert!(browser.calls().is_empty());
}

#[test]
fn a_host_can_guard_a_handle_for_work_outside_the_hooks() {
    let seen = Seen::default();
    let set = one(Actor::new("task", Act::Nothing, &seen).with(Capability::PageNavigate));
    let page = RecordingPage::new();

    let guarded = set.guarded_page("task", &page).unwrap();
    let denied = block_on(guarded.send("Fetch.enable", json!({}))).unwrap_err();
    block_on(guarded.navigate("https://a.test/")).unwrap();

    assert!(is_refusal(&denied, "task", "Fetch.enable"), "{denied:?}");
    assert_eq!(page.calls(), [Call::Navigate("https://a.test/".into())]);
    assert!(matches!(
        set.guarded_page("nobody", &page),
        Err(PluginError::Config(_))
    ));
}

#[test]
fn the_policy_table_is_public_and_matches_the_adr() {
    let none = json!({});
    let proxied = json!({"proxyServer": "http://p:1"});
    assert_eq!(
        cdp_policy::required("Network.getCookies", &none),
        [Capability::CookiesRead]
    );
    assert_eq!(
        cdp_policy::required("Storage.setCookies", &none),
        [Capability::CookiesWrite]
    );
    assert_eq!(
        cdp_policy::required("Storage.clearDataForOrigin", &none),
        [Capability::StorageClear]
    );
    assert_eq!(
        cdp_policy::required("Page.addScriptToEvaluateOnNewDocument", &none),
        [Capability::PageScript(HostScope::Everywhere)]
    );
    assert_eq!(
        cdp_policy::required("Page.navigate", &none),
        [Capability::PageNavigate]
    );
    assert_eq!(
        cdp_policy::required("Target.createBrowserContext", &none),
        [Capability::Contexts]
    );
    assert_eq!(
        cdp_policy::required("Target.createBrowserContext", &proxied),
        [Capability::Contexts, Capability::LaunchProxy]
    );
    assert_eq!(
        cdp_policy::required("Browser.setDownloadBehavior", &none),
        [Capability::HostFsWrite(PathScope::RunOutput)]
    );
    assert_eq!(
        cdp_policy::required("Emulation.setDeviceMetricsOverride", &none),
        [Capability::Cdp("Emulation".into())]
    );
    for unknown in ["Nope.method", "NoDomain", "Network.", ".enable", ""] {
        assert_eq!(
            cdp_policy::required(unknown, &none),
            [Capability::Raw(RawKind::Cdp)],
            "{unknown:?}"
        );
    }
    assert!(cdp_policy::host_owned("Fetch.anything").is_some());
    assert!(cdp_policy::host_owned("FETCH.enable").is_some());
    assert!(cdp_policy::host_owned("Target.setAutoAttach").is_some());
    assert!(cdp_policy::host_owned("Browser.crash").is_some());
    assert!(cdp_policy::host_owned("Browser.getVersion").is_none());
    assert!(cdp_policy::host_owned("Target.createTarget").is_none());
}

// Budgets.

#[test]
fn the_default_limits_are_the_documented_ones() {
    for (hook, seconds) in [
        ("before_launch", 30),
        ("on_test_end", 30),
        ("before_navigate", 5),
        ("on_request", 2),
        ("on_page_created", 10),
        ("on_browser", 10),
        ("before_close", 10),
        ("on_close", 10),
        ("after_navigate", 10),
        ("on_context_created", 10),
    ] {
        assert_eq!(
            Budgets::default_for(hook),
            Duration::from_secs(seconds),
            "{hook}"
        );
        assert_eq!(
            Budgets::default().limit_for(hook),
            Duration::from_secs(seconds)
        );
    }
}

#[test]
fn a_plugin_may_ask_for_another_limit_but_not_beyond_four_times_the_default() {
    let mut asks = Budgets::default();
    asks.on_request = Some(Duration::from_secs(3));
    asks.before_navigate = Some(Duration::from_secs(1_000));
    asks.on_test_end = Some(Duration::ZERO);
    asks.other = Some(Duration::from_secs(1));

    assert_eq!(asks.limit_for("on_request"), Duration::from_secs(3));
    assert_eq!(asks.limit_for("before_navigate"), Duration::from_secs(20));
    assert_eq!(
        asks.limit_for("on_test_end"),
        Duration::from_secs(30),
        "zero counts as not asking"
    );
    assert_eq!(asks.limit_for("after_navigate"), Duration::from_secs(1));
    assert_eq!(
        asks.limit_for("on_page_created"),
        Duration::from_secs(10),
        "on_page_created has a field of its own"
    );
}

#[test]
fn on_request_that_takes_two_seconds_fails_the_request() {
    let log = log();
    let timer = Arc::new(ManualTimer::new());
    let set = set_of([Probe::new("slow", Mode::Hang, &log).with(Capability::NetIntercept)])
        .with_timer(timer.clone());
    let request = request();

    let mut decision = pin!(set.on_request(&request));
    assert!(poll(&mut decision).is_pending());
    timer.advance(Duration::from_millis(1_999));
    assert!(poll(&mut decision).is_pending(), "one millisecond is left");
    timer.advance(Duration::from_millis(1));

    let Poll::Ready(RequestDecision::Block(reason)) = poll(&mut decision) else {
        panic!("the request was not blocked when the limit passed");
    };
    assert!(
        reason.contains("slow") && reason.contains("timed out"),
        "{reason}"
    );
}

#[test]
fn a_fast_on_request_is_not_cut_short_by_the_timer() {
    let log = log();
    let set = set_of([Probe::new("quick", Mode::Quiet, &log).with(Capability::NetIntercept)])
        .with_timer(Arc::new(ManualTimer::new()));

    assert_eq!(
        block_on(set.on_request(&request())),
        RequestDecision::Continue
    );
}

#[test]
fn a_slow_before_navigate_times_out_after_five_seconds() {
    let log = log();
    let timer = Arc::new(ManualTimer::new());
    let set = set_of([Probe::new("slow", Mode::Hang, &log)]).with_timer(timer.clone());
    let page = RecordingPage::new();
    let navigation = Navigation::program("https://a.test/");

    let mut result = pin!(set.before_navigate(&page, &navigation));
    assert!(poll(&mut result).is_pending());
    timer.advance(Duration::from_secs(5) - Duration::from_millis(1));
    assert!(poll(&mut result).is_pending());
    timer.advance(Duration::from_millis(1));

    let Poll::Ready(Err(error)) = poll(&mut result) else {
        panic!("the navigation was not cancelled when the limit passed");
    };
    assert!(matches!(error, PluginError::Timeout(limit) if limit == Duration::from_secs(5)));
}

#[test]
fn a_slow_on_test_end_times_out_after_thirty_seconds_and_keeps_the_verdict() {
    let log = log();
    let timer = Arc::new(ManualTimer::new());
    let set = set_of([Probe::new("slow", Mode::Hang, &log).with(Capability::TestHooks)])
        .with_timer(timer.clone());
    let test = TestInfo::new("t");

    let mut result = pin!(set.on_test_end(&test, &TestOutcome::Passed, None));
    assert!(poll(&mut result).is_pending());
    timer.advance(Duration::from_secs(29));
    assert!(poll(&mut result).is_pending());
    timer.advance(Duration::from_secs(1));

    let Poll::Ready((verdict, failures)) = poll(&mut result) else {
        panic!("on_test_end did not finish when the limit passed");
    };
    assert_eq!(verdict, TestVerdict::Keep);
    assert!(
        matches!(failures.as_slice(), [PluginError::Timeout(limit)] if *limit == Duration::from_secs(30))
    );
}

#[test]
fn the_other_hooks_get_ten_seconds_and_a_plugin_can_lower_its_own_limit() {
    let log = log();
    let mut asks = Budgets::default();
    asks.on_page_created = Some(Duration::from_secs(1));
    for (probe, limit) in [
        (Probe::new("slow", Mode::Hang, &log), 10),
        (Probe::new("impatient", Mode::Hang, &log).budgets(asks), 1),
    ] {
        let timer = Arc::new(ManualTimer::new());
        let set = set_of([probe]).with_timer(timer.clone());
        let page = RecordingPage::new();

        let mut result = pin!(set.on_page_created(&page));
        assert!(poll(&mut result).is_pending());
        timer.advance(Duration::from_secs(limit) - Duration::from_millis(1));
        assert!(poll(&mut result).is_pending());
        timer.advance(Duration::from_millis(1));

        let Poll::Ready(Err(error)) = poll(&mut result) else {
            panic!("on_page_created did not stop after {limit} s");
        };
        assert!(
            matches!(error, PluginError::Timeout(found) if found == Duration::from_secs(limit)),
            "{error:?}"
        );
    }
}

#[test]
fn without_a_timer_nothing_times_out() {
    let log = log();
    let set = set_of([Probe::new("quick", Mode::Quiet, &log)]);

    block_on(set.on_page_created(&RecordingPage::new())).unwrap();
    block_on(set.before_navigate(
        &RecordingPage::new(),
        &Navigation::program("https://a.test/"),
    ))
    .unwrap();

    assert_eq!(
        entries(&log),
        ["quick:on_page_created", "quick:before_navigate"]
    );
}
