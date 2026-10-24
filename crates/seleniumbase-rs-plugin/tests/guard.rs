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
use seleniumbase_rs_plugin_testing::{ManualTimer, RecordingBrowser, RecordingPage, block_on};

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
