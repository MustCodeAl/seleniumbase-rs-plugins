//! The lifecycle hooks added in 0.1.3: navigation, contexts, tests, protocol
//! events and `before_close`, and how the set combines and gates them.

use std::sync::{Arc, Mutex};

use seleniumbase_rs_plugin::Timer;
use seleniumbase_rs_plugin::{
    BrowserFamily, BrowserHandle, Capability, CapabilitySet, Category, ContextHandle, ContextId,
    ContextSettings, Engine, HostInfo, LaunchContext, MAX_REDIRECTS, Metadata, NavDecision,
    NavOutcome, Navigation, PageHandle, Plugin, PluginError, PluginSet, ProtocolEvent, Result,
    Seals, TestInfo, TestOutcome, TestVerdict, async_trait,
};
use seleniumbase_rs_plugin_testing::{RecordingBrowser, RecordingPage, block_on};
use serde_json::{Value, json};

type Log = Arc<Mutex<Vec<String>>>;

/// A plugin whose behaviour each test sets up.
#[derive(Default)]
struct Probe {
    name: &'static str,
    caps: Vec<Capability>,
    seals: Seals,
    decision: Option<NavDecision>,
    context_edit: Option<fn(&mut ContextSettings)>,
    verdict: Option<&'static str>,
    events: &'static [&'static str],
    fail: &'static [&'static str],
    log: Log,
}

impl Probe {
    fn named(name: &'static str, log: &Log) -> Self {
        Self {
            name,
            log: Arc::clone(log),
            ..Self::default()
        }
    }

    fn with(mut self, capability: Capability) -> Self {
        self.caps.push(capability);
        self
    }

    fn note(&self, what: impl std::fmt::Display) {
        self.log
            .lock()
            .unwrap()
            .push(format!("{}:{what}", self.name));
    }

    fn outcome(&self, hook: &str) -> Result<()> {
        if self.fail.contains(&hook) {
            Err(PluginError::other(format!("{hook} boom")))
        } else {
            Ok(())
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
            .seal(self.seals)
    }
    fn protocol_events(&self) -> &[&str] {
        self.events
    }
    async fn before_context(&self, settings: &mut ContextSettings) -> Result<()> {
        self.note("before_context");
        if let Some(edit) = self.context_edit {
            edit(settings);
        }
        self.outcome("before_context")
    }
    async fn on_context_created(&self, context: &dyn ContextHandle) -> Result<()> {
        self.note(format!("created {}", context.id()));
        self.outcome("on_context_created")
    }
    async fn on_context_closed(&self, id: &ContextId) -> Result<()> {
        self.note(format!("closed {id}"));
        self.outcome("on_context_closed")
    }
    async fn before_navigate(
        &self,
        _page: &dyn PageHandle,
        navigation: &Navigation,
    ) -> Result<NavDecision> {
        self.note(format!("before_navigate {}", navigation.url));
        self.outcome("before_navigate")?;
        Ok(self.decision.clone().unwrap_or(NavDecision::Continue))
    }
    async fn after_navigate(&self, _page: &dyn PageHandle, outcome: &NavOutcome) -> Result<()> {
        self.note(format!("after_navigate {}", outcome.url));
        self.outcome("after_navigate")
    }
    async fn on_protocol_event(
        &self,
        _browser: &dyn BrowserHandle,
        event: &ProtocolEvent,
    ) -> Result<()> {
        self.note(format!("event {}", event.method));
        self.outcome("on_protocol_event")
    }
    async fn before_close(&self, _browser: &dyn BrowserHandle) -> Result<()> {
        self.note("before_close");
        self.outcome("before_close")
    }
    async fn on_test_start(&self, test: &TestInfo) -> Result<()> {
        self.note(format!("start {}", test.name));
        self.outcome("on_test_start")
    }
    async fn on_test_end(
        &self,
        test: &TestInfo,
        outcome: &TestOutcome,
        page: Option<&dyn PageHandle>,
    ) -> Result<TestVerdict> {
        self.note(format!(
            "end {} {outcome:?} page={}",
            test.name,
            page.is_some()
        ));
        self.outcome("on_test_end")?;
        Ok(self
            .verdict
            .map_or(TestVerdict::Keep, |m| TestVerdict::Fail(m.to_owned())))
    }
}

fn log() -> Log {
    Log::default()
}

fn entries(log: &Log) -> Vec<String> {
    log.lock().unwrap().clone()
}

fn go(url: &str) -> Navigation {
    Navigation::program(url)
}

fn navigate(set: &PluginSet, url: &str) -> Result<Navigation> {
    block_on(set.before_navigate(&RecordingPage::new(), &go(url)))
}

fn redirecting(name: &'static str, to: &str, log: &Log) -> Probe {
    Probe {
        decision: Some(NavDecision::Redirect(to.to_owned())),
        ..Probe::named(name, log).with(Capability::PageNavigate)
    }
}

// ---- navigation ---------------------------------------------------------

#[test]
fn a_navigation_goes_on_when_no_plugin_objects() {
    let log = log();
    let set = PluginSet::new()
        .with(Probe::named("a", &log))
        .unwrap()
        .with(Probe::named("b", &log))
        .unwrap();
    let nav = navigate(&set, "https://a.test/").unwrap();
    assert_eq!(nav, go("https://a.test/"));
    assert_eq!(
        entries(&log),
        [
            "a:before_navigate https://a.test/",
            "b:before_navigate https://a.test/"
        ]
    );
}

#[test]
fn the_first_cancel_wins_and_names_the_plugin_and_the_address() {
    let log = log();
    let cancel = |name, reason: &str| Probe {
        decision: Some(NavDecision::Cancel(reason.to_owned())),
        ..Probe::named(name, &log)
    };
    let set = PluginSet::new()
        .with(Probe::named("a", &log))
        .unwrap()
        .with(cancel("b", "off limits"))
        .unwrap()
        .with(cancel("c", "later"))
        .unwrap();
    let error = navigate(&set, "https://x.test/").unwrap_err();
    assert!(matches!(error, PluginError::NavigationCancelled { .. }));
    assert_eq!(
        error.to_string(),
        "navigation to https://x.test/ cancelled by plugin b: off limits"
    );
    // The plugin after the one that cancelled is not asked.
    assert_eq!(entries(&log).len(), 2, "{:?}", entries(&log));
}

#[test]
fn a_redirect_is_applied_at_once_so_later_plugins_see_it() {
    let log = log();
    let set = PluginSet::new()
        .with(redirecting("a", "https://b.test/", &log))
        .unwrap()
        .with(Probe::named("b", &log))
        .unwrap();
    let nav = navigate(&set, "https://a.test/").unwrap();
    assert_eq!(nav.url, "https://b.test/");
    assert_eq!(nav.origin, go("x").origin);
    assert_eq!(
        entries(&log),
        [
            "a:before_navigate https://a.test/",
            "b:before_navigate https://b.test/"
        ]
    );
}

#[test]
fn a_redirect_may_only_go_to_http_https_about_blank_or_data() {
    for allowed in [
        "http://a.test/",
        "https://a.test/",
        "HTTPS://A.TEST/",
        "about:blank",
        "data:text/html,hi",
    ] {
        let set = PluginSet::new()
            .with(redirecting("a", allowed, &log()))
            .unwrap();
        assert_eq!(navigate(&set, "https://x.test/").unwrap().url, allowed);
    }
    for refused in [
        "file:///etc/passwd",
        "javascript:alert(1)",
        "chrome://settings",
        "about:blank#x",
        " https://a.test/",
        "",
    ] {
        let set = PluginSet::new()
            .with(redirecting("a", refused, &log()))
            .unwrap();
        let error = navigate(&set, "https://x.test/").unwrap_err();
        assert!(
            matches!(&error, PluginError::Hook { plugin, hook, message }
                if plugin == "a" && *hook == "before_navigate" && message.contains("refused")),
            "{refused:?}: {error:?}"
        );
    }
}

#[test]
fn a_redirect_needs_the_page_navigate_capability() {
    let log = log();
    let mut plugin = redirecting("a", "https://b.test/", &log);
    plugin.caps.clear();
    let set = PluginSet::new().with(plugin).unwrap();
    let error = navigate(&set, "https://x.test/").unwrap_err().to_string();
    assert!(error.contains("page.navigate"), "{error}");
}

#[test]
fn redirect_chains_stop_at_five() {
    // Every plugin sends the navigation somewhere new, so a set of `n` plugins
    // makes `n` redirects. Up to MAX_REDIRECTS go through; the next is refused.
    for n in 0..=(MAX_REDIRECTS + 7) {
        let mut set = PluginSet::new();
        for i in 0..n {
            let name: &'static str = Box::leak(format!("p{i}").into_boxed_str());
            let to = format!("https://hop{i}.test/");
            set = set.with(redirecting(name, &to, &log())).unwrap();
        }
        let result = navigate(&set, "https://start.test/");
        if n <= MAX_REDIRECTS {
            let expected = if n == 0 {
                "https://start.test/".to_owned()
            } else {
                format!("https://hop{}.test/", n - 1)
            };
            assert_eq!(result.unwrap().url, expected, "n = {n}");
        } else {
            let error = result.unwrap_err().to_string();
            assert!(error.contains("at most 5 times"), "n = {n}: {error}");
        }
    }
    assert_eq!(MAX_REDIRECTS, 5);
}

#[test]
fn a_failing_before_navigate_stops_the_navigation_and_names_the_hook() {
    let log = log();
    let set = PluginSet::new()
        .with(Probe {
            fail: &["before_navigate"],
            ..Probe::named("a", &log)
        })
        .unwrap();
    let error = navigate(&set, "https://x.test/").unwrap_err();
    assert!(
        matches!(&error, PluginError::Hook { plugin, hook, .. }
            if plugin == "a" && *hook == "before_navigate"),
        "{error:?}"
    );
}

#[test]
fn after_navigate_reaches_every_plugin_and_collects_failures() {
    let log = log();
    let set = PluginSet::new()
        .with(Probe {
            fail: &["after_navigate"],
            ..Probe::named("a", &log)
        })
        .unwrap()
        .with(Probe::named("b", &log))
        .unwrap();
    let outcome = NavOutcome::new("https://x.test/").status(200);
    let failures = block_on(set.after_navigate(&RecordingPage::new(), &outcome));
    assert_eq!(failures.len(), 1);
    assert!(failures[0].to_string().contains("after_navigate"));
    assert_eq!(
        entries(&log),
        [
            "a:after_navigate https://x.test/",
            "b:after_navigate https://x.test/"
        ]
    );
}

#[test]
fn a_navigation_outcome_is_ok_without_an_error_and_below_status_400() {
    assert!(NavOutcome::new("u").ok());
    assert!(NavOutcome::new("u").status(204).ok());
    assert!(NavOutcome::new("u").status(399).ok());
    assert!(!NavOutcome::new("u").status(404).ok());
    assert!(!NavOutcome::new("u").status(200).failed("net::ERR").ok());
}

// ---- contexts -----------------------------------------------------------

fn tor_like(log: &Log) -> Probe {
    Probe {
        context_edit: Some(|s| s.proxy = Some("socks5://127.0.0.1:9".to_owned())),
        seals: Seals::CONTEXT_PROXY,
        ..Probe::named("tor", log)
            .with(Capability::Contexts)
            .with(Capability::LaunchProxy)
    }
}

#[test]
fn context_hooks_reach_only_plugins_that_hold_the_contexts_capability() {
    let log = log();
    let set = PluginSet::new()
        .with(Probe::named("plain", &log))
        .unwrap()
        .with(Probe::named("ctx", &log).with(Capability::Contexts))
        .unwrap();
    let browser = RecordingBrowser::new().with_contexts();
    let mut settings = ContextSettings::new();
    block_on(set.before_context(&mut settings)).unwrap();
    let context = block_on(browser.new_context(settings)).unwrap();
    block_on(set.on_context_created(&*context)).unwrap();
    let id = context.id().clone();
    assert!(block_on(set.on_context_closed(&id)).is_empty());
    assert_eq!(
        entries(&log),
        [
            "ctx:before_context".to_owned(),
            format!("ctx:created {id}"),
            format!("ctx:closed {id}")
        ]
    );
}

#[test]
fn a_plugin_may_set_the_context_proxy_with_launch_proxy() {
    let set = PluginSet::new().with(tor_like(&log())).unwrap();
    let mut settings = ContextSettings::new();
    block_on(set.before_context(&mut settings)).unwrap();
    assert_eq!(settings.proxy.as_deref(), Some("socks5://127.0.0.1:9"));
}

#[test]
fn a_context_proxy_change_without_launch_proxy_is_refused() {
    let mut plugin = tor_like(&log());
    plugin.caps = vec![Capability::Contexts];
    let set = PluginSet::new().with(plugin).unwrap();
    let error = block_on(set.before_context(&mut ContextSettings::new())).unwrap_err();
    assert!(
        matches!(&error, PluginError::Capability { capability, .. } if capability == "launch.proxy"),
        "{error:?}"
    );
}

#[test]
fn a_sealed_context_proxy_cannot_be_changed_by_a_later_plugin() {
    let log = log();
    let other = Probe {
        context_edit: Some(|s| s.proxy = Some("http://elsewhere:1".to_owned())),
        ..Probe::named("other", &log)
            .with(Capability::Contexts)
            .with(Capability::LaunchProxy)
    };
    let set = PluginSet::new()
        .with(tor_like(&log))
        .unwrap()
        .with(other)
        .unwrap();
    let error = block_on(set.before_context(&mut ContextSettings::new())).unwrap_err();
    assert!(
        matches!(&error, PluginError::Sealed { field, a, b }
            if *field == "context.proxy" && a == "tor" && b == "other"),
        "{error:?}"
    );
}

#[test]
fn the_context_bypass_list_only_grows() {
    let log = log();
    let grow = Probe {
        context_edit: Some(|s| s.bypass.push("localhost".to_owned())),
        ..Probe::named("grow", &log)
            .with(Capability::Contexts)
            .with(Capability::LaunchProxy)
    };
    let shrink = Probe {
        context_edit: Some(|s| s.bypass.clear()),
        ..Probe::named("shrink", &log)
            .with(Capability::Contexts)
            .with(Capability::LaunchProxy)
    };
    let mut settings = ContextSettings::new();
    block_on(
        PluginSet::new()
            .with(grow)
            .unwrap()
            .before_context(&mut settings),
    )
    .unwrap();
    assert_eq!(settings.bypass, ["localhost"]);
    let set = PluginSet::new()
        .with(Probe {
            context_edit: Some(|s| s.bypass.push("localhost".to_owned())),
            ..Probe::named("grow", &log)
                .with(Capability::Contexts)
                .with(Capability::LaunchProxy)
        })
        .unwrap()
        .with(shrink)
        .unwrap();
    let error = block_on(set.before_context(&mut ContextSettings::new())).unwrap_err();
    assert!(error.to_string().contains("only grow"), "{error}");
}

#[test]
fn a_failing_context_hook_stops_the_context_and_closing_collects_failures() {
    let log = log();
    let failing = |name, hook| Probe {
        fail: hook,
        ..Probe::named(name, &log).with(Capability::Contexts)
    };
    let set = PluginSet::new()
        .with(failing(
            "a",
            &["before_context", "on_context_created", "on_context_closed"],
        ))
        .unwrap()
        .with(failing("b", &[]))
        .unwrap();
    let error = block_on(set.before_context(&mut ContextSettings::new())).unwrap_err();
    assert!(error.to_string().contains("before_context"), "{error}");
    let browser = RecordingBrowser::new().with_contexts();
    let context = block_on(browser.new_context(ContextSettings::new())).unwrap();
    let error = block_on(set.on_context_created(&*context)).unwrap_err();
    assert!(error.to_string().contains("on_context_created"), "{error}");
    log.lock().unwrap().clear();
    let failures = block_on(set.on_context_closed(&ContextId::new("c1")));
    assert_eq!(failures.len(), 1);
    assert_eq!(entries(&log), ["a:closed c1", "b:closed c1"]);
}

// ---- tests --------------------------------------------------------------

#[test]
fn failing_verdicts_are_joined_in_run_order_and_errors_do_not_change_them() {
    let log = log();
    let hooked = |name, verdict, fail| Probe {
        verdict,
        fail,
        ..Probe::named(name, &log).with(Capability::TestHooks)
    };
    let set = PluginSet::new()
        .with(hooked("a", Some("two broken links"), &[]))
        .unwrap()
        .with(hooked("b", None, &["on_test_end"]))
        .unwrap()
        .with(hooked("c", Some("1 console error"), &[]))
        .unwrap();
    let test = TestInfo::new("checkout::pays").file("tests/checkout.rs");
    let page = RecordingPage::new();
    let (verdict, failures) = block_on(set.on_test_end(&test, &TestOutcome::Passed, Some(&page)));
    assert_eq!(
        verdict,
        TestVerdict::Fail("two broken links; 1 console error".into())
    );
    assert_eq!(failures.len(), 1);
    assert!(failures[0].to_string().contains("on_test_end"));
    assert_eq!(
        entries(&log),
        [
            "a:end checkout::pays Passed page=true",
            "b:end checkout::pays Passed page=true",
            "c:end checkout::pays Passed page=true"
        ]
    );
}

#[test]
fn a_test_nobody_objects_to_is_kept() {
    let log = log();
    let set = PluginSet::new()
        .with(Probe::named("a", &log).with(Capability::TestHooks))
        .unwrap();
    let (verdict, failures) = block_on(set.on_test_end(
        &TestInfo::new("t"),
        &TestOutcome::Failed("boom".into()),
        None,
    ));
    assert_eq!((verdict, failures.len()), (TestVerdict::Keep, 0));
    assert_eq!(entries(&log), ["a:end t Failed(\"boom\") page=false"]);
}

#[test]
fn test_hooks_reach_only_plugins_that_hold_test_hooks() {
    let log = log();
    let set = PluginSet::new()
        .with(Probe {
            verdict: Some("never"),
            ..Probe::named("plain", &log)
        })
        .unwrap()
        .with(Probe::named("hooked", &log).with(Capability::TestHooks))
        .unwrap();
    let test = TestInfo::new("t");
    assert!(block_on(set.on_test_start(&test)).is_empty());
    let (verdict, _) = block_on(set.on_test_end(&test, &TestOutcome::Skipped, None));
    assert_eq!(verdict, TestVerdict::Keep);
    assert_eq!(
        entries(&log),
        ["hooked:start t", "hooked:end t Skipped page=false"]
    );
}

#[test]
fn a_failing_test_start_is_collected_and_the_others_still_run() {
    let log = log();
    let hooked = |name, fail| Probe {
        fail,
        ..Probe::named(name, &log).with(Capability::TestHooks)
    };
    let set = PluginSet::new()
        .with(hooked("a", &["on_test_start"]))
        .unwrap()
        .with(hooked("b", &[]))
        .unwrap();
    assert_eq!(block_on(set.on_test_start(&TestInfo::new("t"))).len(), 1);
    assert_eq!(entries(&log), ["a:start t", "b:start t"]);
}

// ---- protocol events and before_close -----------------------------------

#[test]
fn a_protocol_event_goes_only_to_plugins_that_asked_for_its_name() {
    let log = log();
    let listening = |name, events| Probe {
        events,
        ..Probe::named(name, &log)
    };
    let set = PluginSet::new()
        .with(listening("logs", &["Log.entryAdded"]))
        .unwrap()
        .with(listening(
            "errors",
            &["Runtime.exceptionThrown", "Log.entryAdded"],
        ))
        .unwrap()
        .with(listening("deaf", &[]))
        .unwrap();
    assert_eq!(
        set.protocol_events(),
        ["Log.entryAdded", "Runtime.exceptionThrown"]
    );
    let browser = RecordingBrowser::new();
    let event = ProtocolEvent::new("Log.entryAdded", json!({"entry": {}}));
    assert!(block_on(set.on_protocol_event(&browser, &event)).is_empty());
    let other = ProtocolEvent::new("Runtime.exceptionThrown", Value::Null);
    block_on(set.on_protocol_event(&browser, &other));
    assert_eq!(
        entries(&log),
        [
            "logs:event Log.entryAdded",
            "errors:event Log.entryAdded",
            "errors:event Runtime.exceptionThrown"
        ]
    );
}

#[test]
fn target_and_browser_events_need_the_matching_cdp_capability() {
    let log = log();
    let listening = |name, grant: Option<Capability>| {
        let mut probe = Probe {
            events: &["Target.targetCreated"],
            ..Probe::named(name, &log)
        };
        probe.caps.extend(grant);
        probe
    };
    let target = Capability::Cdp("Target".into());
    let set = PluginSet::new()
        .with(listening("blind", None))
        .unwrap()
        .with_trusted(
            listening("allowed", Some(target.clone())),
            std::slice::from_ref(&target),
        )
        .unwrap();
    assert_eq!(set.protocol_events(), ["Target.targetCreated"]);
    block_on(set.on_protocol_event(
        &RecordingBrowser::new(),
        &ProtocolEvent::new("Target.targetCreated", Value::Null),
    ));
    assert_eq!(entries(&log), ["allowed:event Target.targetCreated"]);
}

#[test]
fn before_close_reaches_every_plugin_and_collects_failures() {
    let log = log();
    let set = PluginSet::new()
        .with(Probe {
            fail: &["before_close"],
            ..Probe::named("a", &log)
        })
        .unwrap()
        .with(Probe::named("b", &log))
        .unwrap();
    let failures = block_on(set.before_close(&RecordingBrowser::new()));
    assert_eq!(failures.len(), 1);
    assert_eq!(entries(&log), ["a:before_close", "b:before_close"]);
}

// ---- what the set checks before anything starts -------------------------

fn launch() -> LaunchContext {
    LaunchContext {
        engine: Engine::Cdp,
        family: BrowserFamily::Chromium,
        headless: true,
        connecting: false,
    }
}

#[test]
fn webdriver_refuses_plugins_that_need_contexts_tasks_or_test_hooks() {
    for capability in [
        Capability::Contexts,
        Capability::Task,
        Capability::TestHooks,
    ] {
        let set = PluginSet::new()
            .with(Probe::named("needy", &log()).with(capability.clone()))
            .unwrap();
        set.check_with(&launch(), &HostInfo::cdp()).unwrap();
        let error = set
            .check_with(&launch(), &HostInfo::webdriver(BrowserFamily::Chromium))
            .unwrap_err();
        assert!(
            matches!(&error, PluginError::Unsupported { capability: c, .. } if *c == capability.to_string()),
            "{capability}: {error:?}"
        );
    }
}

#[test]
fn a_set_made_from_grants_runs_hooks_only_for_what_was_granted() {
    let log = log();
    let plugin = Probe::named("a", &log).with(Capability::TestHooks);
    let set = PluginSet::new()
        .with_grants(plugin, CapabilitySet::new())
        .unwrap();
    assert!(block_on(set.on_test_start(&TestInfo::new("t"))).is_empty());
    assert!(entries(&log).is_empty());
}

#[test]
fn a_set_knows_its_timer_only_when_given_one() {
    use std::sync::Arc;
    use std::time::Duration;
    let set = PluginSet::new();
    assert!(set.clock().is_none());
    let timer = Arc::new(seleniumbase_rs_plugin_testing::ManualTimer::new());
    let set = set.with_timer(timer.clone());
    let clock = set.clock().unwrap();
    timer.advance(Duration::from_secs(2));
    assert_eq!(clock.now_ms(), Timer::now_ms(timer.as_ref()));
    // The timer survives `for_launch`.
    assert!(set.for_launch().clock().is_some());
}

// ---- handle defaults ----------------------------------------------------

struct Bare;

#[async_trait]
impl PageHandle for Bare {
    fn engine(&self) -> Engine {
        Engine::Cdp
    }
    async fn send(&self, _method: &str, _params: Value) -> Result<Value> {
        Ok(Value::Null)
    }
    async fn add_init_script(&self, _source: &str) -> Result<()> {
        Ok(())
    }
    async fn evaluate(&self, expression: &str) -> Result<Value> {
        Ok(if expression == "location.href" {
            json!("https://bare.test/")
        } else {
            Value::Null
        })
    }
}

#[async_trait]
impl BrowserHandle for Bare {
    fn engine(&self) -> Engine {
        Engine::Cdp
    }
    fn family(&self) -> BrowserFamily {
        BrowserFamily::Chromium
    }
    async fn send(&self, _method: &str, _params: Value) -> Result<Value> {
        Ok(Value::Null)
    }
}

#[test]
fn a_handle_that_offers_nothing_new_says_so_and_url_falls_back_to_evaluate() {
    let page: &dyn PageHandle = &Bare;
    assert_eq!(block_on(page.url()).unwrap(), "https://bare.test/");
    assert_eq!(page.id().as_str(), "unknown");
    assert!(page.context().is_none());
    for error in [
        block_on(page.navigate("https://x.test/")).unwrap_err(),
        block_on(page.block_urls(&["*.png".to_owned()])).unwrap_err(),
        block_on(page.close()).unwrap_err(),
    ] {
        assert!(matches!(error, PluginError::NotSupported(_)), "{error:?}");
    }
    let browser: &dyn BrowserHandle = &Bare;
    assert!(browser.extensions().is_empty());
    assert_eq!(browser.id().as_str(), "unknown");
    assert!(matches!(
        block_on(browser.new_context(ContextSettings::new())).err().unwrap(),
        PluginError::NotSupported(what) if what == "new_context"
    ));
    assert!(matches!(
        block_on(browser.new_page(None)).err().unwrap(),
        PluginError::NotSupported(what) if what == "new_page"
    ));
}
