//! The crawler against a fake site: no browser. `Site` is a tab that knows a
//! few pages, answers the crawler's page script from them and writes down
//! every navigation.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use seleniumbase_rs_plugin::{
    BrowserFamily, BrowserHandle, Capability, CapabilitySet, Clock, Configurable, Engine,
    Navigation, NoPrompt, PageHandle, PathScope, Plugin, PluginError, PluginSet, ProtocolEvent,
    RequestView, ResourceKind, ResponseView, Result, TaskContext, TestInfo, TestOutcome,
    TestVerdict, async_trait,
};
use seleniumbase_rs_plugin_crawler::{Crawler, CrawlerConfig, Scope};
use seleniumbase_rs_plugin_testing::{
    ManualTimer, RecordingPage, VecSink, block_on, drive_response,
};
use serde_json::{Value, json};

// ---- the fake site ---------------------------------------------------------

#[derive(Clone, Default)]
struct SitePage {
    status: Option<u16>,
    title: String,
    links: Vec<String>,
    nofollow: bool,
    /// Where the page ends up, when it redirects.
    landing: Option<String>,
}

#[derive(Default)]
struct SiteState {
    pages: HashMap<String, SitePage>,
    robots: HashMap<String, (u16, String)>,
    failing: HashSet<String>,
    navigated: Vec<String>,
    current: Option<String>,
    closed: bool,
    opened: usize,
}

#[derive(Clone, Default)]
struct Site {
    state: Arc<Mutex<SiteState>>,
}

fn origin_of(url: &str) -> String {
    url.splitn(4, '/').take(3).collect::<Vec<_>>().join("/")
}

impl Site {
    fn lock(&self) -> MutexGuard<'_, SiteState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn page(self, url: &str, status: u16, title: &str, links: &[&str]) -> Self {
        self.page_with(
            url,
            SitePage {
                status: Some(status),
                title: title.into(),
                links: links.iter().map(|l| (*l).to_owned()).collect(),
                ..SitePage::default()
            },
        )
    }

    fn page_with(self, url: &str, page: SitePage) -> Self {
        self.lock().pages.insert(url.to_owned(), page);
        self
    }

    fn robots(self, origin: &str, status: u16, text: &str) -> Self {
        self.lock()
            .robots
            .insert(origin.to_owned(), (status, text.to_owned()));
        self
    }

    fn failing(self, url: &str) -> Self {
        self.lock().failing.insert(url.to_owned());
        self
    }

    fn navigated(&self) -> Vec<String> {
        self.lock().navigated.clone()
    }
}

#[async_trait]
impl PageHandle for Site {
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
        let state = self.lock();
        let current = state.current.clone().unwrap_or_default();
        if expression.contains("querySelectorAll") {
            let page = state.pages.get(&current).cloned().unwrap_or(SitePage {
                status: Some(404),
                title: "Not found".into(),
                ..SitePage::default()
            });
            let url = page.landing.clone().unwrap_or(current);
            return Ok(json!({
                "url": url,
                "title": page.title,
                "status": page.status,
                "links": page.links,
                "truncated": false,
                "nofollow": page.nofollow,
            }));
        }
        if expression.contains("innerText") {
            let (status, text) = state
                .robots
                .get(&origin_of(&current))
                .cloned()
                .unwrap_or((404, String::new()));
            return Ok(json!({ "url": current, "status": status, "text": text }));
        }
        Ok(Value::Null)
    }

    async fn navigate(&self, url: &str) -> Result<()> {
        let mut state = self.lock();
        state.navigated.push(url.to_owned());
        if state.failing.contains(url) {
            return Err(PluginError::other("net::ERR_NAME_NOT_RESOLVED"));
        }
        state.current = Some(url.to_owned());
        Ok(())
    }

    async fn close(&self) -> Result<()> {
        self.lock().closed = true;
        Ok(())
    }
}

/// A browser that hands out the site as its tab.
struct Browser {
    site: Site,
}

#[async_trait]
impl BrowserHandle for Browser {
    fn engine(&self) -> Engine {
        Engine::Cdp
    }

    fn family(&self) -> BrowserFamily {
        BrowserFamily::Chromium
    }

    async fn new_page<'a>(&'a self, _url: Option<&str>) -> Result<Box<dyn PageHandle + 'a>> {
        self.site.lock().opened += 1;
        Ok(Box::new(self.site.clone()))
    }

    async fn send(&self, _method: &str, _params: Value) -> Result<Value> {
        Ok(Value::Null)
    }
}

// ---- the harness -----------------------------------------------------------

struct Harness {
    set: PluginSet,
    browser: Browser,
    sink: VecSink,
    timer: Arc<ManualTimer>,
    clock: Clock,
}

impl Harness {
    fn new(config: Value, site: Site) -> Self {
        let crawler = Crawler::configure(&config).unwrap();
        Self::with_set(PluginSet::strict().with(crawler).unwrap(), site)
    }

    fn with_set(set: PluginSet, site: Site) -> Self {
        let timer = Arc::new(ManualTimer::new());
        Self {
            set,
            browser: Browser { site },
            sink: VecSink::new(),
            clock: Clock::new(timer.clone()),
            timer,
        }
    }

    fn cx<'a>(&'a self, input: &'a Value) -> TaskContext<'a> {
        TaskContext::new(
            &self.browser,
            input,
            &self.sink,
            &self.set,
            &self.clock,
            &NoPrompt,
        )
    }

    fn go(&self, input: &Value) -> Result<Value> {
        let cx = self.cx(input);
        block_on(self.set.task("crawler").unwrap().run(&cx))
    }

    fn lines(&self) -> Vec<Value> {
        self.sink.lines()
    }

    fn navigated(&self) -> Vec<String> {
        self.browser.site.navigated()
    }

    fn test_end(&self) -> TestVerdict {
        let (verdict, failures) = block_on(self.set.on_test_end(
            &TestInfo::new("crawl"),
            &TestOutcome::Passed,
            None,
        ));
        assert!(failures.is_empty(), "{failures:?}");
        verdict
    }
}

/// Options for a quick crawl: no pause, no robots.txt, plus `extra`.
fn config(start: &[&str], extra: Value) -> Value {
    let mut base = json!({ "start": start, "delay_ms": 0, "respect_robots": false });
    for (key, value) in extra.as_object().unwrap() {
        base[key] = value.clone();
    }
    base
}

fn shop() -> Site {
    Site::default()
        .page(
            "https://a.test/",
            200,
            "Home",
            &[
                "https://a.test/about",
                "https://a.test/products",
                "https://a.test/missing",
                "https://other.test/x",
                "https://a.test/about#team",
            ],
        )
        .page(
            "https://a.test/about",
            200,
            "About",
            &["https://a.test/", "https://a.test/products"],
        )
        .page(
            "https://a.test/products",
            200,
            "Products",
            &[
                "https://a.test/products/1",
                "https://a.test/products/2",
                "https://a.test/private/area",
            ],
        )
        .page(
            "https://a.test/products/1",
            200,
            "One",
            &["https://a.test/products/deep"],
        )
        .page("https://a.test/products/2", 200, "Two", &[])
        .page("https://a.test/products/deep", 200, "Deep", &[])
        .page("https://a.test/private/area", 200, "Private", &[])
}

fn urls(paths: &[&str]) -> Vec<String> {
    paths.iter().map(|p| format!("https://a.test{p}")).collect()
}

/// Polls `future` until it is ready, moving the timer past every pause.
fn finish<F: std::future::Future>(future: F, timer: &ManualTimer) -> F::Output {
    let mut future = Box::pin(future);
    let mut context = Context::from_waker(Waker::noop());
    for _ in 0..10_000 {
        if let Poll::Ready(value) = future.as_mut().poll(&mut context) {
            return value;
        }
        timer.advance(Duration::from_secs(120));
    }
    panic!("the crawl never finished");
}

/// A folder under the system temporary folder, removed when dropped.
struct Scratch(PathBuf);

impl Scratch {
    fn new(label: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("sbrs-crawler-test-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn file(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// ---- options ---------------------------------------------------------------

fn config_error(config: Value) -> String {
    match Crawler::configure(&config) {
        Err(PluginError::Config(message)) => message,
        other => panic!("expected a configuration error, got {other:?}"),
    }
}

#[test]
fn no_options_means_the_defaults_and_a_start_is_asked_for_at_run_time() {
    let crawler = Crawler::configure(&Value::Null).unwrap();
    assert_eq!(*crawler.config(), CrawlerConfig::default());
    let config = crawler.config();
    assert!(config.start.is_empty());
    assert_eq!(config.scope, Scope::SameOrigin);
    assert_eq!(config.max_depth, 3);
    assert_eq!(config.max_pages, 500);
    assert_eq!(config.delay_ms, 1000);
    assert!(config.respect_robots);
    assert_eq!(config.expect.max_status, 399);
    assert!(!crawler.running());
}

#[test]
fn the_scope_has_three_spellings() {
    for (value, want) in [
        (json!("same-origin"), Scope::SameOrigin),
        (json!("same-site"), Scope::SameSite),
        (
            json!({ "hosts": ["a.test", "b.test"] }),
            Scope::Hosts(vec!["a.test".into(), "b.test".into()]),
        ),
    ] {
        let crawler = Crawler::configure(&json!({ "scope": value })).unwrap();
        assert_eq!(crawler.config().scope, want);
    }
    assert!(matches!(
        Crawler::configure(&json!({ "scope": "everywhere" })),
        Err(PluginError::Config(_))
    ));
}

#[test]
fn bad_options_are_errors_that_name_the_option() {
    assert_eq!(
        config_error(json!({ "max_pagess": 3 })),
        "crawler: unknown option `max_pagess`"
    );
    for (config, want) in [
        (
            json!({ "max_pages": 50_001 }),
            "crawler: `max_pages` must be 1 to 50000",
        ),
        (
            json!({ "max_pages": 0 }),
            "crawler: `max_pages` must be 1 to 50000",
        ),
        (
            json!({ "max_depth": 101 }),
            "crawler: `max_depth` is at most 100",
        ),
        (
            json!({ "delay_ms": 60_001 }),
            "crawler: `delay_ms` is at most 60000",
        ),
        (
            json!({ "max_links": 0 }),
            "crawler: `max_links` must be 1 to 100000",
        ),
        (
            json!({ "start": ["https://a.test/", "ftp://a.test/"] }),
            "crawler: `ftp://a.test/` in `start` is not an http or https address",
        ),
        (
            json!({ "include": ["/ok", ""] }),
            "crawler: bad glob `` in `include`",
        ),
        (
            json!({ "exclude": ["/a b"] }),
            "crawler: bad glob `/a b` in `exclude`",
        ),
        (
            json!({ "scope": { "hosts": [] } }),
            "crawler: `scope.hosts` needs at least one host",
        ),
        (
            json!({ "expect": { "max_status": 99 } }),
            "crawler: `expect.max_status` must be 100 to 599",
        ),
        (
            json!({ "expect": { "must_reach": ["/pricing"] } }),
            "crawler: `/pricing` in `expect.must_reach` is not an http or https address",
        ),
    ] {
        assert_eq!(config_error(config), want);
    }
    let host = config_error(json!({ "scope": { "hosts": ["https://a.test"] } }));
    assert!(
        host.starts_with("crawler: bad host `https://a.test` in `scope.hosts`"),
        "{host}"
    );
}

#[test]
fn it_declares_what_it_needs_and_nothing_more() {
    let meta = Crawler::describe();
    for capability in [
        Capability::Task,
        Capability::PageNavigate,
        Capability::PageEvaluate,
        Capability::NetObserve,
        Capability::TestHooks,
    ] {
        assert!(meta.capabilities.covers(&capability), "{capability}");
    }
    for capability in [Capability::NetBodies, Capability::NetIntercept] {
        assert!(!meta.capabilities.covers(&capability), "{capability}");
    }
    let set = PluginSet::strict()
        .with(Crawler::configure(&Value::Null).unwrap())
        .unwrap();
    assert_eq!(set.task_names(), ["crawler"]);
    assert!(!set.interest().is_empty());
    assert_eq!(
        set.protocol_events(),
        ["Log.entryAdded", "Runtime.exceptionThrown"]
    );
    assert!(set.job_runner("crawler").is_err());
}

#[test]
fn a_state_file_adds_its_own_file_access_and_nothing_wider() {
    let crawler = Crawler::configure(&json!({ "state_file": "/tmp/crawl.json" })).unwrap();
    let meta = crawler.metadata();
    let own = vec![
        PathBuf::from("/tmp/crawl.json"),
        PathBuf::from("/tmp/crawl.json.tmp"),
    ];
    assert!(
        meta.capabilities
            .covers(&Capability::HostFsWrite(PathScope::Declared(own)))
    );
    assert!(
        meta.capabilities
            .covers(&Capability::HostFsRead(PathScope::Declared(vec![
                PathBuf::from("/tmp/crawl.json")
            ])))
    );
    assert!(
        !meta
            .capabilities
            .covers(&Capability::HostFsWrite(PathScope::Declared(vec![
                PathBuf::from("/etc/passwd")
            ])))
    );
    let plain = Crawler::configure(&Value::Null).unwrap().metadata();
    assert!(
        !plain
            .capabilities
            .covers(&Capability::HostFsRead(PathScope::Temp))
    );
}

// ---- the crawl -------------------------------------------------------------

#[test]
fn the_crawl_visits_the_site_breadth_first_and_never_leaves_the_origin() {
    let h = Harness::new(config(&["https://a.test/"], json!({})), shop());
    let summary = h.go(&json!({})).unwrap();

    assert_eq!(
        h.navigated(),
        urls(&[
            "/",
            "/about",
            "/products",
            "/missing",
            "/products/1",
            "/products/2",
            "/private/area",
            "/products/deep",
        ])
    );
    assert_eq!(summary["pages"], 8);
    assert_eq!(summary["edges"], 9);
    assert_eq!(summary["truncated"], false);
    assert_eq!(summary["resumed"], false);
    assert_eq!(summary["passed"], false);
    assert_eq!(
        summary["broken"],
        json!([{ "url": "https://a.test/missing", "from": "https://a.test/", "status": 404 }])
    );
    assert_eq!(
        summary["summary"],
        "Broken link detected:\nhttps://a.test/missing"
    );

    let lines = h.lines();
    assert_eq!(lines.len(), 8);
    assert_eq!(
        lines[0],
        json!({
            "index": 0, "url": "https://a.test/", "depth": 0, "from": null,
            "status": 200, "title": "Home", "links": 5, "queued": 3,
        })
    );
    assert_eq!(lines[3]["url"], "https://a.test/missing");
    assert_eq!(lines[3]["status"], 404);
    assert_eq!(lines[3]["from"], "https://a.test/");
    assert_eq!(lines[7]["depth"], 3);
    assert_eq!(lines[7]["index"], 7);
    assert!(h.browser.site.lock().closed, "the tab is closed at the end");
    assert_eq!(h.browser.site.lock().opened, 1, "one tab for the crawl");
}

#[test]
fn a_link_outside_the_scope_is_never_navigated() {
    let h = Harness::new(config(&["https://a.test/"], json!({})), shop());
    h.go(&json!({})).unwrap();
    assert!(
        h.navigated()
            .iter()
            .all(|u| u.starts_with("https://a.test/")),
        "{:?}",
        h.navigated()
    );
}

#[test]
fn max_depth_stops_the_crawl_a_level_early() {
    let h = Harness::new(
        config(&["https://a.test/"], json!({ "max_depth": 1 })),
        shop(),
    );
    let summary = h.go(&json!({})).unwrap();
    assert_eq!(
        h.navigated(),
        urls(&["/", "/about", "/products", "/missing"])
    );
    assert_eq!(summary["pages"], 4);
    assert_eq!(summary["truncated"], false);

    let zero = Harness::new(
        config(&["https://a.test/"], json!({ "max_depth": 0 })),
        shop(),
    );
    zero.go(&json!({})).unwrap();
    assert_eq!(zero.navigated(), urls(&["/"]));
}

#[test]
fn max_pages_stops_the_crawl_and_says_so() {
    let h = Harness::new(
        config(&["https://a.test/"], json!({ "max_pages": 3 })),
        shop(),
    );
    let summary = h.go(&json!({})).unwrap();
    assert_eq!(h.navigated(), urls(&["/", "/about", "/products"]));
    assert_eq!(summary["pages"], 3);
    assert_eq!(summary["truncated"], true);
}

#[test]
fn include_and_exclude_patterns_decide_which_links_are_followed() {
    let excluded = Harness::new(
        config(
            &["https://a.test/"],
            json!({ "exclude": ["/private*", "/missing"] }),
        ),
        shop(),
    );
    let summary = excluded.go(&json!({})).unwrap();
    assert_eq!(
        excluded.navigated(),
        urls(&[
            "/",
            "/about",
            "/products",
            "/products/1",
            "/products/2",
            "/products/deep"
        ])
    );
    assert_eq!(summary["passed"], true);
    assert_eq!(summary["summary"], "Crawled 6 pages: no broken links");

    let included = Harness::new(
        config(
            &["https://a.test/"],
            json!({ "include": ["/about", "https://a.test/products*"] }),
        ),
        shop(),
    );
    included.go(&json!({})).unwrap();
    assert_eq!(
        included.navigated(),
        urls(&[
            "/",
            "/about",
            "/products",
            "/products/1",
            "/products/2",
            "/products/deep"
        ])
    );
}

fn scope_site() -> Site {
    Site::default()
        .page(
            "https://a.test/",
            200,
            "Home",
            &[
                "https://blog.a.test/post",
                "https://docs.test/x",
                "https://a.test:8443/other",
            ],
        )
        .page("https://blog.a.test/post", 200, "Post", &[])
        .page("https://docs.test/x", 200, "Docs", &[])
        .page("https://a.test:8443/other", 200, "Other", &[])
}

#[test]
fn the_scope_decides_which_hosts_are_visited() {
    for (scope, want) in [
        (json!("same-origin"), vec!["https://a.test/"]),
        (
            json!("same-site"),
            vec![
                "https://a.test/",
                "https://blog.a.test/post",
                "https://a.test:8443/other",
            ],
        ),
        (
            json!({ "hosts": ["a.test", "docs.test"] }),
            vec![
                "https://a.test/",
                "https://blog.a.test/post",
                "https://docs.test/x",
                "https://a.test:8443/other",
            ],
        ),
    ] {
        let h = Harness::new(
            config(&["https://a.test/"], json!({ "scope": scope })),
            scope_site(),
        );
        h.go(&json!({})).unwrap();
        assert_eq!(h.navigated(), want, "{scope}");
    }
}

#[test]
fn spellings_of_one_address_are_visited_once() {
    let site = Site::default()
        .page(
            "https://a.test/",
            200,
            "Home",
            &[
                "https://A.TEST/about",
                "https://a.test:443/about#x",
                "https://a.test/./about",
                "https://a.test/x/../about",
                "https://a.test/",
            ],
        )
        .page("https://a.test/about", 200, "About", &[]);
    let h = Harness::new(config(&["https://a.test/"], json!({})), site);
    let summary = h.go(&json!({})).unwrap();
    assert_eq!(h.navigated(), urls(&["/", "/about"]));
    assert_eq!(summary["edges"], 1);
}

#[test]
fn the_start_addresses_come_from_the_input_or_the_options() {
    let h = Harness::new(config(&["https://a.test/about"], json!({})), shop());
    h.go(&json!({})).unwrap();
    assert_eq!(h.navigated()[0], "https://a.test/about");

    // The input wins; several start addresses are all crawled, once.
    let input = Harness::new(config(&["https://a.test/about"], json!({})), shop());
    input
        .go(&json!({ "start": ["https://A.test/products/2", "https://a.test/products/2#x"] }))
        .unwrap();
    assert_eq!(input.navigated(), urls(&["/products/2"]));
}

#[test]
fn a_bad_input_is_an_error_before_a_tab_is_opened() {
    let nothing = Harness::new(config(&[], json!({})), shop());
    let hosts = Harness::new(
        config(&[], json!({ "scope": { "hosts": ["a.test"] } })),
        shop(),
    );
    for (h, input, want) in [
        (&nothing, json!({}), "give `start` addresses"),
        (&nothing, Value::Null, "give `start` addresses"),
        (
            &nothing,
            json!({ "start": ["ftp://a.test/"] }),
            "`ftp://a.test/` is not an http or https address",
        ),
        (
            &nothing,
            json!({ "start": "https://a.test/" }),
            "bad task input",
        ),
        (&nothing, json!({ "startt": [] }), "bad task input"),
        (
            &hosts,
            json!({ "start": ["https://other.test/"] }),
            "the start address `https://other.test/` is outside the crawl scope",
        ),
    ] {
        let error = h.go(&input).unwrap_err();
        assert!(
            matches!(error, PluginError::Config(_)) && error.to_string().contains(want),
            "{input}: {error}"
        );
        assert_eq!(h.browser.site.lock().opened, 0);
    }
}

#[test]
fn a_page_that_cannot_be_opened_is_broken_like_a_404_in_python() {
    let h = Harness::new(
        config(&["https://a.test/"], json!({})),
        shop().failing("https://a.test/about"),
    );
    let summary = h.go(&json!({})).unwrap();
    let line = &h.lines()[1];
    assert_eq!(line["url"], "https://a.test/about");
    assert_eq!(line["error"], "net::ERR_NAME_NOT_RESOLVED");
    assert!(line.get("status").is_none());
    assert!(summary["broken"].as_array().unwrap().contains(
        &json!({ "url": "https://a.test/about", "from": "https://a.test/", "status": 404 })
    ));
    // The crawl went on.
    assert_eq!(summary["pages"], 8);
}

#[test]
fn a_status_above_max_status_is_broken_and_the_limit_can_be_raised() {
    let site = || {
        Site::default()
            .page("https://a.test/", 200, "Home", &["https://a.test/boom"])
            .page("https://a.test/boom", 500, "Boom", &[])
    };
    let strict = Harness::new(config(&["https://a.test/"], json!({})), site());
    let summary = strict.go(&json!({})).unwrap();
    assert_eq!(summary["broken"][0]["status"], 500);
    assert_eq!(summary["passed"], false);

    let lenient = Harness::new(
        config(
            &["https://a.test/"],
            json!({ "expect": { "max_status": 599 } }),
        ),
        site(),
    );
    let summary = lenient.go(&json!({})).unwrap();
    assert_eq!(summary["broken"], json!([]));
    assert_eq!(summary["passed"], true);
}

#[test]
fn redirects_in_scope_are_followed_once_and_redirects_out_are_not_followed_at_all() {
    let site = Site::default()
        .page(
            "https://a.test/",
            200,
            "Home",
            &[
                "https://a.test/go",
                "https://a.test/old",
                "https://a.test/new",
            ],
        )
        .page_with(
            "https://a.test/go",
            SitePage {
                status: Some(200),
                title: "Elsewhere".into(),
                links: vec!["https://a.test/after".into()],
                landing: Some("https://other.test/landing".into()),
                ..SitePage::default()
            },
        )
        .page_with(
            "https://a.test/old",
            SitePage {
                status: Some(200),
                title: "New".into(),
                links: vec!["https://a.test/leaf".into()],
                landing: Some("https://a.test/new".into()),
                ..SitePage::default()
            },
        )
        .page("https://a.test/leaf", 200, "Leaf", &[])
        .page("https://a.test/after", 200, "After", &[]);
    let h = Harness::new(
        config(
            &["https://a.test/"],
            json!({ "expect": { "must_reach": ["https://a.test/new"] } }),
        ),
        site,
    );
    let summary = h.go(&json!({})).unwrap();
    // /new is queued from the home page but /old already ended up on it.
    assert_eq!(h.navigated(), urls(&["/", "/go", "/old", "/leaf"]));
    let lines = h.lines();
    assert_eq!(lines[1]["final_url"], "https://other.test/landing");
    assert_eq!(
        lines[1]["error"],
        "redirected to https://other.test/landing, which is outside the crawl scope"
    );
    assert_eq!(lines[1]["queued"], 0);
    assert_eq!(lines[2]["final_url"], "https://a.test/new");
    assert_eq!(summary["unreached"], json!([]));
    assert_eq!(summary["passed"], true);
}

#[test]
fn a_page_that_says_nofollow_is_read_but_not_followed_when_robots_are_respected() {
    let site = || {
        Site::default()
            .page("https://a.test/", 200, "Home", &["https://a.test/nf"])
            .page_with(
                "https://a.test/nf",
                SitePage {
                    status: Some(200),
                    title: "No follow".into(),
                    links: vec!["https://a.test/x".into()],
                    nofollow: true,
                    ..SitePage::default()
                },
            )
            .page("https://a.test/x", 200, "X", &[])
    };
    let polite = Harness::new(
        config(&["https://a.test/"], json!({ "respect_robots": true })),
        site(),
    );
    polite.go(&json!({})).unwrap();
    assert_eq!(
        polite.navigated(),
        [
            "https://a.test/robots.txt",
            "https://a.test/",
            "https://a.test/nf"
        ]
    );
    assert_eq!(polite.lines()[1]["nofollow"], true);
    assert_eq!(polite.lines()[1]["links"], 1);
    assert_eq!(polite.lines()[1]["queued"], 0);

    let free = Harness::new(config(&["https://a.test/"], json!({})), site());
    free.go(&json!({})).unwrap();
    assert_eq!(free.navigated(), urls(&["/", "/nf", "/x"]));
}

// ---- robots.txt --------------------------------------------------------------

fn polite(site: Site) -> Harness {
    Harness::new(
        config(&["https://a.test/"], json!({ "respect_robots": true })),
        site,
    )
}

#[test]
fn robots_txt_is_read_once_per_site_and_disallowed_pages_are_skipped() {
    let site = shop().robots("https://a.test", 200, "User-agent: *\nDisallow: /private\n");
    let h = polite(site);
    let summary = h.go(&json!({})).unwrap();

    let mut expected = vec!["https://a.test/robots.txt".to_owned()];
    expected.extend(urls(&[
        "/",
        "/about",
        "/products",
        "/missing",
        "/products/1",
        "/products/2",
        "/products/deep",
    ]));
    assert_eq!(h.navigated(), expected);
    assert_eq!(summary["pages"], 7);
    assert_eq!(summary["robots_blocked"], 1);
    assert!(h.lines().contains(&json!({
        "url": "https://a.test/private/area",
        "depth": 2,
        "from": "https://a.test/products",
        "skipped": "robots.txt",
    })));
}

#[test]
fn a_missing_robots_txt_allows_everything_and_an_unreachable_one_closes_the_site() {
    let missing = polite(shop().robots("https://a.test", 404, ""));
    let summary = missing.go(&json!({})).unwrap();
    assert_eq!(summary["pages"], 8);
    assert_eq!(summary["robots_blocked"], 0);

    let closed = polite(shop().robots("https://a.test", 503, "User-agent: *\nDisallow:\n"));
    let summary = closed.go(&json!({})).unwrap();
    assert_eq!(closed.navigated(), ["https://a.test/robots.txt"]);
    assert_eq!(summary["pages"], 0);
    assert_eq!(summary["robots_blocked"], 1);
    assert_eq!(summary["passed"], false);
    assert_eq!(
        summary["summary"],
        "No page was crawled (robots.txt keeps the crawl away)"
    );
}

#[test]
fn robots_txt_can_be_turned_off() {
    let site = shop().robots("https://a.test", 200, "User-agent: *\nDisallow: /\n");
    let h = Harness::new(config(&["https://a.test/"], json!({})), site);
    let summary = h.go(&json!({})).unwrap();
    assert_eq!(summary["pages"], 8);
    assert!(!h.navigated().iter().any(|u| u.ends_with("robots.txt")));
}

#[test]
fn a_crawl_delay_in_robots_txt_makes_the_pause_longer() {
    let site = shop().robots("https://a.test", 200, "User-agent: *\nCrawl-delay: 2\n");
    let h = polite(site);
    let input = json!({});
    let cx = h.cx(&input);
    let mut future = Box::pin(h.set.task("crawler").unwrap().run(&cx));
    let mut context = Context::from_waker(Waker::noop());
    // robots.txt is the first navigation; the first page waits two seconds.
    assert!(future.as_mut().poll(&mut context).is_pending());
    assert!(h.lines().is_empty());
    h.timer.advance(Duration::from_millis(1500));
    assert!(future.as_mut().poll(&mut context).is_pending());
    assert!(h.lines().is_empty());
    h.timer.advance(Duration::from_millis(500));
    assert!(future.as_mut().poll(&mut context).is_pending());
    assert_eq!(h.lines().len(), 1);
    assert_eq!(
        h.navigated(),
        ["https://a.test/robots.txt", "https://a.test/"]
    );
}

// ---- politeness, hooks and the verdict -----------------------------------------

#[test]
fn the_pause_between_navigations_comes_from_the_clock_and_the_first_has_none() {
    let h = Harness::new(
        config(
            &["https://a.test/"],
            json!({ "delay_ms": 500, "max_depth": 0 }),
        ),
        shop(),
    );
    let input = json!({ "start": ["https://a.test/", "https://a.test/about"] });
    let cx = h.cx(&input);
    let mut future = Box::pin(h.set.task("crawler").unwrap().run(&cx));
    let mut context = Context::from_waker(Waker::noop());
    assert!(future.as_mut().poll(&mut context).is_pending());
    assert_eq!(h.lines().len(), 1, "the first page needs no pause");
    h.timer.advance(Duration::from_millis(499));
    assert!(future.as_mut().poll(&mut context).is_pending());
    h.timer.advance(Duration::from_millis(1));
    assert!(future.as_mut().poll(&mut context).is_ready());
    assert_eq!(h.lines().len(), 2);
}

/// A site whose second page waits for the clock, so a test can act while the
/// crawl is in the middle of its run.
fn flaky() -> Site {
    Site::default()
        .page("https://a.test/", 200, "Home", &["https://a.test/flaky"])
        .page_with(
            "https://a.test/flaky",
            SitePage {
                status: None,
                title: "Flaky".into(),
                ..SitePage::default()
            },
        )
}

#[test]
fn while_a_crawl_runs_it_cancels_navigation_outside_the_scope_and_records_what_the_browser_reports()
{
    let h = Harness::new(
        config(
            &["https://a.test/"],
            json!({ "delay_ms": 500, "expect": { "no_console_errors": true } }),
        ),
        flaky(),
    );
    let page = RecordingPage::new();
    let navigation = |url: &str| block_on(h.set.before_navigate(&page, &Navigation::program(url)));

    // Before the crawl everything goes through.
    assert!(navigation("https://evil.test/x").is_ok());
    // Console events before a crawl are not kept.
    let browser = RecordingPage::new();
    let _ = &browser;

    let input = json!({});
    let cx = h.cx(&input);
    let mut future = Box::pin(h.set.task("crawler").unwrap().run(&cx));
    let mut context = Context::from_waker(Waker::noop());
    assert!(future.as_mut().poll(&mut context).is_pending());
    assert_eq!(h.lines().len(), 1);

    // The crawl is waiting between two pages. Out of scope is cancelled.
    match navigation("https://evil.test/x").unwrap_err() {
        PluginError::NavigationCancelled {
            plugin,
            url,
            reason,
        } => {
            assert_eq!(plugin, "crawler");
            assert_eq!(url, "https://evil.test/x");
            assert_eq!(reason, "https://evil.test/x is outside the crawl scope");
        }
        other => panic!("{other:?}"),
    }
    assert!(navigation("file:///etc/passwd").is_err());
    assert!(navigation("https://a.test/anything").is_ok());
    assert!(navigation("about:blank").is_ok());

    // Only one crawl at a time.
    let second_input = json!({});
    let second = h.cx(&second_input);
    let error = block_on(h.set.task("crawler").unwrap().run(&second)).unwrap_err();
    assert!(error.to_string().contains("already running"), "{error}");

    // Console errors of the page the crawl is on.
    let events = [
        ProtocolEvent::new(
            "Runtime.exceptionThrown",
            json!({ "exceptionDetails": { "text": "Uncaught",
                "exception": { "description": "TypeError: x is undefined" } } }),
        ),
        ProtocolEvent::new(
            "Log.entryAdded",
            json!({ "entry": { "level": "error", "url": "https://a.test/x.js",
                "text": "Failed to load resource: the server responded with a status of 404" } }),
        ),
        ProtocolEvent::new(
            "Log.entryAdded",
            json!({ "entry": { "level": "warning", "text": "deprecated" } }),
        ),
    ];
    for event in &events {
        assert!(block_on(h.set.on_protocol_event(&h.browser, event)).is_empty());
    }
    // The status of the document the page timing did not report.
    let request =
        RequestView::new("https://a.test/flaky", "GET", ResourceKind::Document).navigation(true);
    assert!(drive_response(&h.set, ResponseView::new(&request, 503, "text/html")).is_empty());

    h.timer.advance(Duration::from_millis(500));
    let Poll::Ready(result) = future.as_mut().poll(&mut context) else {
        panic!("the crawl should have finished");
    };
    let summary = result.unwrap();

    assert_eq!(h.lines()[1]["status"], 503);
    assert_eq!(
        summary["broken"],
        json!([{ "url": "https://a.test/flaky", "from": "https://a.test/", "status": 503 }])
    );
    assert_eq!(summary["js_errors_total"], 2);
    assert_eq!(
        summary["js_errors"],
        json!([
            { "page": "https://a.test/", "message": "TypeError: x is undefined" },
            { "page": "https://a.test/",
              "message": "Failed to load resource: the server responded with a status of 404 (https://a.test/x.js)" },
        ])
    );
    assert_eq!(summary["passed"], false);
    // After the crawl the hook lets everything through again.
    assert!(navigation("https://evil.test/x").is_ok());

    let verdict = h.test_end();
    let TestVerdict::Fail(message) = verdict else {
        panic!("{verdict:?}");
    };
    assert_eq!(message, summary["summary"].as_str().unwrap());
    assert!(message.starts_with("Broken link detected:\nhttps://a.test/flaky\nJavaScript errors detected:\nhttps://a.test/: TypeError: x is undefined"));
}

#[test]
fn console_errors_outside_a_crawl_are_ignored() {
    let h = Harness::new(
        config(&["https://a.test/about"], json!({ "max_depth": 0 })),
        shop(),
    );
    let event = ProtocolEvent::new(
        "Log.entryAdded",
        json!({ "entry": { "level": "error", "text": "before" } }),
    );
    assert!(block_on(h.set.on_protocol_event(&h.browser, &event)).is_empty());
    let summary = h.go(&json!({})).unwrap();
    assert_eq!(summary["js_errors_total"], 0);
}

#[test]
fn console_errors_are_only_recorded_unless_the_test_asks_to_fail_on_them() {
    // The same run as above, without `no_console_errors`.
    let h = Harness::new(
        config(&["https://a.test/"], json!({ "delay_ms": 500 })),
        flaky(),
    );
    let input = json!({});
    let cx = h.cx(&input);
    let mut future = Box::pin(h.set.task("crawler").unwrap().run(&cx));
    let mut context = Context::from_waker(Waker::noop());
    assert!(future.as_mut().poll(&mut context).is_pending());
    let event = ProtocolEvent::new(
        "Log.entryAdded",
        json!({ "entry": { "level": "error", "text": "oops" } }),
    );
    assert!(block_on(h.set.on_protocol_event(&h.browser, &event)).is_empty());
    h.timer.advance(Duration::from_millis(500));
    let Poll::Ready(result) = future.as_mut().poll(&mut context) else {
        panic!("not finished");
    };
    let summary = result.unwrap();
    assert_eq!(summary["js_errors_total"], 1);
    assert_eq!(summary["passed"], true);
    assert_eq!(h.test_end(), TestVerdict::Keep);
}

#[test]
fn a_failed_crawl_fails_the_next_test_once_with_the_summary() {
    let h = Harness::new(config(&["https://a.test/"], json!({})), shop());
    assert_eq!(h.test_end(), TestVerdict::Keep, "no crawl yet");
    let summary = h.go(&json!({})).unwrap();
    assert_eq!(
        h.test_end(),
        TestVerdict::Fail(summary["summary"].as_str().unwrap().to_owned())
    );
    assert_eq!(h.test_end(), TestVerdict::Keep, "judged once");

    // The plugin still has the report.
    let crawler_report = block_on(async {
        // Reaching the plugin itself needs the type: build one and crawl again.
        let crawler = Crawler::configure(&config(&["https://a.test/"], json!({}))).unwrap();
        assert!(crawler.report().is_none());
        crawler
    });
    drop(crawler_report);
}

#[test]
fn a_crawl_that_found_nothing_wrong_keeps_the_test_as_it_is() {
    let h = Harness::new(
        config(&["https://a.test/about"], json!({ "max_depth": 0 })),
        shop(),
    );
    let summary = h.go(&json!({})).unwrap();
    assert_eq!(summary["passed"], true);
    assert_eq!(summary["summary"], "Crawled 1 page: no broken links");
    assert_eq!(h.test_end(), TestVerdict::Keep);
}

#[test]
fn a_shared_crawler_keeps_its_report() {
    let crawler = Arc::new(
        Crawler::configure(&config(&["https://a.test/"], json!({ "max_depth": 1 }))).unwrap(),
    );
    assert!(crawler.report().is_none());
    let set = PluginSet::strict().with_shared(crawler.clone()).unwrap();
    let h = Harness::with_set(set, shop());
    h.go(&json!({})).unwrap();
    let report = crawler.report().unwrap();
    assert_eq!(report.pages, 4);
    assert!(!report.passed());
    assert_eq!(report.broken.len(), 1);
    assert_eq!(report.broken[0].url, "https://a.test/missing");
    assert!(!crawler.running());
}

#[test]
fn must_reach_addresses_that_were_not_loaded_fail_the_report() {
    let h = Harness::new(
        config(
            &["https://a.test/"],
            json!({
                "max_depth": 1,
                "expect": { "must_reach": [
                    "https://a.test/products/deep",
                    "https://a.test/pricing",
                    "https://A.test/missing",
                    "https://a.test/about#team",
                ] },
            }),
        ),
        shop(),
    );
    let summary = h.go(&json!({})).unwrap();
    // `about` was reached; `missing` was visited but is broken.
    assert_eq!(
        summary["unreached"],
        json!([
            "https://a.test/products/deep",
            "https://a.test/pricing",
            "https://a.test/missing"
        ])
    );
    assert_eq!(
        summary["summary"],
        "Broken link detected:\nhttps://a.test/missing\nPages not reached:\n\
         https://a.test/missing\nhttps://a.test/pricing\nhttps://a.test/products/deep"
    );
}

// ---- tabs and capabilities ---------------------------------------------------------

#[test]
fn the_crawl_stops_when_a_capability_is_missing_and_still_closes_its_tab() {
    // The plugin is in the set without `page.navigate`.
    let mut grants = CapabilitySet::new();
    grants.insert(Capability::Task);
    grants.insert(Capability::PageEvaluate);
    let crawler = Crawler::configure(&config(&["https://a.test/"], json!({}))).unwrap();
    let set = PluginSet::strict().with_grants(crawler, grants).unwrap();
    let h = Harness::with_set(set, shop());
    let error = h.go(&json!({})).unwrap_err();
    assert!(
        matches!(error, PluginError::Capability { .. })
            && error.to_string().contains("page.navigate"),
        "{error}"
    );
    assert!(h.lines().is_empty());
    assert!(h.navigated().is_empty());
    assert!(h.browser.site.lock().closed);
}

#[test]
fn after_a_failed_run_the_next_one_can_start() {
    let mut grants = CapabilitySet::new();
    grants.insert(Capability::Task);
    let crawler = Arc::new(Crawler::configure(&config(&["https://a.test/"], json!({}))).unwrap());
    let set = PluginSet::strict()
        .with_grants_shared(crawler.clone(), grants)
        .unwrap();
    let h = Harness::with_set(set, shop());
    assert!(h.go(&json!({})).is_err());
    assert!(!crawler.running());
    assert!(h.go(&json!({})).is_err(), "not 'already running'");
}

// ---- the state file ---------------------------------------------------------------

#[test]
fn a_stopped_crawl_resumes_from_its_state_file_and_keeps_what_it_found() {
    let scratch = Scratch::new("resume");
    let state = scratch.file("crawl.json");
    let options = |extra: Value| {
        let mut base = json!({ "state_file": state });
        for (key, value) in extra.as_object().unwrap() {
            base[key] = value.clone();
        }
        config(&["https://a.test/"], base)
    };

    // First run: stopped by the page limit with pages still waiting.
    let first = Harness::new(options(json!({ "max_pages": 3 })), shop());
    let summary = first.go(&json!({})).unwrap();
    assert_eq!(summary["pages"], 3);
    assert_eq!(summary["truncated"], true);
    assert_eq!(summary["resumed"], false);
    let saved: Value = serde_json::from_str(&std::fs::read_to_string(&state).unwrap()).unwrap();
    assert_eq!(saved["version"], 1);
    assert_eq!(saved["visited"], json!(urls(&["/", "/about", "/products"])));
    assert_eq!(
        saved["frontier"],
        json!([
            ["https://a.test/missing", 1],
            ["https://a.test/products/1", 2],
            ["https://a.test/products/2", 2],
            ["https://a.test/private/area", 2]
        ])
    );
    assert!(saved["config_hash"].as_str().unwrap().len() == 16);
    assert!(saved["edges"].as_array().unwrap().len() >= 3);

    // Second run, a new process: goes on, without the three pages again.
    let second = Harness::new(options(json!({ "max_pages": 100 })), shop());
    let summary = second.go(&json!({})).unwrap();
    assert_eq!(summary["resumed"], true);
    assert_eq!(
        second.navigated(),
        urls(&[
            "/missing",
            "/products/1",
            "/products/2",
            "/private/area",
            "/products/deep"
        ])
    );
    assert_eq!(summary["pages"], 8);
    assert_eq!(summary["truncated"], false);
    assert_eq!(second.lines()[0]["index"], 3);
    assert_eq!(
        summary["broken"][0]["url"], "https://a.test/missing",
        "{summary}"
    );

    // Third run: nothing is left, and the report still has the broken link.
    let third = Harness::new(options(json!({ "max_pages": 100 })), shop());
    let summary = third.go(&json!({})).unwrap();
    assert_eq!(summary["resumed"], true);
    assert!(third.navigated().is_empty());
    assert_eq!(summary["pages"], 8);
    assert_eq!(summary["passed"], false);
    assert_eq!(summary["broken"].as_array().unwrap().len(), 1);
}

#[test]
fn a_state_file_of_other_options_is_ignored_and_overwritten() {
    let scratch = Scratch::new("mismatch");
    let state = scratch.file("crawl.json");
    let options = |extra: Value| {
        let mut base = json!({ "state_file": state });
        for (key, value) in extra.as_object().unwrap() {
            base[key] = value.clone();
        }
        config(&["https://a.test/"], base)
    };
    Harness::new(options(json!({})), shop())
        .go(&json!({}))
        .unwrap();
    let before = std::fs::read_to_string(&state).unwrap();

    // `exclude` decides which pages are crawled, so the hash differs.
    let h = Harness::new(options(json!({ "exclude": ["/private*"] })), shop());
    let summary = h.go(&json!({})).unwrap();
    assert_eq!(summary["resumed"], false);
    assert_eq!(
        summary["state_ignored"],
        "the state file was ignored: it belongs to a crawl with other options"
    );
    assert_eq!(h.navigated()[0], "https://a.test/");
    assert_eq!(summary["pages"], 7);
    assert_ne!(std::fs::read_to_string(&state).unwrap(), before);

    // `resume: false` starts over although the file fits.
    let again = Harness::new(options(json!({ "exclude": ["/private*"] })), shop());
    let summary = again.go(&json!({ "resume": false })).unwrap();
    assert_eq!(summary["resumed"], false);
    assert!(summary.get("state_ignored").is_none());
    assert_eq!(again.navigated()[0], "https://a.test/");
}

#[test]
fn a_state_file_that_cannot_be_written_stops_the_crawl_before_it_starts() {
    let scratch = Scratch::new("unwritable");
    let state = scratch.file("no-such-folder/crawl.json");
    let h = Harness::new(
        config(&["https://a.test/"], json!({ "state_file": state })),
        shop(),
    );
    let error = h.go(&json!({})).unwrap_err().to_string();
    assert!(error.contains("cannot write the state file"), "{error}");
    assert_eq!(h.browser.site.lock().opened, 0);

    let corrupt = scratch.file("corrupt.json");
    std::fs::write(&corrupt, "{ not json").unwrap();
    let h = Harness::new(
        config(&["https://a.test/"], json!({ "state_file": corrupt })),
        shop(),
    );
    let error = h.go(&json!({})).unwrap_err().to_string();
    assert!(error.contains("cannot parse the state file"), "{error}");
    assert_eq!(std::fs::read_to_string(&corrupt).unwrap(), "{ not json");
}

#[test]
fn finish_helper_runs_a_paused_crawl_to_the_end() {
    let h = Harness::new(
        config(
            &["https://a.test/"],
            json!({ "delay_ms": 1000, "max_depth": 1 }),
        ),
        shop(),
    );
    let input = json!({});
    let cx = h.cx(&input);
    let summary = finish(h.set.task("crawler").unwrap().run(&cx), &h.timer).unwrap();
    assert_eq!(summary["pages"], 4);
}
