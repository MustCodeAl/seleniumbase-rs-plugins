//! Crawls a site you own or may test, from its links, and reports what is
//! broken: pages that do not load or answer an error status, addresses that
//! must be reachable and are not, and errors in the browser console. A test can
//! fail on that report.
//!
//! Use it only on sites you own or have permission to test. It follows plain
//! `<a href>` links with `http` and `https` addresses; it never clicks, submits
//! a form or runs a page's scripts on purpose. It reads `robots.txt` and obeys
//! it unless you turn that off, waits between pages (`delay_ms`, one second by
//! default) and stops at `max_pages`.
//!
//! ```
//! use seleniumbase_rs_plugin::PluginSet;
//! use seleniumbase_rs_plugin_crawler::{Crawler, CrawlerConfig};
//!
//! let config = CrawlerConfig {
//!     start: vec!["https://example.com/".into()],
//!     max_depth: 2,
//!     max_pages: 100,
//!     ..CrawlerConfig::default()
//! };
//! let crawler = Crawler::new(config)?;
//! let plugins = PluginSet::strict().with(crawler)?;
//! assert_eq!(plugins.names(), ["crawler"]);
//! assert_eq!(plugins.task_names(), ["crawler"]);
//! # Ok::<(), seleniumbase_rs_plugin::PluginError>(())
//! ```
//!
//! # The crawl
//!
//! The plugin is a [`Task`] (`sbrs plugin run crawler`). The input is
//! `{"start": [...], "resume": true}`; without `start` the `start` option is
//! used. One tab does the work, breadth first, one navigation at a time:
//!
//! 1. Each address is checked against `robots.txt` of its site. The file is
//!    opened in the tab like any page, so the proxy and privacy plugins apply
//!    to it. A 4xx answer means no rules, a 5xx answer or none means the site
//!    is closed to the crawl. Groups for `sbrs` come before `*`, the longest
//!    rule wins, `Allow` wins a tie and a `Crawl-delay` (at most a minute)
//!    makes the pause longer.
//! 2. The page is opened and one script reads its title, its HTTP status
//!    (from the navigation timing entry, else from the response the host
//!    reported) and its `a[href]` links with an `http(s)` address. A page with
//!    `<meta name="robots" content="nofollow">` is read but its links are not
//!    followed.
//! 3. Each link is normalised (lower-case scheme and host, no default port, no
//!    fragment, dot segments resolved) and dropped when it is already known,
//!    outside the `scope`, not matched by `include` or matched by `exclude`.
//!    The rest wait in line at one depth more.
//!
//! A link outside the scope is never navigated: the crawl does not queue it and
//! the plugin's `before_navigate` hook cancels such a navigation
//! (`<url> is outside the crawl scope`) while a crawl runs. A page that
//! redirects out of the scope is recorded and its links are not followed.
//!
//! # Records and the report
//!
//! Each page writes one line to the sink: `{"index", "url", "depth", "from",
//! "status", "title", "links", "queued"}`, with `final_url` after a redirect,
//! `nofollow`, or `error` (and no `status`) when the page could not be read. A
//! page that robots.txt keeps away writes `{"url", "depth", "from", "skipped":
//! "robots.txt"}`. The task returns the [`Report`] as JSON: `pages`, `edges`
//! (a count), `broken` (`{url, from, status}`), `js_errors`, `unreached`,
//! `robots_blocked`, `truncated`, `passed` and `summary`.
//!
//! A page is **broken** when its status is above `expect.max_status` (399, so
//! every 4xx and 5xx; Python SeleniumBase counts only 404) or when it does not
//! load (counted as 404, as in Python). The text of [`Report::summary`] is the
//! text of Python's `assert_no_404_errors`.
//!
//! # As a test plugin
//!
//! The plugin holds [`Capability::TestHooks`]. After a crawl, the next
//! `on_test_end` fails the test with [`Report::summary`] unless the report
//! [`passed`](Report::passed): no broken page, every `expect.must_reach`
//! address reached, and no console error when `expect.no_console_errors` is
//! set. Console errors come from the DevTools events `Runtime.exceptionThrown`
//! and `Log.entryAdded` (level `error`), which the host delivers to the plugin.
//!
//! # Resuming
//!
//! With `state_file` the crawl is written down (to a temporary file that is
//! renamed over the old one) every few pages and when the run ends, and a later
//! run goes on from it, but only when the options that decide which pages are
//! crawled (`start`, `scope`, `include`, `exclude`, `max_depth`,
//! `respect_robots`) are the same. Another file is ignored and overwritten;
//! `max_pages`, `delay_ms` and `expect` may change between runs.
//!
//! # Not covered
//!
//! Only pages are checked. Images, scripts and stylesheets are not requested
//! on their own, and links outside the scope are counted nowhere: Python
//! SeleniumBase sends a HEAD request for every link, this crawler never leaves
//! the scope. One crawl runs at a time per plugin. `ArtifactsWrite` waits for an
//! artifact API in the plugin host, so the report is returned, not saved.

mod config;
mod crawl;
mod report;
mod robots;
mod scope;
mod state;
mod url;

use std::collections::HashMap;
use std::fmt::Display;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use seleniumbase_rs_plugin::{
    BrowserHandle, Capability, Category, Configurable, Metadata, NavDecision, Navigation,
    NetworkInterest, PageHandle, PathScope, Plugin, PluginError, ProtocolEvent, RequestFilter,
    Requirements, ResourceKind, ResponseView, Result, Task, TaskContext, TestInfo, TestOutcome,
    TestVerdict, async_trait, config::options,
};
use serde_json::Value;

pub use config::{
    CrawlerConfig, Expect, MAX_DELAY_MS, MAX_DEPTH_LIMIT, MAX_LINKS_LIMIT, MAX_LIST,
    MAX_PAGES_LIMIT, Scope,
};
pub use crawl::{MAX_EDGES, MAX_QUEUE};
pub use report::{Broken, JsError, MAX_JS_ERRORS, Report};

use scope::Matcher;
use url::normalise;

/// The name the plugin is enabled by.
const NAME: &str = "crawler";

/// The DevTools events the plugin reads console errors from.
static EVENTS: [&str; 2] = ["Runtime.exceptionThrown", "Log.entryAdded"];

/// The most document statuses kept while a crawl runs.
const MAX_STATUSES: usize = 10_000;

/// The longest console message kept.
const MAX_MESSAGE_CHARS: usize = 500;

/// A configuration or input error of the crawler.
pub(crate) fn bad(why: impl Display) -> PluginError {
    PluginError::Config(format!("crawler: {why}"))
}

/// What the hooks know about the crawl that is running.
#[derive(Debug, Default)]
struct Live {
    active: bool,
    /// The address the crawl is on, for console errors.
    current: Option<String>,
    matcher: Option<Arc<Matcher>>,
    /// The statuses of the documents the host reported.
    statuses: HashMap<String, u16>,
    js_errors: Vec<JsError>,
    js_total: usize,
}

/// The report of the last crawl, and whether a test has been judged by it.
#[derive(Debug)]
struct Finished {
    report: Report,
    judged: bool,
}

/// Marks the crawl as over when dropped, however the run ended.
struct RunGuard<'a>(&'a Crawler);

impl Drop for RunGuard<'_> {
    fn drop(&mut self) {
        let mut live = self.0.live();
        live.active = false;
        live.current = None;
        live.matcher = None;
    }
}

/// The crawler plugin. See the [crate documentation](crate).
#[derive(Debug)]
pub struct Crawler {
    config: CrawlerConfig,
    live: Mutex<Live>,
    finished: Mutex<Option<Finished>>,
}

impl Crawler {
    /// Builds the plugin from `config`.
    ///
    /// # Errors
    ///
    /// [`PluginError::Config`] for a start address that is not `http(s)`, a
    /// bad host or glob, or a limit out of range.
    pub fn new(config: CrawlerConfig) -> Result<Self> {
        config.check()?;
        Ok(Self {
            config,
            live: Mutex::default(),
            finished: Mutex::default(),
        })
    }

    /// The options the plugin was built with.
    #[must_use]
    pub fn config(&self) -> &CrawlerConfig {
        &self.config
    }

    /// The report of the last finished crawl, if there was one.
    #[must_use]
    pub fn report(&self) -> Option<Report> {
        self.finished().as_ref().map(|done| done.report.clone())
    }

    /// Whether a crawl is running.
    #[must_use]
    pub fn running(&self) -> bool {
        self.live().active
    }

    fn live(&self) -> MutexGuard<'_, Live> {
        self.live.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn finished(&self) -> MutexGuard<'_, Option<Finished>> {
        self.finished.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Starts a crawl with `matcher`; one crawl runs at a time.
    fn begin(&self, matcher: &Arc<Matcher>) -> Result<RunGuard<'_>> {
        let mut live = self.live();
        if live.active {
            return Err(PluginError::other("crawler: a crawl is already running"));
        }
        *live = Live {
            active: true,
            matcher: Some(Arc::clone(matcher)),
            ..Live::default()
        };
        Ok(RunGuard(self))
    }

    fn set_current(&self, url: Option<&str>) {
        self.live().current = url.map(str::to_owned);
    }

    /// The status the host reported for the document at `url`.
    fn recorded_status(&self, url: &str) -> Option<u16> {
        self.live().statuses.get(url).copied()
    }
}

#[async_trait]
impl Plugin for Crawler {
    fn name(&self) -> &str {
        NAME
    }

    fn requirements(&self) -> Requirements {
        Requirements::CHROMIUM_ONLY
    }

    /// The metadata of [`Configurable::describe`], plus read and write access
    /// to the `state_file` (and the temporary file beside it) when there is one.
    fn metadata(&self) -> Metadata {
        let mut metadata = Self::describe();
        if let Some(path) = &self.config.state_file {
            let paths = vec![path.clone(), state::temp_path(path)];
            metadata = metadata
                .capability(Capability::HostFsRead(PathScope::Declared(vec![
                    path.clone(),
                ])))
                .capability(Capability::HostFsWrite(PathScope::Declared(paths)));
        }
        metadata
    }

    fn network(&self) -> NetworkInterest {
        NetworkInterest::none().observe(RequestFilter::any().kinds([ResourceKind::Document]))
    }

    fn protocol_events(&self) -> &[&str] {
        &EVENTS
    }

    fn task(&self) -> Option<&dyn Task> {
        Some(self)
    }

    /// While a crawl runs, cancels a navigation to an address outside the
    /// scope. Outside a crawl it lets everything through.
    async fn before_navigate(
        &self,
        _page: &dyn PageHandle,
        navigation: &Navigation,
    ) -> Result<NavDecision> {
        // The blank page a new tab starts on is not a destination.
        if navigation.url == "about:blank" {
            return Ok(NavDecision::Continue);
        }

        let matcher = {
            let live = self.live();
            if !live.active {
                return Ok(NavDecision::Continue);
            }
            live.matcher.clone()
        };
        let allowed = matcher.is_some_and(|matcher| {
            normalise(&navigation.url).is_some_and(|url| matcher.host_allows(&url))
        });
        Ok(if allowed {
            NavDecision::Continue
        } else {
            NavDecision::Cancel(format!("{} is outside the crawl scope", navigation.url))
        })
    }

    /// Keeps the status of the documents loaded during a crawl, for pages whose
    /// navigation timing does not say.
    async fn on_response(&self, response: &ResponseView<'_>) -> Result<()> {
        if response.request.kind != ResourceKind::Document || response.status == 0 {
            return Ok(());
        }
        let Some(url) = normalise(&response.request.url) else {
            return Ok(());
        };
        let mut live = self.live();
        if live.active && (live.statuses.len() < MAX_STATUSES || live.statuses.contains_key(&url)) {
            live.statuses.insert(url, response.status);
        }
        Ok(())
    }

    /// Records the console errors of a crawl.
    async fn on_protocol_event(
        &self,
        _browser: &dyn BrowserHandle,
        event: &ProtocolEvent,
    ) -> Result<()> {
        let message = match event.method.as_str() {
            "Runtime.exceptionThrown" => {
                let details = &event.params["exceptionDetails"];
                details["exception"]["description"]
                    .as_str()
                    .or_else(|| details["text"].as_str())
                    .map(str::to_owned)
            }
            "Log.entryAdded" => {
                let entry = &event.params["entry"];
                if entry["level"] == "error" {
                    entry["text"]
                        .as_str()
                        .map(|text| match entry["url"].as_str() {
                            Some(url) if !url.is_empty() => format!("{text} ({url})"),
                            _ => text.to_owned(),
                        })
                } else {
                    None
                }
            }
            _ => None,
        };
        let Some(message) = message else {
            return Ok(());
        };
        let mut live = self.live();
        if !live.active {
            return Ok(());
        }
        live.js_total += 1;
        if live.js_errors.len() < MAX_JS_ERRORS {
            let page = live.current.clone();
            live.js_errors.push(JsError {
                page,
                message: message.chars().take(MAX_MESSAGE_CHARS).collect(),
            });
        }
        Ok(())
    }

    /// Fails the test with [`Report::summary`] if the last crawl, which no test
    /// has been judged by yet, did not pass.
    async fn on_test_end(
        &self,
        _test: &TestInfo,
        _outcome: &TestOutcome,
        _page: Option<&dyn PageHandle>,
    ) -> Result<TestVerdict> {
        let mut finished = self.finished();
        Ok(match finished.as_mut() {
            Some(done) if !done.judged => {
                done.judged = true;
                if done.report.passed() {
                    TestVerdict::Keep
                } else {
                    TestVerdict::Fail(done.report.summary())
                }
            }
            _ => TestVerdict::Keep,
        })
    }
}

#[async_trait]
impl Task for Crawler {
    /// Crawls from `{"start": [...]}` (else the `start` option) and returns the
    /// report as JSON, with `resumed`. See the [crate documentation](crate) for
    /// the lines written to the sink.
    ///
    /// # Errors
    ///
    /// [`PluginError::Config`] for a bad input, no start address or a start
    /// address outside the scope; an error if a crawl is already running, the
    /// state file cannot be read or written, or a capability is missing. A page
    /// that fails does not stop the crawl.
    async fn run(&self, cx: &TaskContext<'_>) -> Result<Value> {
        self.crawl(cx).await
    }
}

impl Configurable for Crawler {
    const NAME: &'static str = NAME;

    fn describe() -> Metadata {
        Metadata::new(Category::Testing)
            .version(env!("CARGO_PKG_VERSION"))
            .summary("Crawls a site you may test from its links and reports broken pages and console errors")
            .capabilities([
                Capability::Task,
                Capability::PageNavigate,
                Capability::PageEvaluate,
                Capability::NetObserve,
                Capability::TestHooks,
            ])
    }

    /// Options: see [`CrawlerConfig`].
    fn configure(value: &Value) -> Result<Self> {
        Self::new(options(NAME, value)?)
    }
}
