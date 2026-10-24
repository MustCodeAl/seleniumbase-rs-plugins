//! Rules for the requests a browser sends, a record of the responses it gets,
//! and a task that fetches a list of URLs through it, with its cookies.
//!
//! The fetcher works on what the user's own browser session does. It does not
//! make requests the browser would not make, it does not hide anything, and it
//! sends nothing anywhere else.
//!
//! ```
//! use seleniumbase_rs_plugin::PluginSet;
//! use seleniumbase_rs_plugin_fetcher::{Fetcher, FetcherConfig};
//!
//! let config = FetcherConfig {
//!     strip: vec!["image".into(), "font".into()],
//!     block: vec!["*://ads.example.com/*".into()],
//!     capture: vec!["*/api/*".into()],
//!     ..FetcherConfig::default()
//! };
//! let fetcher = Fetcher::new(config)?;
//! let plugins = PluginSet::strict().with(fetcher)?;
//! assert_eq!(plugins.names(), ["fetcher"]);
//! # Ok::<(), seleniumbase_rs_plugin::PluginError>(())
//! ```
//!
//! # Rules and records
//!
//! Everything is declared in [`Plugin::network`]: the host runs the rules and
//! the plugin is not called for them.
//!
//! - `strip` fails the requests of some kinds of resource, `block` those whose
//!   URL matches a pattern.
//! - `headers` adds request headers, to every request or only to those that
//!   match `header_urls`.
//! - `capture` records the responses whose URL matches, up to
//!   `max_body_bytes` of each body, in a log of at most `max_captures`
//!   entries (the oldest go first). Read it with [`Fetcher::captured`] or
//!   drain it with [`Fetcher::take_captured`]. The request headers in a
//!   record are redacted for `Cookie`, `Authorization`, `Proxy-Authorization`
//!   and `Set-Cookie`: the plugin does not hold `net.sensitive`.
//!
//! `strip` and `block` overlap with the `block-resources` plugin: that one is
//! the preset, this one is for rules of your own and for the records.
//!
//! # Fetching
//!
//! The plugin is a [`JobRunner`] (`{"url": "https://..."}` gives
//! `{"url", "status", "mime", "text", "truncated"}`) and a [`Task`]
//! (`{"urls": [...]}`). Both call `fetch(url, { credentials: "include" })`
//! inside a page, so the request obeys that page's cross-origin rules, carries
//! the cookies the browser holds for the site, and goes through the proxy and
//! privacy plugins like any other. The task therefore opens each site's front
//! page first (`warm_up`, on by default) so the fetch is same-origin.
//!
//! # Not covered
//!
//! The host decides how interception works. Without it, only `strip` and
//! `block` can be applied (through `Network.setBlockedURLs`); `headers` and
//! `capture` then do nothing, and the host says so.

mod capture;
mod config;
mod job;

use std::sync::Arc;

use seleniumbase_rs_plugin::{
    BrowserHandle, Capability, Category, Configurable, JobRunner, Metadata, NetRule,
    NetworkInterest, PageHandle, Plugin, PluginError, RequestFilter, Requirements, ResponseView,
    Result, Task, TaskContext, async_trait, config::options,
};
use serde_json::{Value, json};

pub use capture::Captured;
pub use config::{FetcherConfig, MAX_BODY_LIMIT, MAX_CAPTURES_LIMIT, MAX_HEADERS};
pub use job::{MAX_DELAY_MS, MAX_URLS};

use capture::{CaptureLog, now_ms};
use job::{Job, TaskInput, origin, read_reply};

/// The name the plugin is enabled by.
const NAME: &str = "fetcher";

/// The fetcher plugin. See the [crate documentation](crate).
#[derive(Debug)]
pub struct Fetcher {
    config: FetcherConfig,
    interest: NetworkInterest,
    log: Arc<CaptureLog>,
}

impl Fetcher {
    /// Builds the plugin from `config`.
    ///
    /// # Errors
    ///
    /// [`PluginError::Config`] for an unknown resource kind in `strip`, a bad
    /// glob, a header that cannot be set, or a limit out of range.
    pub fn new(config: FetcherConfig) -> Result<Self> {
        let checked = config.check()?;
        let mut interest = NetworkInterest::none();
        if !checked.kinds.is_empty() {
            interest = interest.rule(NetRule::block(RequestFilter::any().kinds(checked.kinds)));
        }
        for glob in &config.block {
            interest = interest.rule(NetRule::block(RequestFilter::any().url(glob.as_str())));
        }
        if !config.headers.is_empty() {
            if config.header_urls.is_empty() {
                interest = interest.rule(NetRule::set_headers(
                    RequestFilter::any(),
                    config.headers.clone(),
                ));
            }
            for glob in &config.header_urls {
                interest = interest.rule(NetRule::set_headers(
                    RequestFilter::any().url(glob.as_str()),
                    config.headers.clone(),
                ));
            }
        }
        for glob in &config.capture {
            let mut filter = RequestFilter::any().url(glob.as_str());
            if config.max_body_bytes > 0 {
                filter = filter.max_body(config.max_body_bytes);
            }
            interest = interest.observe(filter);
        }
        let log = Arc::new(CaptureLog::new(config.max_captures));
        Ok(Self {
            config,
            interest,
            log,
        })
    }

    /// The options the plugin was built with.
    #[must_use]
    pub fn config(&self) -> &FetcherConfig {
        &self.config
    }

    /// The responses recorded so far, oldest first.
    #[must_use]
    pub fn captured(&self) -> Vec<Captured> {
        self.log.snapshot()
    }

    /// The responses recorded so far, oldest first, and empties the log.
    #[must_use]
    pub fn take_captured(&self) -> Vec<Captured> {
        self.log.take()
    }

    /// How many responses the log holds.
    #[must_use]
    pub fn captured_len(&self) -> usize {
        self.log.len()
    }

    /// How many records were pushed out of the log because it was full.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.log.dropped()
    }

    /// Fetches the URL of `job` in `page`.
    async fn fetch(&self, page: &dyn PageHandle, job: &Job) -> Result<Value> {
        let script = job.script(self.config.max_body_bytes)?;
        let reply = page.evaluate(&script).await?;
        read_reply(&reply)
    }
}

#[async_trait]
impl Plugin for Fetcher {
    fn name(&self) -> &str {
        NAME
    }

    fn requirements(&self) -> Requirements {
        Requirements::CHROMIUM_ONLY
    }

    fn metadata(&self) -> Metadata {
        Self::describe()
    }

    fn network(&self) -> NetworkInterest {
        self.interest.clone()
    }

    async fn on_response(&self, response: &ResponseView<'_>) -> Result<()> {
        self.log.push(Captured::of(response, now_ms()));
        Ok(())
    }

    fn task(&self) -> Option<&dyn Task> {
        Some(self)
    }

    fn job_runner(&self) -> Option<&dyn JobRunner> {
        Some(self)
    }
}

#[async_trait]
impl JobRunner for Fetcher {
    /// Runs `{"url": "https://...", "max_bytes": N}` in `page`: the page
    /// fetches the address with its cookies and the answer is
    /// `{"url", "status", "mime", "text", "truncated"}`. The page must be on
    /// the site of the address (or the site must allow it), as for any
    /// `fetch` call.
    async fn run_job(&self, page: &dyn PageHandle, job: &Value) -> Result<Value> {
        self.fetch(page, &Job::parse(job)?).await
    }
}

#[async_trait]
impl Task for Fetcher {
    /// Fetches `{"urls": [...]}` one after the other in one tab.
    ///
    /// `delay_ms` (default 0) pauses between fetches. With `warm_up` (default
    /// true) the tab goes to the front page of a site before the first fetch
    /// from it, so the fetch is same-origin and carries the site's cookies;
    /// `false` fetches from wherever the tab is.
    ///
    /// Each URL records one line to the sink, `{"index", "url", "status",
    /// "mime", "text", "truncated"}` or `{"index", "url", "error"}`. A URL
    /// that fails does not stop the others; a missing capability does. The
    /// summary is `{"total", "ok", "failed", "captured"}`.
    async fn run(&self, cx: &TaskContext<'_>) -> Result<Value> {
        let input = TaskInput::parse(cx.input)?;
        let browser = cx.plugins.guarded_browser(NAME, cx.browser)?;
        let page = browser.new_page(None).await?;
        let mut here: Option<String> = None;
        let mut ok = 0_u64;
        let mut failed = 0_u64;
        let mut outcome = Ok(());
        for (index, url) in input.urls.iter().enumerate() {
            if index > 0 && !input.delay().is_zero() {
                cx.clock.sleep(input.delay()).await;
            }
            let fetched = async {
                let site = origin(url)?;
                if input.warm_up && here.as_deref() != Some(site.as_str()) {
                    page.navigate(&format!("{site}/")).await?;
                    here = Some(site);
                }
                self.fetch(&*page, &Job::parse(&json!({ "url": url }))?)
                    .await
            }
            .await;
            let line = match fetched {
                Ok(mut reply) => {
                    ok += 1;
                    reply["index"] = json!(index);
                    reply["url"] = json!(url);
                    reply
                }
                Err(error @ PluginError::Capability { .. }) => {
                    outcome = Err(error);
                    break;
                }
                Err(error) => {
                    failed += 1;
                    json!({ "index": index, "url": url, "error": error.to_string() })
                }
            };
            if let Err(error) = cx.sink.record(&line) {
                outcome = Err(error);
                break;
            }
        }
        // The tab is ours: close it whatever happened.
        let _ = page.close().await;
        outcome?;
        Ok(json!({
            "total": input.urls.len(),
            "ok": ok,
            "failed": failed,
            "captured": self.log.len(),
        }))
    }
}

impl Configurable for Fetcher {
    const NAME: &'static str = NAME;

    fn describe() -> Metadata {
        Metadata::new(Category::Core)
            .version(env!("CARGO_PKG_VERSION"))
            .summary("Sets, blocks and records requests, and fetches URLs through the browser")
            .capabilities([
                Capability::NetIntercept,
                Capability::NetObserve,
                Capability::Task,
                Capability::PageEvaluate,
                Capability::PageNavigate,
            ])
            .optional(Capability::NetBodies)
    }

    /// Options: see [`FetcherConfig`].
    fn configure(value: &Value) -> Result<Self> {
        Self::new(options(NAME, value)?)
    }
}
