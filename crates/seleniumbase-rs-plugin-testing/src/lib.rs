//! Recording fakes of the seleniumbase-rs plugin handles.
//!
//! [`RecordingPage`] and [`RecordingBrowser`] implement [`PageHandle`] and
//! [`BrowserHandle`] without a browser: they write down every command and
//! script a plugin sends, so a test checks what a hook did.
//!
//! ```
//! use seleniumbase_rs_plugin::{async_trait, PageHandle, Plugin, PluginSet, Result};
//! use seleniumbase_rs_plugin_testing::{Call, RecordingPage};
//!
//! struct Hello;
//!
//! #[async_trait]
//! impl Plugin for Hello {
//!     fn name(&self) -> &str {
//!         "hello"
//!     }
//!     async fn on_page_created(&self, page: &dyn PageHandle) -> Result<()> {
//!         page.add_init_script("window.hello = 1").await
//!     }
//! }
//!
//! # tokio_test_block_on(async {
//! let page = RecordingPage::new();
//! PluginSet::new().with(Hello)?.on_page_created(&page).await?;
//! assert_eq!(page.calls(), [Call::InitScript("window.hello = 1".into())]);
//! # Ok::<(), seleniumbase_rs_plugin::PluginError>(())
//! # }).unwrap();
//! # fn tokio_test_block_on<F: std::future::Future>(future: F) -> F::Output {
//! #     seleniumbase_rs_plugin_testing::block_on(future)
//! # }
//! ```

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use seleniumbase_rs_plugin::{
    BrowserFamily, BrowserHandle, Engine, PageHandle, PluginError, Result, async_trait,
};
use serde_json::Value;
use std::sync::Arc;

use seleniumbase_rs_plugin::{
    Clock, ContextHandle, ContextId, ContextSettings, ExtensionWorker, LoadedExtension, PageId,
};

mod contexts;
mod drive;
mod timer;

pub use contexts::FakeContext;
pub use drive::{VecSink, drive_request, drive_response};
pub use timer::ManualTimer;

/// One thing a plugin asked a fake handle to do.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum Call {
    /// A DevTools Protocol command with its parameters.
    Send(String, Value),
    /// A script for every new document.
    InitScript(String),
    /// An expression to evaluate.
    Evaluate(String),
    /// A navigation to this address.
    Navigate(String),
    /// A question about the tab's current address.
    Url,
    /// A request to close the tab.
    Close,
    /// URL patterns to block.
    BlockUrls(Vec<String>),
    /// A new browser context with these settings.
    NewContext(ContextSettings),
    /// A new tab, at this address if given.
    NewPage(Option<String>),
    /// A request to dispose a context.
    Dispose,
    /// A question about the extension service workers that run now.
    ExtensionWorkers,
}

#[derive(Debug, Default)]
struct Recorder {
    calls: Mutex<Vec<Call>>,
    replies: Mutex<HashMap<String, Value>>,
    failing: Mutex<Option<String>>,
    /// Canned answers to `evaluate`: the first whose text the expression contains.
    evaluations: Mutex<Vec<(String, Value)>>,
    /// The address `url()` answers with; `navigate` changes it.
    location: Mutex<Option<String>>,
}

impl Recorder {
    fn record(&self, call: Call) {
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(call);
    }

    fn calls(&self) -> Vec<Call> {
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn answer(&self, method: &str) -> Result<Value> {
        let failing = self.failing.lock().unwrap_or_else(PoisonError::into_inner);
        if failing.as_deref() == Some(method) {
            return Err(PluginError::other(format!("{method} failed (fake)")));
        }
        let replies = self.replies.lock().unwrap_or_else(PoisonError::into_inner);
        Ok(replies.get(method).cloned().unwrap_or(Value::Null))
    }
}

/// A fake tab that records what a plugin asks of it.
#[derive(Debug)]
pub struct RecordingPage {
    engine: Engine,
    recorder: Arc<Recorder>,
    id: PageId,
    context: Option<ContextId>,
}

/// A clone is another handle to the same tab: both write to one record.
impl Clone for RecordingPage {
    fn clone(&self) -> Self {
        Self {
            engine: self.engine,
            recorder: Arc::clone(&self.recorder),
            id: self.id.clone(),
            context: self.context.clone(),
        }
    }
}

impl Default for RecordingPage {
    fn default() -> Self {
        Self::new()
    }
}

/// Builds a [`RecordingPage`]. [`RecordingPage::builder`] starts from
/// [`RecordingPage::new`]; [`RecordingPage::into_builder`] starts from a page
/// that already exists. `evaluating`, `at`, `in_context`, `failing` and
/// `replying` stay on the page.
#[must_use = "a builder does nothing until `build` is called"]
#[derive(Debug)]
pub struct RecordingPageBuilder {
    page: RecordingPage,
}

impl Default for RecordingPageBuilder {
    fn default() -> Self {
        Self {
            page: RecordingPage::new(),
        }
    }
}

impl RecordingPageBuilder {
    /// Sets the id [`PageHandle::id`] answers with.
    #[must_use]
    pub fn id(mut self, id: PageId) -> Self {
        self.page.id = id;
        self
    }

    /// The page.
    #[must_use]
    pub fn build(self) -> RecordingPage {
        self.page
    }
}

impl RecordingPage {
    /// A fake tab of the pure CDP engine.
    #[must_use]
    pub fn new() -> Self {
        Self::on(Engine::Cdp)
    }

    /// A fake tab of `engine`.
    #[must_use]
    pub fn on(engine: Engine) -> Self {
        Self {
            engine,
            recorder: Arc::default(),
            id: PageId::unknown(),
            context: None,
        }
    }

    /// Makes `evaluate` answer with `reply` for an expression that contains
    /// `substring`; the first match wins, and other expressions answer `null`.
    #[must_use]
    pub fn evaluating(self, substring: &str, reply: Value) -> Self {
        self.recorder
            .evaluations
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((substring.to_owned(), reply));
        self
    }

    /// Sets the address [`PageHandle::url`] answers with.
    #[must_use]
    pub fn at(self, url: &str) -> Self {
        *self
            .recorder
            .location
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(url.to_owned());
        self
    }

    /// A builder that starts from [`new`](Self::new).
    #[must_use]
    pub fn builder() -> RecordingPageBuilder {
        RecordingPageBuilder::default()
    }

    /// A builder that starts from this page.
    #[must_use]
    pub fn into_builder(self) -> RecordingPageBuilder {
        RecordingPageBuilder { page: self }
    }

    /// Puts the tab in a context, which [`PageHandle::context`] reports.
    #[must_use]
    pub fn in_context(mut self, context: ContextId) -> Self {
        self.context = Some(context);
        self
    }

    /// Makes `method` (or `"add_init_script"`, `"evaluate"`) answer with an error.
    #[must_use]
    pub fn failing(self, method: &str) -> Self {
        *self
            .recorder
            .failing
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(method.to_owned());
        self
    }

    /// Makes `method` answer with `reply` (otherwise `null`).
    #[must_use]
    pub fn replying(self, method: &str, reply: Value) -> Self {
        self.recorder
            .replies
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(method.to_owned(), reply);
        self
    }

    /// Everything the plugins asked for, in order.
    #[must_use]
    pub fn calls(&self) -> Vec<Call> {
        self.recorder.calls()
    }
}

#[async_trait]
impl PageHandle for RecordingPage {
    fn engine(&self) -> Engine {
        self.engine
    }

    async fn send(&self, method: &str, params: Value) -> Result<Value> {
        self.recorder.record(Call::Send(method.to_owned(), params));
        self.recorder.answer(method)
    }

    async fn add_init_script(&self, source: &str) -> Result<()> {
        self.recorder.record(Call::InitScript(source.to_owned()));
        self.recorder.answer("add_init_script").map(drop)
    }

    async fn evaluate(&self, expression: &str) -> Result<Value> {
        self.recorder.record(Call::Evaluate(expression.to_owned()));
        let canned = self
            .recorder
            .evaluations
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .find(|(substring, _)| expression.contains(substring.as_str()))
            .map(|(_, reply)| reply.clone());
        match canned {
            Some(reply) => Ok(reply),
            None => self.recorder.answer("evaluate"),
        }
    }

    fn id(&self) -> PageId {
        self.id.clone()
    }

    fn context(&self) -> Option<ContextId> {
        self.context.clone()
    }

    async fn url(&self) -> Result<String> {
        self.recorder.record(Call::Url);
        self.recorder.answer("url")?;
        Ok(self
            .recorder
            .location
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
            .unwrap_or_else(|| "about:blank".to_owned()))
    }

    async fn navigate(&self, url: &str) -> Result<()> {
        self.recorder.record(Call::Navigate(url.to_owned()));
        self.recorder.answer("navigate")?;
        *self
            .recorder
            .location
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(url.to_owned());
        Ok(())
    }

    async fn block_urls(&self, patterns: &[String]) -> Result<()> {
        self.recorder.record(Call::BlockUrls(patterns.to_vec()));
        self.recorder.answer("block_urls").map(drop)
    }

    async fn close(&self) -> Result<()> {
        self.recorder.record(Call::Close);
        self.recorder.answer("close").map(drop)
    }
}

/// The answers of [`BrowserHandle::extension_workers`]: one snapshot for each
/// call, the last one repeating.
#[derive(Debug, Default)]
struct WorkerScript {
    snapshots: Vec<Vec<ExtensionWorker>>,
    next: usize,
}

/// A fake browser that records what a plugin asks of it.
#[derive(Debug)]
pub struct RecordingBrowser {
    engine: Engine,
    family: BrowserFamily,
    recorder: Arc<Recorder>,
    world: Option<Arc<contexts::World>>,
    extensions: Vec<LoadedExtension>,
    workers: Mutex<WorkerScript>,
    clock: Option<Clock>,

    made_contexts: Mutex<Vec<FakeContext>>,
    made_pages: Mutex<Vec<RecordingPage>>,
}

impl Default for RecordingBrowser {
    fn default() -> Self {
        Self::new()
    }
}

/// Builds a [`RecordingBrowser`]. [`RecordingBrowser::builder`] starts from
/// [`RecordingBrowser::new`]; [`RecordingBrowser::into_builder`] starts from a
/// browser that already exists. `failing` and `replying` stay on the browser.
#[must_use = "a builder does nothing until `build` is called"]
#[derive(Debug)]
pub struct RecordingBrowserBuilder {
    browser: RecordingBrowser,
}

impl Default for RecordingBrowserBuilder {
    fn default() -> Self {
        Self {
            browser: RecordingBrowser::new(),
        }
    }
}

impl RecordingBrowserBuilder {
    /// Lets plugins open contexts and tabs (`BrowserHandle::new_context` and
    /// `BrowserHandle::new_page`) and counts them.
    #[must_use]
    pub fn contexts(mut self) -> Self {
        self.browser.world = Some(Arc::new(contexts::World::default()));
        self
    }

    /// Sets the extensions `BrowserHandle::extensions` reports.
    #[must_use]
    pub fn extensions(mut self, extensions: Vec<LoadedExtension>) -> Self {
        self.browser.extensions = extensions;
        self
    }

    /// Scripts [`BrowserHandle::extension_workers`]: the first call answers
    /// with the first snapshot, the second with the second, and the last one
    /// repeats. Without a script the call answers
    /// [`PluginError::NotSupported`], as a host without the query does.
    #[must_use]
    pub fn workers(mut self, snapshots: Vec<Vec<ExtensionWorker>>) -> Self {
        self.browser.workers = Mutex::new(WorkerScript { snapshots, next: 0 });
        self
    }

    /// Gives the browser a clock, which [`BrowserHandle::clock`] reports. A
    /// browser reached through a plugin set reports the set's clock first.
    #[must_use]
    pub fn clock(mut self, clock: Clock) -> Self {
        self.browser.clock = Some(clock);
        self
    }

    /// The browser.
    #[must_use]
    pub fn build(self) -> RecordingBrowser {
        self.browser
    }
}

impl RecordingBrowser {
    /// A fake Chromium browser on the pure CDP engine.
    #[must_use]
    pub fn new() -> Self {
        Self::of(Engine::Cdp, BrowserFamily::Chromium)
    }

    /// A fake browser of `family` on `engine`.
    #[must_use]
    pub fn of(engine: Engine, family: BrowserFamily) -> Self {
        Self {
            engine,
            family,
            recorder: Arc::default(),
            world: None,
            extensions: Vec::new(),
            workers: Mutex::default(),
            clock: None,
            made_contexts: Mutex::default(),
            made_pages: Mutex::default(),
        }
    }

    /// A builder that starts from [`new`](Self::new).
    #[must_use]
    pub fn builder() -> RecordingBrowserBuilder {
        RecordingBrowserBuilder::default()
    }

    /// A builder that starts from this browser.
    #[must_use]
    pub fn into_builder(self) -> RecordingBrowserBuilder {
        RecordingBrowserBuilder { browser: self }
    }

    /// Makes the browser-level command `method` answer with `reply` (otherwise
    /// `null`).
    #[must_use]
    pub fn replying(self, method: &str, reply: Value) -> Self {
        self.recorder
            .replies
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(method.to_owned(), reply);
        self
    }

    /// Everything the plugins asked for, in order.
    #[must_use]
    pub fn calls(&self) -> Vec<Call> {
        self.recorder.calls()
    }
}

#[async_trait]
impl BrowserHandle for RecordingBrowser {
    fn engine(&self) -> Engine {
        self.engine
    }

    fn family(&self) -> BrowserFamily {
        self.family
    }

    fn extensions(&self) -> Vec<LoadedExtension> {
        self.extensions.clone()
    }

    async fn extension_workers(&self) -> Result<Vec<ExtensionWorker>> {
        self.recorder.record(Call::ExtensionWorkers);
        self.recorder.answer("extension_workers")?;
        let mut script = self.workers.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(last) = script.snapshots.len().checked_sub(1) else {
            return Err(PluginError::unsupported("extension_workers"));
        };
        let at = script.next.min(last);
        script.next = at + 1;
        Ok(script.snapshots[at].clone())
    }

    fn clock(&self) -> Option<Clock> {
        self.clock.clone()
    }

    async fn new_context<'a>(
        &'a self,
        settings: ContextSettings,
    ) -> Result<Box<dyn ContextHandle + 'a>> {
        Ok(Box::new(self.make_context(settings)?))
    }

    async fn new_page<'a>(&'a self, url: Option<&str>) -> Result<Box<dyn PageHandle + 'a>> {
        self.make_page(url)
    }

    async fn send(&self, method: &str, params: Value) -> Result<Value> {
        self.recorder.record(Call::Send(method.to_owned(), params));
        self.recorder.answer(method)
    }
}

/// Runs a future to completion on the current thread, for tests and examples
/// that do not want a runtime. The fakes never wait, so nothing else is needed.
pub fn block_on<F: Future>(future: F) -> F::Output {
    use std::pin::pin;
    use std::task::{Context, Poll, Waker};

    let mut future = pin!(future);
    let mut context = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(output) = future.as_mut().poll(&mut context) {
            return output;
        }
        std::thread::yield_now();
    }
}

/// Like [`block_on`] for a future that waits on a [`ManualTimer`]: whenever the
/// future is pending, the timer moves on by `step`, so poll loops and time
/// limits finish without a real wait. A future that waits for something other
/// than the timer never finishes.
///
/// ```
/// use std::sync::Arc;
/// use std::time::Duration;
/// use seleniumbase_rs_plugin::Clock;
/// use seleniumbase_rs_plugin_testing::{block_on_advancing, ManualTimer};
///
/// let timer = Arc::new(ManualTimer::new());
/// let clock = Clock::new(timer.clone());
/// let answer = block_on_advancing(&timer, Duration::from_secs(1), async {
///     clock.sleep(Duration::from_secs(5)).await;
///     "done"
/// });
/// assert_eq!(answer, "done");
/// assert_eq!(timer.elapsed(), Duration::from_secs(5));
/// ```
pub fn block_on_advancing<F: Future>(timer: &ManualTimer, step: Duration, future: F) -> F::Output {
    use std::pin::pin;
    use std::task::{Context, Poll, Waker};

    let mut future = pin!(future);
    let mut context = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(output) = future.as_mut().poll(&mut context) {
            return output;
        }
        timer.advance(step);
    }
}
