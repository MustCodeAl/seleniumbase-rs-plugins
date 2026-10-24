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

use seleniumbase_rs_plugin::{
    BrowserFamily, BrowserHandle, Engine, PageHandle, PluginError, Result, async_trait,
};
use serde_json::Value;
use std::sync::Arc;

use seleniumbase_rs_plugin::{ContextHandle, ContextId, ContextSettings, LoadedExtension, PageId};

mod contexts;
mod drive;
mod timer;

pub use contexts::FakeContext;
pub use drive::{VecSink, drive_request, drive_response};
pub use timer::ManualTimer;

/// One thing a plugin asked a fake handle to do.
#[derive(Clone, Debug, PartialEq)]
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

    /// Sets the id [`PageHandle::id`] answers with.
    #[must_use]
    pub fn with_id(mut self, id: PageId) -> Self {
        self.id = id;
        self
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

/// A fake browser that records what a plugin asks of it.
#[derive(Debug)]
pub struct RecordingBrowser {
    engine: Engine,
    family: BrowserFamily,
    recorder: Arc<Recorder>,
    world: Option<Arc<contexts::World>>,
    extensions: Vec<LoadedExtension>,
    made_contexts: Mutex<Vec<FakeContext>>,
    made_pages: Mutex<Vec<RecordingPage>>,
}

impl Default for RecordingBrowser {
    fn default() -> Self {
        Self::new()
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
            made_contexts: Mutex::default(),
            made_pages: Mutex::default(),
        }
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
