//! Fake browser contexts and tabs that count how many of them are alive.
//!
//! [`RecordingBrowser::with_contexts`] turns on `new_context` and `new_page`.
//! Contexts and tabs the plugin opens are fakes that write down what happens to
//! them, and the browser counts how many are open at once, so a test can check
//! that a plugin keeps to its concurrency limit and closes what it opens.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use seleniumbase_rs_plugin::{
    ContextHandle, ContextId, ContextSettings, Engine, LoadedExtension, PageHandle, PageId,
    PluginError, Result, async_trait,
};
use serde_json::Value;

use crate::{Call, Recorder, RecordingBrowser, RecordingPage};

#[derive(Clone, Copy, Debug, Default)]
struct Counts {
    contexts_live: usize,
    contexts_max: usize,
    contexts_made: usize,
    pages_live: usize,
    pages_max: usize,
    pages_made: usize,
}

/// What the browser keeps count of.
#[derive(Debug, Default)]
pub(crate) struct World {
    counts: Mutex<Counts>,
}

impl World {
    fn counts(&self) -> MutexGuard<'_, Counts> {
        self.counts.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn open_context(&self) -> usize {
        let mut counts = self.counts();
        counts.contexts_live += 1;
        counts.contexts_made += 1;
        counts.contexts_max = counts.contexts_max.max(counts.contexts_live);
        counts.contexts_made
    }

    fn open_page(&self) -> usize {
        let mut counts = self.counts();
        counts.pages_live += 1;
        counts.pages_made += 1;
        counts.pages_max = counts.pages_max.max(counts.pages_live);
        counts.pages_made
    }

    fn close_pages(&self, count: usize) {
        let mut counts = self.counts();
        counts.pages_live = counts.pages_live.saturating_sub(count);
    }
}

/// A fake browser context. Cloning gives another handle to the same context.
#[derive(Clone, Debug)]
pub struct FakeContext {
    id: ContextId,
    settings: ContextSettings,
    world: Arc<World>,
    recorder: Arc<Recorder>,
    open_pages: Arc<AtomicUsize>,
    disposed: Arc<AtomicBool>,
    pages: Arc<Mutex<Vec<RecordingPage>>>,
}

impl FakeContext {
    /// The settings the context was made with.
    #[must_use]
    pub fn settings(&self) -> &ContextSettings {
        &self.settings
    }

    /// Whether `dispose` was called.
    #[must_use]
    pub fn disposed(&self) -> bool {
        self.disposed.load(Ordering::SeqCst)
    }

    /// The tabs opened in this context, in order.
    #[must_use]
    pub fn pages(&self) -> Vec<RecordingPage> {
        self.pages
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// What was asked of the context itself: [`Call::NewPage`] and
    /// [`Call::Dispose`].
    #[must_use]
    pub fn calls(&self) -> Vec<Call> {
        self.recorder.calls()
    }
}

#[async_trait]
impl ContextHandle for FakeContext {
    fn id(&self) -> &ContextId {
        &self.id
    }

    async fn new_page<'a>(&'a self, url: Option<&str>) -> Result<Box<dyn PageHandle + 'a>> {
        self.recorder.record(Call::NewPage(url.map(str::to_owned)));
        self.recorder.answer("new_page")?;
        let serial = self.world.open_page();
        self.open_pages.fetch_add(1, Ordering::SeqCst);
        let page = RecordingPage::new()
            .with_id(PageId::new(format!("{}-page-{serial}", self.id)))
            .in_context(self.id.clone());
        self.pages
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(page.clone());
        Ok(Box::new(CountedPage {
            page,
            world: Arc::clone(&self.world),
            open_pages: Some(Arc::clone(&self.open_pages)),
            closed: AtomicBool::new(false),
        }))
    }

    async fn dispose(&self) -> Result<()> {
        self.recorder.record(Call::Dispose);
        self.recorder.answer("dispose")?;
        if !self.disposed.swap(true, Ordering::SeqCst) {
            let mut counts = self.world.counts();
            counts.contexts_live = counts.contexts_live.saturating_sub(1);
            drop(counts);
            self.world
                .close_pages(self.open_pages.swap(0, Ordering::SeqCst));
        }
        Ok(())
    }
}

/// Takes one off `counter` unless it is zero; says whether it did.
fn take_one(counter: &AtomicUsize) -> bool {
    let mut current = counter.load(Ordering::SeqCst);
    while current > 0 {
        match counter.compare_exchange(current, current - 1, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => return true,
            Err(actual) => current = actual,
        }
    }
    false
}

/// A recording tab that gives its place back to the count when it is closed.
struct CountedPage {
    page: RecordingPage,
    world: Arc<World>,
    open_pages: Option<Arc<AtomicUsize>>,
    closed: AtomicBool,
}

#[async_trait]
impl PageHandle for CountedPage {
    fn engine(&self) -> Engine {
        self.page.engine()
    }

    fn id(&self) -> PageId {
        PageHandle::id(&self.page)
    }

    fn context(&self) -> Option<ContextId> {
        PageHandle::context(&self.page)
    }

    async fn send(&self, method: &str, params: Value) -> Result<Value> {
        self.page.send(method, params).await
    }

    async fn add_init_script(&self, source: &str) -> Result<()> {
        self.page.add_init_script(source).await
    }

    async fn evaluate(&self, expression: &str) -> Result<Value> {
        self.page.evaluate(expression).await
    }

    async fn url(&self) -> Result<String> {
        self.page.url().await
    }

    async fn navigate(&self, url: &str) -> Result<()> {
        self.page.navigate(url).await
    }

    async fn block_urls(&self, patterns: &[String]) -> Result<()> {
        self.page.block_urls(patterns).await
    }

    async fn close(&self) -> Result<()> {
        self.page.close().await?;
        if !self.closed.swap(true, Ordering::SeqCst) {
            // A tab of a disposed context was already counted out by `dispose`.
            let counted = self.open_pages.as_ref().is_none_or(|open| take_one(open));
            if counted {
                self.world.close_pages(1);
            }
        }
        Ok(())
    }
}

impl RecordingBrowser {
    /// Lets plugins open contexts and tabs (`BrowserHandle::new_context` and
    /// `BrowserHandle::new_page`) and counts them.
    #[must_use]
    pub fn with_contexts(mut self) -> Self {
        self.world = Some(Arc::new(World::default()));
        self
    }

    /// Makes `method` (`"new_context"`, `"new_page"`, `"dispose"` or a protocol
    /// command) answer with an error.
    #[must_use]
    pub fn failing(self, method: &str) -> Self {
        *self
            .recorder
            .failing
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(method.to_owned());
        self
    }

    /// Sets the extensions `BrowserHandle::extensions` reports.
    #[must_use]
    pub fn with_extensions(mut self, extensions: Vec<LoadedExtension>) -> Self {
        self.extensions = extensions;
        self
    }

    fn count<T>(&self, read: impl FnOnce(Counts) -> T) -> T {
        let counts = self
            .world
            .as_ref()
            .map_or_else(Counts::default, |world| *world.counts());
        read(counts)
    }

    /// Contexts open now.
    #[must_use]
    pub fn live_contexts(&self) -> usize {
        self.count(|c| c.contexts_live)
    }

    /// The most contexts that were ever open at once.
    #[must_use]
    pub fn max_live_contexts(&self) -> usize {
        self.count(|c| c.contexts_max)
    }

    /// Contexts made in all.
    #[must_use]
    pub fn contexts_made(&self) -> usize {
        self.count(|c| c.contexts_made)
    }

    /// Tabs open now, in contexts or not.
    #[must_use]
    pub fn live_pages(&self) -> usize {
        self.count(|c| c.pages_live)
    }

    /// The most tabs that were ever open at once.
    #[must_use]
    pub fn max_live_pages(&self) -> usize {
        self.count(|c| c.pages_max)
    }

    /// Tabs opened in all.
    #[must_use]
    pub fn pages_made(&self) -> usize {
        self.count(|c| c.pages_made)
    }

    /// The contexts made so far, in order.
    #[must_use]
    pub fn contexts(&self) -> Vec<FakeContext> {
        self.made_contexts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The tabs opened outside any context, in order.
    #[must_use]
    pub fn pages(&self) -> Vec<RecordingPage> {
        self.made_pages
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub(crate) fn make_context(&self, settings: ContextSettings) -> Result<FakeContext> {
        self.recorder.record(Call::NewContext(settings.clone()));
        self.recorder.answer("new_context")?;
        let world = self
            .world
            .as_ref()
            .ok_or_else(|| PluginError::unsupported("new_context"))?;
        let serial = world.open_context();
        let context = FakeContext {
            id: ContextId::new(format!("context-{serial}")),
            settings,
            world: Arc::clone(world),
            recorder: Arc::default(),
            open_pages: Arc::default(),
            disposed: Arc::default(),
            pages: Arc::default(),
        };
        self.made_contexts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(context.clone());
        Ok(context)
    }

    pub(crate) fn make_page(&self, url: Option<&str>) -> Result<Box<dyn PageHandle + '_>> {
        self.recorder.record(Call::NewPage(url.map(str::to_owned)));
        self.recorder.answer("new_page")?;
        let world = self
            .world
            .as_ref()
            .ok_or_else(|| PluginError::unsupported("new_page"))?;
        let serial = world.open_page();
        let page = RecordingPage::new().with_id(PageId::new(format!("page-{serial}")));
        self.made_pages
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(page.clone());
        Ok(Box::new(CountedPage {
            page,
            world: Arc::clone(world),
            open_pages: None,
            closed: AtomicBool::new(false),
        }))
    }
}
