//! Fakes shared by the batcher's tests: a plugin with a job runner whose
//! behaviour a test picks, and a rig that runs the batcher's task against the
//! plugin API's fake browser.

#![allow(dead_code)]

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};

use seleniumbase_rs_plugin::{
    Capability, Category, Clock, Configurable, JobRunner, Metadata, NoPrompt, PageHandle, Plugin,
    PluginError, PluginSet, Result, Sink, TaskContext, async_trait,
};
use seleniumbase_rs_plugin_batcher::Batcher;
use seleniumbase_rs_plugin_testing::{ManualTimer, RecordingBrowser, VecSink, block_on};
use serde_json::{Value, json};

/// Gives the other futures a turn: pending once, then ready.
pub struct YieldNow(bool);

pub fn yield_now() -> YieldNow {
    YieldNow(false)
}

impl Future for YieldNow {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.0 {
            Poll::Ready(())
        } else {
            self.0 = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

/// What a [`Worker`] does with a job.
#[derive(Clone, Copy, Debug)]
pub enum Mode {
    /// Answers `{"echo": job}`.
    Echo,
    /// Fails with a browser error for the first `n` tries of a job, then
    /// answers `{"echo": job, "tries": tries}`.
    FailTimes(usize),
    /// Fails, with a browser error, every job whose `n` is odd.
    FailOdd,
    /// Fails like a navigation a plugin cancelled.
    Cancelled,
    /// Fails like a request a plugin blocked.
    Blocked,
    /// Fails because the plugin lacks a capability.
    Capability,
    /// Never answers.
    Stuck,
    /// Evaluates a script in the tab it got and answers `{"value": ...}`.
    Evaluate,
}

/// A plugin with a job runner. A job is `{"n": id, "yields": k}`: the runner
/// gives the other jobs `k` turns before it acts.
pub struct Worker {
    name: &'static str,
    mode: Mode,
    tries: Mutex<HashMap<u64, usize>>,
    total: AtomicUsize,
}

impl Worker {
    pub fn new(name: &'static str, mode: Mode) -> Arc<Self> {
        Arc::new(Self {
            name,
            mode,
            tries: Mutex::default(),
            total: AtomicUsize::new(0),
        })
    }

    /// How often the runner was called.
    pub fn total(&self) -> usize {
        self.total.load(Ordering::SeqCst)
    }

    /// How often the runner was called for the job `n`.
    pub fn tries_of(&self, n: u64) -> usize {
        self.tries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&n)
            .copied()
            .unwrap_or(0)
    }
}

#[async_trait]
impl Plugin for Worker {
    fn name(&self) -> &str {
        self.name
    }

    fn metadata(&self) -> Metadata {
        Metadata::new(Category::Core)
            .capabilities([Capability::PageEvaluate, Capability::PageNavigate])
    }

    fn job_runner(&self) -> Option<&dyn JobRunner> {
        Some(self)
    }
}

#[async_trait]
impl JobRunner for Worker {
    async fn run_job(&self, page: &dyn PageHandle, job: &Value) -> Result<Value> {
        self.total.fetch_add(1, Ordering::SeqCst);
        let n = job["n"].as_u64().unwrap_or(0);
        let tries = {
            let mut tries = self.tries.lock().unwrap_or_else(PoisonError::into_inner);
            let entry = tries.entry(n).or_default();
            *entry += 1;
            *entry
        };
        for _ in 0..job["yields"].as_u64().unwrap_or(0) {
            yield_now().await;
        }
        match self.mode {
            Mode::Echo => Ok(json!({ "echo": job })),
            Mode::FailTimes(failures) if tries <= failures => Err(PluginError::other(format!(
                "net::ERR_CONNECTION_RESET (try {tries})"
            ))),
            Mode::FailTimes(_) => Ok(json!({ "echo": job, "tries": tries })),
            Mode::FailOdd if n % 2 == 1 => Err(PluginError::other("net::ERR_FAILED")),
            Mode::FailOdd => Ok(json!({ "echo": job })),
            Mode::Cancelled => Err(PluginError::NavigationCancelled {
                plugin: "policy".into(),
                url: "https://a.test/".into(),
                reason: "not allowed".into(),
            }),
            Mode::Blocked => Err(PluginError::other(
                "navigation failed: net::ERR_BLOCKED_BY_CLIENT",
            )),
            Mode::Capability => Err(PluginError::Capability {
                plugin: self.name.into(),
                capability: "page.navigate".into(),
                reason: "not granted".into(),
            }),
            Mode::Stuck => std::future::pending().await,
            Mode::Evaluate => page
                .evaluate("1 + 1")
                .await
                .map(|value| json!({ "value": value })),
        }
    }
}

/// A plugin without a job runner.
pub struct Plain;

#[async_trait]
impl Plugin for Plain {
    fn name(&self) -> &str {
        "plain"
    }

    fn metadata(&self) -> Metadata {
        Metadata::new(Category::Core)
    }
}

/// The batcher built from `options`.
pub fn batcher(options: Value) -> Batcher {
    Batcher::configure(&options).unwrap()
}

/// A strict set with the batcher and the workers.
pub fn set_with(options: Value, workers: &[&Arc<Worker>]) -> PluginSet {
    let mut set = PluginSet::strict().with(batcher(options)).unwrap();
    for worker in workers {
        set = set
            .with_shared(Arc::clone(*worker) as Arc<dyn Plugin>)
            .unwrap();
    }
    set
}

/// `count` jobs `{"n": i, "yields": yields, "url": ...}`.
pub fn jobs(count: u64, yields: u64) -> Value {
    json!({ "jobs": (0..count)
        .map(|n| json!({ "n": n, "yields": yields, "url": format!("https://a.test/{n}") }))
        .collect::<Vec<_>>() })
}

/// The `index` of each line, in the order they were written.
pub fn indexes(lines: &[Value]) -> Vec<u64> {
    lines
        .iter()
        .map(|line| line["index"].as_u64().unwrap())
        .collect()
}

/// A fake browser that counts contexts and tabs, a sink, and a clock that
/// moves when a test says so.
pub struct Rig {
    pub browser: RecordingBrowser,
    pub sink: VecSink,
    pub timer: Arc<ManualTimer>,
    pub clock: Clock,
}

impl Rig {
    pub fn new() -> Self {
        Self::with_browser(RecordingBrowser::new().with_contexts())
    }

    pub fn with_browser(browser: RecordingBrowser) -> Self {
        let timer = Arc::new(ManualTimer::new());
        Self {
            browser,
            sink: VecSink::new(),
            clock: Clock::new(timer.clone()),
            timer,
        }
    }

    /// Runs the batcher's task to the end. The fakes never wait, so no time
    /// has to pass.
    pub fn run(&self, set: &PluginSet, input: &Value) -> Result<Value> {
        self.run_with(set, input, &self.sink)
    }

    pub fn run_with(&self, set: &PluginSet, input: &Value, sink: &dyn Sink) -> Result<Value> {
        let cx = TaskContext::new(&self.browser, input, sink, set, &self.clock, &NoPrompt);
        block_on(set.task("batcher").unwrap().run(&cx))
    }
}

/// Polls `future` once with a waker that does nothing.
pub fn poll_once<T>(future: &mut Pin<Box<impl Future<Output = T>>>) -> Poll<T> {
    future
        .as_mut()
        .poll(&mut Context::from_waker(std::task::Waker::noop()))
}
