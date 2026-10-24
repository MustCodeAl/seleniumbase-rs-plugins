//! Tasks, job runners, the clock and the timer.

use std::sync::Arc;
use std::time::Duration;

use seleniumbase_rs_plugin::{
    Capability, Category, Clock, JobRunner, Metadata, NoPrompt, NullSink, PageHandle, Plugin,
    PluginError, PluginSet, Prompt, Result, Sink, Task, TaskContext, Timer, async_trait,
};
use seleniumbase_rs_plugin_testing::{
    Call, ManualTimer, RecordingBrowser, RecordingPage, VecSink, block_on,
};
use serde_json::{Value, json};

/// A plugin with a task that records its input and runs a job through another
/// plugin's runner.
struct Worker {
    name: &'static str,
    with_task: bool,
    caps: Vec<Capability>,
}

impl Worker {
    fn new(name: &'static str) -> Self {
        Self {
            name,
            with_task: true,
            caps: vec![Capability::Task],
        }
    }
}

#[async_trait]
impl Plugin for Worker {
    fn name(&self) -> &str {
        self.name
    }
    fn metadata(&self) -> Metadata {
        Metadata::new(Category::Core).capabilities(self.caps.clone())
    }
    fn task(&self) -> Option<&dyn Task> {
        self.with_task.then_some(self as &dyn Task)
    }
    fn job_runner(&self) -> Option<&dyn JobRunner> {
        Some(self)
    }
}

#[async_trait]
impl Task for Worker {
    async fn run(&self, cx: &TaskContext<'_>) -> Result<Value> {
        cx.sink.record(&json!({"started": cx.input}))?;
        let page = RecordingPage::new();
        let echoed = cx
            .plugins
            .job_runner(self.name)?
            .run_job(&page, &json!({"url": "https://x.test/"}))
            .await?;
        cx.sink.record(&echoed)?;
        // A job that never ends is cut off by the clock's limit.
        let stuck = cx
            .clock
            .timeout(Duration::from_secs(30), std::future::pending::<()>())
            .await;
        Ok(json!({"timed_out": stuck.is_err(), "browser": cx.browser.id().as_str()}))
    }
}

#[async_trait]
impl JobRunner for Worker {
    async fn run_job(&self, page: &dyn PageHandle, job: &Value) -> Result<Value> {
        page.navigate(job["url"].as_str().unwrap_or_default())
            .await?;
        Ok(json!({"at": page.url().await?}))
    }
}

#[test]
fn a_task_gets_the_browser_input_sink_plugins_and_clock() {
    let set = PluginSet::new().with(Worker::new("worker")).unwrap();
    let timer = Arc::new(ManualTimer::new());
    let clock = Clock::new(timer.clone());
    let browser = RecordingBrowser::new();
    let sink = VecSink::new();
    let input = json!({"depth": 2});
    let cx = TaskContext::new(&browser, &input, &sink, &set, &clock, &NoPrompt);
    let task = set.task("worker").unwrap();
    // The task waits on the clock for thirty seconds; the helper moves time on
    // whenever the task is pending, so its time limit runs out.
    let run = task.run(&cx);
    let mut run = std::pin::pin!(run);
    let summary = poll_with_timer(&mut run, &timer);
    assert_eq!(
        summary.unwrap(),
        json!({"timed_out": true, "browser": "unknown"})
    );
    assert_eq!(
        sink.lines(),
        [
            json!({"started": {"depth": 2}}),
            json!({"at": "https://x.test/"})
        ]
    );
}

/// Polls `future`; whenever it is pending, moves the timer an hour on.
fn poll_with_timer<T>(
    future: &mut std::pin::Pin<&mut impl std::future::Future<Output = T>>,
    timer: &ManualTimer,
) -> T {
    use std::task::{Context, Poll, Waker};
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..100 {
        if let Poll::Ready(value) = future.as_mut().poll(&mut cx) {
            return value;
        }
        timer.advance(Duration::from_secs(3600));
    }
    panic!("the task never finished");
}

#[test]
fn task_lookup_explains_each_way_it_can_fail() {
    let set = PluginSet::new()
        .with(Worker::new("worker"))
        .unwrap()
        .with(Worker {
            with_task: false,
            ..Worker::new("no-task")
        })
        .unwrap()
        .with(Worker {
            caps: Vec::new(),
            ..Worker::new("no-cap")
        })
        .unwrap();
    assert!(set.task("worker").is_ok());
    let missing = set.task("ghost").err().unwrap();
    assert!(
        matches!(&missing, PluginError::Config(m) if m.contains("`ghost`")),
        "{missing:?}"
    );
    let none = set.task("no-task").err().unwrap();
    assert!(
        matches!(&none, PluginError::Config(m) if m.contains("offers no task")),
        "{none:?}"
    );
    let denied = set.task("no-cap").err().unwrap();
    assert!(
        matches!(&denied, PluginError::Capability { capability, .. } if capability == "task"),
        "{denied:?}"
    );
    assert_eq!(set.task_names(), ["worker", "no-cap"]);
}

#[test]
fn a_job_runner_is_found_by_plugin_name() {
    let set = PluginSet::new().with(Worker::new("worker")).unwrap();
    let page = RecordingPage::new();
    let result = block_on(
        set.job_runner("worker")
            .unwrap()
            .run_job(&page, &json!({"url": "https://y.test/"})),
    )
    .unwrap();
    assert_eq!(result, json!({"at": "https://y.test/"}));
    assert_eq!(
        page.calls(),
        [Call::Navigate("https://y.test/".into()), Call::Url]
    );
    assert!(set.job_runner("ghost").is_err());
}

#[test]
fn a_set_refuses_a_task_its_plugin_did_not_declare_a_capability_for() {
    use seleniumbase_rs_plugin::{BrowserFamily, Engine, LaunchContext};
    let launch = LaunchContext {
        engine: Engine::Cdp,
        family: BrowserFamily::Chromium,
        headless: true,
        connecting: false,
    };
    let set = PluginSet::new()
        .with(Worker {
            caps: Vec::new(),
            ..Worker::new("no-cap")
        })
        .unwrap();
    let error = set.check(&launch).unwrap_err();
    assert!(
        matches!(&error, PluginError::Capability { capability, .. } if capability == "task"),
        "{error:?}"
    );
    PluginSet::new()
        .with(Worker::new("worker"))
        .unwrap()
        .check(&launch)
        .unwrap();
}

#[test]
fn the_sink_and_prompt_defaults_do_nothing_or_refuse() {
    NullSink.record(&json!({})).unwrap();
    let error = block_on(NoPrompt.wait("sign in", &RecordingPage::new())).unwrap_err();
    assert!(matches!(error, PluginError::NotSupported(_)), "{error:?}");
}

#[test]
fn the_clock_times_out_a_future_and_lets_a_finished_one_through() {
    let timer = Arc::new(ManualTimer::new());
    let clock = Clock::new(timer.clone());
    // Done before the limit.
    let quick = clock.timeout(Duration::from_secs(5), async { 7 });
    assert_eq!(block_on(quick).unwrap(), 7);
    // Not done: the limit counts from the call, and time moves past it.
    let stuck = clock.timeout(Duration::from_secs(5), std::future::pending::<u8>());
    timer.advance(Duration::from_secs(4));
    timer.advance(Duration::from_secs(1));
    let error = block_on(stuck).unwrap_err();
    assert!(
        matches!(error, PluginError::Timeout(d) if d == Duration::from_secs(5)),
        "{error:?}"
    );
    assert_eq!(error.to_string(), "timed out after 5s");
}

#[test]
fn a_sleep_ends_when_the_timer_reaches_it_and_now_follows_the_timer() {
    let timer = ManualTimer::new();
    let before = timer.now_ms();
    let mut sleep = timer.sleep(Duration::from_secs(2));
    use std::task::{Context, Poll, Waker};
    let mut cx = Context::from_waker(Waker::noop());
    assert!(sleep.as_mut().poll(&mut cx).is_pending());
    timer.advance(Duration::from_millis(1999));
    assert!(sleep.as_mut().poll(&mut cx).is_pending());
    timer.advance(Duration::from_millis(1));
    assert_eq!(sleep.as_mut().poll(&mut cx), Poll::Ready(()));
    assert_eq!(timer.now_ms() - before, 2000);
    // A zero sleep is ready at once.
    assert_eq!(
        timer.sleep(Duration::ZERO).as_mut().poll(&mut cx),
        Poll::Ready(())
    );
}
