//! Tasks and job runners: plugins that do work of their own.
//!
//! Most plugins react to what the browser does. A [`Task`] is a plugin the
//! user starts by name (`sbrs plugin run crawler`): it gets a browser, an
//! input, a [`Sink`] for its results and a [`Clock`]. A [`JobRunner`] is the
//! smaller piece a batching plugin calls once per job, with a page it opened.

use std::fmt;

use serde_json::Value;

use crate::{
    BrowserHandle, Capability, Clock, PageHandle, PluginError, PluginSet, Result, async_trait,
};

/// Where a task writes its results, one JSON value at a time. On the command
/// line it is a JSONL file; in an MCP client it is progress.
pub trait Sink: Send + Sync {
    /// Records one result.
    ///
    /// # Errors
    ///
    /// If the result could not be written.
    fn record(&self, line: &Value) -> Result<()>;
}

/// A sink that drops everything.
#[derive(Clone, Copy, Debug, Default)]
pub struct NullSink;

impl Sink for NullSink {
    fn record(&self, _line: &Value) -> Result<()> {
        Ok(())
    }
}

/// How a task asks a person to do something in the browser, such as signing
/// in, and waits until they are done.
#[async_trait]
pub trait Prompt: Send + Sync {
    /// Shows `message` and waits until the person is done. `page` is the tab
    /// they work in.
    ///
    /// # Errors
    ///
    /// If nobody can be asked, or the wait ended.
    async fn wait(&self, message: &str, page: &dyn PageHandle) -> Result<()>;
}

/// A prompt for hosts where no person is at the keyboard: waiting fails.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoPrompt;

#[async_trait]
impl Prompt for NoPrompt {
    async fn wait(&self, _message: &str, _page: &dyn PageHandle) -> Result<()> {
        Err(PluginError::unsupported("waiting for a person"))
    }
}

/// What a task gets when it runs.
#[non_exhaustive]
pub struct TaskContext<'a> {
    /// The browser to work with.
    pub browser: &'a dyn BrowserHandle,
    /// The task's input, as the user gave it.
    pub input: &'a Value,
    /// Where results go.
    pub sink: &'a dyn Sink,
    /// The plugins of this run, to reach a [`JobRunner`] by name.
    pub plugins: &'a PluginSet,
    /// Sleeps, time limits and the time.
    pub clock: &'a Clock,
    /// How to ask a person for help.
    pub prompt: &'a dyn Prompt,
}

impl<'a> TaskContext<'a> {
    /// A context from its parts.
    #[must_use]
    pub fn new(
        browser: &'a dyn BrowserHandle,
        input: &'a Value,
        sink: &'a dyn Sink,
        plugins: &'a PluginSet,
        clock: &'a Clock,
        prompt: &'a dyn Prompt,
    ) -> Self {
        Self {
            browser,
            input,
            sink,
            plugins,
            clock,
            prompt,
        }
    }
}

impl fmt::Debug for TaskContext<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TaskContext")
            .field("input", &self.input)
            .finish_non_exhaustive()
    }
}

/// Work a plugin does when the user starts it. The plugin needs
/// [`Capability::Task`].
#[async_trait]
pub trait Task: Send + Sync {
    /// Does the work and returns a summary. Results that come one by one go to
    /// `cx.sink`; they stay there when the task fails.
    ///
    /// # Errors
    ///
    /// Whatever stopped the task; the caller shows it.
    async fn run(&self, cx: &TaskContext<'_>) -> Result<Value>;
}

/// One kind of job a batching plugin can hand out, such as fetching a URL.
#[async_trait]
pub trait JobRunner: Send + Sync {
    /// Runs `job` in `page`, which the caller opened and will close.
    ///
    /// # Errors
    ///
    /// If the job failed.
    async fn run_job(&self, page: &dyn PageHandle, job: &Value) -> Result<Value>;
}

impl PluginSet {
    /// The task of the plugin called `name`.
    ///
    /// # Errors
    ///
    /// [`PluginError::Config`] if no plugin has that name or it offers no task;
    /// [`PluginError::Capability`] if it does not hold [`Capability::Task`].
    pub fn task(&self, name: &str) -> Result<&dyn Task> {
        let entry = self.named(name)?;
        let task = entry
            .plugin
            .task()
            .ok_or_else(|| PluginError::Config(format!("plugin `{name}` offers no task")))?;
        if !entry.grants.covers(&Capability::Task) {
            return Err(crate::denied(
                name,
                Capability::Task,
                "it offers a task without the capability",
            ));
        }
        Ok(task)
    }

    /// The job runner of the plugin called `name`.
    ///
    /// # Errors
    ///
    /// [`PluginError::Config`] if no plugin has that name or it offers no job
    /// runner.
    pub fn job_runner(&self, name: &str) -> Result<&dyn JobRunner> {
        self.named(name)?
            .plugin
            .job_runner()
            .ok_or_else(|| PluginError::Config(format!("plugin `{name}` offers no job runner")))
    }

    /// The names of the plugins that offer a task, in run order.
    #[must_use]
    pub fn task_names(&self) -> Vec<&str> {
        self.ordered()
            .into_iter()
            .filter(|entry| entry.plugin.task().is_some())
            .map(|entry| entry.plugin.name())
            .collect()
    }
}
