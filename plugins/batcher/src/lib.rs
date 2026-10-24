//! Runs another plugin's jobs over a list of inputs: a few at a time, each in
//! a tab of its own, with a time limit, retries and a resume file.
//!
//! The batcher works on what the user's own browser session does. It opens
//! tabs, hands each one to a job runner and closes it; it adds no traffic of
//! its own and sends nothing anywhere else. Use it on pages you load and sites
//! you may test.
//!
//! ```
//! use seleniumbase_rs_plugin::{Configurable, PluginSet};
//! use seleniumbase_rs_plugin_batcher::Batcher;
//!
//! let batcher = Batcher::configure(&serde_json::json!({
//!     "concurrency": 4,
//!     "chunk_size": 50,
//!     "retries": 2,
//! }))?;
//! let plugins = PluginSet::strict().with(batcher)?;
//! assert_eq!(plugins.names(), ["batcher"]);
//! # Ok::<(), seleniumbase_rs_plugin::PluginError>(())
//! ```

mod config;
mod job;
mod resume;
mod run;

use seleniumbase_rs_plugin::{
    Capability, Category, Configurable, Metadata, PathScope, Plugin, Requirements, Result, Task,
    TaskContext, async_trait, config::options,
};
use serde_json::Value;

pub use config::{
    BatcherConfig, MAX_BACKOFF_MS, MAX_CHUNK_SIZE, MAX_CONCURRENCY, MAX_JOB_TIMEOUT_SECS,
    MAX_JOBS_LIMIT, MAX_RETRIES,
};

/// The name the plugin is enabled by.
pub(crate) const NAME: &str = "batcher";

/// The batcher plugin. See the [crate documentation](crate).
#[derive(Debug)]
pub struct Batcher {
    config: BatcherConfig,
}

impl Batcher {
    /// Builds the plugin from `config`.
    ///
    /// # Errors
    ///
    /// [`PluginError::Config`](seleniumbase_rs_plugin::PluginError::Config) for
    /// an option out of range or a runner name that cannot be one.
    pub fn new(config: BatcherConfig) -> Result<Self> {
        config.check()?;
        Ok(Self { config })
    }

    /// The options the plugin was built with.
    #[must_use]
    pub fn config(&self) -> &BatcherConfig {
        &self.config
    }
}

#[async_trait]
impl Plugin for Batcher {
    fn name(&self) -> &str {
        NAME
    }

    fn requirements(&self) -> Requirements {
        Requirements::CHROMIUM_ONLY
    }

    fn task(&self) -> Option<&dyn Task> {
        Some(self)
    }

    /// What [`Configurable::describe`] says, plus what the options add: the
    /// plugin whose runner does the work, and the resume file.
    fn metadata(&self) -> Metadata {
        let mut meta = Self::describe();
        if !self.config.opens() {
            meta = meta.requires(self.config.runner.clone());
        }
        if let Some(path) = &self.config.resume_file {
            let scope = PathScope::Declared(vec![path.clone()]);
            meta = meta
                .capability(Capability::HostFsRead(scope.clone()))
                .capability(Capability::HostFsWrite(scope));
        }
        meta
    }
}

#[async_trait]
impl Task for Batcher {
    /// Runs `{"jobs": [...]}`: the jobs go to the runner in chunks, a few tabs
    /// at a time, and each one records a line to the sink,
    /// `{"chunk", "index", "job", "outcome"}`. See the [crate documentation](crate).
    async fn run(&self, cx: &TaskContext<'_>) -> Result<Value> {
        run::run(&self.config, cx).await
    }
}

impl Configurable for Batcher {
    const NAME: &'static str = NAME;

    fn describe() -> Metadata {
        Metadata::new(Category::Environment)
            .version(env!("CARGO_PKG_VERSION"))
            .summary("Runs another plugin's jobs over a list of inputs with bounded concurrency, retries and a resume file")
            .capabilities([
                Capability::Task,
                Capability::Contexts,
                Capability::PageNavigate,
                Capability::PageEvaluate,
            ])
    }

    /// Options: see [`BatcherConfig`].
    fn configure(value: &Value) -> Result<Self> {
        Self::new(options(NAME, value)?)
    }
}
