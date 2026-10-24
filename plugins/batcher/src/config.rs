//! The options of the batcher, and the checks that make a bad one an error at
//! start-up instead of a surprise halfway through a long run.

use std::path::PathBuf;
use std::time::Duration;

use seleniumbase_rs_plugin::{PluginError, Result};
use serde::{Deserialize, Serialize};

/// The most jobs that may run at once.
pub const MAX_CONCURRENCY: usize = 32;

/// The most jobs one browser context may serve.
pub const MAX_CHUNK_SIZE: usize = 10_000;

/// The largest `max_jobs` accepted.
pub const MAX_JOBS_LIMIT: usize = 1_000_000;

/// The most retries after a first failure.
pub const MAX_RETRIES: u8 = 3;

/// The longest time limit for one attempt, in seconds.
pub const MAX_JOB_TIMEOUT_SECS: u64 = 3600;

/// The longest pause before a retry, in milliseconds.
pub const MAX_BACKOFF_MS: u64 = 60_000;

/// The runner that opens a URL and records its title.
pub(crate) const OPEN_RUNNER: &str = "open";

/// What the batcher does, as a program or a config file states it.
///
/// ```
/// use seleniumbase_rs_plugin_batcher::BatcherConfig;
///
/// let config: BatcherConfig = serde_json::from_value(serde_json::json!({
///     "concurrency": 4,
///     "runner": "fetcher",
///     "resume_file": "done.jsonl",
/// }))?;
/// assert_eq!(config.chunk_size, 25);
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct BatcherConfig {
    /// Jobs in flight at once, each in a tab of its own (1 to 32).
    pub concurrency: usize,
    /// Jobs served by one browser context before it is closed and a fresh
    /// one is made. A context has its own cookies and, with a privacy plugin
    /// such as `tor`, its own circuit.
    pub chunk_size: usize,
    /// The time limit of one attempt, in seconds.
    pub job_timeout_secs: u64,
    /// How often a failed job is tried again (0 to 3).
    pub retries: u8,
    /// The pause before the first retry, in milliseconds; each later retry
    /// waits twice as long, up to one minute.
    pub backoff_ms: u64,
    /// `open`, or the name of the plugin whose job runner does the work,
    /// such as `fetcher` or `extractor`.
    pub runner: String,
    /// The most jobs one run accepts.
    pub max_jobs: usize,
    /// `true` writes the records in the order of the jobs, `false` in the
    /// order the jobs finish.
    pub ordered: bool,
    /// Whether a tab goes to the front page of a job's site (`url`) before
    /// the runner starts, so a fetch in the page is same-origin. Unset: on for
    /// the `fetcher` runner, off for every other.
    pub warm_up: Option<bool>,
    /// A file that lists the jobs already done, so a second run with the
    /// same jobs skips them. It is created if it is missing.
    pub resume_file: Option<PathBuf>,
}

impl Default for BatcherConfig {
    fn default() -> Self {
        Self {
            concurrency: 2,
            chunk_size: 25,
            job_timeout_secs: 60,
            retries: 1,
            backoff_ms: 500,
            runner: OPEN_RUNNER.to_owned(),
            max_jobs: 10_000,
            ordered: false,
            warm_up: None,
            resume_file: None,
        }
    }
}

impl BatcherConfig {
    /// Checks every option.
    pub(crate) fn check(&self) -> Result<()> {
        let bad = |what: String| Err(PluginError::Config(format!("batcher: {what}")));
        if !(1..=MAX_CONCURRENCY).contains(&self.concurrency) {
            return bad(format!("`concurrency` is from 1 to {MAX_CONCURRENCY}"));
        }
        if !(1..=MAX_CHUNK_SIZE).contains(&self.chunk_size) {
            return bad(format!("`chunk_size` is from 1 to {MAX_CHUNK_SIZE}"));
        }
        if !(1..=MAX_JOB_TIMEOUT_SECS).contains(&self.job_timeout_secs) {
            return bad(format!(
                "`job_timeout_secs` is from 1 to {MAX_JOB_TIMEOUT_SECS}"
            ));
        }
        if self.retries > MAX_RETRIES {
            return bad(format!("`retries` is at most {MAX_RETRIES}"));
        }
        if self.backoff_ms > MAX_BACKOFF_MS {
            return bad(format!("`backoff_ms` is at most {MAX_BACKOFF_MS}"));
        }
        if !(1..=MAX_JOBS_LIMIT).contains(&self.max_jobs) {
            return bad(format!("`max_jobs` is from 1 to {MAX_JOBS_LIMIT}"));
        }
        let runner = self.runner.trim();
        if runner.is_empty() || runner != self.runner || runner.chars().any(char::is_whitespace) {
            return bad("`runner` is `open` or the name of a plugin".into());
        }
        if runner == crate::NAME {
            return bad("`runner` cannot be the batcher itself".into());
        }
        if self
            .resume_file
            .as_ref()
            .is_some_and(|path| path.as_os_str().is_empty())
        {
            return bad("`resume_file` is empty".into());
        }
        Ok(())
    }

    /// Whether the runner is the built-in one.
    pub(crate) fn opens(&self) -> bool {
        self.runner == OPEN_RUNNER
    }

    /// Whether a tab visits the site of a job before the runner starts.
    pub(crate) fn warms_up(&self) -> bool {
        self.warm_up.unwrap_or(self.runner == "fetcher")
    }

    /// The time limit of one attempt.
    #[must_use]
    pub fn job_timeout(&self) -> Duration {
        Duration::from_secs(self.job_timeout_secs)
    }

    /// The pause after the failed attempt number `attempt` (1 for the first):
    /// `backoff_ms`, then twice that, and so on, at most a minute.
    #[must_use]
    pub fn backoff(&self, attempt: u32) -> Duration {
        let factor = 1_u64
            .checked_shl(attempt.saturating_sub(1))
            .unwrap_or(u64::MAX);
        Duration::from_millis(self.backoff_ms.saturating_mul(factor).min(MAX_BACKOFF_MS))
    }
}
