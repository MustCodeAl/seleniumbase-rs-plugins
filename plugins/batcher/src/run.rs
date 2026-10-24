//! The task: the jobs go to a browser context in chunks, a few tabs work at a
//! time, and every job ends as one line for the sink.

use std::pin::Pin;

use futures_util::stream::{self, Stream, StreamExt};
use seleniumbase_rs_plugin::{
    BrowserHandle, ContextHandle, ContextSettings, JobRunner, PageHandle, PluginError, Result,
    TaskContext,
};
use serde_json::{Value, json};

use crate::NAME;
use crate::config::BatcherConfig;
use crate::job::{self, Failure, Finished, Next};
use crate::resume::ResumeLog;

/// Who does the work of a job.
enum Runner<'a> {
    /// The built-in runner: open the URL, record its title.
    Open,
    /// The job runner of another plugin of the set.
    Plugin {
        name: &'a str,
        runner: &'a dyn JobRunner,
    },
}

/// A job that still has to run: its place in the input, the job and its name
/// in the resume file.
struct Pending<'a> {
    index: usize,
    job: &'a Value,
    key: String,
}

/// What the summary counts.
#[derive(Default)]
struct Tally {
    ok: u64,
    failed: u64,
    skipped: u64,
    retried: u64,
    chunks: u64,
}

/// Runs the task `cx` describes with the options `config`.
pub(crate) async fn run(config: &BatcherConfig, cx: &TaskContext<'_>) -> Result<Value> {
    let jobs = job::parse_jobs(cx.input, config.max_jobs)?;
    let runner = if config.opens() {
        Runner::Open
    } else {
        let runner = cx.plugins.job_runner(&config.runner).map_err(|error| {
            let detail = match error {
                PluginError::Config(detail) => detail,
                other => other.to_string(),
            };
            PluginError::Config(format!("batcher: runner `{}`: {detail}", config.runner))
        })?;
        Runner::Plugin {
            name: &config.runner,
            runner,
        }
    };
    let mut resume = config
        .resume_file
        .as_deref()
        .map(ResumeLog::open)
        .transpose()?;
    let mut tally = Tally::default();
    let mut pending = Vec::with_capacity(jobs.len());
    for (index, job) in jobs.iter().enumerate() {
        let key = job::job_key(&config.runner, job);
        if resume.as_ref().is_some_and(|log| log.is_done(&key)) {
            tally.skipped += 1;
            cx.sink.record(&job::skipped_line(index, job))?;
        } else {
            pending.push(Pending { index, job, key });
        }
    }

    let run = Run { config, cx, runner };
    let browser = cx.plugins.guarded_browser(NAME, cx.browser)?;
    for (number, chunk) in pending.chunks(config.chunk_size).enumerate() {
        let context = browser.new_context(ContextSettings::new()).await?;
        tally.chunks += 1;
        let done = run
            .chunk(&*context, number, chunk, &mut resume, &mut tally)
            .await;
        // The context is ours: close it, and its tabs, whatever happened.
        let _ = context.dispose().await;
        done?;
    }
    Ok(json!({
        "total": jobs.len(),
        "ok": tally.ok,
        "failed": tally.failed,
        "skipped": tally.skipped,
        "retried": tally.retried,
        "chunks": tally.chunks,
    }))
}

/// The options, the task's context and the runner, shared by every job.
struct Run<'a, 'cx> {
    config: &'a BatcherConfig,
    cx: &'a TaskContext<'cx>,
    runner: Runner<'a>,
}

impl Run<'_, '_> {
    /// Runs the jobs of one chunk in `context`, at most `concurrency` at a
    /// time, and writes their lines as they finish (or, with `ordered`, in the
    /// order of the input).
    ///
    /// A job that fails is a line, not an error. An error ends the chunk: a
    /// missing capability, a sink that cannot write, a resume file that cannot
    /// be written.
    async fn chunk(
        &self,
        context: &dyn ContextHandle,
        number: usize,
        chunk: &[Pending<'_>],
        resume: &mut Option<ResumeLog>,
        tally: &mut Tally,
    ) -> Result<()> {
        let jobs = stream::iter(chunk).map(|pending| self.job(context, number, pending));
        let width = self.config.concurrency;
        let mut finished: Pin<Box<dyn Stream<Item = Result<Finished>> + Send + '_>> =
            if self.config.ordered {
                Box::pin(jobs.buffered(width))
            } else {
                Box::pin(jobs.buffer_unordered(width))
            };
        while let Some(done) = finished.next().await {
            let done = done?;
            self.cx.sink.record(&done.line())?;
            tally.retried += done.retries();
            if !done.is_ok() {
                tally.failed += 1;
                continue;
            }
            tally.ok += 1;
            // After the line: a crash in between runs the job again.
            if let (Some(log), Ok(at)) = (
                resume.as_mut(),
                chunk.binary_search_by_key(&done.index, |pending| pending.index),
            ) {
                log.mark(&chunk[at].key, done.index)?;
            }
        }
        Ok(())
    }

    /// Runs one job, trying again after a pause when a try fails in a way
    /// another try may mend.
    async fn job(
        &self,
        context: &dyn ContextHandle,
        number: usize,
        pending: &Pending<'_>,
    ) -> Result<Finished> {
        let mut attempts = 0_u32;
        let answer = loop {
            attempts += 1;
            let error = match self.attempt(context, pending.job).await {
                Ok(result) => break Ok(result),
                Err(error) => error,
            };
            match job::next_step(&error) {
                Next::Abort => return Err(error),
                Next::Retry if attempts <= u32::from(self.config.retries) => {
                    self.cx.clock.sleep(self.config.backoff(attempts)).await;
                }
                _ => {
                    break Err(Failure {
                        denied: job::is_denial(&error),
                        message: error.to_string(),
                    });
                }
            }
        };
        Ok(Finished {
            chunk: number,
            index: pending.index,
            job: pending.job.clone(),
            attempts,
            answer,
        })
    }

    /// One try: a new tab, the runner under the time limit, the tab closed.
    async fn attempt(&self, context: &dyn ContextHandle, job: &Value) -> Result<Value> {
        let page = context.new_page(None).await?;
        let timed = self
            .cx
            .clock
            .timeout(self.config.job_timeout(), self.work(&*page, job))
            .await;
        // The tab is ours: close it whatever happened.
        let _ = page.close().await;
        timed.and_then(|inner| inner)
    }

    /// The work of a job in `page`. A plugin's runner gets the tab as that
    /// plugin sees it, with its capabilities and no more.
    async fn work(&self, page: &dyn PageHandle, job: &Value) -> Result<Value> {
        match &self.runner {
            Runner::Open => job::open(page, job).await,
            Runner::Plugin { name, runner } => {
                if self.config.warms_up() {
                    job::warm_up(page, job).await?;
                }
                let guarded = self.cx.plugins.guarded_page(name, page)?;
                runner.run_job(&guarded, job).await
            }
        }
    }
}
