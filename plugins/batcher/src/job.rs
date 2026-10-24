//! Jobs and task input: what the task accepts, how a job is named in the
//! resume file, how a failure is judged, the records the task writes, and the
//! built-in `open` runner.

use seleniumbase_rs_plugin::{PageHandle, PluginError, Result};
use serde::Deserialize;
use serde_json::{Value, json};

/// FNV-1a, 128 bits: the offset basis and the prime.
const FNV_OFFSET: u128 = 0x6c62_272e_07bb_0142_62b8_2175_6295_c58d;
const FNV_PRIME: u128 = 0x0000_0000_0100_0000_0000_0000_0000_013b;

/// The task's input: `{"jobs": [...]}`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TaskInput {
    jobs: Option<Vec<Value>>,
}

/// The jobs of the task input. The error says what is wrong with it.
pub(crate) fn parse_jobs(input: &Value, max_jobs: usize) -> Result<Vec<Value>> {
    let missing =
        || PluginError::Config("batcher: the task input needs `jobs`, a list of jobs".into());
    if input.is_null() {
        return Err(missing());
    }
    let parsed: TaskInput = serde_json::from_value(input.clone())
        .map_err(|error| PluginError::Config(format!("batcher: bad task input: {error}")))?;
    let jobs = parsed.jobs.ok_or_else(missing)?;
    if jobs.is_empty() {
        return Err(PluginError::Config("batcher: `jobs` is empty".into()));
    }
    if jobs.len() > max_jobs {
        return Err(PluginError::Config("batcher: too many jobs".into()));
    }
    Ok(jobs)
}

/// JSON with the keys of every object in order, so the same job always has the
/// same text.
fn canonical(value: &Value, out: &mut String) {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<_> = map.iter().collect();
            entries.sort_by(|a, b| a.0.cmp(b.0));
            out.push('{');
            for (position, (key, item)) in entries.into_iter().enumerate() {
                if position > 0 {
                    out.push(',');
                }
                out.push_str(&Value::from(key.as_str()).to_string());
                out.push(':');
                canonical(item, out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (position, item) in items.iter().enumerate() {
                if position > 0 {
                    out.push(',');
                }
                canonical(item, out);
            }
            out.push(']');
        }
        scalar => out.push_str(&scalar.to_string()),
    }
}

/// The name of a job in the resume file: 32 hex digits of a hash of the runner
/// and the job. The file holds no job text, so it can hold no secret a job
/// carries.
pub(crate) fn job_key(runner: &str, job: &Value) -> String {
    let mut text = String::from(runner);
    text.push('\0');
    canonical(job, &mut text);
    let mut hash = FNV_OFFSET;
    for byte in text.bytes() {
        hash ^= u128::from(byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    format!("{hash:032x}")
}

/// What to do after a job failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Next {
    /// Try again if tries are left: the failure may pass.
    Retry,
    /// The failure is the answer: another try gives the same one.
    Stop,
    /// The whole run cannot go on: every job would fail the same way.
    Abort,
}

/// Judges a failure. A policy denial (a navigation a plugin cancelled, a
/// request it blocked), a bad job and a missing feature are never retried; a
/// missing capability ends the run; a time limit, a failing hook and a browser
/// error are retried.
pub(crate) fn next_step(error: &PluginError) -> Next {
    match error {
        PluginError::Capability { .. } | PluginError::Unsupported { .. } => Next::Abort,
        PluginError::Timeout(_) | PluginError::Hook { .. } => Next::Retry,
        PluginError::Other(_) if !is_denial(error) => Next::Retry,
        _ => Next::Stop,
    }
}

/// Whether a plugin's policy refused the job: it cancelled a navigation, or
/// blocked a request (Chrome reports `ERR_BLOCKED_BY_CLIENT`).
pub(crate) fn is_denial(error: &PluginError) -> bool {
    match error {
        PluginError::NavigationCancelled { .. } | PluginError::Sealed { .. } => true,
        PluginError::Other(message) => message.contains("ERR_BLOCKED_BY_CLIENT"),
        _ => false,
    }
}

/// Why a job failed.
#[derive(Debug)]
pub(crate) struct Failure {
    pub(crate) message: String,
    pub(crate) denied: bool,
}

/// A job that ran: what it gave and how many attempts it took.
#[derive(Debug)]
pub(crate) struct Finished {
    pub(crate) chunk: usize,
    pub(crate) index: usize,
    pub(crate) job: Value,
    pub(crate) attempts: u32,
    pub(crate) answer: std::result::Result<Value, Failure>,
}

impl Finished {
    pub(crate) fn is_ok(&self) -> bool {
        self.answer.is_ok()
    }

    /// The attempts after the first.
    pub(crate) fn retries(&self) -> u64 {
        u64::from(self.attempts.saturating_sub(1))
    }

    /// The line for the sink: `{chunk, index, job, outcome}`, where `outcome`
    /// is `{status: "ok", attempts, result}` or `{status: "failed", attempts,
    /// error, denied?}`.
    pub(crate) fn line(&self) -> Value {
        let outcome = match &self.answer {
            Ok(result) => json!({
                "status": "ok",
                "attempts": self.attempts,
                "result": result,
            }),
            Err(failure) => {
                let mut outcome = json!({
                    "status": "failed",
                    "attempts": self.attempts,
                    "error": failure.message,
                });
                if failure.denied {
                    outcome["denied"] = Value::Bool(true);
                }
                outcome
            }
        };
        json!({
            "chunk": self.chunk,
            "index": self.index,
            "job": self.job,
            "outcome": outcome,
        })
    }
}

/// The line for a job the resume file says is done.
pub(crate) fn skipped_line(index: usize, job: &Value) -> Value {
    json!({
        "chunk": Value::Null,
        "index": index,
        "job": job,
        "outcome": { "status": "skipped" },
    })
}

/// The job of the built-in `open` runner.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OpenJob {
    url: String,
}

/// The built-in runner: opens `{"url": "https://..."}` in `page` and answers
/// `{"title", "url"}`, the title and the address the tab ended on.
pub(crate) async fn open(page: &dyn PageHandle, job: &Value) -> Result<Value> {
    let job: OpenJob = serde_json::from_value(job.clone())
        .map_err(|error| PluginError::Config(format!("batcher: bad job: {error}")))?;
    origin(&job.url)?;
    page.navigate(&job.url).await?;
    let title = match page.evaluate("document.title").await? {
        Value::String(title) => title,
        Value::Null => String::new(),
        other => {
            return Err(PluginError::other(format!(
                "batcher: unexpected title from the page: {other}"
            )));
        }
    };
    let url = page.url().await?;
    Ok(json!({ "title": title, "url": url }))
}

/// The scheme, host and port of an `http` or `https` URL, as `origin/`
/// without the slash; the error says what is wrong with the URL.
pub(crate) fn origin(url: &str) -> Result<String> {
    let bad = |why: &str| PluginError::Config(format!("batcher: `{url}` {why}"));
    if url.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(bad("has a space or control character"));
    }
    let lower = url.to_ascii_lowercase();
    let scheme_len = if lower.starts_with("https://") {
        8
    } else if lower.starts_with("http://") {
        7
    } else {
        return Err(bad("is not an http or https address"));
    };
    let authority = lower[scheme_len..]
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    if authority.is_empty() {
        return Err(bad("has no host"));
    }
    if authority.contains('@') {
        return Err(bad("carries credentials, which are not accepted"));
    }
    Ok(format!("{}{authority}", &lower[..scheme_len]))
}

/// Takes a tab to the front page of the site a job's `url` names, if it has
/// one, so a fetch from the tab is same-origin.
pub(crate) async fn warm_up(page: &dyn PageHandle, job: &Value) -> Result<()> {
    let Some(url) = job.get("url").and_then(Value::as_str) else {
        return Ok(());
    };
    let site = origin(url)?;
    page.navigate(&format!("{site}/")).await
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn the_task_input_needs_a_list_of_jobs() {
        let message = |input: Value| match parse_jobs(&input, 3) {
            Err(PluginError::Config(message)) => message,
            other => panic!("{input}: {other:?}"),
        };
        assert!(message(Value::Null).contains("needs `jobs`"));
        assert!(message(json!({})).contains("needs `jobs`"));
        assert!(message(json!({ "jobs": [] })).contains("empty"));
        assert!(message(json!({ "jobs": "x" })).contains("bad task input"));
        assert!(message(json!({ "jobs": [1], "urls": [] })).contains("urls"));
        assert_eq!(
            message(json!({ "jobs": [1, 2, 3, 4] })),
            "batcher: too many jobs"
        );
        assert_eq!(
            parse_jobs(&json!({ "jobs": [1, {"a": 2}, "c"] }), 3).unwrap(),
            [json!(1), json!({"a": 2}), json!("c")]
        );
    }

    #[test]
    fn a_job_has_one_name_whatever_the_order_of_its_keys() {
        let a = json!({ "url": "https://a.test/", "extract": { "x": 1, "y": [1, 2] } });
        let b = json!({ "extract": { "y": [1, 2], "x": 1 }, "url": "https://a.test/" });
        assert_eq!(job_key("fetcher", &a), job_key("fetcher", &b));
        assert_eq!(job_key("fetcher", &a).len(), 32);
        assert!(
            job_key("fetcher", &a)
                .bytes()
                .all(|b| b.is_ascii_hexdigit())
        );
    }

    #[test]
    fn a_job_name_changes_with_the_runner_and_with_every_part_of_the_job() {
        let job = json!({ "url": "https://a.test/1" });
        let keys = [
            job_key("fetcher", &job),
            job_key("extractor", &job),
            job_key("fetcher", &json!({ "url": "https://a.test/2" })),
            job_key(
                "fetcher",
                &json!({ "url": "https://a.test/1", "max_bytes": 1 }),
            ),
            job_key("fetcher", &json!(["https://a.test/1"])),
            job_key("fetcher", &json!("https://a.test/1")),
            job_key("fetchera", &json!({ "url": "https://a.test/1" })),
        ];
        for (i, a) in keys.iter().enumerate() {
            for b in &keys[i + 1..] {
                assert_ne!(a, b);
            }
        }
        // The text of a job does not leak into its name.
        assert!(!keys[0].contains("a.test"));
    }

    fn other(message: &str) -> PluginError {
        PluginError::other(message)
    }

    #[test]
    fn failures_are_judged_by_what_another_try_could_change() {
        let denied = PluginError::NavigationCancelled {
            plugin: "p".into(),
            url: "https://a.test/".into(),
            reason: "no".into(),
        };
        assert!(is_denial(&denied));
        assert_eq!(next_step(&denied), Next::Stop);
        let blocked = other("navigation failed: net::ERR_BLOCKED_BY_CLIENT");
        assert!(is_denial(&blocked));
        assert_eq!(next_step(&blocked), Next::Stop);
        for retry in [
            PluginError::Timeout(Duration::from_secs(1)),
            other("net::ERR_CONNECTION_RESET"),
            PluginError::Hook {
                plugin: "p".into(),
                hook: "after_navigate",
                message: "x".into(),
            },
        ] {
            assert_eq!(next_step(&retry), Next::Retry, "{retry}");
            assert!(!is_denial(&retry));
        }
        for stop in [
            PluginError::Config("bad job".into()),
            PluginError::unsupported("close"),
            PluginError::Panicked {
                plugin: "p".into(),
                hook: "run",
            },
        ] {
            assert_eq!(next_step(&stop), Next::Stop, "{stop}");
        }
        let capability = PluginError::Capability {
            plugin: "p".into(),
            capability: "page.navigate".into(),
            reason: "r".into(),
        };
        assert_eq!(next_step(&capability), Next::Abort);
    }

    #[test]
    fn origin_keeps_scheme_host_and_port() {
        assert_eq!(
            origin("https://Example.com/a?b#c").unwrap(),
            "https://example.com"
        );
        assert_eq!(
            origin("http://localhost:8080").unwrap(),
            "http://localhost:8080"
        );
    }

    #[test]
    fn origin_refuses_what_is_not_a_plain_web_address() {
        for url in [
            "file:///etc/passwd",
            "data:text/html,x",
            "javascript:alert(1)",
            "ftp://example.com/",
            "https://",
            "https://user:pw@example.com/",
            "https://example.com/a b",
            "",
        ] {
            assert!(origin(url).is_err(), "{url}");
        }
    }

    #[test]
    fn the_line_of_a_job_has_the_same_shape_whatever_happened() {
        let job = json!({ "url": "https://a.test/" });
        let ok = Finished {
            chunk: 1,
            index: 4,
            job: job.clone(),
            attempts: 2,
            answer: Ok(json!({ "title": "t" })),
        };
        assert_eq!(
            ok.line(),
            json!({ "chunk": 1, "index": 4, "job": job, "outcome":
                { "status": "ok", "attempts": 2, "result": { "title": "t" } } })
        );
        assert_eq!(ok.retries(), 1);
        let failed = Finished {
            chunk: 0,
            index: 0,
            job: job.clone(),
            attempts: 1,
            answer: Err(Failure {
                message: "no".into(),
                denied: true,
            }),
        };
        assert_eq!(
            failed.line()["outcome"],
            json!({ "status": "failed", "attempts": 1, "error": "no", "denied": true })
        );
        assert_eq!(failed.retries(), 0);
        assert!(!failed.is_ok());
        assert_eq!(
            skipped_line(7, &job),
            json!({ "chunk": null, "index": 7, "job": job, "outcome": { "status": "skipped" } })
        );
    }
}
