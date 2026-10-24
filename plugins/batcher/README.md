# seleniumbase-rs-plugin-batcher

Runs another plugin's jobs over a list of inputs: a few at a time, each in a tab
of its own, with a time limit, retries with a growing pause and a resume file.
It writes one JSON line for each job.

It works on what the user's own browser session does: it opens tabs, hands each
one to a job runner and closes it. It adds no traffic of its own, hides nothing
and sends nothing anywhere else. Use it on pages you load and sites you may
test. It is not a test runner (`-n` belongs to the runner of `sbrs test`); it
runs data jobs.

- Category: `environment`. Chromium over CDP only.
- Capabilities: `task`, `contexts`, `page.navigate`, `page.evaluate`. With
  `resume_file` it also declares `host.fs.read` and `host.fs.write` for that one
  path. With `runner` set to a plugin's name, that plugin becomes a dependency
  and must be in the set.
- Hooks: `task`. It uses the `job_runner` of another plugin (`fetcher`,
  `extractor`) or its own `open` runner.

## Options

Set them under `[plugins.batcher]` in `sbase_config.toml` or with
`--plugin-opt batcher.KEY=<TOML>`. A misspelt option is an error, and so is a
value out of range.

| Option | Default | Meaning |
|---|---|---|
| `concurrency` | 2 | Jobs in flight at once, each in its own tab (1 to 32). Raise it when the machine and the site can take it. |
| `chunk_size` | 25 | Jobs served by one browser context (1 to 10000). Then the context and its tabs are closed and a fresh one is made, so cookies do not pile up and a privacy plugin such as `tor` can give each chunk its own circuit. Chunks run one after the other. |
| `job_timeout_secs` | 60 | The time limit of one attempt (1 to 3600). |
| `retries` | 1 | How often a failed job is tried again (0 to 3). |
| `backoff_ms` | 500 | The pause before the first retry; each later one waits twice as long, at most a minute (0 to 60000). There is no jitter. |
| `runner` | `"open"` | `open`, or the name of the plugin whose job runner does the work: `fetcher`, `extractor`. |
| `max_jobs` | 10000 | The most jobs one run accepts (1 to 1000000). |
| `ordered` | `false` | `true` writes the lines in the order of the jobs, `false` in the order they finish. |
| `warm_up` | unset | Whether a tab goes to the front page of the job's site (its `url`) before the runner starts, so a `fetch` in the page is same-origin. Unset means on for `fetcher` and off for everything else. |
| `resume_file` | none | A file that lists the jobs already done. See below. |

```toml
[plugins.batcher]
concurrency = 4
chunk_size = 50
retries = 2
runner = "fetcher"
resume_file = "done.jsonl"
```

## The task

```bash
sbrs plugin run batcher --input jobs.json --out results.jsonl \
  --plugin fetcher --plugin-opt 'batcher.runner="fetcher"'
```

The input is a list of jobs; what a job looks like is up to the runner.

```json
{"jobs": [{"url": "https://example.com/a"}, {"url": "https://example.com/b"}]}
```

- `open` (the default runner) takes `{"url": "https://..."}` (http or https,
  no credentials), opens it and answers `{"title", "url"}`, the title and the
  address the tab ended on.
- `fetcher` takes `{"url", "max_bytes"}` and answers `{url, status, mime, text,
  truncated}`.
- `extractor` takes its own request (`{"url", "extract": {...}}`) and answers
  `{url, title, schema, records, problems}`.

Each job records one line to the sink:

```json
{"chunk": 0, "index": 0, "job": {"url": "https://example.com/a"}, "outcome": {"status": "ok", "attempts": 1, "result": {"title": "Example", "url": "https://example.com/a"}}}
{"chunk": 0, "index": 1, "job": {"url": "https://example.com/b"}, "outcome": {"status": "failed", "attempts": 2, "error": "net::ERR_NAME_NOT_RESOLVED"}}
{"chunk": null, "index": 2, "job": {"url": "https://example.com/c"}, "outcome": {"status": "skipped"}}
```

`index` is the place of the job in the input, so lines that come in the order
the jobs finish can be put back in order. `chunk` counts the contexts of this
run (jobs skipped by the resume file have none). A failed job has `denied: true`
when a plugin's policy refused it.

The task returns

```json
{"total": 3, "ok": 1, "failed": 1, "skipped": 1, "retried": 1, "chunks": 1}
```

where `retried` counts the extra attempts of all jobs.

## Retries, time limits and denials

- Each attempt has a tab of its own and the time limit `job_timeout_secs`; the
  tab is closed whatever happened. A time limit, a browser error and a failing
  hook are tried again, up to `retries` times, after `backoff_ms`, twice that,
  and so on.
- A job that a plugin's policy refused is never tried again: a navigation a
  plugin cancelled, a request it blocked (`ERR_BLOCKED_BY_CLIENT`). Neither is a
  bad job (a URL that is not http or https, an unknown key).
- A job that fails is a line, and the others go on. A missing capability ends
  the run, because every job would fail the same way; so does a sink that cannot
  write. The context and its tabs are closed first. Lines already written stay.
- Dropping the task (Ctrl-C) stops everything at once; nothing is tried again.

## The resume file

With `resume_file`, a job that finished well is written down after its line
reached the sink. A second run with the same jobs and the same runner skips
those jobs (a `skipped` line each, written first) and runs the rest, including
the jobs that failed. A crash between the line and the entry runs the job
again rather than losing its line.

The file is JSON lines, `{"key": "<32 hex digits>", "index": 3}`. The key is a
hash of the runner and the job; no job text is stored, so a job that carries a
token leaves none in the file. A job counts as the same job whatever the order
of its keys, but a different runner is a different job. A last line cut off by
a crash is ignored; any other line that is not an entry stops the run before a
context is made. The file is created if it is missing and is never removed.

## Limits

- The runner sees the tab as its own plugin does: with that plugin's
  capabilities and no more. The batcher itself holds `page.navigate` and
  `page.evaluate` for its `open` runner and the warm-up, and its tabs are
  checked against them too.
- `warm_up` needs a `url` in the job; a job without one is run as it is.
- The host makes the context. Whether `before_context` of other plugins runs
  for it (as `tor` needs) is up to the host's `new_context`.
- Nothing in it has run in a real Chrome yet; the tests use the plugin API's
  fakes (`seleniumbase-rs-plugin-testing`) and the real `fetcher`.

## Test it

```rust
use seleniumbase_rs_plugin::{Configurable, PluginSet};
use seleniumbase_rs_plugin_batcher::Batcher;

let batcher = Batcher::configure(&serde_json::json!({ "concurrency": 4, "retries": 2 }))?;
let set = PluginSet::strict().with(batcher)?;
assert_eq!(set.task_names(), ["batcher"]);
```

With `RecordingBrowser::with_contexts()` the fakes count live contexts and tabs,
so a test can check that `concurrency` is kept (see `tests/run.rs`).
