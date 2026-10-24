# Changelog

All notable changes to the crates in this repository. The crates share one
version; it stays 0.1.x until the next release.

## Unreleased

### Added

- `seleniumbase-rs-plugin-shield`: the `shield` plugin (category Privacy). It
  turns off Chromium's background telemetry (verified switches and features, and
  at the `strict` level a resolver rule per browser-process host), sets privacy
  preferences, applies Chrome's `disable_non_proxied_udp` WebRTC policy, adds a
  relay-only `RTCPeerConnection` shim, blocks third-party cookies, blocks
  `extra_block_hosts` (subdomains and any port) with a raw
  `Network.setBlockedURLs`, and refuses a persistent profile. Typed options with
  `deny_unknown_fields`. `clear_between_tests` and `sweep_stale_profiles` wait
  for plugin API hooks that do not exist: both default to `false` and `true` is
  a configuration error until they work.
- `seleniumbase-rs-plugin-fetcher`: the `fetcher` plugin (category Core, Chromium
  over CDP). Declarative network rules through `network()`: `strip` fails whole
  kinds of resource (never documents), `block` fails URL patterns, `headers` adds
  request headers (to every request or only to `header_urls`; framing headers and
  line breaks are refused), and `capture` records matching responses in a log
  bounded by `max_captures` and `max_body_bytes` (`Fetcher::captured`,
  `take_captured`). `Cookie`, `Authorization`, `Proxy-Authorization` and
  `Set-Cookie` stay redacted in a record: the plugin does not hold
  `net.sensitive`. It is also a `JobRunner` (`{"url"}` gives `{url, status, mime,
  text, truncated}` through an in-page `fetch` with the browser's cookies; the URL
  travels as a JSON literal) and a `Task` (`{"urls": [...]}`, one tab, one sink
  line per URL, a pause between fetches, the site's front page opened first so
  the fetch is same-origin). Capabilities: `net.intercept`, `net.observe`, `task`,
  `page.evaluate`, `page.navigate`; optional `net.bodies`.
- `seleniumbase-rs-plugin-extractor`: the `extractor` plugin (category Core,
  Chromium over CDP). `Extractor::discover` finds JSON-LD blocks, tables and
  groups of repeated elements and returns typed `Schema`s (`text`, `number`,
  `money`, `date`, `url`); `extract` and `extract_values` read records with one,
  and a value that is missing or does not fit becomes a `Problem`, not an error;
  `Schema::json_schema` describes the records. A `select` map of CSS selectors
  reads exactly what it names, and a job can also return the page text, links,
  tables and meta data. The page script is pure and stops at `max_nodes`. It is a
  `JobRunner` and a `Task` (`{"urls": [...], "extract": {...}}` or `{"jobs":
  [...]}`, one sink line per page). Capabilities: `page.evaluate`,
  `page.navigate`, `task`. The `auto_save` option of the design is not provided:
  the plugin host has no artifact API yet. Chrome tests (`extractor_chrome.rs`)
  are `#[ignore]`d.
- `seleniumbase-rs-plugin-batcher`: the `batcher` plugin (category Environment,
  Chromium over CDP). Its task takes `{"jobs": [...]}` and runs each job through
  a job runner, the built-in `open` (opens a URL, answers `{title, url}`) or the
  `runner` of another plugin in the set such as `fetcher` or `extractor`, which
  gets the tab with its own capabilities only. `concurrency` (default 2, up to
  32) tabs work at a time; jobs go to a browser context in chunks of
  `chunk_size` (25), one context after the other, and the context and its tabs
  are closed after each chunk. Each attempt has a tab of its own and the time
  limit `job_timeout_secs` (60); a time limit, a browser error or a failing hook
  is tried again up to `retries` times (1) after `backoff_ms` (500), twice that,
  and so on; a policy denial (a cancelled navigation, `ERR_BLOCKED_BY_CLIENT`)
  and a bad job are never tried again, and a missing capability ends the run.
  One line per job goes to the sink, `{chunk, index, job, outcome}`, in the order
  the jobs finish or, with `ordered`, in the order of the input; the summary is
  `{total, ok, failed, skipped, retried, chunks}`. `resume_file` lists the jobs
  that finished (a hash of the runner and the job, no job text), so a second run
  skips them. `warm_up` takes the tab to the job's site first (on for `fetcher`).
  Capabilities: `task`, `contexts`, `page.navigate`, `page.evaluate`, and the
  resume path when set. The only new dependency is `futures-util` (`std` only).
- `seleniumbase-rs-plugin-crawler`: the `crawler` plugin (category Testing,
  Chromium over CDP) for sites you own or may test. As a `Task` (`sbrs plugin
  run crawler`, input `{"start": [...], "resume": true}`) it crawls `a[href]`
  links breadth first in one tab: scope `same-origin`, `same-site` or `{hosts}`,
  `include`/`exclude` globs, links normalised and deduplicated, `max_depth` (3),
  `max_pages` (500, at most 50000), `delay_ms` (1000), robots.txt read in the tab
  and obeyed unless `respect_robots = false` (`sbrs` group before `*`, longest
  rule, `Crawl-delay`), page-level `nofollow`. It writes one sink line per page
  (`url`, `depth`, `from`, `status`, `title`, `links`, `queued`, or `error`) and
  returns a `Report` (`pages`, `edges`, `broken`, `js_errors`, `unreached`,
  `robots_blocked`, `truncated`, `passed`, `summary`). A page is broken above
  `expect.max_status` (399) or when it does not load (counted as 404); the
  summary uses the wording of Python's `assert_no_404_errors`. As a test plugin
  it cancels navigation outside the scope while a crawl runs
  (`before_navigate`), records console errors from `Runtime.exceptionThrown` and
  `Log.entryAdded`, and fails the next `on_test_end` with the summary unless the
  report passed (`expect.must_reach`, `expect.no_console_errors`). An optional
  `state_file` (temporary file and rename) resumes a stopped crawl when the
  options that choose the pages are unchanged. Capabilities: `task`,
  `page.navigate`, `page.evaluate`, `net.observe`, `test.hooks`; with a state
  file also `host.fs.read` and `host.fs.write` for that file. The
  `#[ignore]`d `crawler_chrome` test passed in headless Chrome against a local fixture site (a stand-in tab, not the host's CDP engine).


- `seleniumbase-rs-plugins-builtin`: one cargo feature per built-in plugin
  (`shield`, `block-resources`, `crx`; none on by default), re-exports, and
  `registry()`, a `Registry` with every enabled plugin. The `wasm` host is not
  included because it has no `Configurable` implementation.
- `seleniumbase-rs-plugin` 0.1.3: the hook surface of plugin phase 2, all
  additive. New `Plugin` hooks with default bodies: `before_navigate` (a
  `NavDecision` of `Continue`, `Redirect` or `Cancel`), `after_navigate`,
  `on_request` (`RequestDecision::Continue` or `Block`), `on_response`,
  `on_protocol_event`, `before_context`, `on_context_created`,
  `on_context_closed`, `before_close`, `on_test_start` and `on_test_end` (a
  `TestVerdict` of `Keep` or `Fail`). New declarations: `network()` (a
  `NetworkInterest` of rules the host runs, `observe` filters and `intercept`
  filters), `protocol_events()`, `task()` (`Task`, `TaskContext`, `Sink`,
  `Prompt`) and `job_runner()` (`JobRunner`). New handle methods, all
  defaulting to `PluginError::NotSupported`: `BrowserHandle::{id, extensions,
  new_context, new_page}`, `PageHandle::{id, context, url, navigate,
  block_urls, close}`, and the `ContextHandle` trait. `PluginSet` has one
  dispatcher per hook with these rules: the first `Cancel` wins and no
  navigation happens; redirects apply in order, at most five, only to `http`,
  `https`, `about:blank` and `data:` addresses and only with `page.navigate`;
  any `Block` wins for requests and a failing `on_request` blocks; failing
  verdicts join with `; `; hooks behind `contexts`, `net.intercept`,
  `net.observe` and `test.hooks` reach only plugins that hold the capability;
  `Cookie`, `Authorization`, `Proxy-Authorization` and `Set-Cookie` headers
  read `[redacted]` without `net.sensitive`; response bodies need `net.bodies`
  and a `max_body`; a changed context proxy needs `launch.proxy` and honours
  `Seals::CONTEXT_PROXY`. `check` also refuses a `network()` or `task()` the
  plugin has no grant for. `Timer`, `Clock` and `PluginSet::with_timer` give
  tasks sleeps and time limits without a runtime. `config::options` reads typed
  options (`unknown option` errors name the plugin). A plugin written for 0.1.0
  compiles and behaves as before (`tests/legacy.rs`).
- `seleniumbase-rs-plugin-testing` 0.1.3: `Call::{Navigate, Url, Close,
  BlockUrls, NewContext, NewPage, Dispose}`, `RecordingPage::{evaluating, at,
  with_id, in_context}` (clonable), `RecordingBrowser::{with_contexts, failing,
  with_extensions}` with live and peak counts of contexts and tabs and
  `FakeContext`, `ManualTimer`, `drive_request`, `drive_response` and `VecSink`.
- `seleniumbase-rs-plugin` 0.1.3: a plugin cannot take the host down. A panic
  in any hook is caught and becomes `PluginError::Panicked { plugin, hook }`
  (the dispatchers of `before_launch`, `on_browser`, `on_page_created` and
  `on_close` now go through the same `run_hook` as the new hooks). A set that
  has a timer (`PluginSet::with_timer`) cuts every hook off at its limit with
  `PluginError::Timeout`: `before_navigate` 5 s, `on_request` 2 s (the request
  is blocked), `on_test_end` and `before_launch` 30 s, every other hook 10 s.
  `Metadata::budget` can ask for another limit per hook (`Budgets` gained
  `before_navigate`, `on_request`, `on_test_end`, `before_close`, `on_close` and
  `other`), at most four times the default (`Budgets::{default_for,
  limit_for}`); without a timer nothing times out. Every browser, tab and
  context handle a hook gets is a `Guarded<H>` made for that plugin: a protocol
  command needs the capabilities `cdp_policy::required` names (a plugin with
  `raw:cdp` may send any other command), `Fetch.*`, `Target.setAutoAttach`,
  `Browser.close`, `Browser.crash` and `Browser.crashGpuProcess` are refused for
  every plugin (`cdp_policy::host_owned`), a raw `Network.setBlockedURLs` is
  turned into `PageHandle::block_urls` (and sent as it was on a tab that does
  not offer that), `navigate` inside `before_navigate` and `new_page` or
  `new_context` inside a page or context hook fail with `PluginError::Reentrant`,
  and handles opened through a guarded handle are guarded too.
  `PluginSet::{guarded_browser, guarded_page, guarded_context}` guard a handle
  for work outside the hooks, such as a task. Tests in `tests/guard.rs`.

### Changed

- The crates are at version 0.1.3.
- `HostInfo` for WebDriver hosts no longer offers `Task` and `TestHooks`, so
  `PluginSet::check_with` refuses a plugin that needs them there (they were
  already refused for `Contexts` and the `Net*` capabilities).
- `seleniumbase-rs-plugin-testing`: `Call` has new variants, so an exhaustive
  `match` on it needs an arm for them.
- `seleniumbase-rs-plugin`: the `config` module is public (its items were
  already re-exported at the crate root).
- `seleniumbase-rs-plugin`: a plugin's raw `Network.setBlockedURLs` reaches the
  tab as `block_urls`, so a recording tab shows `Call::BlockUrls` where it
  showed `Call::Send("Network.setBlockedURLs", ..)`; the tests of
  `block-resources` and `wasm` and `tests/legacy.rs` were updated to match.
  A plugin that sends a command without the capability the table names (for
  example `Network.getCookies` without `cookies.read`) now gets an error; the
  legacy capability set (`raw:cdp`) still covers every command the host does
  not keep for itself.
- `seleniumbase-rs-plugin`: `PluginError` has two new variants, `Panicked` and
  `Reentrant`.

