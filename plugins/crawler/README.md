# seleniumbase-rs-plugin-crawler

Crawls a site from its links and reports what is broken: pages that do not load
or answer an error status, addresses that must be reachable and are not, and
errors in the browser console. A test can fail on that report.

Use it only on sites you own or have permission to test. It follows plain
`<a href>` links with `http` and `https` addresses. It never clicks, submits a
form or runs a page's scripts on purpose. It reads `robots.txt` and obeys it
unless you turn that off, waits between pages and stops at a page limit.

- Category: `testing`. Chromium over CDP only.
- Capabilities: `task`, `page.navigate`, `page.evaluate`, `net.observe`,
  `test.hooks`. With a `state_file`, also `host.fs.read` and `host.fs.write`
  for that file (and the `.tmp` file beside it) only. It holds no
  `net.intercept`, `net.bodies` or `net.sensitive`.
- Hooks: `network()` (observes documents), `protocol_events()`
  (`Runtime.exceptionThrown`, `Log.entryAdded`), `before_navigate`,
  `on_response`, `on_protocol_event`, `on_test_end`, `task`.

## Options

Set them under `[plugins.crawler]` in `sbase_config.toml` or with
`--plugin-opt crawler.KEY=<TOML>`. A misspelt option is an error.

| Option | Default | Meaning |
|---|---|---|
| `start` | `[]` | Where the crawl starts. The task input may give `start` instead; one of them is required. |
| `scope` | `"same-origin"` | `"same-origin"` (scheme, host and port of a start address), `"same-site"` (its host and subdomains; a rule of thumb, not the public-suffix list) or `{ hosts = ["example.com"] }` (those hosts and their subdomains). |
| `include` | `[]` | Patterns a followed link must match, if any (`*` any run of characters, `?` one). A pattern that starts with `/` is matched against the path and query, any other against the whole address. Start addresses are not filtered. |
| `exclude` | `[]` | Patterns of links not to follow, matched like `include`. |
| `max_depth` | 3 | How many links deep; start addresses are depth 0 (at most 100). |
| `max_pages` | 500 | Most pages loaded (1 to 50000). |
| `delay_ms` | 1000 | Pause between two navigations (at most 60000). A `Crawl-delay` in robots.txt can make it longer (at most a minute). |
| `respect_robots` | `true` | Read and obey robots.txt. `false` is for sites you own or may test. |
| `max_links` | 1000 | Most links read from one page (1 to 100000). |
| `state_file` | none | A JSON file that keeps the crawl so it can be resumed. |
| `expect.max_status` | 399 | A page above it is broken. 399 makes every 4xx and 5xx broken; Python SeleniumBase counts only 404. A page that does not load counts as 404, as in Python. |
| `expect.must_reach` | `[]` | Addresses the crawl must load. One it did not load, or that was broken, is `unreached`. |
| `expect.no_console_errors` | `false` | Console errors fail the report. They are recorded either way. |

```toml
[plugins.crawler]
start = ["https://staging.example.com/"]
scope = "same-origin"
exclude = ["/logout*", "*?print=1"]
max_depth = 4
max_pages = 200
delay_ms = 500
state_file = "crawl-state.json"

[plugins.crawler.expect]
must_reach = ["https://staging.example.com/pricing"]
no_console_errors = true
```

## The task

```text
sbrs plugin run crawler --input crawl.json --out pages.jsonl
```

The input is `{"start": ["https://staging.example.com/"], "resume": true}`; both
keys are optional. One tab does the work, breadth first, one navigation at a
time:

1. The address is checked against the robots.txt of its site, which is opened in
   the tab once per site like any page (so proxy and privacy plugins apply). A
   4xx answer means no rules; a 5xx answer or none closes the site to the
   crawl. A group for `sbrs` wins over `*`, the longest rule wins, `Allow` wins a
   tie, `*` and a trailing `$` work in a rule.
2. The page is opened. One script reads its title, its HTTP status (from the
   navigation timing entry, else from the response the host reported) and its
   `a[href]` links. A page with `<meta name="robots" content="nofollow">` is read
   but its links are not followed.
3. Links are normalised (lower-case scheme and host, default port and fragment
   dropped, dot segments resolved) and queued unless known, outside the scope,
   filtered by `include` or `exclude`, or deeper than `max_depth`.

A link outside the scope is never navigated. While a crawl runs the plugin's
`before_navigate` cancels such a navigation with `<url> is outside the crawl
scope`. A page that redirects out of the scope is recorded, and its links are
not followed.

Each page writes one line to the sink:

```json
{"index": 0, "url": "https://staging.example.com/", "depth": 0, "from": null, "status": 200, "title": "Home", "links": 12, "queued": 9}
{"index": 3, "url": "https://staging.example.com/old", "depth": 1, "from": "https://staging.example.com/", "status": 404, "title": "Not found", "links": 0, "queued": 0}
{"index": 4, "url": "https://staging.example.com/x", "depth": 2, "from": "https://staging.example.com/a", "error": "net::ERR_CONNECTION_RESET"}
{"url": "https://staging.example.com/admin", "depth": 1, "from": "https://staging.example.com/", "skipped": "robots.txt"}
```

A line may also carry `final_url` (after a redirect), `nofollow` or `error`. The
task returns the report:

```json
{"pages": 31, "edges": 120, "broken": [{"url": "https://staging.example.com/old", "from": "https://staging.example.com/", "status": 404}],
 "js_errors": [], "js_errors_total": 0, "unreached": [], "robots_blocked": 1, "truncated": false,
 "passed": false, "summary": "Broken link detected:\nhttps://staging.example.com/old", "resumed": false}
```

`summary` uses the wording of Python's `assert_no_404_errors` (`Broken link
detected:` or `Broken links detected:`, the addresses sorted, one per line). A
crawl that loaded no page does not pass.

## As a test plugin

After a crawl, the next `on_test_end` fails the test with the summary unless the
report passed: no broken page, every `must_reach` address loaded, and no console
error when `no_console_errors` is set. A report judges one test. Read it with
`Crawler::report()`.

## Resuming

With `state_file` the crawl is written to `<file>.tmp` and renamed over the file
every few pages and at the end. A later run goes on from it when the options that
decide which pages are crawled (`start`, `scope`, `include`, `exclude`,
`max_depth`, `respect_robots`) are the same; another file is ignored (the result
says `state_ignored`) and overwritten. `max_pages`, `delay_ms` and `expect` may
change, so a crawl stopped by the page limit can be resumed with a higher one.
`"resume": false` in the input starts over.

```json
{"version": 1, "config_hash": "9f2c1d0a7b3e4a55", "visited": [], "frontier": [["https://staging.example.com/a", 1]],
 "edges": [["https://staging.example.com/", "https://staging.example.com/a"]], "broken": [], "pages": 1, "blocked": []}
```

## Limits

- Pages only: images, scripts and stylesheets are not checked, and a link outside
  the scope is neither followed nor checked (Python sends a HEAD request for
  every link; this crawler never leaves the scope).
- One crawl at a time per plugin; a second `run` fails with `crawler: a crawl is
  already running`.
- At most 200000 addresses are queued and 200000 links recorded as `edges`; the
  report keeps the first 200 console errors and counts the rest.
- `ArtifactsWrite` waits for an artifact API in the plugin host: the report is
  returned, not saved.
- Console errors need the host to deliver `Runtime.exceptionThrown` and
  `Log.entryAdded` to plugins.
- Nothing in it has run in a real Chrome yet unless the `crawler_chrome` test was
  run; the other tests use the plugin API's fakes
  (`seleniumbase-rs-plugin-testing`).

## Test it

```rust
use seleniumbase_rs_plugin::{Configurable, PluginSet};
use seleniumbase_rs_plugin_crawler::Crawler;

let crawler = Crawler::configure(&serde_json::json!({
    "start": ["https://example.com/"],
    "max_pages": 20,
}))?;
let set = PluginSet::strict().with(crawler)?;
assert_eq!(set.task_names(), ["crawler"]);
```

The tests in `tests/crawler.rs` drive a whole crawl against a fake tab, and
`tests/crawler_chrome.rs` (`#[ignore]`) crawls a small local site in headless
Chrome.
