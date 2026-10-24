# seleniumbase-rs-plugin-fetcher

Rules for the requests a browser sends, a record of the responses it gets, and
a task that fetches a list of URLs through the browser with its cookies.

It works on what the user's own browser session does: it adds no traffic the
browser would not send, hides nothing, and sends nothing anywhere else. Use it
on pages you load and sites you may test.

- Category: `core`. Chromium over CDP only.
- Capabilities: `net.intercept`, `net.observe`, `task`, `page.evaluate`,
  `page.navigate`; optional `net.bodies` (without it a record has no body).
  It does not hold `net.sensitive`, so `Cookie`, `Authorization`,
  `Proxy-Authorization` and `Set-Cookie` read `[redacted]` in every record.
- Hooks: `network()` (rules and observe filters), `on_response`, `task`,
  `job_runner`.

## Options

Set them under `[plugins.fetcher]` in `sbase_config.toml` or with
`--plugin-opt fetcher.KEY=<TOML>`. A misspelt option is an error.

| Option | Default | Meaning |
|---|---|---|
| `strip` | `[]` | Kinds of resource to fail: `stylesheet`, `image`, `media`, `font`, `script`, `xhr`, `fetch`, `websocket`, `other`. Documents cannot be stripped. |
| `block` | `[]` | URL patterns to fail (`*` any run of characters, `?` one). |
| `capture` | `[]` | URL patterns whose responses are recorded. |
| `headers` | `{}` | Request headers to add. `Host`, `Content-Length`, `Transfer-Encoding`, `Connection`, `Upgrade`, `Expect`, `TE` and `Trailer` cannot be set; values may not hold line breaks. |
| `header_urls` | `[]` | URL patterns the `headers` go to. Empty means every request, third parties included: give patterns when a header carries a secret. |
| `max_body_bytes` | 2 MiB | Most bytes kept of a captured or fetched body (`0` keeps none; at most 64 MiB). |
| `max_captures` | 500 | Most records kept; the oldest go first (at most 100000). |

```toml
[plugins.fetcher]
strip = ["image", "font", "media"]
block = ["*://ads.example.com/*"]
capture = ["*/api/*"]
headers = { "Accept-Language" = "de" }
header_urls = ["https://example.com/*"]
```

## Records

`Fetcher::captured()` returns the log and `Fetcher::take_captured()` drains it.
A record is `{url, method, status, mime, text | base64, truncated, outcome,
headers, at_ms}`. `text` is set for text types and for bodies that are valid
UTF-8, `base64` for the rest; `outcome` is `ok`, `failed` or `blocked`.

## Fetching: the job runner and the task

Both fetch inside a page with `fetch(url, { credentials: "include" })`. The
request therefore obeys that page's cross-origin rules, carries the cookies the
browser holds for the site, and goes through the proxy and privacy plugins
like any other request. The URL travels as a JSON literal and is never pasted
into the script. Only `http` and `https` addresses without credentials are
accepted.

Job (for a batching plugin):

```json
{"url": "https://example.com/api/items", "max_bytes": 100000}
```

gives

```json
{"url": "https://example.com/api/items", "status": 200, "mime": "application/json", "text": "{\"items\":[]}", "truncated": false}
```

Task, started with `sbrs plugin run fetcher --input urls.json`:

```json
{"urls": ["https://example.com/a", "https://example.com/b"], "delay_ms": 500, "warm_up": true}
```

It opens one tab and fetches each URL in turn. With `warm_up` (the default) the
tab first goes to the front page of a site (`https://example.com/`) so the
fetch is same-origin; `false` fetches from wherever the tab is. Each URL records
one line to the sink:

```json
{"index": 0, "url": "https://example.com/a", "status": 200, "mime": "text/html", "text": "<!doctype html>...", "truncated": false}
{"index": 1, "url": "https://example.com/b", "error": "net::ERR_FAILED"}
```

and the task returns `{"total": 2, "ok": 1, "failed": 1, "captured": 0}`. A URL
that fails does not stop the others; a missing capability does. At most 10000
URLs and a pause of at most 60 s.

## Limits

- `headers` and `capture` need the host's request interception. Without it the
  host applies `strip` and `block` through `Network.setBlockedURLs` and says
  that the rest is not available.
- Fetched text is decoded as UTF-8: the task is for text and JSON, not files.
- Nothing in it has run in a real Chrome yet; the tests use the plugin API's
  fakes (`seleniumbase-rs-plugin-testing`).

## Test it

```rust
use seleniumbase_rs_plugin::{Configurable, PluginSet, RequestView, ResourceKind};
use seleniumbase_rs_plugin_fetcher::Fetcher;
use seleniumbase_rs_plugin_testing::drive_request;

let fetcher = Fetcher::configure(&serde_json::json!({ "strip": ["image"] }))?;
let set = PluginSet::strict().with(fetcher)?;
let image = RequestView::new("https://a.test/x.png", "GET", ResourceKind::Image);
assert!(matches!(drive_request(&set, image), seleniumbase_rs_plugin::RequestDecision::Block(_)));
```
