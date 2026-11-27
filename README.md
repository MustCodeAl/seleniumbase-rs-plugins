# seleniumbase-rs plugins

Plugins for [seleniumbase-rs](https://github.com/MustCodeAl/seleniumbase-rs): Rust
crates that extend how a browser starts, what every tab receives, and what tasks
can run on it. The design is
[ADR 004](https://github.com/MustCodeAl/seleniumbase-rs/blob/main/docs/adr/004-plugin-framework.md).

> [!NOTE]
> Plugins run in seleniumbase-rs (v0.10.0+; plugin host available since v0.9.3) behind its `plugins` feature in both
> the pure CDP engine (`sb_cdp`) and the WebDriver engine (`BaseCase`). The
> [Browser Plugins guide](https://github.com/MustCodeAl/seleniumbase-rs/blob/main/docs/tutorials/plugins.md)
> shows how to attach a plugin set to a browser.

Documentation lives on the seleniumbase-rs docs site:
[Plugins](https://mustcodeal-seleniumbase-rs.docs7.io/plugins/overview).

## Built-in plugins

The seven official built-in plugins live in `seleniumbase-rs-plugins-builtin`, each behind a cargo feature (`shield`, `crx`, `browser`, `fetcher`, `extractor`, `batcher`, `crawler`):

| Plugin | What it does | Install |
|---|---|---|
| [`shield`](https://github.com/MustCodeAl/seleniumbase-rs-plugins/tree/main/plugins/shield) | Privacy hardening for Chromium: disables background telemetry, WebRTC address leaks, and third-party cookies; enforces ephemeral profiles; includes opt-in Tor SOCKS5 routing (`tor` feature, `shield.tor = true`) with per-context circuit isolation and `.onion` resolution | `cargo add seleniumbase-rs-plugin-shield --git https://github.com/MustCodeAl/seleniumbase-rs-plugins` |
| [`crx`](https://github.com/MustCodeAl/seleniumbase-rs-plugins/tree/main/plugins/crx) | Unified Chromium extension loader: loads `.crx` (CRX3/CRX2), `.zip`, and unpacked Manifest V3 extension folders with optional service-worker readiness waits (`wait_for_workers`) | `cargo add seleniumbase-rs-plugin-crx --git https://github.com/MustCodeAl/seleniumbase-rs-plugins` |
| [`browser`](https://github.com/MustCodeAl/seleniumbase-rs-plugins/tree/main/plugins/browser) | Containerized persistent browser sessions: persists cookies, `localStorage`/`sessionStorage`, auth state, open tabs, and regional identity across runs with TTL expiry, geolocation targeting (40+ country presets), proxy IP auto-rotation, interactive sign-in capture, and dynamic SPA flow extraction | `cargo add seleniumbase-rs-plugin-browser --git https://github.com/MustCodeAl/seleniumbase-rs-plugins` |
| [`fetcher`](https://github.com/MustCodeAl/seleniumbase-rs-plugins/tree/main/plugins/fetcher) | Request interception rules (strip, block, add headers), response recording, and a task that fetches URLs through the browser with its cookies | `cargo add seleniumbase-rs-plugin-fetcher --git https://github.com/MustCodeAl/seleniumbase-rs-plugins` |
| [`extractor`](https://github.com/MustCodeAl/seleniumbase-rs-plugins/tree/main/plugins/extractor) | Discovers structured data on a page (JSON-LD, tables, repeated cards, CSS selectors) and extracts typed JSON records or clean markdown | `cargo add seleniumbase-rs-plugin-extractor --git https://github.com/MustCodeAl/seleniumbase-rs-plugins` |
| [`batcher`](https://github.com/MustCodeAl/seleniumbase-rs-plugins/tree/main/plugins/batcher) | Runs lists of jobs across bounded concurrent browser tabs in isolated contexts with timeouts, retries, backoff, and a resume file | `cargo add seleniumbase-rs-plugin-batcher --git https://github.com/MustCodeAl/seleniumbase-rs-plugins` |
| [`crawler`](https://github.com/MustCodeAl/seleniumbase-rs-plugins/tree/main/plugins/crawler) | Breadth-first site crawler respecting `robots.txt`, depth/page limits, and scope filters, reporting broken pages and console errors | `cargo add seleniumbase-rs-plugin-crawler --git https://github.com/MustCodeAl/seleniumbase-rs-plugins` |

## Community plugins

Standalone workspace crates that you add individually rather than through `seleniumbase-rs-plugins-builtin`:

| Plugin | What it does | Install |
|---|---|---|
| [`block-resources`](https://github.com/MustCodeAl/seleniumbase-rs-plugins/tree/main/plugins/block-resources) | Stops pages from loading images, fonts, media, stylesheets, or custom URL patterns via CDP `ResourceKind` rules and `Network.setBlockedURLs` | `cargo add seleniumbase-rs-plugin-block-resources --git https://github.com/MustCodeAl/seleniumbase-rs-plugins` |
| [`imap`](https://github.com/MustCodeAl/seleniumbase-rs-plugins/tree/main/plugins/imap) | Waits read-only over IMAPS for a verification email and extracts its one-time code or link (`password_env` must start with `IMAP_`, `MAIL_`, or `SB_`) | `cargo add seleniumbase-rs-plugin-imap --git https://github.com/MustCodeAl/seleniumbase-rs-plugins` |
| [`behavior-dataset`](https://github.com/MustCodeAl/seleniumbase-rs-plugins/tree/main/plugins/behavior-dataset) | Live-site human user journey explorer and synthetic behavioral ML dataset generator | `cargo add seleniumbase-rs-plugin-behavior-dataset --git https://github.com/MustCodeAl/seleniumbase-rs-plugins` |
| [`cloud-logging`](https://github.com/MustCodeAl/seleniumbase-rs-plugins/tree/main/plugins/cloud-logging) | Uploads test artifacts to Google Cloud Storage or Azure Blob Storage | `cargo add seleniumbase-rs-plugin-cloud-logging --git https://github.com/MustCodeAl/seleniumbase-rs-plugins` |
| [`langchain`](https://github.com/MustCodeAl/seleniumbase-rs-plugins/tree/main/plugins/langchain) | Agentic browser tool definitions and action runner for LLM frameworks | `cargo add seleniumbase-rs-plugin-langchain --git https://github.com/MustCodeAl/seleniumbase-rs-plugins` |
| [`ocr`](https://github.com/MustCodeAl/seleniumbase-rs-plugins/tree/main/plugins/ocr) | OCR model cache resolution, PNG validation, and text extraction task | `cargo add seleniumbase-rs-plugin-ocr --git https://github.com/MustCodeAl/seleniumbase-rs-plugins` |
| [`owasp`](https://github.com/MustCodeAl/seleniumbase-rs-plugins/tree/main/plugins/owasp) | Passive OWASP security auditing (headers, CSP, CORS, cookies, JWT, DOM, forms, SCA) and OWASP PTK extension bridge | `cargo add seleniumbase-rs-plugin-owasp --git https://github.com/MustCodeAl/seleniumbase-rs-plugins` |

## The framework

| Crate | What it is | Install |
|---|---|---|
| [`seleniumbase-rs-plugin`](https://github.com/MustCodeAl/seleniumbase-rs-plugins/tree/main/crates/seleniumbase-rs-plugin) | Core plugin API (`Plugin`, `PluginSet`, `LaunchSettings`, `Package`, `BrowserHandle`, `PageHandle`) plus optional `wasm` feature (`seleniumbase_rs_plugin::wasm`, sandboxed `wasmi` host for WebAssembly plugins) | `cargo add seleniumbase-rs-plugin --git https://github.com/MustCodeAl/seleniumbase-rs-plugins` |
| [`seleniumbase-rs-plugins-builtin`](https://github.com/MustCodeAl/seleniumbase-rs-plugins/tree/main/crates/seleniumbase-rs-plugins-builtin) | Built-in plugin aggregator behind one feature per plugin (`shield`, `crx`, `browser`, `fetcher`, `extractor`, `batcher`, `crawler`) and `registry()` | `cargo add seleniumbase-rs-plugins-builtin --git https://github.com/MustCodeAl/seleniumbase-rs-plugins --features shield` |
| [`seleniumbase-rs-plugin-testing`](https://github.com/MustCodeAl/seleniumbase-rs-plugins/tree/main/crates/seleniumbase-rs-plugin-testing) | Recording fakes (`RecordingBrowser`, `RecordingPage`, `ManualTimer`, `VecSink`) to test plugins without Chrome | `cargo add --dev seleniumbase-rs-plugin-testing --git https://github.com/MustCodeAl/seleniumbase-rs-plugins` |
| [`template`](https://github.com/MustCodeAl/seleniumbase-rs-plugins/tree/main/template) | Starter template for writing a custom plugin | copy the folder |

More plugins live in their own repositories, such as
[tauri-plugin-sbrs-automation](https://github.com/MustCodeAl/tauri-plugin-sbrs-automation).
Search GitHub for the topic `seleniumbase-rs-plugin` to find community plugins.

## Using the built-in registry

`seleniumbase-rs-plugins-builtin` has one feature per built-in plugin and none enabled by
default, so a build compiles only what it asks for. `registry()` returns a
`Registry` of enabled plugins and constructs them from name and JSON options:

```rust
use seleniumbase_rs_plugins_builtin::{registry, PluginSpec};
use serde_json::json;

// Cargo.toml: seleniumbase-rs-plugins-builtin = { ..., features = ["shield", "browser"] }
let set = registry().plugin_set(&[
    PluginSpec::new("shield").options(json!({ "level": "strict", "tor": true })),
    PluginSpec::new("browser").options(json!({ "session": "checkout", "country": "DE" })),
])?;
```

## WebAssembly plugin host (`wasm` feature)

Write plugins in any language that compiles to WebAssembly and load them via the framework's `wasm` feature (`seleniumbase-rs-plugin = { ..., features = ["wasm"] }`):

- Sandboxed with `wasmi` (zero host imports, configurable fuel and memory limits).
- See [`crates/seleniumbase-rs-plugin/WASM_README.md`](crates/seleniumbase-rs-plugin/WASM_README.md) for the ABI and [`crates/seleniumbase-rs-plugin/examples/hello.wat`](crates/seleniumbase-rs-plugin/examples/hello.wat).

## Writing a Rust plugin

```rust
use seleniumbase_rs_plugin::{async_trait, PageHandle, Plugin, Result};

pub struct Hello;

#[async_trait]
impl Plugin for Hello {
    fn name(&self) -> &str {
        "hello"
    }

    async fn on_page_created(&self, page: &dyn PageHandle) -> Result<()> {
        page.add_init_script("console.log('hello from a plugin')").await
    }
}
```

1. Copy [`template/`](https://github.com/MustCodeAl/seleniumbase-rs-plugins/tree/main/template) (or run `sbrs plugin new`) and name the crate `seleniumbase-rs-plugin-<name>`.
2. Test it offline with `seleniumbase-rs-plugin-testing` (`RecordingPage`, `RecordingBrowser`).
3. Publish it on GitHub with topic `seleniumbase-rs-plugin`.

> [!WARNING]
> A plugin runs with your program's privileges and sees pages, cookies, and credentials handled by the browser. Audit plugins before enabling them.

## License

MIT.
