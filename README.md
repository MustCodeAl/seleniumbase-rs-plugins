# seleniumbase-rs plugins

Plugins for [seleniumbase-rs](https://github.com/MustCodeAl/seleniumbase-rs): Rust
crates that change how a browser starts and what every tab gets, the way
puppeteer-extra plugins do for Puppeteer. The design is
[ADR 004](https://github.com/MustCodeAl/seleniumbase-rs/blob/main/docs/adr/004-plugin-framework.md).

> [!NOTE]
> Early. Plugins run in seleniumbase-rs behind its `plugins` feature: in the
> pure CDP engine (`sb_cdp`) since 0.3.0 and in the WebDriver engine
> (`BaseCase`) since 0.4.0. The
> [Browser Plugins guide](https://github.com/MustCodeAl/seleniumbase-rs/blob/main/docs/tutorials/plugins.md)
> shows how to attach a set to a browser.

The documentation for these plugins is part of the seleniumbase-rs site:
[Plugins](https://mustcodeal-seleniumbase-rs.docs7.io/plugins/overview).

## Plugins you can install

Every plugin is its own crate. Add the ones you want to your project; they are
also examples of how to write one.

| Plugin | What it does | Install |
|---|---|---|
| [`batcher`](https://github.com/MustCodeAl/seleniumbase-rs-plugins/tree/main/plugins/batcher) | Runs a list of jobs in browser tabs, a few at a time and in chunks, with a time limit, retries with backoff and a resume file, and one result line per job (a job runs the built-in `open` or another plugin such as `fetcher` or `extractor`) | `cargo add seleniumbase-rs-plugin-batcher --git https://github.com/MustCodeAl/seleniumbase-rs-plugins` |
| [`block-resources`](https://github.com/MustCodeAl/seleniumbase-rs-plugins/tree/main/plugins/block-resources) | Stops pages from loading images, fonts or media (faster, less data) | `cargo add seleniumbase-rs-plugin-block-resources --git https://github.com/MustCodeAl/seleniumbase-rs-plugins` |
| [`browser`](https://github.com/MustCodeAl/seleniumbase-rs-plugins/tree/main/plugins/browser) | Loads browser extensions into the Chromium browser seleniumbase-rs starts, from `.zip` and `.crx` files and unpacked folders (Python's `--extension-zip` and `--extension-dir`), after checking that each one is Manifest V3; it replaces `crx` and cannot share a set with it. The worker-wait and session options of the design are not implemented yet | `cargo add seleniumbase-rs-plugin-browser --git https://github.com/MustCodeAl/seleniumbase-rs-plugins` |
| [`crawler`](https://github.com/MustCodeAl/seleniumbase-rs-plugins/tree/main/plugins/crawler) | Crawls the links of a site you own or may test, breadth first in one tab, with a scope, a depth and page limit, a delay and robots.txt, and reports broken pages and JavaScript errors (as a task, or as a test plugin that fails the test) | `cargo add seleniumbase-rs-plugin-crawler --git https://github.com/MustCodeAl/seleniumbase-rs-plugins` |
| [`crx`](https://github.com/MustCodeAl/seleniumbase-rs-plugins/tree/main/plugins/crx) | Loads packed Chrome extensions (`.crx`, CRX3 and CRX2) | `cargo add seleniumbase-rs-plugin-crx --git https://github.com/MustCodeAl/seleniumbase-rs-plugins` |
| [`extractor`](https://github.com/MustCodeAl/seleniumbase-rs-plugins/tree/main/plugins/extractor) | Finds structured data on a page (JSON-LD, tables, repeated cards, selectors) and extracts it as JSON, one typed record per card or row, as a job on a tab or a task over a list of URLs | `cargo add seleniumbase-rs-plugin-extractor --git https://github.com/MustCodeAl/seleniumbase-rs-plugins` |
| [`fetcher`](https://github.com/MustCodeAl/seleniumbase-rs-plugins/tree/main/plugins/fetcher) | Rules for the requests a browser sends (strip, block, add headers), a record of the responses, and a task that fetches a list of URLs through the browser with its cookies | `cargo add seleniumbase-rs-plugin-fetcher --git https://github.com/MustCodeAl/seleniumbase-rs-plugins` |
| [`imap`](https://github.com/MustCodeAl/seleniumbase-rs-plugins/tree/main/plugins/imap) | Waits for an email in an IMAP mailbox (read only, over IMAPS) and hands back its one-time code or link, so a login that mails you a code can be driven end to end; the password comes from the environment variable `password_env` names (names starting with `IMAP_`, `MAIL_` or `SB_` only), never from an option | `cargo add seleniumbase-rs-plugin-imap --git https://github.com/MustCodeAl/seleniumbase-rs-plugins` |
| [`shield`](https://github.com/MustCodeAl/seleniumbase-rs-plugins/tree/main/plugins/shield) | Privacy hardening for Chromium: turns off the browser's own telemetry, WebRTC address leaks and third-party cookies, and refuses a persistent profile | `cargo add seleniumbase-rs-plugin-shield --git https://github.com/MustCodeAl/seleniumbase-rs-plugins` |
| [`tor`](https://github.com/MustCodeAl/seleniumbase-rs-plugins/tree/main/plugins/tor) | Routes the Chromium browser seleniumbase-rs starts through a local Tor SOCKS listener that you run yourself (sbrs never installs or starts Tor), gives each browser context circuits of its own, and has Tor resolve every name, so `.onion` services work. It pairs with `shield`: shield turns off the browser's own requests, tor hides your address. It protects you; it is not a way around bans or rate limits | `cargo add seleniumbase-rs-plugin-tor --git https://github.com/MustCodeAl/seleniumbase-rs-plugins` |
| [`wasm`](https://github.com/MustCodeAl/seleniumbase-rs-plugins/tree/main/plugins/wasm) | Runs plugins written in any language that compiles to WebAssembly, sandboxed with wasmi (no host imports, fuel and memory limits) | `cargo add seleniumbase-rs-plugin-wasm --git https://github.com/MustCodeAl/seleniumbase-rs-plugins` |

The framework itself:

| Crate | What it is | Install |
|---|---|---|
| [`seleniumbase-rs-plugin`](https://github.com/MustCodeAl/seleniumbase-rs-plugins/tree/main/crates/seleniumbase-rs-plugin) | The API: `Plugin`, `PluginSet`, `LaunchSettings`, `Package`, the `BrowserHandle` and `PageHandle` traits | `cargo add seleniumbase-rs-plugin --git https://github.com/MustCodeAl/seleniumbase-rs-plugins` |
| [`seleniumbase-rs-plugins-builtin`](https://github.com/MustCodeAl/seleniumbase-rs-plugins/tree/main/crates/seleniumbase-rs-plugins-builtin) | The built-in plugins behind one cargo feature each (`shield`, `block-resources`, `crx`, `fetcher`, `extractor`, `batcher`, `crawler`, `browser`, `imap`, `tor`), and `registry()`, a registry of the enabled ones that builds a plugin from its name and options | `cargo add seleniumbase-rs-plugins-builtin --git https://github.com/MustCodeAl/seleniumbase-rs-plugins --features shield` |
| [`seleniumbase-rs-plugin-testing`](https://github.com/MustCodeAl/seleniumbase-rs-plugins/tree/main/crates/seleniumbase-rs-plugin-testing) | Recording fakes of the handles, to test a plugin without a browser | `cargo add --dev seleniumbase-rs-plugin-testing --git https://github.com/MustCodeAl/seleniumbase-rs-plugins` |
| [`template`](https://github.com/MustCodeAl/seleniumbase-rs-plugins/tree/main/template) | Start your own plugin from here | copy the folder |

More plugins live in their own repositories, such as
[tauri-plugin-sbrs-automation](https://github.com/MustCodeAl/tauri-plugin-sbrs-automation).
Search GitHub for the topic `seleniumbase-rs-plugin` to find community ones.

## Built-in plugins

`seleniumbase-rs-plugins-builtin` has one feature per plugin and none on by
default, so a build compiles only what it asks for. `registry()` returns a
`Registry` of the plugins that are on; the registry builds a plugin from its name
and options. A plugin that denies unknown options, as `shield` does, makes the
registry refuse an option it does not know (check that of each plugin):

```rust
use seleniumbase_rs_plugins_builtin::{registry, PluginSpec};
use serde_json::json;

// Cargo.toml: seleniumbase-rs-plugins-builtin = { ..., features = ["shield"] }
let set = registry().plugin_set(&[
    PluginSpec::new("shield").options(json!({ "level": "strict" })),
])?;
```

The `wasm` host is not in the aggregator yet: it cannot be built from a name and
options until it takes the path of a module.

### shield

Options (`[plugins.shield]`): `level` (`basic` or `strict`), `webrtc` (`off`,
`policy` or `relay-only`), `block_third_party_cookies`, `ephemeral_profile`,
`extra_block_hosts`, `safe_browsing`. The browser switches, features and hosts it
uses were checked against the Chromium source; the list and its sources are in
[`plugins/shield/src/telemetry.rs`](plugins/shield/src/telemetry.rs). Two options,
`clear_between_tests` and `sweep_stale_profiles`, do nothing yet because they
need hooks that the plugin API does not have: they default to `false`, and
`true` is a configuration error until they work. `relay-only` (the default)
forces relay candidates, so WebRTC calls between peers without a TURN server do
not connect; use `policy` if you need them. `strict` makes the browser unable to
resolve a few Google hosts, and pages cannot reach them either. More in the
[shield README](https://github.com/MustCodeAl/seleniumbase-rs-plugins/tree/main/plugins/shield).

## A plugin

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

Every hook is optional: `before_launch` (change the browser's start-up
settings), `on_browser`, `on_page_created`, `on_close`. A plugin can also
declare JavaScript and CSS `packages` for every tab, its `dependencies` on other
plugins, and `requirements` (run last, a visible window, a Chromium browser, a
browser it starts itself). Errors in the launch and page hooks stop the launch or
the tab instead of being skipped.

## Write your own

1. Copy [`template/`](https://github.com/MustCodeAl/seleniumbase-rs-plugins/tree/main/template) and rename the crate to
   `seleniumbase-rs-plugin-<name>`.
2. Test it with `seleniumbase-rs-plugin-testing`: `RecordingPage` and
   `RecordingBrowser` record every command and script your hooks send.
3. Publish it on GitHub with the topic `seleniumbase-rs-plugin` so people find it.

Not a Rust programmer? Write the plugin in any language that compiles to
WebAssembly and load it with the [`wasm`](plugins/wasm) host: the module only
describes the plugin in JSON (a name, browser switches, page scripts, URLs to
block) and runs in a sandbox. The ABI is in [its README](plugins/wasm/README.md).

A plugin depends only on `seleniumbase-rs-plugin`, never on seleniumbase-rs, so
it keeps working as seleniumbase-rs changes.

> [!WARNING]
> A plugin is code that runs with your program's rights and sees every page,
> cookie and password the browser handles. Review a plugin before you add it,
> as you would any dependency.

## Design

- [ADR 004: the plugin framework](https://github.com/MustCodeAl/seleniumbase-rs/blob/main/docs/adr/004-plugin-framework.md):
  the current `Plugin` trait, hooks and `PluginSet`.
- [Plugin architecture (ADR 005, proposed)](docs/adr/0001-plugin-architecture.md):
  the next platform version, with capabilities, five categories, built-in
  plugins in the prebuilt binaries, a plugin store and WASM ABI 2. It targets
  seleniumbase-rs 0.5.0.

## License

MIT.
