---
title: "ADR 005: Plugin Platform v2 (Capabilities, Categories, Distribution, WASM ABI 2)"
---

# ADR 005: Plugin Platform v2 (Capabilities, Categories, Distribution, WASM ABI 2)

## Status

Proposed on 2026-10-16. It amends [ADR 004](https://github.com/MustCodeAl/seleniumbase-rs/blob/main/docs/adr/004-plugin-framework.md) and supersedes these parts of it: "What is not part of this" (WebAssembly plugins and a plugin folder), "Distribution", and phases 4 and 5. The work targets core **0.5.0**. It starts only after 0.4.0 has shipped: the HAR redirect fix, the Tauri plugin, then merge, gate, push, tag and Homebrew.

This ADR is number 005 in the core repository's series. This copy is the first record in the plugins repository, hence the file name 0001.

This ADR merges three draft designs: the API and lifecycle draft, the install and runtime draft, and the security, privacy and WASM draft. Where the drafts disagreed, each claim was checked against the code. Section 2 records what was checked. Section 3 records how each conflict was resolved.

## 1. Context

### What exists (read on 2026-10-16)

| Piece | Where | State |
|---|---|---|
| API crate `seleniumbase-rs-plugin` 0.1.0 | `seleniumbase-rs-plugins/crates/seleniumbase-rs-plugin/src/lib.rs` | `Plugin` has `name`, `dependencies`, `requirements` (a `u8` bitset: `RUN_LAST`, `HEADFUL`, `LAUNCH_ONLY`, `CHROMIUM_ONLY`), `packages`, `before_launch`, `on_browser`, `on_page_created` and `on_close`. `PluginSet` uses insertion order with `RUN_LAST` plugins at the end, and fails closed. Dependencies: async-trait, serde_json, thiserror. |
| Testing crate | `crates/seleniumbase-rs-plugin-testing` | `RecordingPage` and fake handles |
| Official plugins | `plugins/block-resources`, `plugins/crx`, `plugins/wasm` (wasmi 2.0.0, ABI 1, no imports, fuel, `EnforcedLimits::strict()`) | Workspace version 0.1.0, edition 2024, rust-version 1.88 |
| Core feature `plugins` | `Cargo.toml:127-130,166` | Git dependency `version = "0.1"`, **no `rev`**. The crate is re-exported as `seleniumbase_rs::plugin_api`. |
| CDP hook sites | `src/sb_cdp/plugin_hooks.rs`, `browser.rs` (`launch`, `start`, `prepare_session`, close) | Plugins see the browser through borrowed `BrowserLink` and `TabLink`. `settings_of` hides the proxy password. |
| WebDriver hook sites | branch `worktree-wf_eeb3eaf6-7b6-1`, **not merged** | `BrowserConfig::with_plugins`, `src/browser/plugin_hooks.rs`, and also `PageHandle for sb_cdp::Page` (commit `1414182`) |
| Test hooks | `src/plugins/observer.rs` (`TestPlugin`, `Plugins`) | A separate system. `test_finished` runs after the browser has closed. |
| Distribution | `.github/workflows/release.yml:144`, `homebrew-tap/Formula/sbrs.rb:12` | Both build `--features mcp-server` only, so the prebuilt `sbrs` and `sbrs-mcp` have **no plugin support** |

### Requirements

- **(A) Seamless.** Install and enable a plugin with one short line, and let the prebuilt binaries use plugins.
- **(B) Five categories, each with its own feature set:**
  1. Environment
  2. Testing
  3. Extension
  4. Core
  5. Privacy
- **(C) Seven built-in examples:** batcher, crawler, browser, fetcher, extractor, shield and tor.
- **(D) An outline of:**
  - the trait and hooks;
  - declarative metadata;
  - other languages through WASM;
  - code sketches for the seven plugins.
- **Scope.** The platform is for web testing and automation. Privacy features protect the user who runs the tool. Nothing in it is aimed at defeating other sites' security: no CAPTCHA solving, no credential stuffing, no ban or rate-limit evasion.

## 2. Claims checked against the code

| Claim (draft) | Result | Evidence |
|---|---|---|
| The WASM switch denylist misses switches that core refuses (security draft) | **Confirmed.** `FORBIDDEN_FLAGS` lacks `host-resolver-rules`, `host-rules`, `ignore-certificate-errors-spki-list`, `load-component-extension`, `plugin-launcher` and `nacl-gdb-script`. A module can therefore combine DNS mapping with SPKI trust. | `plugins/wasm/src/abi.rs:24-52` vs `src/stealth/evasions.rs:64-86`; match at `abi.rs:245` |
| Blocked-URL lists overwrite each other (API draft) | **Call order confirmed.** `ad_block` sends `Network.setBlockedURLs`, then plugins run and send it again. That the protocol replaces the list is from protocol knowledge, not a run. | `src/sb_cdp/browser.rs:822-840`; `block-resources/src/lib.rs:72`; `wasm/src/lib.rs:153` |
| Pooled browsers share plugin instances (API draft) | **Confirmed.** Every browser launches from a clone of the same `LaunchOptions`. Closing one browser makes `CrxExtensions::on_close` delete every unpacked folder, including those of the other browsers. | `src/sb_cdp/pool.rs:312-316`; `plugins/crx/src/lib.rs:88-95` |
| A plugin's raw `Fetch.enable` breaks proxy auth (API draft) | **Order confirmed.** Core sends `Fetch.enable{handleAuthRequests}` before the plugin hook runs. Plugins cannot receive events, so their `Fetch.enable` can only stall requests. | `browser.rs:830-840` |
| `LaunchContext` is not `#[non_exhaustive]`, so adding a field is breaking (API draft) | **Confirmed.** `LaunchSettings` *is* `#[non_exhaustive]`, so fields can be added to it. | `lib.rs:119-129`, `lib.rs:135-148` |
| An API bump to 0.2 is harmless (install and security drafts) | **Wrong.** Core requires `version = "0.1"` from a git source, and third-party plugins do the same. A 0.2.0 tag breaks every one of them at once. | `Cargo.toml:127-130` |
| ADR 004 says the API is "pinned to a git revision" | **Stale.** There is no `rev`, on purpose. | `Cargo.toml:128-129` |
| batcher and crawler must live in core because they need `BrowserPool` (install draft) | **Not needed.** Core already has `Browser::new_context_with(ContextOptions{proxy,bypass})`, `BrowserContext::new_page` and `dispose`. Handles over these give plugins what batcher and crawler need, with no cycle. | `src/sb_cdp/context.rs:125-232` |
| Core keeps the extension ids from `Extensions.loadUnpacked` (API draft) | **No: they are dropped.** | `browser.rs:311-323` |
| Core already sends `--disable-features=Translate` | **Confirmed. A finding the drafts missed:** a plugin that appends its own `--disable-features=` competes with core's switch. Feature switches must be merged. | `src/sb_cdp/launch.rs:253`; `extra_args` appended at `:294` |
| The Tauri endpoint reports `browserName: "tauri"`, but WebDriver derives the family from the configured browser | **Confirmed** | `tauri-plugin-sbrs-automation/src/webdriver.rs:283`; branch `src/browser/plugin_hooks.rs:40` (`family_of(config.browser)`) |
| `seleniumbase_rs::plugins` is already taken | **Confirmed**: it holds the test reporters | `src/lib.rs:101` |
| Settings read `sbase_config.toml` from the current folder only; env vars use `SB_*` | **Confirmed.** No `sbrs.toml` exists. | `src/config/settings.rs:180-186, 270-278` |
| linkme is in the tree; toml_edit, tokio-socks and wasmi are not in core's lock | **Confirmed.** linkme 0.3.37 and semver 1.0.28 are transitive. The plugins repo locks wasmi 2.0.0. | `Cargo.lock` |
| wasmi 2.0 has `Module::custom_sections`, `imports`, `Store::set_fuel`, `limiter` and `call_resumable` | **Confirmed.** Custom sections are empty if `Config::ignore_custom_sections(true)`, but the host uses `Config::default()`. | registry `wasmi-2.0.0/src/module/mod.rs:463`, `engine/config.rs:396`; `plugins/wasm/src/host.rs:69` |

**Not verified (spikes are needed before a feature depends on these):**

- Chrome cannot send SOCKS5 username and password.
- `setBlockedURLs` replaces the whole list.
- Chrome uses the last of two duplicated switches.
- How `ignore-certificate-errors-spki-list` behaves.
- What `Storage.clearDataForOrigin` clears.
- How Chrome handles `.onion` names.
- Whether page-level blocks and init scripts reach cross-site out-of-process iframes and workers.
- What `plugins-builtin` adds to binary size.
- Whether `cargo add -F` keeps the source spec of a tagged git dependency.

## 3. Conflicts between the drafts and how they are resolved

| # | Topic | Drafts | Decision and reason |
|---|---|---|---|
| 1 | API version | API draft: 0.2 is breaking. The other two: 0.2 is additive. | **Stay on 0.1.x, additive only.** A 0.2 tag breaks every `version = "0.1"` dependent (section 2). Host support is passed in a new `HostInfo` argument rather than a new field on `LaunchContext`. A deliberate breaking 0.2 is kept for crates.io publishing (section 13). |
| 2 | Capability model | API and install drafts: `u32` bitflags. Security draft: an enum with scopes. | **A scoped enum plus `CapabilitySet`, with stable strings.** Bitflags cannot express `page.script:<hosts>` or file-system scopes, and the lockfile and `--grant` need the strings. |
| 3 | Ordering | API draft: phase from category. Security draft: an explicit `Phase`. Install draft: enable order plus `after`. | **An explicit `Phase`, defaulted from the category.** Ties keep insertion order, and `after`/`before` edges are honoured. Legacy plugins go to `Normal`, so a set of legacy plugins only keeps today's order. |
| 4 | Exclusive resources | API draft: `provides`. Security draft: seals. | **Seals.** A sealed scalar field cannot be changed to a different value later. Two sealers are allowed when they set the same value. List fields are append-only for everyone. |
| 5 | `before_navigate` | `&mut Navigation -> ()` vs `&Navigation -> NavDecision` | **`NavDecision`.** Cancelling is a decision, not an error, and a redirect is checked again. |
| 6 | `on_response` | API draft: returns a decision. The other two: observe only. | **Observe only.** Changing responses is deferred. |
| 7 | Network declarations | `NetworkInterest` / `InterceptRule` / `request_patterns` | **`NetworkInterest`.** It holds *declarative rules* that the host runs without calling the plugin (fast; usable by manifests and WASM), plus observe and intercept filters for `on_response` and `on_request`. |
| 8 | `on_test_end` | API draft: returns a verdict. Security draft: `()`. | **It returns `TestVerdict`**, so that assertion plugins can fail a test. |
| 9 | Hook after navigation (install draft) | Only the install draft has one | **Kept, as `after_navigate`.** Extractor's auto-save needs it. |
| 10 | Registry | API draft: a builtin crate. Install draft: a table in core, linkme later. Security draft: a table in core. | **An aggregator crate, `seleniumbase-rs-plugins-builtin`, in the plugins repo, with one feature per plugin.** Core has one optional dependency on it and forwards the features. That keeps two git dependencies on the plugins repo with the same source spec. No linkme and no inventory. Third-party crates register with `Registry::with(Descriptor::of::<P>())`. |
| 11 | Where batcher and crawler live | Install draft: in core (cycle). API draft: in the plugins repo, through handles. | **The plugins repo, through handles** (section 2). The pool becomes contexts in one browser, which also suits an 8 GB machine. |
| 12 | Names | `builtin-plugins` / `plugin-host` / `plugins-builtin`; `SBRS_PLUGINS` vs `SB_PLUGINS`; `sbrs.toml` vs `sbase_config.toml` | **`plugin-<name>`, `plugins-builtin`, `plugin-store`; `SB_PLUGINS`; `[plugins]` in the existing `sbase_config.toml`.** These follow the existing `SB_*` and config conventions. |
| 13 | CLI options | `--plugin name:k=v` vs `--plugin-opt name.key=value` | **`--plugin NAME` plus `--plugin-opt NAME.KEY=<TOML value>`.** A comma separator cannot carry TOML arrays. |
| 14 | Store and lock location | Lock and store under the data dir vs lock in the config dir | **One root: `SB_PLUGINS_DIR`, otherwise `dirs::data_dir()/sbrs/plugins`, holding the store and the user lock (with grants).** A project's `.sbrs/plugins.lock` holds **pins only and never grants**. |
| 15 | Manifest-only plugins (install draft) | Only the install draft has them | **Adopted.** The schema is the WASM ABI 2 manifest plus a static description, checked by the same validator. |
| 16 | WASM ABI 2 | Per-hook exports / run-once `configure` / a custom-section manifest with `on_event` | **ABI 2.0 is run-once:** a manifest in a custom section, plus `sbrs_init`. **ABI 2.1 adds `sbrs_on_event` (the security draft's shape)**, only after the request router has proven itself and has been benchmarked. |
| 17 | Switch policy | Refuse for WASM vs refuse for everyone vs an allowlist | **One refused list, applied to every plugin, native ones included,** with a Critical `raw:switches` escape hatch. Untrusted code (WASM and manifests) is limited to an **allowlist**. The hotfix comes first. |
| 18 | Tor isolation | SOCKS usernames in Chrome vs a local forwarder | **A local forwarder for each isolation domain.** Chrome is believed not to send SOCKS5 credentials (to be confirmed in a spike). The SOCKS client and server are hand-written; tokio-socks is not in the tree. |
| 19 | Grants | Legacy accepted, strict for the registry vs non-Critical granted automatically | **Both.** `with()` grants the declared capabilities except Critical ones. `with_trusted()` names each Critical capability. Sets built from the registry (CLI and MCP) are strict. |
| 20 | Trust in project config | High capabilities need the CLI vs project config never grants | **Both.** Project config may only enable and configure. A High capability enabled from project config also needs the name in the CLI, `SB_PLUGINS` or the user config. |
| 21 | Combining `on_request` decisions | Deny overrides vs the first decision wins | **Deny overrides** (section 6), which makes the result independent of order. |
| 22 | Fixing the blocklist bug | Deny the raw send, use `block_urls` | **Phase 1: core's `TabLink` merges raw `Network.setBlockedURLs` into a per-session union,** with no plugin change. Phase 2 adds `block_urls` with the list kept per plugin, and the guard rewrites raw sends into it. |
| 23 | `TestPlugin` bridge (API draft) | Only the API draft has one | **Deferred.** `test_finished` runs after the browser has closed (`observer.rs:154`), which `on_test_end` (page still open) does not model. The two systems live side by side in 0.5. |
| 24 | Safe Browsing | The security draft turns it off in shield's strict mode | **No level implies it.** It is a separate, explicit `safe_browsing = false`. |
| 25 | Module names | `browser_plugins` vs `plugin_host` | **`seleniumbase_rs::plugin_host`** (host side) **and `seleniumbase_rs::builtin_plugins`** (re-exports). `plugins` stays the test reporters. |

## 4. Decision in one screen

1. **One trait, more hooks, all with default bodies.** The API crate stays on 0.1.x. Plugins may declare `metadata()`: category, phase, capabilities, `requires`, `conflicts`, `after`/`before` and seals. Undeclared plugins keep working as "legacy".
2. **Capabilities are enforced where a plugin reaches the browser:**
   - guarded handles check each CDP command;
   - a before/after comparison of `LaunchSettings` and `ContextSettings` checks each change.

   That holds for every plugin. Host I/O (files, sockets, processes) is *enforced* only for WASM; for native Rust it is *declared*. The docs and `sbrs plugin audit` say which applies.
3. **Built-ins ship in the prebuilt binaries.** `sbrs --plugin shield`, `SB_PLUGINS=shield,tor` or `[plugins] enable = ["shield"]` turns one on. Rust users add one feature (`plugin-shield`) and one builder call.
4. **Third-party code without compiling** comes as WASM modules or TOML manifests. They go into a content-addressed store pinned by SHA-256 with a lockfile, and grants are approved at install. **Native code is never loaded at run time.**
5. **The host owns the shared browser state:**
   - one Fetch interceptor per tab;
   - one blocklist per session;
   - one `--disable-features` switch;
   - structured network fields.

   Plugins declare what they want, and the host merges it.
6. **Phase 0** is a security hotfix. **Phase 1** (one or two days, three agent lanes) delivers metadata, the registry, the CLI, env and config surface, the release features, shield, and the fixes for the blocklist and pool bugs.

## 5. The trait and hooks

```rust
// crates/seleniumbase-rs-plugin/src/plugin.rs (lib.rs re-exports; import paths unchanged)
#[async_trait]
pub trait Plugin: Send + Sync + 'static {
    // --- 0.1.0, unchanged ---
    fn name(&self) -> &str;
    fn dependencies(&self) -> &[&str] { &[] }               // merged into metadata().requires
    fn requirements(&self) -> Requirements { Requirements::empty() }
    fn packages(&self) -> Vec<Package> { Vec::new() }

    // --- declarations, read once when the set is checked ---
    fn metadata(&self) -> Metadata { Metadata::legacy() }   // P1
    fn per_launch(&self) -> Option<Arc<dyn Plugin>> { None } // P1: fresh instance per browser (pools)
    fn network(&self) -> NetworkInterest { NetworkInterest::none() } // P2
    fn protocol_events(&self) -> &[&str] { &[] }            // P2: e.g. ["Log.entryAdded"]
    fn task(&self) -> Option<&dyn Task> { None }            // P3: active plugins
    fn job_runner(&self) -> Option<&dyn JobRunner> { None } // P3: usable by batcher

    // --- browser lifecycle ---
    async fn before_launch(&self, _l: &mut LaunchSettings) -> Result<()> { Ok(()) }
    async fn on_browser(&self, _b: &dyn BrowserHandle) -> Result<()> { Ok(()) }
    async fn on_page_created(&self, _p: &dyn PageHandle) -> Result<()> { Ok(()) }
    async fn before_close(&self, _b: &dyn BrowserHandle) -> Result<()> { Ok(()) }         // P2
    async fn on_close(&self) -> Result<()> { Ok(()) }

    // --- contexts (P2) ---
    async fn before_context(&self, _c: &mut ContextSettings) -> Result<()> { Ok(()) }
    async fn on_context_created(&self, _c: &dyn ContextHandle) -> Result<()> { Ok(()) }
    async fn on_context_closed(&self, _id: &ContextId) -> Result<()> { Ok(()) }

    // --- navigation and network (P2) ---
    async fn before_navigate(&self, _p: &dyn PageHandle, _n: &Navigation) -> Result<NavDecision> { Ok(NavDecision::Continue) }
    async fn after_navigate(&self, _p: &dyn PageHandle, _n: &NavOutcome) -> Result<()> { Ok(()) }
    async fn on_request(&self, _r: &RequestView) -> Result<RequestDecision> { Ok(RequestDecision::Continue) }
    async fn on_response(&self, _r: &ResponseView<'_>) -> Result<()> { Ok(()) }
    async fn on_protocol_event(&self, _b: &dyn BrowserHandle, _e: &ProtocolEvent) -> Result<()> { Ok(()) }

    // --- tests (P3) ---
    async fn on_test_start(&self, _t: &TestInfo) -> Result<()> { Ok(()) }
    async fn on_test_end(&self, _t: &TestInfo, _o: &TestOutcome, _p: Option<&dyn PageHandle>)
        -> Result<TestVerdict> { Ok(TestVerdict::Keep) }
}
```

Notes on the hooks:

- **`before_navigate` covers only navigation the program starts:**
  - `Page::goto` and `goto_if_not_url`;
  - MCP `navigate`;
  - `BaseCase::open` once the WebDriver hooks are merged.

  Navigation the page starts itself is seen through `on_request` with `navigation: true`.
- **A `NavDecision::Redirect(url)` is checked again.** `http`, `https`, `about:blank` and `data:` are allowed. `file:`, `chrome:` and `javascript:` are allowed only when the caller asked for them.
- **`before_close` gets a browser handle,** so a plugin can save state or clear storage. `on_close` stays for file cleanup. Teardown keeps today's forward order; reversing it is an open question.
- **`on_test_end` runs while the test's page is still open.** `TestVerdict::Fail(msg)` fails the test; messages from several plugins are joined.

### Handles

Handles are always borrowed. Every handle-returning method carries `'a`, so a plugin cannot store a handle. A stored handle would create a cycle (`Browser` → options → plugin → `Browser`), and then `Inner::drop` would never kill the process.

```rust
pub struct BrowserId(Arc<str>); pub struct PageId(Arc<str>); pub struct ContextId(Arc<str>);

#[async_trait] pub trait BrowserHandle: Send + Sync {
    fn engine(&self) -> Engine; fn family(&self) -> BrowserFamily;      // BrowserFamily gains Embedded (Tauri)
    async fn send(&self, method: &str, params: Value) -> Result<Value>;
    fn id(&self) -> BrowserId { BrowserId::unknown() }
    fn extensions(&self) -> Vec<LoadedExtension> { Vec::new() }         // ids core keeps from Extensions.loadUnpacked
    async fn new_context<'a>(&'a self, _s: ContextSettings) -> Result<Box<dyn ContextHandle + 'a>> { Err(unsupported("new_context")) }
    async fn new_page<'a>(&'a self, _url: Option<&str>) -> Result<Box<dyn PageHandle + 'a>> { Err(unsupported("new_page")) }
}
#[async_trait] pub trait ContextHandle: Send + Sync {
    fn id(&self) -> &ContextId;
    async fn new_page<'a>(&'a self, url: Option<&str>) -> Result<Box<dyn PageHandle + 'a>>;
    async fn dispose(&self) -> Result<()>;
}
#[async_trait] pub trait PageHandle: Send + Sync {
    /* engine, send, add_init_script, evaluate: unchanged */
    fn id(&self) -> PageId { PageId::unknown() }
    fn context(&self) -> Option<ContextId> { None }
    async fn url(&self) -> Result<String> { /* evaluate("location.href") */ }
    async fn navigate(&self, _url: &str) -> Result<()> { Err(unsupported("navigate")) }      // runs before_navigate
    async fn block_urls(&self, _p: &[String]) -> Result<()> { Err(unsupported("block_urls")) } // host keeps a union
    async fn screenshot(&self) -> Result<Vec<u8>> { Err(unsupported("screenshot")) }
    async fn close(&self) -> Result<()> { Err(unsupported("close")) }
}
```

- **Core implements these for its own types.** `sb_cdp::Page` already does so on the WebDriver branch. `Browser` maps to `Browser::new_context_with`, and `BrowserContext` maps to `new_page` and `dispose`.
- **`PluginSet` wraps every handle it passes to a hook in a per-plugin `Guarded<H>` inside the API crate,** so the guard works for any engine and can be tested with fakes. The guard checks three things:
  - **Capabilities:** each command is checked through `cdp_policy::required`.
  - **The host denylist:**
    - `Fetch.*` (owned by the router);
    - `Target.setAutoAttach`;
    - `Browser.close` and `Browser.crash`;
    - raw `Network.setBlockedURLs`, which is rewritten into `block_urls` for that plugin.
  - **Re-entrancy:** `navigate` inside `before_navigate`, and `new_page` or `new_context` inside a page or context hook, fail with `PluginError::Reentrant`.

### Failure rules (one table for both engines)

| Where | Error, timeout or panic does |
|---|---|
| `check` | stops before anything starts |
| `before_launch`, `on_browser`, `before_context`, `on_context_created`, `on_page_created`, packages, `before_navigate` | stops that launch, context, tab or navigation; a half-made tab or context is closed |
| `on_request` | the request fails with `Fetch.failRequest(BlockedByClient)`; the event `cdp.plugin.request.failed` names the plugin |
| `on_response`, `after_navigate`, `on_protocol_event`, `on_test_start`, `before_close`, `on_close`, `on_context_closed`, and an *error* from `on_test_end` | logged at WARN and collected; teardown always finishes |
| `on_test_end` returning `TestVerdict::Fail` | the test fails |
| `Task::run` | the error goes to the caller; results already recorded stay in the sink |

How the rules are carried out:

- **Panics.** Each hook future is polled inside a small `catch_unwind` wrapper in the API crate, with no new dependency. A panic becomes `PluginError::Panicked { plugin, hook }`.
- **Budgets.** `PluginSet::with_timer(Arc<dyn Timer>)` keeps the API crate free of any runtime: core passes a tokio sleeper, and tests pass a `ManualTimer`. Without a timer there are no timeouts, as today. Plugins can override the defaults in `Metadata::budgets`, capped by the set's maxima.

| Hook | Default budget |
|---|---|
| `before_launch` | 30 s |
| `on_page_created`, `before_close`, `on_close` | 10 s |
| `before_navigate` | 5 s |
| `on_request` | 2 s |
| `on_test_end` | 30 s |

## 6. Network: the host owns interception

```rust
#[non_exhaustive] #[derive(Clone, Debug, Default)]
pub struct NetworkInterest {
    pub rules: Vec<NetRule>,            // run by the host; the plugin is never called
    pub observe: Vec<RequestFilter>,    // -> on_response (bodies only with net.bodies and a max)
    pub intercept: Vec<RequestFilter>,  // -> on_request
}
pub struct NetRule { pub filter: RequestFilter, pub action: RuleAction /* Block | SetHeaders(BTreeMap) */ }
pub struct RequestFilter { pub url: Option<String> /* glob */, pub kinds: Vec<ResourceKind>, pub methods: Vec<String>, pub max_body: Option<usize> }
#[non_exhaustive] pub enum ResourceKind { Document, Stylesheet, Image, Media, Font, Script, Xhr, Fetch, WebSocket, Other }
pub struct RequestView { pub url: String, pub method: String, pub kind: ResourceKind, pub headers: Headers /* redacted */,
                         pub navigation: bool, pub page: Option<PageId>, pub context: Option<ContextId> }
pub enum RequestDecision { Continue, Block(String), Modify(RequestPatch), Fulfill(Fulfillment) }
pub struct ResponseView<'a> { pub request: &'a RequestView, pub status: u16, pub mime: &'a str,
                              pub body: Option<&'a [u8]>, pub truncated: bool, pub outcome: Outcome /* Ok | Failed | Blocked{by} */ }
```

**`FetchRouter`** is a new file, `src/sb_cdp/plugin_network.rs`, with one router per session. It owns the one `Fetch.enable` and merges three sources into it:

- proxy auth (`ProxyAuth`);
- the user's `Page::intercept` rules (reusing `intercept.rs` `Rule` and `glob_match`);
- every plugin's `NetworkInterest`.

The patterns are the union of all three, so Chrome pauses only matching requests. When no plugin intercepts, the router adds nothing.

The router is supervised. If its task ends, it sends `Fetch.disable` and marks the page failed, so requests cannot hang.

**Combining decisions.** Precedence, highest first:

1. a Fulfill from the user's `Page::intercept` (nothing leaves the machine);
2. any plugin Block (deny overrides);
3. the Fulfill from the one plugin that holds `net.fulfill` (the `FULFILL` seal);
4. Modify patches, composed in plugin order;
5. Continue.

Blocked and failed requests reach observers with `outcome: Blocked { by }`. `Cookie`, `Authorization`, `Proxy-Authorization` and `Set-Cookie` are redacted unless the plugin holds `net.sensitive`.

**Blocklist.** Core keeps one union per session: core's `ad_block`, each plugin's list kept apart, and raw sends. It sends a single `Network.setBlockedURLs`.

## 7. Metadata, categories, phases and seals

```rust
#[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Category { Environment, Testing, Extension, Core, Privacy }

#[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Phase { Prepare, Normal, Enforce, Observe, Last }

pub struct Seals(u8); // PROXY, CONTEXT_PROXY, WEBRTC, HEADLESS, FULFILL

#[non_exhaustive] #[derive(Clone, Debug)]
pub struct Metadata {
    pub category: Option<Category>,          // None = legacy plugin
    pub version: Cow<'static, str>,
    pub summary: Cow<'static, str>,
    pub capabilities: CapabilitySet,         // required
    pub optional: CapabilitySet,             // used if granted
    pub requires: Vec<Cow<'static, str>>,    // Cow: batcher's dependency comes from its config
    pub conflicts: Vec<Cow<'static, str>>,
    pub after: Vec<Cow<'static, str>>, pub before: Vec<Cow<'static, str>>,
    pub phase: Option<Phase>,                // None: from category
    pub seals: Seals,
    pub budgets: Budgets,
}
impl Metadata {
    pub fn new(category: Category) -> Self;  // declared
    pub fn legacy() -> Self;                 // undeclared: legacy capability set + a deprecation warning
    // builder: version, summary, capability, capabilities, optional, requires, conflicts_with, after, before, phase, seal, budget
}
```

**Ordering (`order.rs`).**

1. **Expand per-launch instances.** `PluginSet::for_launch()` replaces each plugin that offers `per_launch()`.
2. **Build the graph.** The edges come from:
   - `requires` (merged with the legacy `dependencies()`);
   - `after` and `before`, which apply only when the other plugin is in the set.
3. **Sort with Kahn's algorithm.** Among ready nodes, the lowest `(phase, insertion index)` goes first.
   - Phase is `Last` for `RUN_LAST`, otherwise `metadata.phase`, otherwise taken from the category:

     | Category | Default phase |
     |---|---|
     | Environment | Prepare |
     | Extension, Core | Normal |
     | Privacy | Enforce |
     | Testing | Observe |
     | none (legacy) | Normal |

   - A set of legacy plugins only therefore keeps exactly today's order. `plugins_run_in_order_with_run_last_ones_at_the_end` still passes.
4. **Errors.** Each of these stops the launch before anything starts:
   - `Cycle`
   - `MissingDependency`
   - `Conflict { a, b }`
   - `Sealed { field, a, b }` when two plugins seal one field with values that differ
   - `Unsupported { plugin, capability, engine }`
   - `Config`
   - in a strict set, `Undeclared`

   The order is computed in `check()` and cached. Core calls `check()` before and after `before_launch`, as today.

**Seals apply to scalar fields only.** The proxy, the context proxy, the WebRTC policy, headless, and the one fulfiller. A later plugin, or the user's own options, may not change a sealed field to a *different* value. List fields are append-only for every plugin: args, prefs keys already set, `host_resolver_rules`, `disable_features` and the blocklist. A plugin that removes another plugin's entry fails with `PluginError::Capability`.

### What the platform gives each category (requirement B)

| Category | Default phase | Hooks it typically uses | Typical capabilities | Never by default | What the host provides |
|---|---|---|---|---|---|
| 1 Environment (presets, runtime, CLI switches, proxies, headless) | Prepare | `before_launch`, `before_context`, `task` | `launch.args`, `launch.prefs`, `launch.headless`, `launch.proxy` (High), `contexts`, `task` | `page.*`, `cookies.*`, `host.*` | `--plugin-opt` and `[plugins.<name>]` typed config; manifest presets without code; job orchestration through `Task` |
| 2 Testing (assertions, lifecycle, CI reporters, recording fakes) | Observe | `on_test_start`, `on_test_end`, `on_response`, `on_protocol_event`, `task` | `test.hooks`, `net.observe`, `page.evaluate`, `artifacts.write` (run output only) | `launch.*`, `net.intercept` | verdicts; a run-output folder; the testing crate (`RecordingPage`, `FakeBrowser`, `Timeline`, `ManualTimer`, `assert_denied!`) |
| 3 Extension (CRX/CRX3, background workers, unpacked content scripts) | Normal | `before_launch`, `on_browser`, `on_protocol_event`, `before_close`, `on_close` | `launch.extensions` (High), `host.fs.read:<declared>`, `host.fs.write:temp`, `cdp:Extensions`; needs `LAUNCH_ONLY` and `CHROMIUM_ONLY` | `page.script:*`, `cookies.*` | the bounded CRX unpacker; extension ids from `loadUnpacked`; worker target events; later CRX3 signature checks and `expect_id` |
| 4 Core (CDP interception, network logging, resource blocking) | Normal | `network()`, `on_request`, `on_response`, `on_page_created`, `job_runner` | `net.observe`, `net.intercept`, `net.bodies` (High), `cdp:Network`, `page.evaluate` | `cookies.read`, `launch.proxy` | the `FetchRouter`, declarative rules, the blocklist union, bounded bodies |
| 5 Privacy (hardening, telemetry, WebRTC, cookie isolation, disk footprint) | Enforce | `before_launch`, `before_context`, `on_context_closed`, `on_test_end`, `on_close` | `launch.network`, `launch.prefs`, `launch.proxy` with seals, `page.script:*` (shims), `storage.clear`, `contexts`, `host.net:loopback` | `raw:*`, `net.bodies` | seals; the Enforce phase; structured network fields (`host_resolver_rules`, `webrtc_policy`, `disable_features`, `disable_quic`) merged by core into single switches |

`LaunchSettings` gains these fields. All are additive, because the struct is already `#[non_exhaustive]`.

```rust
pub host_resolver_rules: Vec<String>,   // core joins them into one --host-resolver-rules
pub webrtc_policy: Option<WebRtcPolicy>, // API-crate enum; core maps it to LaunchOptions::webrtc (launch.rs:269)
pub disable_features: Vec<String>,      // merged with core's own "Translate" (launch.rs:253) into ONE switch
pub enable_features: Vec<String>,
pub disable_quic: bool,
fn profile(&self) -> &ProfileView;       // read-only: Ephemeral | Persistent(PathBuf)
```

`ContextSettings { proxy: Option<String> /* no password, as settings_of */, proxy_bypass: Vec<String> }` is `#[non_exhaustive]` and maps to `ContextOptions`.

## 8. Capabilities and the security model

### Threat model

| Actor | Trust |
|---|---|
| Native Rust plugin crates | Same process, same rights. They cannot be sandboxed. |
| WASM modules and manifests | Untrusted and sandboxed |
| Project config in a cloned repo | Untrusted: it may enable plugins, never grant capabilities |
| Web pages | Hostile: they can tamper with page-world shims and probe localhost |
| Distribution channels (git, releases, the tap) | Supply chain |
| An LLM driving `sbrs-mcp` | Prompt-injectable |

**Assets:**

- the user's browser data;
- the host's files, processes and sockets;
- the user's network identity (real IP, DNS, LAN addresses);
- the integrity of test results.

### The capability enum

```rust
#[non_exhaustive] #[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Capability {
    LaunchArgs, LaunchPrefs, LaunchHeadless, LaunchNetwork, LaunchProxy, LaunchExtensions, LaunchProfile,
    PageScript(HostScope), PageEvaluate, PageNavigate, Cdp(Cow<'static, str> /* domain */),
    NetObserve, NetSensitive, NetBodies, NetIntercept, NetFulfill,
    CookiesRead, CookiesWrite, StorageClear, Contexts,
    TestHooks, Task, ArtifactsWrite,
    HostNet(NetScope), HostFsRead(PathScope), HostFsWrite(PathScope), HostProcess,
    Clock, Random, State { persist: bool },
    Raw(RawKind /* Cdp | Switches */),
}
pub enum HostScope { Hosts(Vec<String>), Everywhere }
pub enum NetScope { Loopback, Any }
pub enum PathScope { Temp, RunOutput, Declared(Vec<PathBuf>) }
pub enum Risk { Low, Medium, High, Critical }
pub enum Enforcement { Enforced, DeclaredOnly }
impl Capability { pub fn risk(&self) -> Risk; pub fn wasm_grantable(&self) -> bool; pub fn enforcement(&self, wasm: bool) -> Enforcement; }
// FromStr/Display: "launch.args", "page.script:example.com,example.org", "page.script:*", "cdp:Network",
// "net.bodies", "host.net:loopback", "host.fs.write:temp", "raw:cdp" ...
pub struct CapabilitySet(BTreeSet<Capability>); // covers(), legacy()
```

**Risk levels:**

| Risk | Capabilities |
|---|---|
| Low | `launch.args` (refused list applied), `page.script:<hosts>`, `net.observe`, `test.hooks`, `clock`, `random`, `state` |
| Medium | `launch.prefs`, `launch.headless`, `launch.profile`, `page.evaluate`, `page.navigate`, `net.intercept`, `storage.clear`, `contexts`, `task`, `artifacts.write`, most `cdp:<Domain>` |
| High | `page.script:*`, `cookies.*`, `net.sensitive`, `net.bodies`, `net.fulfill`, `launch.proxy`, `launch.network`, `launch.extensions`, `host.net`, `host.fs.*` |
| Critical | `raw:*`, `host.process`, `cdp:Target`, `cdp:Browser` |

Critical capabilities are never grantable to WASM. Neither are `host.process`, `host.fs.*`, `host.net`, `launch.extensions` or `launch.profile`.

### How the capability policy is applied

**`cdp_policy::required(method, params) -> Vec<Capability>`** works by domain, with overrides for single methods:

| Method | Needs |
|---|---|
| `Network.getAllCookies`, `Network.getCookies`, `Storage.getCookies` | `cookies.read` |
| `Network.setCookie(s)`, `Storage.setCookies` | `cookies.write` |
| `Network.clearBrowserCookies`, `Network.clearBrowserCache`, `Storage.clearDataForOrigin` | `storage.clear` |
| `Network.getResponseBody` | `net.bodies` |
| `Runtime.evaluate` | `page.evaluate` |
| `Page.addScriptToEvaluateOnNewDocument` | `page.script:*` |
| `Page.navigate` | `page.navigate` |
| `Target.createBrowserContext` | `contexts`, plus `launch.proxy` (and the seal check) when it carries `proxyServer` |
| `Browser.setDownloadBehavior` | `host.fs.write` |
| `Fetch.*` | denied |
| an unknown method | `raw:cdp` |

**`SwitchPolicy`** has one refused list. It lives in the API crate and is the union of today's two lists plus:

- `js-flags`;
- `disable-site-isolation-trials`;
- `allow-file-access-from-files`;
- `unsafely-treat-insecure-origin-as-secure`;
- `allow-running-insecure-content`;
- `log-net-log`, `net-log-capture-mode`;
- `enable-logging`, `log-file`;
- `disk-cache-dir`, `crash-dumps-dir`;
- `single-process`.

The rules:

- **Parsing** accepts `-x` and `--x`, any case, and `=value`. `--disable-features` and `--enable-features` are checked feature by feature, for example `IsolateOrigins` and `site-per-process`.
- **Refused for everyone.** Any plugin that adds a refused switch is refused, native or not. A native plugin that truly needs one declares `raw:switches`, and the user names it in `with_trusted`.
- **Untrusted plugins (WASM, manifests)** may only use an **allowlist** of benign switches: `--lang`, `--window-size`, `--mute-audio`, `--force-device-scale-factor`, `--disable-gpu`, `--hide-scrollbars`, and a checked `--blink-settings`. Network effects go through the structured fields.
- **Core's own list stays.** Core's `evasions.rs` list serves the always-on stealth payloads and stays where it is. A core test under `plugins` asserts that it is a subset of the API's list.

### Grants

- **`PluginSet::with(p)`** grants p's declared capabilities except Critical ones.
- **`with_trusted(p, &[Capability])`** must name each Critical capability.
- **`with_grants(p, set)`** is used by the CLI and MCP; the grants come from the lockfile.
- **`audit()`** returns rows of name, category, capability, risk, granted and enforcement.
- **Legacy plugins** get `CapabilitySet::legacy()` (today's behaviour, `raw:cdp` included) and a deprecation warning. **Strict sets** (CLI, MCP, sets built from the registry) refuse them.
- **Host support** is checked in `check_with(&LaunchContext, &HostInfo)`, which is new; `check()` stays.

  | Host | Supported capabilities |
  |---|---|
  | CDP | all |
  | WebDriver with Chromium | `page.*`, `cdp:*` through `goog/cdp/execute`, the launch fields `BrowserConfig` maps; no events, `contexts` or `net.*` |
  | Firefox and Safari | page scripts and evaluate, and the launch fields `BrowserConfig` maps |
  | Tauri (`Embedded`, detected from the session's returned `browserName`) | page scripts and evaluate only |

- **Denials.** Every denial emits `plugin.capability.denied` with the plugin, the capability and the method. Parameter values are never logged.

> Capabilities are a contract enforced at the API surface. For native Rust plugins they are **not** a sandbox: such a plugin can still use `std` directly. Only WASM is sandboxed. The docs, `sbrs plugin info` and `sbrs plugin audit` show the enforcement column.

### Trust in config and MCP

- **Precedence.** For values: CLI, then env (`SB_PLUGINS`, `SB_NO_PLUGINS`, `SB_PLUGINS_DIR`), then the project's `sbase_config.toml`, then the user's `dirs::config_dir()/sbrs/config.toml`.
- **What project config may do.** It may enable and configure built-ins and plugins that are already approved. It never grants, and it never adds a source.
- **High capabilities from project config.** Enabling a plugin with `launch.proxy`, `host.*` or `artifacts.write` outside the run output from project config also needs the name in the CLI, `SB_PLUGINS` or the user config. At launch, one INFO line lists each active plugin and where it was enabled.
- **MCP.** The operator allowlists plugins with `sbrs-mcp --plugin ...`. The `start_browser` tool takes `plugins: [...]`, which must be a subset of that list. `list_plugins` is read-only. **There is no MCP tool to install or grant**, which defends against prompt injection.

## 9. Install and enable (requirement A)

| Who | Install | Enable |
|---|---|---|
| Rust, built-in | `features = ["plugin-shield"]`, or `plugins-builtin` for all of them, on the existing `seleniumbase-rs` dependency. `sbrs plugin add shield` edits it with `toml_edit` (phase 4). | `.plugin(Shield::default())`, `.plugins_named(["shield"])`, or no code at all: `.plugin_selection(&settings.plugins)` with `[plugins] enable = ["shield"]` or `SB_PLUGINS=shield` |
| Rust, third-party crate | `cargo add seleniumbase-rs-plugin-foo --git URL` | `.plugin(Foo::new())`; by name after `registry.with(Descriptor::of::<Foo>())` |
| Prebuilt `sbrs` / `sbrs-mcp` | nothing: the built-ins are compiled in | `sbrs --plugin shield --plugin-opt 'shield.level="strict"' open URL`, `SB_PLUGINS=shield,tor`, `[plugins] enable = [...]`, `sbrs-mcp --server cdp --plugin shield` |
| Prebuilt, WASM or manifest (phase 3) | `sbrs plugin add ./de-locale.toml`, or `sbrs plugin add https://.../x.wasm --sha256 HEX [--grant net.intercept]` | as above, by the name the plugin declares |
| CI with pinned plugins | commit `.sbrs/plugins.lock` (pins only), then `sbrs plugin sync --grant ...` | as above |

```toml
# sbase_config.toml
[plugins]
enable = ["shield", "fetcher"]          # order = insertion order within a phase

[plugins.shield]
level = "strict"

[plugins.fetcher]
strip = ["image", "font", "media"]
capture = ["*://localhost:*/api/*"]
```

### Core surface

Features:

```toml
seleniumbase-rs-plugin          = { version = "0.1", git = "https://github.com/MustCodeAl/seleniumbase-rs-plugins", optional = true }
seleniumbase-rs-plugins-builtin = { version = "0.1", git = "https://github.com/MustCodeAl/seleniumbase-rs-plugins", optional = true }

plugins = ["dep:seleniumbase-rs-plugin"]
plugin-shield = ["plugins", "dep:seleniumbase-rs-plugins-builtin", "seleniumbase-rs-plugins-builtin/shield"]
# plugin-tor, -fetcher, -extractor, -browser, -batcher, -crawler, -block-resources, -crx, -wasm: same shape
plugins-builtin = ["plugin-shield", "plugin-tor", "plugin-fetcher", "plugin-extractor", "plugin-browser",
                   "plugin-batcher", "plugin-crawler", "plugin-block-resources", "plugin-crx"]
plugin-store = ["plugins", "plugin-wasm", "seleniumbase-rs-plugins-builtin/declarative", "dep:toml_edit"] # phase 3
```

A CI check parses `Cargo.toml` and fails if the two plugins-repo dependencies use different source specs. Two specs would resolve to two `seleniumbase-rs-plugin` crates, and their `Plugin` traits would not match.

Modules:

- **`config/plugins.rs`** holds `PluginSelection { enable, config: BTreeMap<String, toml::Value>, deny_capabilities }`. It is always compiled. A non-empty selection in a build without plugin support **fails closed** with the hint "rebuild with --features plugins-builtin".
- **`plugin_host/`** (feature `plugins`) holds `Registry` assembly, `build(&PluginSelection) -> PluginSet` (strict) and, in phase 3, the store.
- **`builtin_plugins`** re-exports the aggregator crate.

Builder methods:

- **`LaunchOptionsBuilder`** gets `plugin(impl Plugin)`, `plugins_named(I)` and `plugin_selection(&PluginSelection)`. `build()` reports a duplicate or unknown name as `SeleniumBaseError::Plugin`, and the message lists the known names and the command that installs a missing one.
- **`BrowserConfig`** gets the same methods once the WebDriver branch is merged.

CLI and MCP:

- `sbrs` gets the global flags `--plugin`, `--plugin-opt`, `--no-plugins` and `--plugins-dir`.
- `sbrs plugin list|info` arrive in phase 1, `run` in phase 3, and `add|remove|verify|sync|gc|enable|disable|audit` in phase 3 and 4.
- The logic lives in library functions (`src/cli/plugin_cmd.rs`), so the planned move to `usage` as the CLI parser is mechanical.
- `sbrs-mcp` gets `--plugin`, `--plugin-opt`, a `plugins` argument on `start_browser`, `list_plugins`, and `run_plugin_task` (phase 3, allowlisted).

### Typed config and the registry (API crate)

```rust
pub trait Configurable: Plugin + Sized {
    const NAME: &'static str;
    type Config: serde::de::DeserializeOwned + Default;   // #[serde(deny_unknown_fields)]: a typo fails closed
    fn describe() -> Metadata;                             // static: listable without building
    fn from_config(config: Self::Config) -> Result<Self>;
}
#[derive(Clone, Copy)]
pub struct Descriptor { pub name: &'static str, describe: fn() -> Metadata, build: fn(&Value) -> Result<Arc<dyn Plugin>> }
impl Descriptor { pub fn of<P: Configurable>() -> Self; }
pub struct Registry { /* Vec<Descriptor>; with() refuses duplicate names */ }
pub struct PluginSpec { pub name: String, pub config: Value }
```

- **New dependency.** This adds `serde` to the API crate, so ADR 004's "async-trait, serde_json, thiserror only" becomes "plus serde".
- **Secrets in config** use a `Secret` newtype whose `Debug` is redacted. They are read from an environment variable named in the config, for example `password_env = "TOR_CONTROL_PASSWORD"`.

### Release

| Phase | `release.yml`, Homebrew `sbrs.rb` and `Dockerfile` build with | The formula test checks |
|---|---|---|
| 1 | `--features mcp-server,plugins-builtin` | `sbrs plugin list` shows `shield` |
| 3 | `mcp-server,plugins-builtin,plugin-store` | the same |

- Before choosing the features, run `cargo bloat --release --crates` before and after, one heavy run at a time.
- `std_cargo_args` passes `--locked`, so `Cargo.lock` pins the plugins-repo commit.
- `ci.yml` gets one `plugins-builtin` clippy and test job, and the `msrv` job builds it too.

## 10. Store, manifests and the WASM ABI

### Store

```
$SB_PLUGINS_DIR or dirs::data_dir()/sbrs/plugins/
  plugins.lock                 # TOML, version 1: name, kind, sha256, source, abi, category, capabilities, granted, approved_at
  store/<sha256>.wasm|.toml    # content-addressed, mode 0444, written with a temp file and a rename
```

- **`add`:**
  - HTTPS only, with no redirect to http.
  - Downloads are capped (4 MiB for WASM, 256 KiB for manifests).
  - The SHA-256 is computed with `ring`.
  - `inspect` runs no module code: it reads the custom section only.
  - Each capability is shown with its risk and enforcement level. Off a TTY, `--sha256` is required, and `--grant` must name each High capability; `--yes` never covers High.
- **`load`** reads the file once, hashes that buffer, compares the hash with the lock, and parses the same buffer. There is no gap between the check and the use.
- **`update`** shows the capability diff. A new capability needs fresh approval.
- **Signatures** (phase 4): minisign Ed25519, trusted on first use or with `--key`. The crate is to be checked when chosen.

### Manifest-only plugins (`plugin.toml`, schema 1)

These are for Environment presets and simple Core and Privacy plugins that need no code.

```toml
schema = 1
[plugin]
name = "de-locale"
version = "1.0.0"
category = "environment"
capabilities = ["launch.args", "launch.prefs"]

[launch]
args = ["--lang=de-DE", "--window-size=1280,800"]   # allowlist only
prefs = { "intl.accept_languages" = "de-DE,de" }     # FORBIDDEN_PREFS: download.*, savefile.*, extensions.*, proxy.*

[[scripts]]
hosts = ["localhost"]
code = "window.__e2e = true;"

[block]
urls = ["*://*.doubleclick.net/*"]
kinds = ["media"]                                    # used once the router exists (phase 2)
```

A new crate, `seleniumbase-rs-plugin-declarative`, owns `Declared` and **the one validator**. It moves out of `plugins/wasm/src/abi.rs`, together with the switch list. `WasmPlugin` keeps its type but holds a `Declared`. A test proves that a WAT module and the equivalent manifest yield equal `Declared` values.

### WASM ABI

| ABI | Exports | When the module runs | Imports |
|---|---|---|---|
| **1 (today)** | `sbrs_abi_version`, `sbrs_name`, `sbrs_launch_args`, `sbrs_scripts`, `sbrs_blocked_urls` | once, at load | none |
| **2.0 (phase 3)** | a **custom section `sbrs.manifest`** (JSON: abi, abi_minor, name, version, category, capabilities, events, request_patterns, instance, on_error, limits; `deny_unknown_fields`), plus `sbrs_abi_version() = 2`, `sbrs_alloc(len) -> ptr` and `sbrs_init(ptr, len) -> i64` (the user's config in; a static description like ABI 1 out, plus prefs and declarative network rules) | once, at load | namespace `sbrs_v2`: `log` (sanitised, at most 64 KiB per call) |
| **2.1 (phase 4, after the router and a benchmark)** | adds `sbrs_on_event(kind, ptr, len) -> i64`, which returns `{"decision":..., "actions":[...]}` | per event listed in the manifest; one instance per browser or per context | adds gated `now_ms` (`clock`, 100 ms resolution), `random_fill` (`random`), `kv_get`/`kv_put` (`state`; 1 MiB, 256 keys) |

Event kinds:

| Kind | Event |
|---|---|
| 1 | before_launch |
| 2 | browser |
| 3 | page_created |
| 4 | before_navigate |
| 5 | request |
| 6 | response |
| 7 | context_created |
| 8 | context_closed |
| 9 | test_start |
| 10 | test_end |
| 11 | close |
| 12 | action_result |

Actions are limited to 64 per event: `cdp` (its result comes back as an `action_result` event), `init_script`, `report` (the host writes the file) and `log`. Every action goes through the same `cdp_policy` and `SwitchPolicy`.

Rules that apply to every ABI version:

- **Imports.** `module.imports()` is checked before instantiation. An import outside `sbrs_v2`, an ungranted import, or an imported memory, table or global is refused.
- **No host I/O.** There is no file system, socket, environment or process access. A module reaches the network only through the browser, and only under its grants.
- **Limits:**

  | Limit | Value |
  |---|---|
  | Fuel per call | 5M by default; 1M for request and response events |
  | Memory | 16 MiB per instance |
  | Instances | at most 16 per plugin |
  | Reply size | at most 1 MiB |
  | Breaker | 5 traps in 60 s disables the plugin; for a Privacy or FailClosed plugin it aborts the session |

  Calls are serialised per instance by a std `Mutex` that is never held across `.await`.
- **Versioning.**
  - The host speaks versions 1 and 2.
  - Within 2, events, actions and manifest fields are only ever added (`abi_minor`).
  - The import namespace carries the version (`sbrs_v3` later).
  - v1 modules keep working, but under the new `SwitchPolicy`. That tightening is a documented security fix.
- **Rejected:**
  - wasmtime: JIT and a larger trusted base. It is revisited only if the `cdp_latency` benchmark shows p99 above 1 ms per `on_request`.
  - Full WASI. A "WASI-lite" shim (`random_get`, `clock_time_get`, `fd_write` to the log, `proc_exit`, each gated) is a later option.

What WASM can do in each category:

| Category | Manifest / ABI 1 / 2.0 | ABI 2.1 | Native only |
|---|---|---|---|
| 1 Environment | allowlisted switches and prefs, headless, window size, proxy with a High grant, presets with parameters through `sbrs_init` | contexts as presets | executable paths, persistent profiles |
| 2 Testing | metadata | `test_end` → `report` action and verdict; `page.evaluate` assertions | reporters that talk to the network |
| 3 Extension | none | none | CRX handling and extension lifecycle (they need the file system) |
| 4 Core | blocklists, kind rules, header rules | `request` decisions (block, fulfill, modify headers); redacted request logs | response bodies at scale, raw CDP |
| 5 Privacy | telemetry blocklists, WebRTC shim script, privacy prefs | `storage.clear` on `context_closed` | tor (sockets), cleaning files on disk |

## 11. The seven built-in plugins

Each plugin is a crate under `plugins/<name>` that depends only on the API crate and its own dependencies. Each implements `Configurable` and is listed in the aggregator's `registry()`. Defaults are conservative.

### shield (category 5)

Privacy hardening, blocking the browser's own outbound telemetry, and cleaning up what a session leaves behind.

```rust
#[derive(Clone, Debug, Deserialize)] #[serde(default, deny_unknown_fields)]
pub struct ShieldConfig {
    pub level: Level,                    // Basic (default) | Strict
    pub webrtc: WebRtcMode,              // Off | Policy | RelayOnly (default)
    pub block_third_party_cookies: bool, // true
    pub ephemeral_profile: bool,         // true: refuse a persistent profile
    pub sweep_stale_profiles: bool,      // false
    pub clear_between_tests: bool,       // true (phase 3)
    pub extra_block_hosts: Vec<String>,
    pub safe_browsing: bool,             // true; false only by explicit choice, never implied by a level
}
pub struct Shield { cfg: ShieldConfig, seen: Mutex<BTreeSet<String>> } // origins seen (no bodies)

impl Configurable for Shield {
    const NAME: &'static str = "shield"; type Config = ShieldConfig;
    fn describe() -> Metadata {
        use Capability::*;
        Metadata::new(Category::Privacy).version(env!("CARGO_PKG_VERSION"))
            .summary("Turns off browser telemetry, WebRTC address leaks and third-party cookies; leaves no profile behind")
            .capabilities([LaunchArgs, LaunchPrefs, LaunchNetwork, LaunchProfile, PageScript(HostScope::Everywhere),
                           NetObserve, StorageClear, TestHooks, HostFsWrite(PathScope::Temp)])
    }
    fn from_config(cfg: ShieldConfig) -> Result<Self> { Ok(Self { cfg, seen: Mutex::default() }) }
}

#[async_trait]
impl Plugin for Shield {
    fn name(&self) -> &str { Self::NAME }
    fn metadata(&self) -> Metadata { Self::describe() }
    fn requirements(&self) -> Requirements { Requirements::CHROMIUM_ONLY }
    fn packages(&self) -> Vec<Package> {               // defence in depth; the policy flag is the main control
        match self.cfg.webrtc { WebRtcMode::RelayOnly => vec![Package::script(WEBRTC_SHIM).everywhere()], _ => vec![] }
    }
    fn network(&self) -> NetworkInterest {             // phase 2: the host blocks, the plugin is not called
        NetworkInterest::none().rule(NetRule::block_hosts(&self.page_hosts())).observe(RequestFilter::documents())
    }
    async fn before_launch(&self, l: &mut LaunchSettings) -> Result<()> {
        if self.cfg.ephemeral_profile && l.profile().is_persistent() {
            return Err(PluginError::other("shield: a persistent profile was set; turn ephemeral_profile off to allow it"));
        }
        l.args.extend(telemetry::SWITCHES.iter().map(|s| (*s).to_owned()));     // versioned list, checked per Chrome stable
        l.disable_features.extend(telemetry::FEATURES.iter().map(|s| (*s).to_owned()));
        for (key, value) in prefs::for_config(&self.cfg) { l.prefs.insert(key.into(), value); }
        if self.cfg.webrtc != WebRtcMode::Off { l.webrtc_policy = Some(WebRtcPolicy::DisableNonProxiedUdp); }
        if self.cfg.level == Level::Strict {                                     // browser-process hosts never reach setBlockedURLs
            l.host_resolver_rules.extend(telemetry::BROWSER_HOSTS.iter().map(|h| format!("MAP {h} ^NOTFOUND")));
        }
        Ok(())
    }
    async fn on_page_created(&self, page: &dyn PageHandle) -> Result<()> {
        // Phase 1: a raw Network.setBlockedURLs, merged into the session's union by core. Phase 2: page.block_urls().
        page.send("Network.setBlockedURLs", json!({ "urls": self.page_patterns() })).await.map(drop)
    }
    async fn on_response(&self, r: &ResponseView<'_>) -> Result<()> { self.remember_origin(&r.request.url); Ok(()) }
    async fn on_test_end(&self, _t: &TestInfo, _o: &TestOutcome, page: Option<&dyn PageHandle>) -> Result<TestVerdict> {
        if let (true, Some(page)) = (self.cfg.clear_between_tests, page) {
            for origin in self.take_seen() {
                page.send("Storage.clearDataForOrigin", json!({ "origin": origin, "storageTypes": "all" })).await?;
            }
        }
        Ok(TestVerdict::Keep)
    }
    async fn on_close(&self) -> Result<()> {
        if self.cfg.sweep_stale_profiles { footprint::sweep_stale("sb-cdp-", Duration::from_secs(86_400))?; } // dead owners only
        Ok(())
    }
}
```

- **What it sets:**
  - **Telemetry switches:** `--disable-background-networking`, `--disable-component-update`, `--disable-domain-reliability`, `--disable-breakpad`, `--disable-sync`, `--no-pings`, `--disable-default-apps`.
  - **Disabled features:** OptimizationHints, OptimizationGuideModelDownloading, MediaRouter, AutofillServerCommunication.
  - **Prefs:**
    - `net.network_prediction_options = 2`;
    - `search.suggest_enabled = false`;
    - `alternate_error_pages.enabled = false`;
    - `spellcheck.use_spelling_service = false`;
    - `profile.block_third_party_cookies`;
    - `privacy_sandbox.m1.*_enabled = false`;
    - the `webrtc.*` IP-handling prefs.

  These names drift between Chrome releases, so the lists are versioned files.
- **Footprint.** Core's `sb-cdp-*` TempDir profile (`launch.rs:793`) is deleted at close, and shield checks that it is gone. Shield deletes files but does not shred them, and OS caches outside the profile are out of scope.
- **Scope.** Shield limits what the user's own browser sends about the user. It does not spoof fingerprints or hide automation; that stays in seleniumbase-rs-stealth.

### tor (category 5)

SOCKS5 routing through a **local** Tor daemon, circuit isolation per context, and connection management. It is native, because it needs loopback sockets.

```rust
#[derive(Clone, Debug, Deserialize)] #[serde(deny_unknown_fields)]
pub struct TorConfig {
    pub socks: SocketAddr,            // default 127.0.0.1:9050; a non-loopback address is refused
    pub control: Option<SocketAddr>,  // 127.0.0.1:9051
    pub control_auth: ControlAuth,    // SafeCookie { path } (default) | PasswordEnv { var }: never a password in a file
    pub isolation: Isolation,         // Browser | PerContext (default)
    pub require_bootstrapped: bool,   // true
}
pub struct Tor { cfg: TorConfig, state: std::sync::Mutex<TorState> } // forwarders by context; lock never held across .await

impl Configurable for Tor {
    const NAME: &'static str = "tor"; type Config = TorConfig;
    fn describe() -> Metadata {
        use Capability::*;
        Metadata::new(Category::Privacy).version(env!("CARGO_PKG_VERSION"))
            .summary("Routes every request through a local Tor daemon, with a separate circuit per browser context")
            .capabilities([LaunchProxy, LaunchNetwork, LaunchPrefs, Contexts, HostNet(NetScope::Loopback)])
            .seal(Seals::PROXY | Seals::CONTEXT_PROXY | Seals::WEBRTC)
    }
    fn from_config(cfg: TorConfig) -> Result<Self> { cfg.validate()?; Ok(Self::new(cfg)) }
}

#[async_trait]
impl Plugin for Tor {
    fn name(&self) -> &str { Self::NAME }
    fn metadata(&self) -> Metadata { Self::describe() }
    fn requirements(&self) -> Requirements { Requirements::CHROMIUM_ONLY | Requirements::LAUNCH_ONLY }
    fn per_launch(&self) -> Option<Arc<dyn Plugin>> { Some(Arc::new(Self::new(self.cfg.clone()))) }
    async fn before_launch(&self, l: &mut LaunchSettings) -> Result<()> {
        if l.proxy.is_some() { return Err(PluginError::other("tor replaces the browser's proxy: remove it, or chain it in torrc")); }
        health::check(&self.cfg).await?;                                  // fail closed: the browser never starts
        let fwd = Forwarder::start(self.cfg.socks, IsolationToken::random()?, FwdLimits::default()).await?;
        l.proxy = Some(format!("socks5://{}", fwd.local_addr()));         // names go to Tor unresolved
        l.host_resolver_rules.push("MAP * ^NOTFOUND , EXCLUDE 127.0.0.1 , EXCLUDE localhost".into()); // no local DNS
        l.disable_quic = true;
        l.webrtc_policy = Some(WebRtcPolicy::DisableNonProxiedUdp);
        l.prefs.insert("net.network_prediction_options".into(), json!(2));
        self.keep_browser_forwarder(fwd); Ok(())
    }
    async fn before_context(&self, c: &mut ContextSettings) -> Result<()> {
        if c.proxy.is_some() { return Err(PluginError::other("tor: a context may not set its own proxy")); }
        if self.cfg.isolation == Isolation::PerContext {
            let fwd = Forwarder::start(self.cfg.socks, IsolationToken::random()?, FwdLimits::default()).await?;
            c.proxy = Some(format!("socks5://{}", fwd.local_addr()));     // Target.createBrowserContext{proxyServer}
            self.park(fwd);
        }
        Ok(())
    }
    async fn on_context_created(&self, c: &dyn ContextHandle) -> Result<()> { self.bind_parked(c.id()); Ok(()) }
    async fn on_context_closed(&self, id: &ContextId) -> Result<()> { self.drop_forwarder(id); Ok(()) } // listener closes
    async fn on_close(&self) -> Result<()> { self.drop_all(); Ok(()) }
}
impl Tor { pub async fn new_identity(&self) -> Result<()>; } // control port SIGNAL NEWNYM, at most once per 10 s
```

- **The forwarder** (`forwarder.rs`, hand-written, fuzzed, about 200 lines) works like this:
  - It accepts SOCKS5 with no authentication from Chrome, CONNECT only; BIND and UDP ASSOCIATE get reply 0x07.
  - It forwards to Tor's SocksPort with RFC 1929 credentials `sbrs-<128-bit random>` / `x`. Tor's `IsolateSOCKSAuth` then gives each context its own circuit.
  - It has a 10 s handshake timeout, at most 256 connections, and bounded reads.
  - When the upstream fails it answers with a failure and **never dials the target directly**.
- **The control port** uses SAFECOOKIE (`ring::hmac`), checks bootstrap at `PROGRESS=100`, and refuses `NoIsolateSOCKSAuth` when isolation is per context.
- **Scope.** Tor protects the person running the automation and lets them test their own onion services. Identity changes are rate-limited and never made per request; the plugin is not a way around bans or rate limits. It never spawns Tor, and `arti-client` is not bundled.

### fetcher (category 4)

Interception of raw HTTP and CDP payloads, asset stripping, and fast content retrieval.

```rust
#[derive(Clone, Debug, Default, Deserialize)] #[serde(default, deny_unknown_fields)]
pub struct FetcherConfig {
    pub strip: Vec<ResourceKind>, pub block: Vec<String> /* globs */, pub capture: Vec<String> /* globs */,
    pub headers: BTreeMap<String, String>, pub max_body_bytes: Option<usize> /* 2 MiB */, pub max_captures: Option<usize> /* 500 */,
}
pub struct Fetcher { cfg: FetcherConfig, log: CaptureLog } // Arc<Mutex<VecDeque<Captured>>>, bounded

impl Configurable for Fetcher {
    const NAME: &'static str = "fetcher"; type Config = FetcherConfig;
    fn describe() -> Metadata {
        use Capability::*;
        Metadata::new(Category::Core).version(env!("CARGO_PKG_VERSION"))
            .summary("Strips assets, blocks URLs, adds headers and captures response bodies")
            .capabilities([NetIntercept, NetObserve]).optional([NetBodies]) // bodies only if granted
    }
    fn from_config(cfg: FetcherConfig) -> Result<Self> { Ok(Self::new(cfg)) }
}

#[async_trait]
impl Plugin for Fetcher {
    fn name(&self) -> &str { Self::NAME }
    fn metadata(&self) -> Metadata { Self::describe() }
    fn requirements(&self) -> Requirements { Requirements::CHROMIUM_ONLY }
    fn network(&self) -> NetworkInterest {                           // all declarative: no on_request round trips
        let max = self.cfg.max_body_bytes.unwrap_or(2 << 20);
        NetworkInterest::none()
            .rules(self.cfg.strip.iter().map(|k| NetRule::block(RequestFilter::kind(*k))))
            .rules(self.cfg.block.iter().map(|g| NetRule::block(RequestFilter::url(g))))
            .rules((!self.cfg.headers.is_empty()).then(|| NetRule::set_headers(RequestFilter::any(), self.cfg.headers.clone())))
            .observe(self.cfg.capture.iter().map(|g| RequestFilter::url(g).max_body(max)))
    }
    async fn on_response(&self, r: &ResponseView<'_>) -> Result<()> { self.log.push_bounded(r, self.max_captures()) }
}

#[async_trait]
impl JobRunner for Fetcher {   // batcher job {"url": ...} -> text, without rendering, with the page's cookies and CORS rules
    async fn run_job(&self, page: &dyn PageHandle, job: &Value) -> Result<Value> {
        let url = job["url"].as_str().ok_or_else(|| PluginError::config("fetcher", "a job needs a `url`"))?;
        let expr = format!("fetch({u},{{credentials:'include'}}).then(async r=>({{status:r.status,\
                            mime:r.headers.get('content-type'),text:(await r.text()).slice(0,{max})}}))",
                           u = Value::from(url), max = self.max_chars());   // URL JSON-escaped
        page.evaluate(&expr).await
    }
}
```

### extractor (category 4)

Automatic discovery of the fields on a page, schema generation, and typed JSON without brittle selectors.

```rust
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)] pub struct Schema { pub page: String, pub records: Vec<RecordSchema> }
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)] pub struct RecordSchema { pub name: String, pub anchor: Anchor, pub fields: Vec<Field> }
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)] pub struct Field { pub name: String, pub ty: FieldType, pub locators: Vec<Anchor>, pub required: bool }
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)] #[serde(tag = "type", rename_all = "kebab-case")]
pub enum FieldType { Text, Number, Money { currency: Option<String> }, Date, Url, Image, Bool }
/// Semantic anchors first; a structural signature only as the last fallback.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)] #[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Anchor { JsonLd { path: String }, Microdata { itemprop: String }, Meta { property: String },
                  Aria { role: String, name: String }, Label { text: String }, TableColumn { header: String },
                  Structural { signature: String, child: u32 } }

pub struct Extractor { cfg: ExtractorConfig } // min_repeats 3, max_nodes 20_000, max_fields 64, auto_save: Option<PathBuf>
const DISCOVER_JS: &str = include_str!("discover.js"); // pure; walks at most max_nodes; no network
const EXTRACT_JS: &str = include_str!("extract.js");

impl Extractor {
    pub async fn discover(&self, page: &dyn PageHandle) -> Result<Schema>;  // JSON-LD, microdata, meta, tables, labels, repeats
    pub async fn extract<T: DeserializeOwned>(&self, page: &dyn PageHandle, s: &Schema) -> Result<Vec<T>>;
    pub async fn extract_values(&self, page: &dyn PageHandle, s: &Schema) -> Result<Extracted>; // missing required -> problems
    #[must_use] pub fn json_schema(record: &RecordSchema) -> Value;         // JSON Schema 2020-12
}

#[async_trait]
impl Plugin for Extractor {
    fn name(&self) -> &str { "extractor" }
    fn metadata(&self) -> Metadata {
        let m = Metadata::new(Category::Core).capability(Capability::PageEvaluate);
        if self.cfg.auto_save.is_some() { m.capability(Capability::ArtifactsWrite) } else { m }
    }
    async fn after_navigate(&self, page: &dyn PageHandle, nav: &NavOutcome) -> Result<()> {
        if let (Some(dir), true) = (&self.cfg.auto_save, nav.ok()) {          // logged hook: errors never break the run
            let schema = self.discover(page).await?;
            write_json(dir, &nav.url, &self.extract_values(page, &schema).await?)?;
        }
        Ok(())
    }
}
#[async_trait]
impl JobRunner for Extractor {  // batcher job {"url"} -> {"schema", "records"}
    async fn run_job(&self, page: &dyn PageHandle, job: &Value) -> Result<Value> {
        page.navigate(job_url(job)?).await?;
        let schema = self.discover(page).await?;
        Ok(json!({ "schema": &schema, "records": self.extract_values(page, &schema).await? }))
    }
}
```

The extractor reads only pages the user loads. Page content is treated as data and never evaluated.

### batcher (category 1)

Splits a queue into chunks, limits concurrency, and runs jobs in parallel. It uses `futures-util` `buffer_unordered`, which is already in the tree and needs no spawning.

```rust
#[derive(Clone, Debug, Deserialize)] #[serde(default, deny_unknown_fields)]
pub struct BatcherConfig { pub concurrency: usize /*1..=32, 4*/, pub chunk_size: usize /*25*/, pub job_timeout_secs: u64 /*60*/,
                           pub retries: u8 /*0..=3, 1*/, pub runner: String /*"open"*/, pub max_jobs: usize /*10_000*/ }
pub struct Batcher { cfg: BatcherConfig }

#[async_trait]
impl Plugin for Batcher {
    fn name(&self) -> &str { "batcher" }
    fn metadata(&self) -> Metadata {
        let m = Metadata::new(Category::Environment).capabilities([Capability::Task, Capability::Contexts]);
        if self.cfg.runner == "open" { m } else { m.requires(self.cfg.runner.clone()) } // dependency from config
    }
    fn task(&self) -> Option<&dyn Task> { Some(self) }
}

#[async_trait]
impl Task for Batcher {
    async fn run(&self, cx: &TaskContext<'_>) -> Result<Value> {
        let jobs = cx.input["jobs"].as_array().ok_or_else(|| PluginError::config("batcher", "input needs a `jobs` array"))?;
        if jobs.len() > self.cfg.max_jobs { return Err(PluginError::config("batcher", "too many jobs")); }
        let runner: &dyn JobRunner = if self.cfg.runner == "open" { &OpenRunner } else { cx.plugins.job_runner(&self.cfg.runner)? };
        let chunks: Vec<ChunkSummary> = stream::iter(jobs.chunks(self.cfg.chunk_size).enumerate())
            .map(|(i, chunk)| self.run_chunk(cx, runner, i, chunk))
            .buffer_unordered(self.cfg.concurrency)              // at most N contexts in flight
            .try_collect().await?;
        Ok(json!(Summary::of(&chunks)))
    }
}
impl Batcher {
    async fn run_chunk(&self, cx: &TaskContext<'_>, runner: &dyn JobRunner, i: usize, jobs: &[Value]) -> Result<ChunkSummary> {
        let ctx = cx.browser.new_context(ContextSettings::default()).await?; // before_context: tor gives it its own circuit
        let mut summary = ChunkSummary::new(i);
        for job in jobs {
            let outcome = retry(cx.clock, self.cfg.retries, || async {         // never retries a policy denial
                let page = ctx.new_page(None).await?;
                let r = cx.clock.timeout(self.cfg.job_timeout(), runner.run_job(page.as_ref(), job)).await;
                let _ = page.close().await; r
            }).await;
            cx.sink.record(&json!({ "chunk": i, "job": job, "outcome": &outcome }))?;
            summary.add(&outcome);
        }
        ctx.dispose().await?;                                    // on_context_closed: shield and tor clean up
        Ok(summary)
    }
}
```

`sbrs plugin run batcher --input jobs.json --plugin-opt 'batcher.runner="extractor"' --plugin extractor`

### crawler (category 2)

Recursive link discovery, state tracking, and verification of the traversal. It is meant for checking sites you own or may test.

```rust
#[derive(Clone, Debug, Deserialize)] #[serde(default, deny_unknown_fields)]
pub struct CrawlerConfig { pub start: Vec<String>, pub scope: Scope /*SameOrigin*/, pub max_depth: u32 /*3*/,
    pub max_pages: usize /*500, cap 50_000*/, pub delay_ms: u64 /*1000*/, pub respect_robots: bool /*true*/,
    pub state_file: Option<PathBuf>, pub expect: Expectations /* max_status, must_reach, no_console_errors */ }
pub struct Crawler { cfg: CrawlerConfig, scope: ScopeMatcher, run: Mutex<Option<Arc<RunState>>>, last: Mutex<Option<Report>> }

#[async_trait]
impl Plugin for Crawler {
    fn name(&self) -> &str { "crawler" }
    fn metadata(&self) -> Metadata {
        use Capability::*;
        Metadata::new(Category::Testing).capabilities([Task, Contexts, PageNavigate, PageEvaluate, NetObserve, TestHooks,
                                                      ArtifactsWrite])
    }
    fn network(&self) -> NetworkInterest { NetworkInterest::none().observe([RequestFilter::kind(ResourceKind::Document)]) }
    fn protocol_events(&self) -> &[&str] { &["Runtime.exceptionThrown", "Log.entryAdded"] }
    fn task(&self) -> Option<&dyn Task> { Some(self) }
    async fn before_navigate(&self, _p: &dyn PageHandle, n: &Navigation) -> Result<NavDecision> {
        Ok(if self.active() && !self.scope.allows(&n.url) { NavDecision::Cancel(format!("{} is outside the crawl scope", n.url)) }
           else { NavDecision::Continue })
    }
    async fn on_response(&self, r: &ResponseView<'_>) -> Result<()> {
        if r.request.navigation { self.with_run(|run| run.status(&r.request.url, r.status)); } Ok(())
    }
    async fn on_protocol_event(&self, _b: &dyn BrowserHandle, e: &ProtocolEvent) -> Result<()> { self.with_run(|run| run.console(e)); Ok(()) }
    async fn on_test_end(&self, _t: &TestInfo, _o: &TestOutcome, _p: Option<&dyn PageHandle>) -> Result<TestVerdict> {
        Ok(match &*locked(&self.last) { Some(r) if !r.passed() => TestVerdict::Fail(r.summary()), _ => TestVerdict::Keep })
    }
}

#[async_trait]
impl Task for Crawler {
    async fn run(&self, cx: &TaskContext<'_>) -> Result<Value> {
        let run = self.begin()?;                                   // one run at a time; resumes from state_file if its config hash matches
        let ctx = cx.browser.new_context(ContextSettings::default()).await?;
        let page = ctx.new_page(None).await?;
        let robots = Robots::load(page.as_ref(), &self.cfg).await?; // fetched inside the page: same proxy and privacy plugins
        let mut frontier = run.resume_or(self.cfg.start.iter().map(|u| (normalize(u), 0)));
        while let Some((url, depth)) = frontier.pop_front() {
            if run.pages() >= self.cfg.max_pages { run.truncated(); break; }
            if !run.first_visit(&url) || !robots.allows(&url) { continue; }
            cx.clock.sleep(self.cfg.delay()).await;               // politeness
            if let Err(e) = page.navigate(&url).await { run.failed(&url, &e); continue; }
            let links: Vec<String> = serde_json::from_value(page.evaluate(LINKS_JS).await?)?; // http(s) a[href] only; no forms
            for link in links.into_iter().map(normalize).filter(|l| self.scope.allows(l)) {
                run.edge(&url, &link);
                if depth < self.cfg.max_depth { frontier.push_back((link, depth + 1)); }
            }
            cx.sink.record(&run.page_record(&url))?;
            run.checkpoint(self.cfg.state_file.as_deref())?;      // temp file + rename
        }
        ctx.dispose().await?;
        let report = run.finish(&self.cfg.expect);                // broken links, unreached must_reach, console errors
        *locked(&self.last) = Some(report.clone()); self.end();
        Ok(serde_json::to_value(report)?)
    }
}
```

### browser (category 3)

Interactive session handling, and extension lifetime bound to the browser. Its config type is `SessionConfig`, to avoid a clash with core's `BrowserConfig`.

```rust
#[derive(Clone, Debug, Deserialize)] #[serde(default, deny_unknown_fields)]
pub struct SessionConfig { pub extensions: Vec<ExtensionSource> /* {crx = "..", expect_id = ".."} | {dir = ".."} */,
    pub wait_for_workers: bool /*true*/, pub worker_timeout_secs: u64 /*10*/, pub session: Option<String>,
    pub save_on_close: bool, pub interactive: bool, pub pause_message: Option<String> }
pub struct BrowserSession { cfg: SessionConfig, state: Mutex<LaunchState> } // this browser's TempDirs and bound extensions

#[async_trait]
impl Plugin for BrowserSession {
    fn name(&self) -> &str { "browser" }
    fn metadata(&self) -> Metadata {
        use Capability::*;
        Metadata::new(Category::Extension).capabilities([LaunchExtensions, Cdp("Extensions".into()), Cdp("Target".into()),
            HostFsRead(PathScope::Declared(self.cfg.paths())), HostFsWrite(PathScope::Temp), Task, Contexts])
            .optional([CookiesRead, CookiesWrite])                 // only for session save/restore
    }
    fn requirements(&self) -> Requirements {
        let r = Requirements::CHROMIUM_ONLY | Requirements::LAUNCH_ONLY;
        if self.cfg.interactive { r | Requirements::HEADFUL } else { r }
    }
    fn per_launch(&self) -> Option<Arc<dyn Plugin>> { Some(Arc::new(Self::new(self.cfg.clone()))) } // pool-safe folders
    fn protocol_events(&self) -> &[&str] { &["Target.targetCreated", "Target.targetDestroyed"] }
    fn task(&self) -> Option<&dyn Task> { self.cfg.interactive.then_some(self as &dyn Task) }
    async fn before_launch(&self, l: &mut LaunchSettings) -> Result<()> {
        for src in &self.cfg.extensions {
            let dir = match src { ExtensionSource::Crx { path, expect_id } => self.unpack(path, expect_id.as_deref())?, // crx crate, 512 MiB cap
                                  ExtensionSource::Dir(d) => d.clone() };
            Manifest::read(&dir)?.require_mv3()?;
            l.extensions.push(dir);
        }
        Ok(())
    }
    async fn on_browser(&self, b: &dyn BrowserHandle) -> Result<()> {
        for ext in b.extensions() { locked(&self.state).bind(ext); }  // ids core now keeps from loadUnpacked
        if self.cfg.wait_for_workers { wait_for_workers(b, &self.ids(), self.cfg.worker_timeout()).await?; }
        if let Some(name) = &self.cfg.session { restore_session(b, name).await?; }
        Ok(())
    }
    async fn on_protocol_event(&self, _b: &dyn BrowserHandle, e: &ProtocolEvent) -> Result<()> {
        locked(&self.state).track_worker(e); Ok(())               // an MV3 worker stopped or restarted
    }
    async fn before_close(&self, b: &dyn BrowserHandle) -> Result<()> {
        if let (Some(name), true) = (&self.cfg.session, self.cfg.save_on_close) { save_session(b, name).await?; } // mode 0600, never logged
        Ok(())
    }
    async fn on_close(&self) -> Result<()> { locked(&self.state).unpacked.clear(); Ok(()) } // only this browser's folders
}

#[async_trait]
impl Task for BrowserSession {   // e.g. sign in once by hand to your own test app and keep the state for fixtures
    async fn run(&self, cx: &TaskContext<'_>) -> Result<Value> {
        let page = cx.browser.new_page(cx.input["url"].as_str()).await?;
        cx.prompt.wait(self.cfg.pause_message(), page.as_ref()).await?; // Enter in the CLI; a resume tool in MCP (open)
        if let Some(name) = &self.cfg.session { save_session(cx.browser, name).await?; }
        Ok(json!({ "extensions": locked(&self.state).snapshot() }))
    }
}
```

**Supporting API** (`task.rs`, phase 3): `Task::run(&TaskContext) -> Result<Value>` and `JobRunner::run_job(&dyn PageHandle, &Value) -> Result<Value>`. `TaskContext` carries:

- `browser`;
- `input`;
- `sink` (JSONL, stdout or MCP progress);
- `plugins`;
- `clock`;
- `prompt`.

Cancellation drops the future, for example on Ctrl-C through `common::shutdown`. Then the browser closes, which runs `before_close` and `on_close`.

## 12. Implementation plan

**Prerequisites (lead, before any agent starts):**

- 0.4.0 has shipped.
- Branch `worktree-wf_eeb3eaf6-7b6-1` is merged into the 0.5 line. It brings the WebDriver hooks, `PageHandle for sb_cdp::Page` and the page helpers.
- The unfinished Docs7 component edits are committed or merged, because they touch `docs/plugins/*`.
- ADR 004's "pinned to a git revision" sentence is corrected.

### Phase 0: security hotfix (hours; plugins 0.1.1, can ship before everything else)

- `crates/seleniumbase-rs-plugin/src/switch_policy.rs`: the unified refused list and a robust parser.
- `plugins/wasm` uses the list; `FORBIDDEN_FLAGS` stays as a re-export, so its tests and the README keep working.
- Regression tests:
  - `v1_module_with_host_resolver_rules_or_spki_list_is_refused`;
  - a proptest that a refused switch is refused in every spelling.
- A core test, under the `plugins` feature, that the `evasions.rs` list is a subset of the API's list.

### Phase 1: shippable in one or two days (three agent lanes with disjoint files; at most three cargo builds at once)

| Lane | Repo and files owned | Delivers |
|---|---|---|
| **A** (starts first; lands its types within hours) | plugins: `crates/seleniumbase-rs-plugin/src/{capability,metadata,order,config,host}.rs`, `lib.rs` re-exports, `crates/seleniumbase-rs-plugin-testing`, `template/` | `Category`, `Phase`, `Capability`/`CapabilitySet` with string forms, `Seals`, `Metadata`, `HostInfo` and `check_with`, strict sets, the Kahn resolver (phases, `after`/`before`, `requires`, `conflicts`, seal conflicts), `per_launch` and `for_launch`, the structured `LaunchSettings` fields and `WebRtcPolicy`, the refused-switch check on the args diff for every plugin (with `with_trusted` and `raw:switches`), `Configurable`/`Descriptor`/`Registry`/`PluginSpec`, fakes. Every change is additive; the version becomes 0.1.2. |
| **B** (after A's types) | plugins: `plugins/shield/**`, `plugins/crx` (`per_launch`, metadata), `plugins/block-resources` and `plugins/wasm` (metadata, `Configurable`), `crates/seleniumbase-rs-plugins-builtin/**` | shield's launch-level parts: switches, prefs, WebRTC policy and shim, strict host rules, page blocklist through the raw send, profile check, sweep. The aggregator crate with features and `registry()`. Recording-fake tests. |
| **C** (after A's types) | core: `Cargo.toml` features; `src/config/plugins.rs`; `src/plugin_host/**`; `src/sb_cdp/plugin_hooks.rs`, `launch.rs` and `browser.rs` (structured fields, one `--disable-features`, `for_launch` in `Browser::launch`, `TabLink` merging `Network.setBlockedURLs` into the per-session union and refusing `Fetch.*`, ids kept from `Extensions.loadUnpacked`, `HostInfo`); `src/browser/plugin_hooks.rs` (`Embedded` from the returned `browserName`); `src/cli/**` (`--plugin`, `--plugin-opt`, `--no-plugins`, `sbrs plugin list` and `sbrs plugin info`); `src/bin/mcp_server.rs` and `src/mcp/cdp.rs` (`--plugin`, the `plugins` argument, `list_plugins`); `completions/sbrs.usage.kdl` | Mock tests with `Browser::launch_mocked`; the lead updates `release.yml`, `ci.yml`, `Dockerfile`, the Homebrew formula and `justfile` to `plugins-builtin` |

The lead then gates the exact commit:

- `fmt`;
- clippy `-D warnings` for `mcp-server test-util plugins-builtin`;
- tests;
- `cargo deny check` and `cargo audit`;
- `mdbook build`.

Then the lead writes `docs/plugins/{installing,capabilities,categories,shield}.md`, updates `tutorials/plugins.md` and the CHANGELOG, and releases 0.5.0-alpha.

### Phase 2: CDP lifecycle and the network (about a week)

- The guard and `cdp_policy` enforcement.
- Owned handle implementations for `Browser` and `BrowserContext`.
- The context hooks, `before_navigate`/`after_navigate` in `goto`, `goto_if_not_url` and MCP `navigate`, and `before_close`.
- The protocol event pump.
- **`FetchRouter`** (the riskiest step): on its own branch, with the `intercept.rs` and `proxy_auth` tests kept green before plugin paths are added, and with real-Chrome tests.
- `block_urls` with the list kept per plugin; budgets, the `Timer` and panic catching.
- The plugins fetcher, extractor and tor, plus shield's network rules.
- Tor spikes first: Chrome and SOCKS auth; DNS and QUIC leaks; `.onion` names.

### Phase 3: tasks, tests, store, WASM ABI 2.0

- `Task`, `JobRunner` and `TaskContext`; `sbrs plugin run`; MCP `run_plugin_task`.
- `on_test_start`/`on_test_end` in `run_browser_test` and the behave runner.
- The plugins batcher, crawler and browser.
- The store, lockfile and manifest plugins (the declarative crate, which takes over validation from wasm).
- `sbrs plugin add|remove|verify|sync|gc|enable|disable|audit`.
- WASM ABI 2.0.
- The `plugin-store` feature in the release.

### Phase 4: parity and hardening

- WebDriver: `before_navigate` in `BaseCase::open`, `before_close` in `quit`, and network hooks once a CDP event channel exists.
- WASM ABI 2.1 event mode, after the `cdp_latency` benchmark.
- `sbrs plugin add <built-in>` editing `Cargo.toml` through `toml_edit`. It refuses ambiguous cases: `workspace = true`, renamed packages, duplicate tables.
- CRX3 signature checks and `expect_id`; minisign signatures.
- The WASI-lite shim.
- cargo-fuzz targets for the SOCKS parser and the ABI 2 parser.
- Checks that page-level effects reach out-of-process iframes and workers.

### Deferred

- Native `dlopen` plugins: **never**.
- A plugin hub or signed index.
- MCP tools and CLI subcommands contributed by plugins.
- Firefox network hooks through BiDi.
- Embedding arti.
- wasmtime and the component model.
- Hot reload.
- Reverse-order teardown.
- `data()` sharing between plugins.
- linkme registration.
- A `TestPlugin` adapter.
- Changing response bodies.
- **API 0.2 together with crates.io publishing:** strict mode by default, and undeclared plugins become an error.

## 13. Tests

- **API crate (fakes, no browser):**
  - ordering: phases plus insertion order, explicit edges beating the phase, a cycle, a legacy-only set keeping today's order;
  - conflicts, seals with values that differ vs equal values;
  - `launch.proxy` changed without the grant is refused; `--no-sandbox` from a native plugin is refused;
  - raw `Fetch.enable` is denied, and raw `Network.setBlockedURLs` is rewritten;
  - re-entrant `navigate` is refused;
  - the `on_request` precedence, one test per pair;
  - a timeout or panic in `on_request` gives Block, and in `on_close` it is logged while the next plugin still runs;
  - verdicts are joined;
  - the registry: an unknown field is a `Config` error, a duplicate name is refused, a strict set refuses an undeclared plugin;
  - `per_launch` gives each launch its own instance;
  - a compile test that a 0.1.0-style plugin builds unchanged.
- **Core with the mock transport:**
  - `ad_block` plus a plugin blocklist gives one `Network.setBlockedURLs` with the union (regression);
  - a pool of two browsers with crx: closing one keeps the other's folder (regression);
  - one `--disable-features` carrying Translate plus the plugins' features;
  - proxy auth plus `Page::intercept` plus a plugin rule give a single `Fetch.enable` with the union (phase 2);
  - a `before_navigate` Cancel sends no `Page.navigate`;
  - `before_context` puts the proxy on `Target.createBrowserContext`, and a seal refuses a user proxy;
  - precedence of CLI, env and file;
  - project config cannot grant;
  - `[plugins]` without the feature is an error;
  - a Tauri endpoint is `Embedded` and refuses a `CHROMIUM_ONLY` plugin at check.
- **Plugins:**
  - shield (switches, prefs, strict host rules, shim, refusal of a persistent profile, the sweep skips live profiles);
  - tor, over loopback with a fake Tor and no Chrome: a distinct token per context, names forwarded without resolving, BIND and UDP refused, Tor down means the target listener sees 0 connections, bootstrap below 100 refuses, SAFECOOKIE rejects a fake server, NEWNYM is rate-limited;
  - fetcher (rules from config, bounded captures, the URL JSON-escaped);
  - extractor (schema from a fixture, a missing required field reported, JSON Schema golden file);
  - batcher (never more than N contexts);
  - crawler (exact visited set on a link graph with a cycle, a 404, an off-origin link and a robots Disallow).
- **Store and WASM:**
  - a tampered file is refused at load;
  - a URL without a sha256 is refused off a TTY;
  - WASM cannot shadow a built-in name;
  - the manifest is read without running code (the start function traps);
  - an ungranted import or one outside `sbrs_v2` is refused before instantiation;
  - fuel and the breaker work;
  - per-context instances share nothing.
- **Real Chrome** (`*_chrome.rs`, `#[ignore]`, one binary at a time, a local server on an ephemeral port, no internet):
  - `plugins_network_chrome.rs`;
  - `shield_chrome.rs`: `webrtc_report().is_clean()`, including inside a cross-site iframe; the profile is gone after close; an SNI recorder sees no telemetry host while a baseline run without shield sees one;
  - `tor_chrome.rs` with a fake Tor;
  - `plugins_batcher_chrome.rs`, `plugins_crawler_chrome.rs`, `plugins_extension_chrome.rs`.
  - A real-Tor check is manual only, behind `SBRS_TEST_TOR`.

## 14. Consequences and risks

- **`FetchRouter` touches `intercept.rs` and `proxy_auth`,** which users depend on. If its task dies, paused requests would hang, so it is supervised and has a fail-safe `Fetch.disable`. Pausing requests costs one round trip each; patterns are limited to the union of the declared filters.
- **Fail-closed `on_request` can break pages.** The docs steer observers to `on_response` and to declarative rules.
- **Capabilities can be oversold.** For native code they are a contract; only WASM is a sandbox. Every listing shows the enforcement level.
- **Mixed sets change order** (category phases). Sets of legacy plugins only do not. The CHANGELOG says so.
- **Git-source coupling.**
  - Builds float to the newest plugins commit until `Cargo.lock` pins one.
  - A future 0.2 breaks third-party plugins at once.
  - Mitigations: additive 0.1.x now; one source spec for both dependencies, enforced by CI; `cargo deny` `allow-git` for the plugins repo; a review of each plugins-repo bump.
- **Leaks that depend on the Chrome version:** prefetch, DoH, QUIC, WebRTC mDNS, component updates, and out-of-process iframes and workers. They are tested with real Chrome before shield or tor claims protection. The telemetry lists are versioned.
- **Tor forwarder.** Any local user can ride its loopback ports, the same exposure as Tor's own SocksPort. Its parser is attack surface, so it is fuzzed. Isolation silently fails under `NoIsolateSOCKSAuth` when no control port is configured; that case only warns.
- **Seals have escape routes.** A raw `Browser::execute` by the user, or raw user args, can bypass them. Core refuses sealed fields in user options, but raw execute cannot be policed; this is documented. On WebDriver there are no context hooks, so isolation is browser-wide only.
- **Approval fatigue, and CI.** CI uses `--grant` plus sha256 pins.
- **Binary size and Homebrew build time** grow with `plugins-builtin` and `plugin-store`. They are measured before bundling.
- **Interactive tasks in MCP** need a resume tool. That is not designed yet.
- **Scope.** batcher and crawler default to polite behaviour: robots.txt on, a delay, same-origin scope, caps, and all traffic through the browser so privacy plugins apply. No plugin solves CAPTCHAs, handles third-party credentials or evades bans. Shield and tor are described as protecting the user who runs them.

## 15. How this was checked

- **No code was built, run or edited.**
- **TokenSave** (with explicit `graph_root`) was used for every indexed file in `seleniumbase-rs`, `seleniumbase-rs-plugins` and `homebrew-tap`.
- **`rtk rg` / `rtk git`** were used only for things outside the index:
  - `release.yml` and `Cargo.lock` (formats the index does not scan);
  - the unmerged WebDriver branch (`git show` / `git diff --stat`);
  - the Tauri plugin repository (`webdriver.rs:283`, not an indexed project);
  - the wasmi 2.0.0 sources in `~/.cargo/registry`.

No TokenSave call failed.
