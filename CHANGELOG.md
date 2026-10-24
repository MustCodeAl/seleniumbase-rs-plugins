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

### Changed

- The crates are at version 0.1.3.
- `HostInfo` for WebDriver hosts no longer offers `Task` and `TestHooks`, so
  `PluginSet::check_with` refuses a plugin that needs them there (they were
  already refused for `Contexts` and the `Net*` capabilities).
- `seleniumbase-rs-plugin-testing`: `Call` has new variants, so an exhaustive
  `match` on it needs an arm for them.
- `seleniumbase-rs-plugin`: the `config` module is public (its items were
  already re-exported at the crate root).

