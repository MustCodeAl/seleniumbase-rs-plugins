# ADR 0001 follow-ups: what core (seleniumbase-rs) needs for phase 2

Phase 1 of the plugins repo (API 0.1.2, additive only) is in place. Core was not changed. Core must do these things before the new API is useful:

1. **Depend on 0.1.2 or later** (`version = "0.1"` already resolves to it). `BrowserFamily` gained `Embedded` and `PluginError` gained variants, both `#[non_exhaustive]`, so exhaustive matches in core need a wildcard arm.
2. **Call `PluginSet::for_launch()`** in `Browser::launch` before `check_with`, so pooled browsers get fresh `per_launch` instances (this fixes the shared `CrxExtensions::on_close` bug).
3. **Call `check_with(&LaunchContext, &HostInfo)`** with `HostInfo::cdp()`, `HostInfo::webdriver(family)` or `HostInfo::embedded()` (Tauri, from the returned `browserName`).
4. **Map the new `LaunchSettings` fields** to `LaunchOptions`: `host_resolver_rules` joined into one `--host-resolver-rules`; `webrtc_policy` to `LaunchOptions::webrtc`; `disable_features` and `enable_features` merged with core's own `Translate` into ONE switch each; `disable_quic`. Seed `LaunchSettings::set_profile` before plugins run.
5. **Merge raw `Network.setBlockedURLs`** into a per-session union in `TabLink` and refuse `Fetch.*` (ADR section 3, row 22).
6. **Keep extension ids** from `Extensions.loadUnpacked`.
7. **Core test**: the `evasions.rs` refused list is a subset of `seleniumbase_rs_plugin::switch_policy::REFUSED_SWITCHES`.
8. Registry, CLI (`--plugin`, `--plugin-opt`, `sbrs plugin list|info`), env and config surface, `plugins-builtin` features, release workflow changes (lane C).

Not done in the plugins repo in phase 1 (needs a decision or later phases):

- `seleniumbase-rs-plugins-builtin` aggregator crate and the `shield` plugin (lane B).
- `Configurable` for `plugins/wasm` (it needs a module path option; the wasm denylist still has its own copy and should re-export `switch_policy`, phase 0).
- The deprecation warning for legacy plugins (the API crate has no logging dependency; core should log it from `Metadata::is_declared()`).
- `Guarded<H>` handles, `cdp_policy`, timers and budgets enforcement, `NetworkInterest` and handle trait extensions (phase 2).
