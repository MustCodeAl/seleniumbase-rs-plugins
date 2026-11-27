# seleniumbase-rs-plugin-shield

Privacy hardening for the Chromium browser started by
[seleniumbase-rs](https://github.com/MustCodeAl/seleniumbase-rs), including opt-in
Tor SOCKS5 routing with per-context circuit isolation. It limits what your own
browser sends about you; it does not spoof fingerprints or hide automation (see
[seleniumbase-rs-stealth](https://github.com/MustCodeAl/seleniumbase-rs-stealth)).

```sh
cargo add seleniumbase-rs-plugin-shield --git https://github.com/MustCodeAl/seleniumbase-rs-plugins
```

```rust
use seleniumbase_rs_plugin::PluginSet;
use seleniumbase_rs_plugin_shield::{Level, Shield, ShieldConfig};

let shield = Shield::new(
    ShieldConfig::new()
        .level(Level::Strict)
        .tor_enabled(),
)?;
let plugins = PluginSet::strict().with(shield)?;
# Ok::<(), seleniumbase_rs_plugin::PluginError>(())
```

## What it does

- Adds browser switches and disables Chromium features responsible for background telemetry (audited against Chromium source in [`src/telemetry.rs`](src/telemetry.rs)).
- Sets privacy preferences: disables network prediction, search suggestions, Link Doctor error pages, Google spelling service, and Privacy Sandbox topics/Protected Audience/ad measurement; blocks third-party cookies.
- Sets Chrome's `disable_non_proxied_udp` WebRTC policy, and with `relay-only` (default) forces relay candidates in every tab.
- Refuses persistent profiles by default (`ephemeral_profile = true`).
- Blocks `extra_block_hosts` and their subdomains on any port via `Network.setBlockedURLs`.
- **Opt-in Tor routing (`tor` Cargo feature, enabled by default)**: when `tor = true` or `[plugins.shield.tor]` is configured, routes browser traffic through a local Tor SOCKS5 listener (`127.0.0.1:9050` by default) via per-context loopback forwarders that inject distinct SOCKS5 credentials for Tor's `IsolateSOCKSAuth`, disables QUIC, and maps DNS resolution through Tor so `.onion` addresses resolve cleanly without local DNS leaks. Never installs, starts, or stops Tor.

## Options

`[plugins.shield]` in `sbase_config.toml` or `--plugin-opt 'shield.level="strict"'`. Unknown options are rejected.

| Option | Default | Notes |
|---|---|---|
| `level` | `basic` | `strict` also blocks browser-process Google telemetry hosts via resolver rules |
| `webrtc` | `relay-only` | `off`, `policy`, or `relay-only` |
| `block_third_party_cookies` | `true` | `false` leaves Chrome's own default |
| `ephemeral_profile` | `true` | `false` allows a persistent profile |
| `extra_block_hosts` | `[]` | Plain host names (no scheme, port, path, or `*`) |
| `safe_browsing` | `true` | `false` disables Safe Browsing via prefs |
| `tor` | unset | `true` (default `127.0.0.1:9050`, `per-context` isolation), `false`, or `[plugins.shield.tor]` table (`socks`, `isolation`, `control`, `control_auth`, `require_bootstrapped`, `probe_timeout_ms`). Requires the `tor` feature. |
| `sweep_stale_profiles` | `false` | Not implemented; `true` returns a config error |
| `clear_between_tests` | `false` | Not implemented; `true` returns a config error |

```toml
[plugins.shield]
level = "strict"

[plugins.shield.tor]
socks = "127.0.0.1:9050"
isolation = "per-context"
```

## Notes

- To build `shield` without Tor dependencies (`ring`, `tokio`), use `default-features = false`.
- When `tor` is enabled, `shield` requires the pure CDP engine (`ContextProxy` + `before_context`), refuses non-loopback `socks`/`control` addresses, and refuses launches that already set a proxy.
- Tests run against recording fakes (`seleniumbase-rs-plugin-testing`) and fake local SOCKS5/control listeners; live Tor tests are `#[ignore]`d.
