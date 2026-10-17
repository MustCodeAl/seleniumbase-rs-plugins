# seleniumbase-rs-plugin-shield

Privacy hardening for the Chromium browser that
[seleniumbase-rs](https://github.com/MustCodeAl/seleniumbase-rs) starts. It limits
what your own browser sends about you. It does not spoof fingerprints or hide
automation; that is the job of
[seleniumbase-rs-stealth](https://github.com/MustCodeAl/seleniumbase-rs-stealth).

```sh
cargo add seleniumbase-rs-plugin-shield --git https://github.com/MustCodeAl/seleniumbase-rs-plugins
```

```rust
use seleniumbase_rs_plugin::PluginSet;
use seleniumbase_rs_plugin_shield::{Level, Shield, ShieldConfig};

let shield = Shield::new(ShieldConfig::new().level(Level::Strict))?;
let plugins = PluginSet::strict().with(shield)?;
# Ok::<(), seleniumbase_rs_plugin::PluginError>(())
```

## What it does

- Adds browser switches and turns off features that stop the browser's
  background network use (the list, with the Chromium source of each entry, is
  in [`src/telemetry.rs`](src/telemetry.rs)).
- Sets privacy preferences: no network prediction, search suggestions, Link
  Doctor error pages or Google spelling service; no Privacy Sandbox topics,
  Protected Audience or ad measurement; third-party cookies blocked.
- Sets Chrome's `disable_non_proxied_udp` WebRTC policy, and with `relay-only`
  (the default) forces relay candidates in every tab. Peers without a TURN
  server cannot connect; use `policy` if you need them.
- Refuses a launch with a persistent profile (`ephemeral_profile`).
- Blocks `extra_block_hosts`, their subdomains, on any port.

## Options

`[plugins.shield]` in a config file, or `--plugin-opt 'shield.level="strict"'`.
An option that is not listed is an error.

| Option | Default | |
|---|---|---|
| `level` | `basic` | `strict` also makes the browser unable to resolve a few Google hosts (see below) |
| `webrtc` | `relay-only` | `off`, `policy` or `relay-only` |
| `block_third_party_cookies` | `true` | `false` leaves the browser's own setting; it never allows them |
| `ephemeral_profile` | `true` | `false` allows a persistent profile |
| `extra_block_hosts` | `[]` | plain host names, no scheme, port, path or `*` |
| `safe_browsing` | `true` | `false` sets the preference that turns it off; nothing else does |
| `sweep_stale_profiles` | `false` | **not implemented**; `true` is an error |
| `clear_between_tests` | `false` | **not implemented**; `true` is an error |

The last two need hooks the plugin API does not have yet. They are refused
instead of accepted so that no config promises a protection that is not running.

## Things to know

- **`strict` is wide.** The block is a browser-wide host resolver rule, so pages
  cannot reach those hosts either. `clients2.google.com` also serves Chrome Web
  Store and extension update downloads, and `clients4.google.com` is also a
  connectivity-check host.
- **`extra_block_hosts` is per tab session.** The block goes out as
  `Network.setBlockedURLs` on each tab's own protocol session. Whether cross-site
  iframes, workers and popups are covered depends on the host applying the list
  to those targets; this was not verified.
- **Shield overwrites.** It sets its preferences and the WebRTC policy even if
  another plugin or the caller set them. Switches and features are only added.
  Put shield last if its values must win.
- **Safe Browsing.** Shield sets no Safe Browsing preference or rule unless
  `safe_browsing = false`. What Chromium's own `--disable-background-networking`
  does to Safe Browsing list updates was not checked.
- **Nothing here has run in a real Chrome.** The tests use the recording fakes
  of `seleniumbase-rs-plugin-testing`. The switches, features, hosts and
  preference names were checked against the Chromium source, not against a
  running browser. Re-check them against each new Chrome stable.
