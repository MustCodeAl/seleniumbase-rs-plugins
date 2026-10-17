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
