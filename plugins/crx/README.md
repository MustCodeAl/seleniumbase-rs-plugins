# seleniumbase-rs-plugin-crx

The single Chromium extension loader for
[seleniumbase-rs](https://github.com/MustCodeAl/seleniumbase-rs). Loads `.crx`
(CRX3 and CRX2), `.zip`, and unpacked Manifest V3 extension folders, with
optional service-worker readiness waits.

```sh
cargo add seleniumbase-rs-plugin-crx --git https://github.com/MustCodeAl/seleniumbase-rs-plugins
```

```rust
use seleniumbase_rs_plugin::PluginSet;
use seleniumbase_rs_plugin_crx::{CrxConfig, CrxExtensions};

let config = CrxConfig::builder()
    .zip("extensions/dark-reader.crx")
    .dir("extensions/my-unpacked-mv3")
    .wait_for_workers(true)
    .build()?;
let plugins = PluginSet::strict().with(CrxExtensions::from_config(config)?)?;
# Ok::<(), seleniumbase_rs_plugin::PluginError>(())
```

## What it does

- **Unified extension loading**: handles `.crx` (CRX3/CRX2), `.zip` archives, and unpacked folders in one plugin (`crx`). Works seamlessly alongside [`browser`](../browser) (containerized persistent sessions) with zero conflict.
- **Safe unpacking**: detects archive format by header bytes, blocks path traversal (`..`, absolute paths), caps unpacked size at 512 MiB, and deletes temporary unpacked folders when the browser closes. Note: `.crx` cryptographic signatures are not verified; load only trusted extensions.
- **Manifest V3 validation**: validates `manifest.json` (`"manifest_version": 3`) by default before launching Chrome (`require_manifest_v3 = true`).
- **Service-worker readiness (`wait_for_workers`)**: optionally polls `BrowserHandle::extension_workers` until every loaded extension declaring `background.service_worker` has a running worker (timeout 1 to 30 s, default 10 s).

## Options

`[plugins.crx]` in `sbase_config.toml`:

| Option | Default | Notes |
|---|---|---|
| `files` | `[]` | Packed `.crx` / `.zip` paths (list or comma-separated string) |
| `extension_zip` | `[]` | Alias for `files` (matches Python `--extension-zip`) |
| `extension_dir` | `[]` | Unpacked extension directories (list or comma-separated string; matches Python `--extension-dir`) |
| `wait_for_workers` | `false` | Wait for loaded MV3 background service workers in `on_browser` |
| `worker_timeout_secs` | `10` | Worker readiness timeout (1 to 30 seconds; requires `wait_for_workers = true`) |
| `require_manifest_v3` | `true` | Require `"manifest_version": 3` in every loaded `manifest.json` |

```toml
[plugins.crx]
extension_zip = ["extensions/adguard.crx"]
extension_dir = ["extensions/custom-mv3"]
wait_for_workers = true
worker_timeout_secs = 15
```
