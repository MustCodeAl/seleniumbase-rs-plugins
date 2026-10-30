# seleniumbase-rs-plugin-browser

Loads browser extensions into the Chromium browser
[seleniumbase-rs](https://github.com/MustCodeAl/seleniumbase-rs) starts, from
`.zip` and `.crx` files and from unpacked folders. It is the plugin form of
Python SeleniumBase's `--extension-zip` and `--extension-dir`, with the same
option names and the same meaning.

```sh
cargo add seleniumbase-rs-plugin-browser --git https://github.com/MustCodeAl/seleniumbase-rs-plugins
```

```rust
use seleniumbase_rs_plugin::PluginSet;
use seleniumbase_rs_plugin_browser::{BrowserSession, SessionConfig};

let config = SessionConfig::new()
    .with_zip("extensions/dark-reader.crx")
    .with_dir("my-extension");
let plugins = PluginSet::strict().with(BrowserSession::new(config)?)?;
# Ok::<(), seleniumbase_rs_plugin::PluginError>(())
```

## What it does

- `extension_zip` takes `.zip` and `.crx` files (CRX2 and CRX3). The format is
  read from the first bytes of the file, not from its name. The archive is
  unpacked, with the code of
  [`seleniumbase-rs-plugin-crx`](../crx), into a temporary folder that belongs
  to one browser and is deleted when that browser closes. Entries that would
  land outside the folder are refused, and so is an archive that unpacks to
  more than 512 MiB. The signature of a `.crx` is **not** verified: load only
  files you trust, as you would install them by hand.
- `extension_dir` takes unpacked extension folders. They are loaded where they
  are and are never changed or deleted.
- The archives are handled first and then the folders, as Python does, each
  list in the order you gave it, after any folder another plugin added. The
  same file or folder named twice is loaded once.
- Every extension, archive or folder, must have a `manifest.json` with
  `"manifest_version": 3`. Everything is checked before the browser starts: a
  path that does not exist, a file of the wrong kind, a bad archive or a
  manifest that is not Manifest V3 fails the launch, and the message names the
  option and the path as you wrote it.
- The plugin adds the folders to the launch settings and no switch. The host
  joins them into Chrome's `--load-extension` list, or loads them over the
  protocol where branded Chrome ignores that switch. Python does not add
  `--disable-extensions-except` either, and neither does this plugin.

It declares the `Extension` category, `LaunchExtensions`, `HostFsRead` for the
paths you configured and, only when you configured archives, `HostFsWrite` for
a temporary folder. It needs a Chromium browser that the program starts (not one
it attaches to).

## Options

`[plugins.browser]` in a config file, or
`--plugin-opt 'browser.extension_dir=["my-extension"]'`. An option that is not
listed is an error.

| Option | Default | |
|---|---|---|
| `extension_zip` | `[]` | `.zip` or `.crx` files: a list, or one text with the paths separated by commas (Python's form). An empty text means none |
| `extension_dir` | `[]` | unpacked extension folders: a list, or comma-separated text. A folder whose path holds a comma is refused, because Chrome's list is split there |

```toml
[plugins.browser]
extension_zip = ["extensions/dark-reader.crx"]
extension_dir = ["my-extension"]
```

## Things to know

- **Headless.** Chrome's old headless mode cannot load extensions; its new mode
  (`--headless=new`, which seleniumbase-rs starts) can. Python loads the
  extensions you name whatever the mode, and so does this plugin; the plugin API
  has one `headless` flag and cannot tell the two modes apart. The only case it
  refuses is an explicit `--headless=old` switch, which would lose the
  extensions without a word.
- **Pools.** Each browser of a pool gets its own copy of the plugin and so its
  own unpacked folders. Closing one browser deletes only its own; the folders
  you named with `extension_dir` are never deleted.
- **Conflicts with `crx`.** One plugin loads extensions per set. This one is a
  superset of `crx` (it also takes `.zip` files and folders and checks the
  manifest), so pick it or `crx`, not both.
- **The manifest check reads plain JSON.** A byte order mark is accepted; a
  manifest with `//` comments is refused as not valid JSON.
- **Not built yet.** The design also has `wait_for_workers`,
  `worker_timeout_secs`, `session`, `save_on_close`, `interactive` and
  `pause_message`. They need hooks the plugin API does not have (a clock in
  `on_browser`, a folder for saved sessions), so they are refused as unknown
  options instead of being accepted and ignored.
- **Order next to a privacy plugin.** The `Extension` category runs in the
  `Normal` phase and `Privacy` in the later `Enforce` phase, so a privacy plugin
  such as `tor` sees the launch after this plugin, whatever order the plugins
  were added in.
- **Nothing here has run in a real Chrome.** The tests drive the plugin through
  a plugin set (with `block_on` from `seleniumbase-rs-plugin-testing`), archives
  built in memory and temporary folders. What Chrome does with the folders, and
  the `--load-extension` list itself, belong to the host and are covered by its
  tests.
