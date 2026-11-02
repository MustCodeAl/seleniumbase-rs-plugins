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
a temporary folder. The other options add capabilities, and only when they are
on (see below). It needs a Chromium browser that the program starts (not one
it attaches to).

## Options

`[plugins.browser]` in a config file, or
`--plugin-opt 'browser.extension_dir=["my-extension"]'`. An option that is not
listed is an error, and so is a combination that makes no sense (an option that
depends on another, a number out of range): the message starts with `browser:`
and names the option, and it comes when the plugin is built, before any browser
starts.

| Option | Default | |
|---|---|---|
| `extension_zip` | `[]` | `.zip` or `.crx` files: a list, or one text with the paths separated by commas (Python's form). An empty text means none |
| `extension_dir` | `[]` | unpacked extension folders: a list, or comma-separated text. A folder whose path holds a comma is refused, because Chrome's list is split there |
| `wait_for_workers` | `false` | wait, once the browser answers, until each extension of this plugin that has a `background.service_worker` has a running worker. Needs an extension |
| `worker_timeout_secs` | `10` | how long that wait lasts, 1 to 30. Needs `wait_for_workers` |
| `session` | none | the name of a saved session (1 to 64 letters, digits, `.`, `_`, `-`, starting with a letter or digit). Its cookies are put back when the browser starts |
| `save_on_close` | `false` | save the browser's cookies under `session` just before it closes. Needs `session` and a host that runs `before_close` (the pure CDP engine; the WebDriver host fails the launch naming the option) |
| `session_dir` | `saved_sessions` | the folder the session files live in, made absolute against the working directory when the plugin is built. Needs `session` |
| `interactive` | `false` | offer the task `sbrs plugin run browser`, which waits for a person to sign in and saves the session. Needs `session` and a headed browser |
| `pause_message` | a default text | what the person is told. Needs `interactive` |

```toml
[plugins.browser]
extension_zip = ["extensions/dark-reader.crx"]
extension_dir = ["my-extension"]
wait_for_workers = true
session = "login"
save_on_close = true
```

## Waiting for the service workers

An MV3 extension does its work in a service worker that Chrome starts a moment
after the extension is loaded. `wait_for_workers` makes the launch wait for it:
in `on_browser` the plugin asks the host (`BrowserHandle::extension_workers`)
every 250 ms, with the plugin set's clock (`BrowserHandle::clock`), until every
extension this plugin loaded whose manifest has a `background.service_worker`
has one running, or `worker_timeout_secs` have passed. Extensions without a
service worker, and extensions another plugin loaded, are not waited for. The
plugin asks the set for a longer limit for `on_browser` (the wait plus 5 s), so
the set's default of 10 s does not cut a long wait short.

It is **off by default**. The host has to implement `extension_workers`; one
that does not (and the WebDriver host, which reports no extension ids) makes the
launch fail with a message that names `wait_for_workers`, instead of waiting for
nothing. A timeout names the option, the extensions that never started and
the time.

## Saved sessions

`session` keeps the cookies of the browser's default context, through
`Storage.getCookies` and `Storage.setCookies`, in `<session_dir>/<session>.json`
(`{"version": 1, "saved_at_ms": ..., "cookies": [...]}`):

- When the browser starts the file is read and its cookies are put back. A
  session that was never saved is a fresh start. Cookies that already expired
  are dropped; session cookies are kept. A file that is corrupt, larger than
  8 MiB, of another version, with more than 5000 cookies, or that is a symbolic
  link is an error that names `session`.
- With `save_on_close` the cookies are written just before the browser closes.
  The file is made through a temporary file in the same folder, created with
  mode `0600`, and renamed over the old one; a folder the plugin creates gets
  mode `0700`; a symbolic link or a folder at the file's place is refused. The
  folder is tested for writing at launch, so a folder that cannot be written
  fails the launch and not the close (where an error is only logged).
- **`save_on_close` needs a host that runs `before_close`.** Only the pure CDP
  engine does, in `Browser::close`. The WebDriver host calls `on_browser` and
  `on_close` only, so there the launch fails in `on_browser` with a message that
  names `save_on_close`, before the session is restored: the cookies would come
  back and never be saved. A pure CDP browser that is dropped without
  `Browser::close` runs `on_close` only and saves nothing, so close it. Without
  `save_on_close` a session is restored on both engines.
- Only the fields `name`, `value`, `domain`, `path`, `expires`, `httpOnly`,
  `secure`, `sameSite`, `priority`, `sourceScheme`, `sourcePort` and
  `partitionKey` are kept and sent; others in the file are dropped.
- **The file holds credentials.** Keep `session_dir` out of version control
  (add `saved_sessions/` to `.gitignore`). No error, log line, task result or
  `Debug` output carries a cookie value: a syntax error names a line and a
  column only, and a message of the browser that repeats a value has it removed.
- **localStorage and sessionStorage are not saved.** DOM storage belongs to a
  tab, and the browser handle has no way to list tabs without the Critical
  capability `cdp:Target`, which the host never grants. Only cookies are kept.
- Saving needs Unix file permissions: `save_on_close` and `interactive` are
  refused elsewhere. Pooled browsers that save the same session race; the last
  one wins.
- `session_dir` is not in the design (the plugin API has no folder for state).
  It declares `host.fs.read` for the file and, when saving, `host.fs.write` for
  the folder, plus `cookies.write` and, when saving, `cookies.read`.

## Signing in by hand

With `interactive = true` (and a `session`) the plugin offers a task, which
`sbrs plugin run browser` starts. The input is a JSON file, as for every task
(`--input`), and the browser must be headed:

```toml
[plugins.browser]
session = "login"
interactive = true
pause_message = "Sign in to the test app, then press Enter here."
```

```sh
echo '{"url": "https://app.test/login"}' > login.json
sbrs plugin run browser --headed --input login.json
```

It opens a tab (at the `url` of the input, `http` or `https` only; without one a
blank tab), prints `pause_message` and waits until you press Enter in the
terminal, then saves the session and prints `{"session": "login", "cookies": 7}`.
The tab is left open; the host closes the browser right after the task. The
plugin needs a headed browser (`Requirements::HEADFUL`: a headless launch is
refused before it starts), a host with tasks (not WebDriver) and a person: over
MCP, where nobody can be asked, the task fails with "`interactive` needs a
person at the keyboard". A session folder that cannot be written is found out
before the prompt. Use it to sign in once, by hand, to your own test
application and keep the state for fixtures, then `session = "login"` restores
it in every later browser.

The list of plugins with a task that `sbrs plugin run` prints when you give it
a name that has none is built from each plugin's default options, so it does not
list `browser` (`interactive` is off by default); `sbrs plugin run browser` with
the options on builds the plugin from them and finds the task.

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
- **The plugin API they need.** `wait_for_workers` uses two methods this release
  adds to `BrowserHandle` with default bodies, `clock()` (None) and
  `extension_workers()` (`NotSupported`); a host that does not implement the
  second one makes `wait_for_workers = true` fail the launch, naming the option.
  `Guarded` hands `clock()` only to a plugin that holds the `clock` capability
  and `extension_workers()` only to one that holds `launch.extensions`.
- **Order next to a privacy plugin.** The `Extension` category runs in the
  `Normal` phase and `Privacy` in the later `Enforce` phase, so a privacy plugin
  such as `tor` sees the launch after this plugin, whatever order the plugins
  were added in.
- **Nothing here has run in a real Chrome.** The tests drive the plugin through
  a plugin set (with `block_on` from `seleniumbase-rs-plugin-testing`), archives
  built in memory and temporary folders. What Chrome does with the folders, and
  the `--load-extension` list itself, belong to the host and are covered by its
  tests.
