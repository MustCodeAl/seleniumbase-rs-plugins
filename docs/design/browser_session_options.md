# The `browser` plugin: worker waiting, saved sessions, interactive sign-in

This note describes four options of `seleniumbase-rs-plugin-browser` that the
first release left out, the plugin API they need, what the host must provide,
and what is not done. The ADR (`docs/adr/0001-plugin-architecture.md`, section
"browser") had them from the start; this note replaces its sketch where the real
API forced a different shape.

## Rule for all of them

A mistake in how the options combine is a `PluginError::Config` that starts with
`browser:` and names the option, raised when the plugin is built, before any
browser starts. An option the host cannot serve fails at the first launch step
that proves it, with a message that names the option. Nothing is accepted and
then ignored.

## Options

| Option | Default | Meaning |
|---|---|---|
| `wait_for_workers` | `false` | After the browser answers, wait until every extension this plugin loaded that has a `background.service_worker` has a running worker. |
| `worker_timeout_secs` | 10 | How long to wait, 1 to 30. Refused unless `wait_for_workers` is on. |
| `session` | none | The name of a saved session. At launch its cookies are put back; a missing file is a fresh start. |
| `save_on_close` | `false` | Save the cookies under `session` just before the browser closes. Needs `session`. |
| `session_dir` | `saved_sessions` | The folder the session files live in, made absolute when the plugin is built. Needs `session`. |
| `interactive` | `false` | Offer a task (`sbrs plugin run browser`) that opens a tab, waits for a person to sign in, and saves the session. Needs `session`; needs a headed browser. |
| `pause_message` | a default text | What the person is told. Needs `interactive`. |

`session_dir` is not in the ADR. The plugin API has no folder for state (the
capabilities `State` and `PathScope::RunOutput` have no API behind them), so the
plugin takes the folder as an option, the way the crawler takes `state_file`.
The owner has to accept it.

### `wait_for_workers`

The default is `false`, not the ADR's `true`. The host that exists today does not
implement `BrowserHandle::extension_workers`, so a default of `true` would make
every existing `extension_zip` or `extension_dir` config fail at launch. The
default may become `true` in the release in which the host ships the query.

Steps, all in `on_browser`:

1. If none of this instance's folders has a service worker in its manifest,
   there is nothing to wait for. Extensions another plugin added are ignored:
   only the folders this instance prepared are matched, by path, against
   `BrowserHandle::extensions()`.
2. Ask `BrowserHandle::extension_workers()` once. `NotSupported` becomes
   "`wait_for_workers` needs a host that reports extension service workers".
3. If the host reports no id for one of the folders (the WebDriver host), fail
   naming the option and the folder.
4. Get `BrowserHandle::clock()`. `None` becomes "needs a clock the host did not
   provide".
5. Poll every 250 ms, with the clock's timeout. On timeout the message names the
   option, the extension ids, their folder names and the number of seconds.

The plugin asks for a longer limit for `on_browser` (`Budgets::other`, the wait
plus 5 s, at most 35 s), because the set's default for that hook is 10 s and the
wait may be 30.

### `session`, `save_on_close`

Only cookies of the browser's default context are saved and restored, through
`Storage.getCookies` and `Storage.setCookies` on the browser. localStorage and
sessionStorage are **not** saved: DOM storage belongs to a tab, the browser
handle cannot list tabs without `cdp:Target` (a Critical capability the host
never grants), and putting storage back needs a navigation per origin. A session
that needs storage is out of scope until the API offers a tab list or a host-side
store.

File: `<session_dir>/<session>.json`, `{"version": 1, "saved_at_ms": N, "cookies": [...]}`.

- The name is `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`: one path component, no
  separator, no NUL, no leading dot.
- Restore: a missing file is not an error. A file that is corrupt, larger than
  8 MiB, has more than 5000 cookies, or has another version is an error that
  names `session`. Cookies that already expired are dropped, session cookies are
  kept. Only these fields reach the browser: `name`, `value`, `domain`, `path`,
  `expires`, `httpOnly`, `secure`, `sameSite`, `priority`, `sourceScheme`,
  `sourcePort`, `partitionKey`; others in the file are dropped.
- Save: a temporary file in the same folder, created with `create_new` and mode
  `0600`, written, then renamed over the target. A symbolic link or a folder at
  the target is refused. A folder the plugin creates gets mode `0700`. Pooled
  browsers that save the same session race; the last one wins.
- With `save_on_close` the folder is made and tested for writing at launch, so a
  folder that cannot be written fails the launch and not the close (where an
  error is only logged).
- Saving needs Unix file permissions: `save_on_close` and `interactive` are
  refused on other systems until ACLs are handled. Restoring works anywhere.

Secrets: the file holds credentials. No error, log line, task result or `Debug`
output carries a cookie value. A parse error reports line and column only,
because `serde_json` quotes the value it did not like. A message of the browser
that repeats a value is scrubbed.

### `interactive`

`Plugin::task()` returns the plugin only when `interactive` is on, so
`sbrs plugin run browser` finds a task only then. It is started as
`sbrs plugin run browser --headed --input login.json` (the input is a JSON file;
`--headed` is the global flag the run command honours), with the options in the
config file or in `--plugin-opt`. The host builds its list of plugins with a
task from default options, so it does not name `browser` in the error it prints
for a name that has no task.

1. Check that the session file can be written (before a person spends time).
2. Open a tab (`input.url`, only `http` or `https`; none gives a blank tab).
3. `Prompt::wait(message, page)`. A prompt that cannot wait (`NoPrompt`, the MCP
   server) becomes "`interactive` needs a person at the keyboard".
4. Save the session as above and return `{"session": name, "cookies": n}`.

The task leaves the tab open: closing the last tab of a headed Chrome can end the
browser, and the host closes it right after the task. `Requirements::HEADFUL`
makes a headless launch fail at the check, and `Capability::Task` makes a
WebDriver host fail.

## Plugin API

All additions have default bodies, so no host or plugin changes shape.

- `BrowserHandle::clock(&self) -> Option<Clock>`; default `None`. `Guarded`
  returns the set's clock (else the host handle's own) only to a plugin that
  holds `Capability::Clock`. That makes the capability mean something.
- `BrowserHandle::extension_workers(&self) -> Result<Vec<ExtensionWorker>>`;
  default `NotSupported`. One entry per service worker running now, for
  extensions this browser loaded. `Guarded` requires `launch.extensions`.
- `ExtensionWorker { id, url }`, `#[non_exhaustive]`, with `new`.
- `Guarded` forwards both: without that, the trait default would shadow the
  host's implementation for every plugin.
- `seleniumbase-rs-plugin-testing`: `RecordingBrowser::{with_workers,
  with_clock, replying}` (`with_extensions` and `failing` were already there,
  in `contexts.rs`; `failing("extension_workers")` now works too),
  `Call::ExtensionWorkers` (`Call` becomes `#[non_exhaustive]`), and
  `block_on_advancing`, which moves a `ManualTimer` on whenever the future is
  pending.

No `Capability` variant and no `HostInfo` flag is added: `HostInfo::supports`
answers per capability, so it cannot say whether a core implements one method.

## What the host must do

- `BrowserLink` (core `src/sb_cdp/plugin_hooks.rs`) implements
  `extension_workers` with `Target.getTargets`, keeping targets of type
  `service_worker` whose URL starts with `chrome-extension://<id>/` for ids in
  `Browser::loaded_extensions`. Until then `wait_for_workers = true` fails at
  launch with a message naming the option.
- The rev pins of both crates in the core `Cargo.toml` move together.

## Not verified

Nothing here ran in a real Chrome. The shapes of `Storage.getCookies`,
`Storage.setCookies` (the `Network.CookieParam` names) and `Target.getTargets`
are written from the protocol as the host's own cookie code uses it, and must be
checked against a headless Chrome and a local fixture extension before release.
The headed `interactive` flow needs a headed run.
