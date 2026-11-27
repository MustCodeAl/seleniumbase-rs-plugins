# seleniumbase-rs-plugin-browser

Containerized persistent browser sessions for
[seleniumbase-rs](https://github.com/MustCodeAl/seleniumbase-rs). Keeps cookies,
`localStorage`, `sessionStorage`, auth state, open tabs, and regional identity
alive across runs, with geolocation targeting, proxy IP auto-rotation,
interactive sign-in capture, and dynamic SPA flow execution.

> Extension loading moved exclusively to [`seleniumbase-rs-plugin-crx`](../crx).
> `browser` and `crx` have zero overlap and compose cleanly in the same `PluginSet`.

```sh
cargo add seleniumbase-rs-plugin-browser --git https://github.com/MustCodeAl/seleniumbase-rs-plugins
```

```rust
use seleniumbase_rs_plugin::PluginSet;
use seleniumbase_rs_plugin_browser::{BrowserSession, RotationMode, SessionConfig};

let config = SessionConfig::builder()
    .session("shop-de")
    .country("DE")
    .proxies(["http://proxy1.example:8080", "http://proxy2.example:8080"])
    .proxy_rotation(RotationMode::PerContext)
    .save_on_close(true)
    .ttl_secs(86_400)
    .build()?;
let plugins = PluginSet::strict().with(BrowserSession::new(config)?)?;
# Ok::<(), seleniumbase_rs_plugin::PluginError>(())
```

Shorthand constructors for quick setup:

```rust
let session = BrowserSession::container("checkout")?;
let geo_session = BrowserSession::for_country("catalog-jp", "JP")?;
```

## What it does

- **Persistent session containers (Format v2)**: stores cookies, per-origin `localStorage` and `sessionStorage`, open tab URLs, and container identity (`country`, `locale`, `timezone`, `geolocation`) in `<session_dir>/<session>.json` (atomic `0600` temp-file rename; `0700` dir; symlinks refused; backward-compatible with v1 cookie files).
- **Session TTL (`ttl_secs`)**: automatically expires stale session containers instead of restoring outdated credentials.
- **Geolocation targeting (`country`, `locale`, `timezone`, `geolocation`)**: built-in regional profiles for 40+ ISO-3166 country codes automatically align Accept-Language/locale, timezone (`Emulation.setTimezoneOverride`), and coordinates (`Emulation.setGeolocationOverride`), with explicit per-field overrides.
- **Proxy IP auto-rotation (`proxies`, `proxy_rotation`)**: supports `sticky`, `round-robin`, and `per-context` rotation across `http`, `https`, `socks4`, `socks5`, and `socks5h` proxies while redacting credentials from logs and `Debug` output.
- **Dynamic SPA flow & extraction task (`sbrs plugin run browser`)**:
  - **Flow mode** (`interactive = false`): executes multi-step browser flows (`navigate`, `wait`, `click`, `type`, `scroll`, `extract`, `sleep_ms`) inside the persistent container and persists updated state when done.
  - **Interactive sign-in capture** (`interactive = true`): opens a headed browser tab so a human can complete login/MFA, then persists cookies, storage, and open tabs to the container file.

## Options

`[plugins.browser]` in `sbase_config.toml`:

| Option | Default | Notes |
|---|---|---|
| `session` | required | Container name (1 to 64 chars: ASCII alphanumeric, `.`, `_`, `-`) |
| `session_dir` | `saved_sessions` | Directory for `<session>.json` files (keep out of git!) |
| `save_on_close` | `true` | Persist cookies, storage, and tabs in `before_close` (pure CDP engine) |
| `ttl_secs` | none | Optional container expiration in seconds |
| `restore_tabs` | `true` | Reopen persisted non-blank HTTP(S) tabs on launch |
| `persist_storage` | `true` | Capture and restore `localStorage` and `sessionStorage` per origin |
| `country` | none | ISO-3166 alpha-2 code (e.g. `US`, `GB`, `DE`, `JP`, `BR`, `AU`) |
| `locale` | from `country` | Explicit BCP-47 locale override |
| `timezone` | from `country` | Explicit IANA timezone override |
| `geolocation` | from `country` | Explicit `{ latitude, longitude, accuracy? }` override |
| `proxies` | `[]` | Proxy pool URLs for IP rotation |
| `proxy_rotation` | `round-robin` | `sticky`, `round-robin`, or `per-context` |
| `interactive` | `false` | Headed manual login capture mode for `sbrs plugin run browser` |
| `pause_message` | default text | Prompt shown during interactive sign-in (requires `interactive = true`) |

```toml
[plugins.browser]
session = "portal-eu"
country = "DE"
ttl_secs = 86400
restore_tabs = true
persist_storage = true
proxies = ["http://eu1.proxy.example:8080", "http://eu2.proxy.example:8080"]
proxy_rotation = "per-context"
```

## Security notes

- Session files contain live credentials (`cookies`, `localStorage`, `sessionStorage`). Keep `saved_sessions/` in `.gitignore`.
- No cookie value, storage value, or proxy password is ever printed in errors, logs, task outputs, or `Debug` output.
- Tests run against `seleniumbase-rs-plugin-testing` fakes (`RecordingBrowser`, `RecordingPage`); live Chrome verification is separate.
