# seleniumbase-rs-plugin-tor

Sends the traffic of the Chromium browser that
[seleniumbase-rs](https://github.com/MustCodeAl/seleniumbase-rs) starts through a
**local Tor daemon**, so that sites do not see the address of the person running
the automation, and lets that person test their own onion services.

It protects the person who runs the automation. It is not a way around bans or
rate limits, and it has no call that asks Tor for a new identity.

```sh
cargo add seleniumbase-rs-plugin-tor --git https://github.com/MustCodeAl/seleniumbase-rs-plugins
```

```rust
use seleniumbase_rs_plugin::PluginSet;
use seleniumbase_rs_plugin_tor::{Isolation, Tor, TorConfig};

let tor = Tor::new(TorConfig::new().isolation(Isolation::PerContext))?;
let plugins = PluginSet::strict().with(tor)?;
# Ok::<(), seleniumbase_rs_plugin::PluginError>(())
```

## What you need

A Tor daemon on this machine with its SocksPort, `127.0.0.1:9050` unless you say
otherwise. **The plugin never installs, starts or stops Tor.** With no daemon the
launch fails before any browser starts:

```
tor: no SOCKS listener at 127.0.0.1:9050; start a local Tor daemon (sbrs never installs or starts Tor)
```

The plugin only talks to loopback addresses, and refuses a `socks` or `control`
address that is not one. It works with a browser the program starts (not one it
attaches to), on the pure CDP engine, with Chromium.

## What it does

In `before_launch`, in this order:

1. Refuses the launch if a proxy is already set (`--proxy`, a `--proxy-*` or
   `--no-proxy-server` argument): remove it, or chain it in `torrc`. Nothing has
   changed yet.
2. Checks Tor: something must answer as SOCKS5 at `socks` (a greeting only: no
   circuit is requested, so no traffic leaves the machine) and, with `control`
   and `require_bootstrapped`, Tor must report `PROGRESS=100`.
3. Starts a local forwarder and sets:

   | Launch setting | Value |
   |---|---|
   | `proxy` | `socks5://127.0.0.1:<forwarder port>` (never with a user name) |
   | `host_resolver_rules` | adds `MAP * ^NOTFOUND , EXCLUDE 127.0.0.1 , EXCLUDE localhost` |
   | `disable_quic` | `true` |
   | `webrtc_policy` | `disable_non_proxied_udp` |
   | pref `net.network_prediction_options` | `2` (no preconnect or prefetch) |

   It seals the proxy, the proxy of new contexts and the WebRTC policy: a plugin
   that runs later cannot change them.

Names go to Tor as names, so Tor resolves them and `.onion` services work.

## Options

`[plugins.tor]` in a config file, or `--plugin-opt 'tor.socks="127.0.0.1:9150"'`.
An option that is not listed is an error.

| Option | Default | |
|---|---|---|
| `socks` | `127.0.0.1:9050` | Tor's SocksPort. Loopback only. |
| `control` | none | Tor's control port, such as `127.0.0.1:9051`. Loopback only. Used to read the bootstrap state, nothing else. Needs `control_auth`. |
| `control_auth` | none | `{ cookie_path = "/var/run/tor/control.authcookie" }` (`SAFECOOKIE`) or `{ password_env = "TOR_CONTROL_PASSWORD" }` (`HASHEDPASSWORD`). A password is never an option value. |
| `isolation` | `per-context` | `per-context` or `browser` |
| `require_bootstrapped` | `true` | Refuse to start the browser until Tor reports that it finished bootstrapping. Needs `control`; without it only the SOCKS5 check is made. |

## Isolation

Chrome speaks SOCKS5 without authentication, so it cannot ask Tor for circuits
of its own. A small forwarder on a loopback port sits between the browser and
Tor and passes every connection to Tor's SocksPort with an isolation parameter
of its own (SOCKS5 user name `<torS0X>0`, password `sbrs-` and 128 random bits;
Tor's SOCKS extensions, proposal 351). Tor's `IsolateSOCKSAuth`, on by default
for a SocksPort, puts streams with different parameters on different circuits.

- `per-context`: every browser context made while the plugin runs gets a
  forwarder of its own (`before_context` sets `ContextSettings::proxy`) and the
  forwarder stops when the context closes. Contexts are made one at a time so
  that each forwarder reaches its own context. At most 128 contexts at once.
  The browser's default context and its other tabs share the browser's
  forwarder.
- `browser`: the whole browser shares one forwarder, so one set of circuits.

The forwarder serves CONNECT only (BIND and UDP ASSOCIATE get reply 7), allows
ten seconds for a handshake, serves at most 256 connections at once, reads at
most a few hundred bytes of handshake, and **never connects to the target
itself**: when Tor cannot be reached or refuses, the browser gets a failure and
nothing else happens.

## Things to know

- **Pair it with `shield`.** Chrome makes requests of its own (see the spike
  below). They go through the proxy too, but then Tor exits see them. The
  `shield` plugin turns most of them off.
- **The proxy URL never has a user name.** Chrome ignores a proxy URL with
  credentials and goes direct (see the spike), so the plugin never builds one.
- **Per-context isolation relies on the daemon.** The plugin does not read the
  daemon's `SocksPort` flags; if it has `NoIsolateSOCKSAuth`, contexts share
  circuits.
- **Control port.** `SAFECOOKIE`: the control port must prove that it knows the
  cookie before the plugin proves the same, and the raw cookie is never sent
  (`COOKIE` and `NULL` authentication are not supported). The cookie file is
  the only file the plugin reads; a plugin configured with one declares
  `host.fs.read` for that path.
- **No new identity.** There is no `SIGNAL NEWNYM` call in this version.
- **Order.** `Category::Privacy` runs after `Category::Extension`, so with the
  `browser` plugin in the set, tor runs second (tested, both insertion orders).
- **A context whose creation fails.** A context that `before_context` prepared
  but that the browser failed to make holds the next one back for five
  seconds; then its forwarder is dropped. If that context was only slow, it
  loses its forwarder: its connections fail, never go direct.

## What was verified

**Not on a real Tor daemon.** The tests use a fake SocksPort and a fake control
port (`tests/support`), and run in a plain `cargo test`. `tests/tor_daemon.rs`
is ignored and runs only with `SB_TEST_TOR_SOCKS` set to a real daemon's
SocksPort; it sends one request to `check.torproject.org` through Tor.

### The Chrome spike (2026-10-30, Chrome 156.0.8078.76, macOS arm64)

The design rests on four facts about Chrome. They were checked by starting
headless Chrome (`--headless=new --remote-debugging-port=0`, a throwaway
profile, URLs as arguments) against a SOCKS5 listener on a loopback port that
answers "no authentication", records the CONNECT and then replies "connection
refused". The test that did it was scratch code and is not part of the crate.
This is what the listener received, and what a Chrome net log showed.

| | Question | Answer |
|---|---|---|
| (a) | Does the CONNECT carry the host name? | Yes: `05 01 00 03 14` + `spike-a.example.test` + `1f 90`. Address type `0x03`, name unresolved, port 8080. The same with `MAP * ~NOTFOUND , EXCLUDE 127.0.0.1 , EXCLUDE localhost` set. |
| (b) | Does Chrome send SOCKS5 credentials? | No. The greeting was `05 01 00` on every connection: one method, no authentication, never `0x02`. With `--proxy-server=socks5://user:pass@127.0.0.1:<port>` Chrome ignored the proxy altogether: **0 connections** to the listener, every request `proxy_info` empty in the net log (direct), and `ERR_NAME_NOT_RESOLVED` from the local resolver for the target. So credentials cannot go in the proxy URL (it fails open), and only a forwarder can give each context its own Tor isolation parameter. |
| (c) | What does Chrome do with a `.onion` name? | It sends it to the proxy as a name: `05 01 00 03 3e` + a 62-byte `….onion` name + `00 50` (port 80), and again with port 443 (`01 bb`). It neither refuses nor resolves it locally. |
| (d) | Does `MAP * …NOTFOUND , EXCLUDE 127.0.0.1` stop local lookups? | Yes, with either spelling. `http://x.localhost:<port>/`, which Chrome resolves to loopback by itself, reached a loopback listener 4 times without the rule and 0 times with `MAP * ~NOTFOUND …` or `MAP * ^NOTFOUND …` (net log: `ERR_NAME_NOT_RESOLVED`, -105). The plugin writes `^NOTFOUND`, as `net/dns/mapped_host_resolver.h` does and as `shield` does. |

Also seen: with `--disable-background-networking`, Chrome still made requests of
its own (`www.google.com:443`, `accounts.google.com:443`,
`clients2.google.com:80`, `update.googleapis.com:80` and `:443`,
`www.gstatic.com:443`); all of them reached the proxy as names. Whether Chrome
has another path that does not use the proxy (for example DNS over HTTPS with a
configured provider) was not examined.

Re-check these against each new Chrome stable.
