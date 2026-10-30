# seleniumbase-rs-plugin-imap

Waits for an email in an IMAP mailbox and hands back its one-time code or link,
so a login that mails you a code can be driven end to end.

The plugin only reads. The mailbox is opened read only (`EXAMINE`) and messages
are fetched with `BODY.PEEK`, so nothing is marked as read, moved or deleted. It
uses [`async-imap`](https://crates.io/crates/async-imap) for the protocol and
[`mail-parser`](https://crates.io/crates/mail-parser) for the messages; TLS is
`tokio-rustls` with the Mozilla root certificates.

## Turn it on

```sh
cargo add seleniumbase-rs-plugin-imap --git https://github.com/MustCodeAl/seleniumbase-rs-plugins
```

Or take it from the built-in registry: depend on
`seleniumbase-rs-plugins-builtin` with the feature `imap`, which builds the
plugin from its name and options (the variable named by `password_env` must be
set when the set is built; the error names it):

```rust
use seleniumbase_rs_plugins_builtin::{registry, PluginSpec};
use serde_json::json;

let set = registry().plugin_set(&[PluginSpec::new("imap").options(json!({
    "host": "imap.example.com",
    "user": "me@example.com",
    "password_env": "MAIL_APP_PASSWORD",
}))])?;
```

The set runs the task `wait_for_email` on the pure CDP engine. A WebDriver host
offers no tasks yet, so `PluginSet::check_with` refuses a set with this plugin
there for `task`; on that engine call `Imap::wait_for_email(&query, &clock)`
yourself (it needs a `Clock`, not a browser). seleniumbase-rs reads the same
options from `[plugins.imap]` in a config file, shown below.

## Options

| Option | Default | Meaning |
|---|---|---|
| `host` | required | The IMAP server, such as `imap.example.com`. The connection is IMAPS (TLS from the first byte). |
| `port` | `993` | The IMAPS port. |
| `user` | required | The login name. |
| `password_env` | required | The NAME of the environment variable that holds the password or app password. |
| `mailbox` | `"INBOX"` | The mailbox to watch. |
| `poll_secs` | `5` | Seconds between two looks at the mailbox (1 to 300). |
| `timeout_secs` | `120` | Seconds to wait for a matching email (1 to 3600). |

Unknown options are refused. The password is never an option: only the name of
the variable is configured. The variable must be set when the plugin is built
(the error names it), the value is read when the task starts, and it is kept out
of every error and every `Debug` output.

```toml
[plugins.imap]
host = "imap.example.com"
user = "me@example.com"
password_env = "MAIL_APP_PASSWORD"
```

## The task

`wait_for_email` takes this input, all of it optional:

| Field | Default | Meaning |
|---|---|---|
| `from` | any | Part of the sender, name or address, without regard to case. |
| `subject_contains` | any | Part of the subject, without regard to case. |
| `since_secs` | `600` | Only messages sent in the last this many seconds (1 to 2 592 000). |
| `extract` | `"both"` | `"code"`, `"link"` or `"both"`. |

It looks at the unread messages of the last `since_secs` every `poll_secs`,
newest first, until one matches every filter or `timeout_secs` have passed.
`extract: "code"` (or `"link"`) only accepts a message that has one; `"both"`
accepts a message that has at least one of them.

Input:

```json
{"from": "no-reply@example.com", "subject_contains": "verify", "extract": "code"}
```

Output, one line to the sink (`code` and `link` appear when asked for and found,
`text` is the start of the body, at most 16 KiB):

```json
{"from":"no-reply@example.com","subject":"Verify your email address","date":"2026-10-24T10:00:00+00:00","code":"482910","text":"Hello,\n\nYour verification code is 482910. ..."}
```

The task's summary is `{"matched": true, "code": true, "link": false}`. When
nothing arrives in time, the error says what was waited for.

### How the code and the link are found

- **Code**: the first run of 4 to 8 digits in the subject and then the text
  that stands closest to a word such as "code", "verification" or "PIN"; if no
  number is near such a word, the first one. Dates, times, prices, decimals,
  numbers inside a word and the digits of a link are not codes. `123 456` is read
  as `123456`.
- **Link**: the first `http(s)` link in the text part, else the first `href` (or
  link) in the HTML part. The sentence's closing punctuation is cut off.

## Limits

- A message is read as far as 256 KiB; at most the 25 newest unseen messages are
  fetched per look, and each is looked at once per wait.
- The search is `UNSEEN SINCE <day>`, so a message that something else already
  marked as read is not seen, and a message from the last minutes that is still
  unread is returned again by the next wait: use a small `since_secs` to skip the
  earlier ones.
- IMAPS with `LOGIN` only: no STARTTLS, no OAuth2, no IDLE (it polls).
- The plugin is in the `Testing` category and declares `task` and `HostNet` for
  any address (the plugin API has no per-host scope; the only host the plugin
  talks to is `host`). It keeps no state: each wait opens its own connection and
  logs out at the end. TLS and the certificate check cannot be turned off.

## Tests

```sh
cargo test -p seleniumbase-rs-plugin-imap
```

runs without a server: the matcher, the extraction (on the messages in
`tests/fixtures`), the options and the wait loop with a scripted source. One
test needs a real mailbox and is `#[ignore]`d:

```sh
SB_TEST_IMAP_HOST=imap.example.com SB_TEST_IMAP_USER=me@example.com \
SB_TEST_IMAP_PASSWORD_ENV=MAIL_APP_PASSWORD \
  cargo test -p seleniumbase-rs-plugin-imap --test plugin -- --ignored
```
