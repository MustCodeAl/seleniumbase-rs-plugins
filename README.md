# seleniumbase-rs plugins

Plugins for [seleniumbase-rs](https://github.com/MustCodeAl/seleniumbase-rs): Rust
crates that change how a browser starts and what every tab gets, the way
puppeteer-extra plugins do for Puppeteer. The design is
[ADR 004](https://github.com/MustCodeAl/seleniumbase-rs/blob/main/docs/adr/004-plugin-framework.md).

> [!NOTE]
> Early. The API crate, the test fakes and the first plugin are here; the hook
> points inside seleniumbase-rs come next, so plugins cannot be attached to a
> browser yet.

## Plugins you can install

Every plugin is its own crate. Add the ones you want to your project; they are
also examples of how to write one.

| Plugin | What it does | Install |
|---|---|---|
| [`block-resources`](plugins/block-resources) | Stops pages from loading images, fonts or media (faster, less data) | `cargo add seleniumbase-rs-plugin-block-resources --git https://github.com/MustCodeAl/seleniumbase-rs-plugins` |
| [`crx`](plugins/crx) | Loads packed Chrome extensions (`.crx`, CRX3 and CRX2) | `cargo add seleniumbase-rs-plugin-crx --git https://github.com/MustCodeAl/seleniumbase-rs-plugins` |

The framework itself:

| Crate | What it is | Install |
|---|---|---|
| [`seleniumbase-rs-plugin`](crates/seleniumbase-rs-plugin) | The API: `Plugin`, `PluginSet`, `LaunchSettings`, `Package`, the `BrowserHandle` and `PageHandle` traits | `cargo add seleniumbase-rs-plugin --git https://github.com/MustCodeAl/seleniumbase-rs-plugins` |
| [`seleniumbase-rs-plugin-testing`](crates/seleniumbase-rs-plugin-testing) | Recording fakes of the handles, to test a plugin without a browser | `cargo add --dev seleniumbase-rs-plugin-testing --git https://github.com/MustCodeAl/seleniumbase-rs-plugins` |
| [`template`](template) | Start your own plugin from here | copy the folder |

More plugins live in their own repositories, such as
[tauri-plugin-sbrs-automation](https://github.com/MustCodeAl/tauri-plugin-sbrs-automation).
Search GitHub for the topic `seleniumbase-rs-plugin` to find community ones.

## A plugin

```rust
use seleniumbase_rs_plugin::{async_trait, PageHandle, Plugin, Result};

pub struct Hello;

#[async_trait]
impl Plugin for Hello {
    fn name(&self) -> &str {
        "hello"
    }

    async fn on_page_created(&self, page: &dyn PageHandle) -> Result<()> {
        page.add_init_script("console.log('hello from a plugin')").await
    }
}
```

Every hook is optional: `before_launch` (change the browser's start-up
settings), `on_browser`, `on_page_created`, `on_close`. A plugin can also
declare JavaScript and CSS `packages` for every tab, its `dependencies` on other
plugins, and `requirements` (run last, a visible window, a Chromium browser, a
browser it starts itself). Errors in the launch and page hooks stop the launch or
the tab instead of being skipped.

## Write your own

1. Copy [`template/`](template) and rename the crate to
   `seleniumbase-rs-plugin-<name>`.
2. Test it with `seleniumbase-rs-plugin-testing`: `RecordingPage` and
   `RecordingBrowser` record every command and script your hooks send.
3. Publish it on GitHub with the topic `seleniumbase-rs-plugin` so people find it.

A plugin depends only on `seleniumbase-rs-plugin`, never on seleniumbase-rs, so
it keeps working as seleniumbase-rs changes.

> [!WARNING]
> A plugin is code that runs with your program's rights and sees every page,
> cookie and password the browser handles. Review a plugin before you add it,
> as you would any dependency.

## License

MIT.
