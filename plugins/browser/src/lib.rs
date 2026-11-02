//! Loads browser extensions into the Chromium browser seleniumbase-rs starts,
//! from `.zip` and `.crx` files and from unpacked folders.
//!
//! The two extension options are the ones Python SeleniumBase has, with the same
//! meaning: `extension_zip` is `--extension-zip` (`.zip` or `.crx` files) and
//! `extension_dir` is `--extension-dir` (unpacked folders). Archives are
//! unpacked, with the `crx` plugin's code, into a temporary folder that belongs
//! to one browser and is deleted when it closes; unpacked folders are loaded
//! where they are and are never touched. Every extension must be Manifest V3,
//! and a path that does not exist fails the launch before the browser starts,
//! with the path in the message.
//!
//! ```
//! use seleniumbase_rs_plugin::PluginSet;
//! use seleniumbase_rs_plugin_browser::{BrowserSession, SessionConfig};
//!
//! let config = SessionConfig::new()
//!     .with_zip("extensions/dark-reader.crx")
//!     .with_dir("my-extension");
//! let plugins = PluginSet::strict().with(BrowserSession::new(config)?)?;
//! assert_eq!(plugins.names(), ["browser"]);
//! # Ok::<(), seleniumbase_rs_plugin::PluginError>(())
//! ```
//!
//! In a config file:
//!
//! ```toml
//! [plugins.browser]
//! extension_zip = ["extensions/dark-reader.crx"]
//! extension_dir = ["my-extension"]
//! ```
//!
//! # What the plugin hands to the host
//!
//! The plugin adds the folders to [`LaunchSettings::extensions`]; it adds no
//! switch. The host joins them into Chrome's `--load-extension` list (or loads
//! them over the protocol, where branded Chrome ignores the switch), which is
//! why a folder path may not hold a comma. Python does not add
//! `--disable-extensions-except` either.
//!
//! # Headless
//!
//! Chrome's old headless mode cannot load extensions and its new one can;
//! Python loads the extensions the user names whatever the mode, and so does
//! this plugin. The one thing it refuses is an explicit `--headless=old`
//! switch, which could only lose the extensions without a word.
//!
//! # Waiting for workers, saved sessions, signing in
//!
//! Three more groups of options use the newer parts of the plugin API. A
//! combination that makes no sense is an error that names the option, before
//! any browser starts; an option the host cannot serve fails the launch and
//! names it too. Nothing is accepted and then ignored.
//!
//! - `wait_for_workers` (with `worker_timeout_secs`, 10 s unless told otherwise)
//!   makes `on_browser` wait until each extension of this plugin that has a
//!   `background.service_worker` has a running worker. It is off by default and
//!   needs a host that implements `BrowserHandle::extension_workers`.
//! - `session` names a saved session: the cookies of the default browser
//!   context, kept in `<session_dir>/<session>.json` (`saved_sessions` in the
//!   working directory unless `session_dir` says otherwise). They are put back
//!   at launch, and with `save_on_close` written just before the browser
//!   closes, through a file only its owner can read. localStorage is not kept.
//!   `save_on_close` needs a host that runs `before_close`, which only the pure
//!   CDP engine does (and only through `Browser::close`: a browser that is
//!   dropped runs `on_close` alone); on the WebDriver host `on_browser` fails
//!   naming the option, before anything is restored.
//! - `interactive` (with `pause_message`) offers the task
//!   `sbrs plugin run browser`: it opens a tab, waits for a person to sign in
//!   by hand in the headed browser, and saves the session.
//!
//! The cookie file holds credentials: no error, log line or `Debug` output
//! carries a value of it. Nothing here has run in a real Chrome.

mod config;
mod interactive;
mod session;

mod source;
mod workers;

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use seleniumbase_rs_plugin::{
    BrowserHandle, Budgets, Capability, Category, Configurable, Engine, LaunchSettings, Metadata,
    PathScope, Plugin, PluginError, Requirements, Result, Task, TaskContext, async_trait,
    config::options,
};
use serde_json::{Value, json};
use tempfile::TempDir;

pub use config::SessionConfig;

/// The name the plugin is enabled by.
const NAME: &str = "browser";

/// Loads extensions from `.zip` and `.crx` files and unpacked folders. See the
/// [crate documentation](crate).
#[derive(Debug)]
pub struct BrowserSession {
    config: SessionConfig,
    /// Where the saved session lives, when `session` is set.
    store: Option<session::Store>,
    /// The folders this browser's archives were unpacked into.
    unpacked: Mutex<Vec<TempDir>>,
    /// The extensions this browser loads that have a service worker.
    workers: Mutex<Vec<source::Worker>>,
}

impl BrowserSession {
    /// Builds the plugin from `config`.
    ///
    /// The paths are not looked at yet: a path that does not exist fails the
    /// launch, in [`Plugin::before_launch`].
    ///
    /// # Errors
    ///
    /// [`PluginError::Config`] for an empty entry, for a folder whose path holds
    /// a comma, and for options that make no sense together (`wait_for_workers`
    /// without an extension, `save_on_close` without `session`, a bad session
    /// name, a number out of range, ...); the message names the option. Also
    /// when `session_dir` is relative and the working directory is unknown.
    /// Nothing is read or written yet.
    pub fn new(config: SessionConfig) -> Result<Self> {
        config.check()?;
        let store = session::Store::from_config(&config)?;
        Ok(Self::build(config, store))
    }

    /// A plugin for options that were already checked.
    fn build(config: SessionConfig, store: Option<session::Store>) -> Self {
        Self {
            config,
            store,
            unpacked: Mutex::new(Vec::new()),
            workers: Mutex::new(Vec::new()),
        }
    }

    /// The options the plugin was built with.
    #[must_use]
    pub fn config(&self) -> &SessionConfig {
        &self.config
    }

    fn unpacked(&self) -> MutexGuard<'_, Vec<TempDir>> {
        self.unpacked.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn workers(&self) -> MutexGuard<'_, Vec<source::Worker>> {
        self.workers.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// What every instance declares, whatever its options.
fn declared() -> Metadata {
    Metadata::new(Category::Extension)
        .version(env!("CARGO_PKG_VERSION"))
        .summary("Loads extensions from .zip and .crx files and unpacked folders into the browser it starts")
        .capability(Capability::LaunchExtensions)
        .conflicts_with("crx")
}

/// The time limits of an instance that waits `seconds` for the workers: the
/// set's 10 s for `on_browser` would end a longer wait with a bare time-out,
/// so the hook gets the wait and some headroom.
fn wait_budgets(seconds: u64) -> Budgets {
    let mut budgets = Budgets::default();
    budgets.other = Some(Duration::from_secs(seconds) + workers::HOOK_HEADROOM);
    budgets
}

impl Configurable for BrowserSession {
    const NAME: &'static str = NAME;

    fn describe() -> Metadata {
        // What an instance may add, depending on its options: cookies for the
        // session, the clock for waiting, a task and a tab for signing in.
        declared()
            .capability(Capability::HostFsWrite(PathScope::Temp))
            .optional(Capability::CookiesRead)
            .optional(Capability::CookiesWrite)
            .optional(Capability::Clock)
            .optional(Capability::Task)
            .optional(Capability::PageNavigate)
    }

    /// Options: `extension_zip` and `extension_dir` (each a list of paths or a
    /// comma-separated text), and `wait_for_workers`, `worker_timeout_secs`,
    /// `session`, `save_on_close`, `session_dir`, `interactive` and
    /// `pause_message`; see [`SessionConfig`].
    /// The files are looked at at launch, not here.
    fn configure(value: &serde_json::Value) -> Result<Self> {
        Self::new(options::<SessionConfig>(NAME, value)?)
    }
}

/// The `interactive` task, started by `sbrs plugin run browser`: a person signs
/// in by hand, in the headed browser, and the cookies are kept as the session.
#[async_trait]
impl Task for BrowserSession {
    async fn run(&self, cx: &TaskContext<'_>) -> Result<Value> {
        let Some(store) = &self.store else {
            // `interactive` without `session` does not pass the check.
            return Err(PluginError::other("browser: `interactive` needs `session`"));
        };
        let url = interactive::start_url(cx.input)?;
        // A folder that cannot be written is found out now, not after a person
        // has signed in.
        store.check_writable()?;
        let browser = cx.plugins.guarded_browser(NAME, cx.browser)?;
        let page = browser.new_page(url).await?;
        cx.prompt
            .wait(self.config.pause_message_or_default(), &*page)
            .await
            .map_err(|error| {
                PluginError::other(format!(
                    "browser: `interactive` needs a person at the keyboard: {error}"
                ))
            })?;
        // The tab stays open: closing the last tab of a headed Chrome can end
        // the browser, and the host closes it right after the task.
        let cookies = session::save(&browser, store).await?;
        let summary = json!({ "session": store.name(), "cookies": cookies });
        cx.sink.record(&summary)?;
        Ok(summary)
    }
}

/// Whether `args` ask for Chrome's old headless mode.
fn asks_for_old_headless(args: &[String]) -> bool {
    args.iter()
        .any(|arg| arg.trim_start_matches('-') == "headless=old")
}

#[async_trait]
impl Plugin for BrowserSession {
    fn name(&self) -> &str {
        NAME
    }

    fn requirements(&self) -> Requirements {
        let needs = Requirements::CHROMIUM_ONLY | Requirements::LAUNCH_ONLY;
        // A person signs in, so there must be a window for them.
        if self.config.interactive {
            needs | Requirements::HEADFUL
        } else {
            needs
        }
    }

    /// The capabilities this instance needs: the declared ones, cookie access
    /// and the session file for a session, the clock (and a longer limit for
    /// `on_browser`) for the wait, the task for `interactive`, the temporary
    /// folder only when it has archives to unpack, and the paths it reads.
    fn metadata(&self) -> Metadata {
        let mut meta = declared();
        if !self.config.extension_zip.is_empty() {
            meta = meta.capability(Capability::HostFsWrite(PathScope::Temp));
        }
        // The paths it reads: the extensions, and the session file.
        let mut reads = self.config.sources();
        if let Some(store) = &self.store {
            reads.push(store.file().to_path_buf());
            meta = meta.capability(Capability::CookiesWrite);
            if self.config.saves() {
                meta =
                    meta.capability(Capability::CookiesRead)
                        .capability(Capability::HostFsWrite(PathScope::Declared(vec![
                            store.dir().to_path_buf(),
                        ])));
            }
        }
        if !reads.is_empty() {
            meta = meta.capability(Capability::HostFsRead(PathScope::Declared(reads)));
        }
        if self.config.wait_for_workers {
            meta = meta
                .capability(Capability::Clock)
                .budget(wait_budgets(self.config.worker_timeout_secs_or_default()));
        }
        if self.config.interactive {
            // The task opens a tab, at an address when the input has one.
            meta = meta
                .capability(Capability::Task)
                .optional(Capability::PageNavigate);
        }
        meta
    }

    /// The task that waits for a person to sign in, when `interactive` is on.
    fn task(&self) -> Option<&dyn Task> {
        self.config.interactive.then_some(self as &dyn Task)
    }

    /// A fresh instance for each browser, so closing one pooled browser does
    /// not delete the unpacked folders of the others.
    fn per_launch(&self) -> Option<Arc<dyn Plugin>> {
        Some(Arc::new(Self::build(
            self.config.clone(),
            self.store.clone(),
        )))
    }

    async fn before_launch(&self, launch: &mut LaunchSettings) -> Result<()> {
        if self.config.is_empty() {
            return Ok(());
        }
        if asks_for_old_headless(&launch.args) {
            return Err(PluginError::other(
                "browser: extensions cannot be loaded in Chrome's old headless mode (--headless=old); use the new headless mode, which supports them",
            ));
        }
        let prepared = source::prepare(&self.config, &std::env::temp_dir())?;
        launch.extensions.extend(prepared.folders);
        self.unpacked().extend(prepared.temps);
        self.workers().extend(prepared.workers);
        Ok(())
    }

    /// Waits for the extensions' service workers when `wait_for_workers` is
    /// on, then puts the saved session back (`session`) and, when it will be
    /// saved, checks that its folder can be written.
    ///
    /// Fails first, naming `save_on_close`, when it is on and the engine does
    /// not run `before_close` (the WebDriver host does not): the session would
    /// be restored and never saved.
    async fn on_browser(&self, browser: &dyn BrowserHandle) -> Result<()> {
        // Only the pure CDP engine runs `before_close`. Elsewhere the session
        // would be restored and then never saved, so refuse before anything
        // is read or written.
        if self.config.save_on_close && browser.engine() != Engine::Cdp {
            return Err(PluginError::other(
                "browser: `save_on_close`: needs a host that runs `before_close` when the browser closes; the WebDriver host does not yet, so the cookies would never be saved. Use the pure CDP engine, or turn `save_on_close` off",
            ));
        }

        if self.config.wait_for_workers {
            let workers = self.workers().clone();
            workers::wait(
                browser,
                &workers,
                self.config.worker_timeout_secs_or_default(),
            )
            .await?;
        }
        if let Some(store) = &self.store {
            session::restore(browser, store).await?;
            if self.config.saves() {
                store.check_writable()?;
            }
        }
        Ok(())
    }

    /// Saves the session when `save_on_close` is on. The browser still
    /// answers commands here.
    async fn before_close(&self, browser: &dyn BrowserHandle) -> Result<()> {
        if self.config.save_on_close
            && let Some(store) = &self.store
        {
            session::save(browser, store).await?;
        }
        Ok(())
    }

    async fn on_close(&self) -> Result<()> {
        // Dropping the folders deletes them. Folders the user named are not
        // in this list.
        self.unpacked().clear();
        Ok(())
    }
}
