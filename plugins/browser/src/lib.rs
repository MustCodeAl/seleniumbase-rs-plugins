//! Loads browser extensions into the Chromium browser seleniumbase-rs starts,
//! from `.zip` and `.crx` files and from unpacked folders.
//!
//! The two options are the ones Python SeleniumBase has, with the same
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
//! # Not built yet
//!
//! The design also has `wait_for_workers`, `session`, `interactive` and
//! friends. They need hooks the plugin API does not offer yet (a clock in
//! `on_browser`, a folder for saved sessions), so they are refused as unknown
//! options instead of being accepted and ignored.

mod config;
mod source;

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use seleniumbase_rs_plugin::{
    Capability, Category, Configurable, LaunchSettings, Metadata, PathScope, Plugin, PluginError,
    Requirements, Result, async_trait, config::options,
};
use tempfile::TempDir;

pub use config::SessionConfig;

/// The name the plugin is enabled by.
const NAME: &str = "browser";

/// Loads extensions from `.zip` and `.crx` files and unpacked folders. See the
/// [crate documentation](crate).
#[derive(Debug)]
pub struct BrowserSession {
    config: SessionConfig,
    /// The folders this browser's archives were unpacked into.
    unpacked: Mutex<Vec<TempDir>>,
}

impl BrowserSession {
    /// Builds the plugin from `config`.
    ///
    /// The paths are not looked at yet: a path that does not exist fails the
    /// launch, in [`Plugin::before_launch`].
    ///
    /// # Errors
    ///
    /// [`PluginError::Config`] for an empty entry, or for a folder whose path
    /// holds a comma.
    pub fn new(config: SessionConfig) -> Result<Self> {
        config.check()?;
        Ok(Self::checked(config))
    }

    /// A plugin for options that were already checked.
    fn checked(config: SessionConfig) -> Self {
        Self {
            config,
            unpacked: Mutex::new(Vec::new()),
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
}

/// What every instance declares, whatever its options.
fn declared() -> Metadata {
    Metadata::new(Category::Extension)
        .version(env!("CARGO_PKG_VERSION"))
        .summary("Loads extensions from .zip and .crx files and unpacked folders into the browser it starts")
        .capability(Capability::LaunchExtensions)
        .conflicts_with("crx")
}

impl Configurable for BrowserSession {
    const NAME: &'static str = NAME;

    fn describe() -> Metadata {
        declared().capability(Capability::HostFsWrite(PathScope::Temp))
    }

    /// Options: `extension_zip` and `extension_dir`, each a list of paths or a
    /// comma-separated text.
    fn configure(value: &serde_json::Value) -> Result<Self> {
        Self::new(options::<SessionConfig>(NAME, value)?)
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
        Requirements::CHROMIUM_ONLY | Requirements::LAUNCH_ONLY
    }

    /// The capabilities this instance needs: the declared ones, the temporary
    /// folder only when it has archives to unpack, and the paths it reads.
    fn metadata(&self) -> Metadata {
        let mut meta = declared();
        if !self.config.extension_zip.is_empty() {
            meta = meta.capability(Capability::HostFsWrite(PathScope::Temp));
        }
        let sources = self.config.sources();
        if !sources.is_empty() {
            meta = meta.capability(Capability::HostFsRead(PathScope::Declared(sources)));
        }
        meta
    }

    /// A fresh instance for each browser, so closing one pooled browser does
    /// not delete the unpacked folders of the others.
    fn per_launch(&self) -> Option<Arc<dyn Plugin>> {
        Some(Arc::new(Self::checked(self.config.clone())))
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
        Ok(())
    }

    async fn on_close(&self) -> Result<()> {
        // Dropping the folders deletes them. Folders the user named are not
        // in this list.
        self.unpacked().clear();
        Ok(())
    }
}
