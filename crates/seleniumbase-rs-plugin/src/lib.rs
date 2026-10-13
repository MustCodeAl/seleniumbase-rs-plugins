//! The plugin API of [seleniumbase-rs](https://github.com/MustCodeAl/seleniumbase-rs).
//!
//! A plugin is a type that implements [`Plugin`]. Its hooks run at fixed points:
//! before a browser starts ([`Plugin::before_launch`]), once it runs
//! ([`Plugin::on_browser`]), for every new tab ([`Plugin::on_page_created`]) and
//! before it closes ([`Plugin::on_close`]). Every hook is optional. A
//! [`PluginSet`] holds the plugins a program uses, checks their dependencies and
//! requirements, and calls them in order; seleniumbase-rs calls the set.
//!
//! A plugin depends only on this crate, never on seleniumbase-rs: the browser
//! and the tab reach it as [`BrowserHandle`] and [`PageHandle`], which both of
//! seleniumbase-rs's engines implement. `seleniumbase-rs-plugin-testing` has
//! recording fakes of them, so a plugin is tested without a browser.
//!
//! # Example
//!
//! ```
//! use seleniumbase_rs_plugin::{async_trait, PageHandle, Plugin, PluginSet, Result};
//!
//! struct Hello;
//!
//! #[async_trait]
//! impl Plugin for Hello {
//!     fn name(&self) -> &str {
//!         "hello"
//!     }
//!
//!     async fn on_page_created(&self, page: &dyn PageHandle) -> Result<()> {
//!         page.add_init_script("console.log('hello from a plugin')").await
//!     }
//! }
//!
//! let set = PluginSet::new().with(Hello)?;
//! assert_eq!(set.names(), ["hello"]);
//! # Ok::<(), seleniumbase_rs_plugin::PluginError>(())
//! ```

use std::collections::HashSet;
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;

pub use async_trait::async_trait;
use serde_json::Value;

/// The result of a hook.
pub type Result<T> = std::result::Result<T, PluginError>;

/// Why a plugin, or the set, refused to go on.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PluginError {
    /// Two plugins in a set have the same name.
    #[error("a plugin named `{0}` is already in the set")]
    DuplicateName(String),
    /// A plugin needs another one that is not in the set.
    #[error(
        "plugin `{plugin}` needs plugin `{missing}`: add the crate that provides it to the set"
    )]
    MissingDependency {
        /// The plugin that has the dependency.
        plugin: String,
        /// The name of the plugin it needs.
        missing: String,
    },
    /// A plugin cannot run with this browser or launch.
    #[error("plugin `{plugin}` cannot run here: {reason}")]
    Requirement {
        /// The plugin that refused.
        plugin: String,
        /// What it needs that is missing.
        reason: String,
    },
    /// A hook failed.
    #[error("plugin `{plugin}` failed in `{hook}`: {message}")]
    Hook {
        /// The plugin whose hook failed.
        plugin: String,
        /// The hook, such as `on_page_created`.
        hook: &'static str,
        /// What went wrong.
        message: String,
    },
    /// Any other failure, with a message for the user.
    #[error("{0}")]
    Other(String),
}

impl PluginError {
    /// A failure described by `message`, for a plugin to return from a hook.
    pub fn other(message: impl Into<String>) -> Self {
        Self::Other(message.into())
    }
}

/// Which of seleniumbase-rs's engines runs the browser.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Engine {
    /// The pure Chrome DevTools Protocol engine (`sb_cdp`).
    Cdp,
    /// The WebDriver engine (`BaseCase`).
    WebDriver,
}

/// The family of the browser a plugin runs with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum BrowserFamily {
    /// Chrome, Chromium, Edge, Brave, Opera.
    Chromium,
    /// Firefox.
    Firefox,
    /// Safari.
    Safari,
}

/// What the set checks a plugin against before a browser starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LaunchContext {
    /// The engine that will run the browser.
    pub engine: Engine,
    /// The browser's family.
    pub family: BrowserFamily,
    /// Whether the browser runs without a window.
    pub headless: bool,
    /// Whether the program attaches to a running browser instead of starting one.
    pub connecting: bool,
}

/// The start-up settings a plugin may change in [`Plugin::before_launch`].
///
/// seleniumbase-rs turns them into the engine's own options after every
/// plugin has run.
#[derive(Clone, Debug, Default, PartialEq)]
#[non_exhaustive]
pub struct LaunchSettings {
    /// Command-line switches for the browser, such as `--lang=de`.
    pub args: Vec<String>,
    /// Browser preferences, as in Chrome's `Preferences` file.
    pub prefs: serde_json::Map<String, Value>,
    /// Unpacked extension folders to load.
    pub extensions: Vec<PathBuf>,
    /// The proxy server, such as `http://127.0.0.1:8080`.
    pub proxy: Option<String>,
    /// Whether the browser runs without a window.
    pub headless: bool,
}

/// Conditions a plugin needs, combined with `|`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Requirements(u8);

impl Requirements {
    /// Run after the plugins without this flag.
    pub const RUN_LAST: Self = Self(1);
    /// Refuse a headless browser.
    pub const HEADFUL: Self = Self(1 << 1);
    /// Refuse a browser the program attaches to instead of starting.
    pub const LAUNCH_ONLY: Self = Self(1 << 2);
    /// Refuse browsers that are not Chromium-based.
    pub const CHROMIUM_ONLY: Self = Self(1 << 3);

    /// No requirements.
    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Whether every flag of `other` is set.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl std::ops::BitOr for Requirements {
    type Output = Self;

    fn bitor(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Kind {
    ScriptUrl(String),
    StyleUrl(String),
    Script(String),
    Style(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Hosts {
    Unset,
    Only(Vec<String>),
    Everywhere,
}

/// JavaScript or CSS that a plugin loads into pages.
///
/// A package must say where it loads, with [`only_on`](Self::only_on) or
/// [`everywhere`](Self::everywhere): the set refuses one that does not, so a
/// plugin never loads a script into every site by accident. Pin the version in a
/// URL and add [`integrity`](Self::integrity) so the browser checks the file.
///
/// ```
/// use seleniumbase_rs_plugin::Package;
///
/// let intro = Package::script_url("https://cdn.jsdelivr.net/npm/intro.js@7.2.0/intro.min.js")
///     .only_on(["example.com"]);
/// assert!(intro.init_script().unwrap().contains("intro.min.js"));
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Package {
    kind: Kind,
    integrity: Option<String>,
    hosts: Hosts,
}

impl Package {
    fn new(kind: Kind) -> Self {
        Self {
            kind,
            integrity: None,
            hosts: Hosts::Unset,
        }
    }

    /// A script loaded from `url`.
    pub fn script_url(url: impl Into<String>) -> Self {
        Self::new(Kind::ScriptUrl(url.into()))
    }

    /// A stylesheet loaded from `url`.
    pub fn style_url(url: impl Into<String>) -> Self {
        Self::new(Kind::StyleUrl(url.into()))
    }

    /// JavaScript run in every matching document before the page's own scripts.
    pub fn script(code: impl Into<String>) -> Self {
        Self::new(Kind::Script(code.into()))
    }

    /// CSS added to every matching document.
    pub fn style(css: impl Into<String>) -> Self {
        Self::new(Kind::Style(css.into()))
    }

    /// The Subresource Integrity hash of the file at the URL, such as
    /// `sha384-...`; the browser refuses a file that does not match.
    #[must_use]
    pub fn integrity(mut self, hash: impl Into<String>) -> Self {
        self.integrity = Some(hash.into());
        self
    }

    /// Loads only on these hosts and their subdomains.
    #[must_use]
    pub fn only_on<I, S>(mut self, hosts: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.hosts = Hosts::Only(hosts.into_iter().map(Into::into).collect());
        self
    }

    /// Loads on every site.
    #[must_use]
    pub fn everywhere(mut self) -> Self {
        self.hosts = Hosts::Everywhere;
        self
    }

    /// The script that loads the package into a document, for
    /// [`PageHandle::add_init_script`]; `None` when it does not say where it
    /// loads.
    #[must_use]
    pub fn init_script(&self) -> Option<String> {
        let hosts = match &self.hosts {
            Hosts::Unset => return None,
            Hosts::Only(hosts) => js(hosts.clone()),
            Hosts::Everywhere => "null".to_owned(),
        };
        let integrity = self
            .integrity
            .as_ref()
            .map(|hash| format!("el.integrity = {}; ", js(hash.as_str())))
            .unwrap_or_default();
        let add = match &self.kind {
            Kind::ScriptUrl(url) => format!(
                "const el = document.createElement('script'); el.src = {}; el.crossOrigin = 'anonymous'; {integrity}(document.head || document.documentElement).appendChild(el);",
                js(url.as_str())
            ),
            Kind::StyleUrl(url) => format!(
                "const el = document.createElement('link'); el.rel = 'stylesheet'; el.href = {}; el.crossOrigin = 'anonymous'; {integrity}(document.head || document.documentElement).appendChild(el);",
                js(url.as_str())
            ),
            Kind::Style(css) => format!(
                "const el = document.createElement('style'); el.textContent = {}; (document.head || document.documentElement).appendChild(el);",
                js(css.as_str())
            ),
            // Inline code runs as soon as the document starts, like any init script.
            Kind::Script(code) => {
                return Some(format!(
                    "(() => {{ const hosts = {hosts}; if (hosts && !hosts.some((h) => location.hostname === h || location.hostname.endsWith('.' + h))) return; {code}\n}})();"
                ));
            }
        };
        Some(format!(
            "(() => {{ const hosts = {hosts}; if (hosts && !hosts.some((h) => location.hostname === h || location.hostname.endsWith('.' + h))) return; const add = () => {{ {add} }}; if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', add, {{ once: true }}); else add(); }})();"
        ))
    }
}

/// A JSON (and so JavaScript) literal of `value`.
fn js(value: impl Into<Value>) -> String {
    value.into().to_string()
}

/// The running browser, as a plugin sees it.
#[async_trait]
pub trait BrowserHandle: Send + Sync {
    /// The engine that runs the browser.
    fn engine(&self) -> Engine;

    /// The browser's family.
    fn family(&self) -> BrowserFamily;

    /// Sends a browser-level Chrome DevTools Protocol command and returns its
    /// result. Browsers without the protocol return an error.
    async fn send(&self, method: &str, params: Value) -> Result<Value>;
}

/// A tab, as a plugin sees it.
#[async_trait]
pub trait PageHandle: Send + Sync {
    /// The engine that runs the tab.
    fn engine(&self) -> Engine;

    /// Sends a Chrome DevTools Protocol command to this tab and returns its
    /// result. Browsers without the protocol return an error.
    async fn send(&self, method: &str, params: Value) -> Result<Value>;

    /// Runs `source` in every document this tab loads from now on, before the
    /// page's own scripts.
    async fn add_init_script(&self, source: &str) -> Result<()>;

    /// Evaluates `expression` in the current document and returns its value.
    async fn evaluate(&self, expression: &str) -> Result<Value>;
}

/// A plugin. Every hook is optional and does nothing by default.
#[async_trait]
pub trait Plugin: Send + Sync + 'static {
    /// The plugin's unique, lower-case name, such as `block-resources`.
    fn name(&self) -> &str;

    /// The names of the plugins this one needs in the same set.
    fn dependencies(&self) -> &[&str] {
        &[]
    }

    /// Conditions this plugin needs.
    fn requirements(&self) -> Requirements {
        Requirements::empty()
    }

    /// JavaScript and CSS to load into every new tab.
    fn packages(&self) -> Vec<Package> {
        Vec::new()
    }

    /// Changes the start-up settings before the browser starts.
    async fn before_launch(&self, _launch: &mut LaunchSettings) -> Result<()> {
        Ok(())
    }

    /// The browser runs: started, or attached to.
    async fn on_browser(&self, _browser: &dyn BrowserHandle) -> Result<()> {
        Ok(())
    }

    /// A tab was attached, before any command of the program runs in it. The
    /// plugin's [`packages`](Self::packages) are already added.
    async fn on_page_created(&self, _page: &dyn PageHandle) -> Result<()> {
        Ok(())
    }

    /// The browser is about to close.
    async fn on_close(&self) -> Result<()> {
        Ok(())
    }
}

/// The plugins a program uses, in the order their hooks run.
///
/// Plugins run in the order they were added, except that those with
/// [`Requirements::RUN_LAST`] run after the rest. An error from
/// [`before_launch`](Self::before_launch), [`on_browser`](Self::on_browser) or
/// [`on_page_created`](Self::on_page_created) stops there and is returned: a
/// plugin that did not run must not leave a browser without what it adds.
#[derive(Clone, Default)]
pub struct PluginSet {
    plugins: Vec<Arc<dyn Plugin>>,
}

impl fmt::Debug for PluginSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PluginSet")
            .field("plugins", &self.names())
            .finish()
    }
}

impl PluginSet {
    /// An empty set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a plugin.
    ///
    /// # Errors
    ///
    /// [`PluginError::DuplicateName`] if a plugin with the same name is in the set.
    pub fn with(self, plugin: impl Plugin) -> Result<Self> {
        self.with_shared(Arc::new(plugin))
    }

    /// Adds a plugin that is shared with other sets.
    ///
    /// # Errors
    ///
    /// [`PluginError::DuplicateName`] if a plugin with the same name is in the set.
    pub fn with_shared(mut self, plugin: Arc<dyn Plugin>) -> Result<Self> {
        if self
            .plugins
            .iter()
            .any(|known| known.name() == plugin.name())
        {
            return Err(PluginError::DuplicateName(plugin.name().to_owned()));
        }
        self.plugins.push(plugin);
        Ok(self)
    }

    /// Whether the set has no plugins.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }

    /// The plugins' names, in the order their hooks run.
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        self.ordered().map(|plugin| plugin.name()).collect()
    }

    fn ordered(&self) -> impl Iterator<Item = &Arc<dyn Plugin>> {
        let last =
            |plugin: &&Arc<dyn Plugin>| plugin.requirements().contains(Requirements::RUN_LAST);
        self.plugins
            .iter()
            .filter(move |plugin| !last(plugin))
            .chain(self.plugins.iter().filter(last))
    }

    /// Checks every plugin's dependencies, requirements and packages against
    /// the browser about to start. seleniumbase-rs calls it before
    /// [`before_launch`](Self::before_launch).
    ///
    /// # Errors
    ///
    /// The first [`PluginError::MissingDependency`] or
    /// [`PluginError::Requirement`] found.
    pub fn check(&self, context: &LaunchContext) -> Result<()> {
        let names: HashSet<&str> = self.plugins.iter().map(|plugin| plugin.name()).collect();
        for plugin in self.ordered() {
            if let Some(missing) = plugin
                .dependencies()
                .iter()
                .find(|name| !names.contains(*name))
            {
                return Err(PluginError::MissingDependency {
                    plugin: plugin.name().to_owned(),
                    missing: (*missing).to_owned(),
                });
            }
            let needs = plugin.requirements();
            let refusal = if needs.contains(Requirements::HEADFUL) && context.headless {
                Some("it needs a browser with a window, not a headless one")
            } else if needs.contains(Requirements::LAUNCH_ONLY) && context.connecting {
                Some("it only works with a browser the program starts, not one it attaches to")
            } else if needs.contains(Requirements::CHROMIUM_ONLY)
                && context.family != BrowserFamily::Chromium
            {
                Some("it needs a Chromium-based browser")
            } else if plugin
                .packages()
                .iter()
                .any(|package| package.init_script().is_none())
            {
                Some("one of its packages says neither `only_on` nor `everywhere`")
            } else {
                None
            };
            if let Some(reason) = refusal {
                return Err(PluginError::Requirement {
                    plugin: plugin.name().to_owned(),
                    reason: reason.to_owned(),
                });
            }
        }
        Ok(())
    }

    /// Lets every plugin change the start-up settings, in order.
    ///
    /// # Errors
    ///
    /// The first hook error, as [`PluginError::Hook`].
    pub async fn before_launch(&self, launch: &mut LaunchSettings) -> Result<()> {
        for plugin in self.ordered() {
            plugin
                .before_launch(launch)
                .await
                .map_err(|error| in_hook(plugin.as_ref(), "before_launch", error))?;
        }
        Ok(())
    }

    /// Tells every plugin the browser runs.
    ///
    /// # Errors
    ///
    /// The first hook error, as [`PluginError::Hook`].
    pub async fn on_browser(&self, browser: &dyn BrowserHandle) -> Result<()> {
        for plugin in self.ordered() {
            plugin
                .on_browser(browser)
                .await
                .map_err(|error| in_hook(plugin.as_ref(), "on_browser", error))?;
        }
        Ok(())
    }

    /// Adds every plugin's packages to a new tab and calls its
    /// [`Plugin::on_page_created`], plugin by plugin.
    ///
    /// # Errors
    ///
    /// The first error, as [`PluginError::Hook`].
    pub async fn on_page_created(&self, page: &dyn PageHandle) -> Result<()> {
        for plugin in self.ordered() {
            for script in plugin.packages().iter().filter_map(Package::init_script) {
                page.add_init_script(&script)
                    .await
                    .map_err(|error| in_hook(plugin.as_ref(), "packages", error))?;
            }
            plugin
                .on_page_created(page)
                .await
                .map_err(|error| in_hook(plugin.as_ref(), "on_page_created", error))?;
        }
        Ok(())
    }

    /// Tells every plugin the browser is about to close. Every plugin runs even
    /// when one fails; the failures are returned for the caller to log.
    pub async fn on_close(&self) -> Vec<PluginError> {
        let mut failures = Vec::new();
        for plugin in self.ordered() {
            if let Err(error) = plugin.on_close().await {
                failures.push(in_hook(plugin.as_ref(), "on_close", error));
            }
        }
        failures
    }
}

/// `error` as a [`PluginError::Hook`] of `plugin`, unless it already is one.
fn in_hook(plugin: &dyn Plugin, hook: &'static str, error: PluginError) -> PluginError {
    match error {
        PluginError::Hook { .. } => error,
        other => PluginError::Hook {
            plugin: plugin.name().to_owned(),
            hook,
            message: other.to_string(),
        },
    }
}
