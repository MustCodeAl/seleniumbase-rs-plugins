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

mod capability;
mod config;
mod host;
mod metadata;
mod order;
pub mod switch_policy;

use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;

pub use async_trait::async_trait;
use serde_json::Value;

pub use capability::{
    Capability, CapabilitySet, Enforcement, HostScope, NetScope, ParseCapabilityError, PathScope,
    RawKind, Risk,
};
pub use config::{Configurable, Descriptor, PluginSpec, Registry};
pub use host::{HostInfo, HostKind};
pub use metadata::{Budgets, Category, Metadata, Phase, Seals};

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
    /// The plugins' ordering edges contain a cycle.
    #[error("these plugins wait for each other: {}", .0.join(", "))]
    Cycle(Vec<String>),
    /// Two plugins that cannot be combined are in the set.
    #[error("plugin `{a}` cannot be combined with plugin `{b}`")]
    Conflict {
        /// The plugin that declares the conflict.
        a: String,
        /// The plugin it conflicts with.
        b: String,
    },
    /// A sealed launch field was changed to a different value.
    #[error("plugin `{b}` cannot change `{field}`, which plugin `{a}` sealed")]
    Sealed {
        /// The sealed field.
        field: &'static str,
        /// The plugin that sealed it.
        a: String,
        /// The plugin that tried to change it.
        b: String,
    },
    /// The host cannot provide a capability the plugin needs.
    #[error("plugin `{plugin}` needs `{capability}`, which {host} does not support")]
    Unsupported {
        /// The plugin.
        plugin: String,
        /// The capability.
        capability: String,
        /// The host.
        host: &'static str,
    },
    /// A capability was used without being granted, or a rule about launch
    /// settings was broken.
    #[error("plugin `{plugin}` is not allowed to use `{capability}`: {reason}")]
    Capability {
        /// The plugin.
        plugin: String,
        /// The capability, or the setting.
        capability: String,
        /// Why it was refused.
        reason: String,
    },
    /// A strict set refuses a plugin that declares no metadata.
    #[error("plugin `{0}` declares no metadata, which a strict set requires")]
    Undeclared(String),
    /// Wrong plugin name or options.
    #[error("plugin configuration: {0}")]
    Config(String),
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
    /// A webview embedded in an app, such as Tauri's.
    Embedded,
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
    /// Host-resolver rules; the host joins them into one switch.
    pub host_resolver_rules: Vec<String>,
    /// The WebRTC IP-handling policy.
    pub webrtc_policy: Option<WebRtcPolicy>,
    /// Features to disable; the host merges them into one switch.
    pub disable_features: Vec<String>,
    /// Features to enable; the host merges them into one switch.
    pub enable_features: Vec<String>,
    /// Whether to turn QUIC off.
    pub disable_quic: bool,
    profile: ProfileView,
}

impl LaunchSettings {
    /// The browser profile, read-only for plugins.
    #[must_use]
    pub fn profile(&self) -> &ProfileView {
        &self.profile
    }

    /// Sets the profile. For the host, before plugins run.
    pub fn set_profile(&mut self, profile: ProfileView) {
        self.profile = profile;
    }
}

/// The browser profile a launch uses.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProfileView {
    /// A fresh profile thrown away at close.
    #[default]
    Ephemeral,
    /// A profile kept in this folder.
    Persistent(PathBuf),
}

/// Chrome's WebRTC IP-handling policies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum WebRtcPolicy {
    /// Chrome's default.
    Default,
    /// Use only the default public interface.
    DefaultPublicInterfaceOnly,
    /// Use the public and private default interfaces.
    DefaultPublicAndPrivateInterfaces,
    /// Send UDP only through the proxy.
    DisableNonProxiedUdp,
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

    /// What the plugin declares about itself. The default is the legacy
    /// metadata: no category and the legacy capabilities.
    fn metadata(&self) -> Metadata {
        Metadata::legacy()
    }

    /// A fresh instance for one browser, for pools; `None` shares this one.
    /// It must have the same name.
    fn per_launch(&self) -> Option<Arc<dyn Plugin>> {
        None
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

/// One plugin in a set, with the capabilities it was granted.
#[derive(Clone)]
struct Entry {
    plugin: Arc<dyn Plugin>,
    grants: CapabilitySet,
}

/// One row of [`PluginSet::audit`].
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct AuditRow {
    /// The plugin's name.
    pub plugin: String,
    /// Its category, `None` for a legacy plugin.
    pub category: Option<Category>,
    /// The capability.
    pub capability: Capability,
    /// How dangerous it is.
    pub risk: Risk,
    /// Whether it was granted.
    pub granted: bool,
    /// Whether the host enforces it for a native plugin.
    pub enforcement: Enforcement,
}

/// The grants a plugin gets from `with`: what it declares, except Critical
/// capabilities. A plugin that declares nothing gets the legacy set.
fn default_grants(meta: &Metadata) -> CapabilitySet {
    if meta.is_declared() {
        meta.capabilities.union(&meta.optional).without_critical()
    } else {
        CapabilitySet::legacy()
    }
}

/// The plugins a program uses, in the order their hooks run.
///
/// The order comes from each plugin's [`Phase`] (from its metadata, or its
/// category's default, or `Last` for [`Requirements::RUN_LAST`]), from
/// `requires`, `after` and `before` edges, and then from insertion order, so a
/// set of plugins without metadata runs in the order they were added, with the
/// `RUN_LAST` ones at the end. An error from
/// [`before_launch`](Self::before_launch), [`on_browser`](Self::on_browser) or
/// [`on_page_created`](Self::on_page_created) stops there and is returned: a
/// plugin that did not run must not leave a browser without what it adds.
#[derive(Clone, Default)]
pub struct PluginSet {
    entries: Vec<Entry>,
    strict: bool,
}

impl fmt::Debug for PluginSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PluginSet")
            .field("plugins", &self.names())
            .field("strict", &self.strict)
            .finish()
    }
}

impl PluginSet {
    /// An empty set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// An empty strict set, which refuses plugins that declare no metadata.
    /// The command line and the MCP server use strict sets.
    #[must_use]
    pub fn strict() -> Self {
        Self {
            entries: Vec::new(),
            strict: true,
        }
    }

    /// Adds a plugin and grants it what it declares, except Critical
    /// capabilities.
    ///
    /// # Errors
    ///
    /// [`PluginError::DuplicateName`] if a plugin with the same name is in the set.
    pub fn with(self, plugin: impl Plugin) -> Result<Self> {
        self.with_shared(Arc::new(plugin))
    }

    /// Adds a plugin that is shared with other sets, with default grants.
    ///
    /// # Errors
    ///
    /// [`PluginError::DuplicateName`] if a plugin with the same name is in the set.
    pub fn with_shared(self, plugin: Arc<dyn Plugin>) -> Result<Self> {
        let grants = default_grants(&plugin.metadata());
        self.with_grants_shared(plugin, grants)
    }

    /// Adds a plugin and, besides the default grants, the named capabilities,
    /// which may be Critical.
    ///
    /// # Errors
    ///
    /// [`PluginError::DuplicateName`] if a plugin with the same name is in the set.
    pub fn with_trusted(self, plugin: impl Plugin, trusted: &[Capability]) -> Result<Self> {
        let mut grants = default_grants(&plugin.metadata());
        for capability in trusted {
            grants.insert(capability.clone());
        }
        self.with_grants_shared(Arc::new(plugin), grants)
    }

    /// Adds a plugin with exactly these grants, as the command line does from
    /// the lockfile.
    ///
    /// # Errors
    ///
    /// [`PluginError::DuplicateName`] if a plugin with the same name is in the set.
    pub fn with_grants(self, plugin: impl Plugin, grants: CapabilitySet) -> Result<Self> {
        self.with_grants_shared(Arc::new(plugin), grants)
    }

    /// [`with_grants`](Self::with_grants) for a shared plugin.
    ///
    /// # Errors
    ///
    /// [`PluginError::DuplicateName`] if a plugin with the same name is in the set.
    pub fn with_grants_shared(
        mut self,
        plugin: Arc<dyn Plugin>,
        grants: CapabilitySet,
    ) -> Result<Self> {
        if self
            .entries
            .iter()
            .any(|known| known.plugin.name() == plugin.name())
        {
            return Err(PluginError::DuplicateName(plugin.name().to_owned()));
        }
        self.entries.push(Entry { plugin, grants });
        Ok(self)
    }

    /// Whether the set has no plugins.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The set for one browser: each plugin that offers
    /// [`Plugin::per_launch`] is replaced by its fresh instance, so pooled
    /// browsers do not share state. Grants are kept.
    #[must_use]
    pub fn for_launch(&self) -> Self {
        Self {
            strict: self.strict,
            entries: self
                .entries
                .iter()
                .map(|entry| Entry {
                    plugin: entry
                        .plugin
                        .per_launch()
                        .filter(|fresh| fresh.name() == entry.plugin.name())
                        .unwrap_or_else(|| Arc::clone(&entry.plugin)),
                    grants: entry.grants.clone(),
                })
                .collect(),
        }
    }

    /// The plugins' names, in the order their hooks run.
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        self.ordered().iter().map(|e| e.plugin.name()).collect()
    }

    fn nodes(&self) -> Vec<order::Node> {
        let owned =
            |v: &[std::borrow::Cow<'static, str>]| v.iter().map(ToString::to_string).collect();
        self.entries
            .iter()
            .map(|entry| {
                let plugin = &entry.plugin;
                let meta = plugin.metadata();
                let phase = if plugin.requirements().contains(Requirements::RUN_LAST) {
                    Phase::Last
                } else {
                    meta.phase
                        .or_else(|| meta.category.map(Category::default_phase))
                        .unwrap_or(Phase::Normal)
                };
                let mut requires: Vec<String> = owned(&meta.requires);
                requires.extend(plugin.dependencies().iter().map(|d| (*d).to_owned()));
                order::Node {
                    name: plugin.name().to_owned(),
                    phase,
                    requires,
                    conflicts: owned(&meta.conflicts),
                    after: owned(&meta.after),
                    before: owned(&meta.before),
                }
            })
            .collect()
    }

    /// The entries in run order. A set that fails [`check`](Self::check) runs
    /// in insertion order with `RUN_LAST` plugins at the end.
    fn ordered(&self) -> Vec<&Entry> {
        match order::resolve(&self.nodes()) {
            Ok(order) => order.into_iter().map(|i| &self.entries[i]).collect(),
            Err(_) => {
                let last = |e: &&Entry| e.plugin.requirements().contains(Requirements::RUN_LAST);
                self.entries
                    .iter()
                    .filter(|e| !last(e))
                    .chain(self.entries.iter().filter(last))
                    .collect()
            }
        }
    }

    /// Checks every plugin against the browser about to start on a host that
    /// supports everything ([`HostInfo::cdp`]). seleniumbase-rs calls it before
    /// [`before_launch`](Self::before_launch).
    ///
    /// # Errors
    ///
    /// See [`check_with`](Self::check_with).
    pub fn check(&self, context: &LaunchContext) -> Result<()> {
        self.check_with(context, &HostInfo::cdp())
    }

    /// Checks the order (cycles, missing `requires`, conflicts), every
    /// plugin's requirements and packages, that a strict set has only declared
    /// plugins, that the host supports each required capability, and that each
    /// required capability is granted.
    ///
    /// # Errors
    ///
    /// The first [`PluginError`] found; nothing has started.
    pub fn check_with(&self, context: &LaunchContext, host: &HostInfo) -> Result<()> {
        order::resolve(&self.nodes())?;
        for entry in self.ordered() {
            let plugin = &entry.plugin;
            let name = plugin.name();
            let meta = plugin.metadata();
            if self.strict && !meta.is_declared() {
                return Err(PluginError::Undeclared(name.to_owned()));
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
                    plugin: name.to_owned(),
                    reason: reason.to_owned(),
                });
            }
            for capability in meta.capabilities.iter() {
                if !host.supports(capability) {
                    return Err(PluginError::Unsupported {
                        plugin: name.to_owned(),
                        capability: capability.to_string(),
                        host: host.name(),
                    });
                }
                if !entry.grants.covers(capability) {
                    return Err(PluginError::Capability {
                        plugin: name.to_owned(),
                        capability: capability.to_string(),
                        reason: "it is required but not granted".to_owned(),
                    });
                }
            }
        }
        Ok(())
    }

    /// One row for every capability each plugin requires or optionally uses:
    /// whether it is granted, its risk, and whether it is enforced.
    #[must_use]
    pub fn audit(&self) -> Vec<AuditRow> {
        let mut rows = Vec::new();
        for entry in self.ordered() {
            let meta = entry.plugin.metadata();
            for capability in meta.capabilities.union(&meta.optional).iter() {
                rows.push(AuditRow {
                    plugin: entry.plugin.name().to_owned(),
                    category: meta.category,
                    capability: capability.clone(),
                    risk: capability.risk(),
                    granted: entry.grants.covers(capability),
                    enforcement: capability.enforcement(false),
                });
            }
        }
        rows
    }

    /// Lets every plugin change the start-up settings, in order. After each
    /// plugin the change is checked: it needs the matching capability, list
    /// fields only grow, refused switches are refused unless the plugin holds
    /// `raw:switches`, and a field another plugin sealed keeps its value.
    ///
    /// # Errors
    ///
    /// The first hook error, as [`PluginError::Hook`], or the first rule
    /// broken, as [`PluginError::Capability`] or [`PluginError::Sealed`].
    pub async fn before_launch(&self, launch: &mut LaunchSettings) -> Result<()> {
        let mut sealed: Vec<(&'static str, String, String)> = Vec::new();
        for entry in self.ordered() {
            let before = launch.clone();
            entry
                .plugin
                .before_launch(launch)
                .await
                .map_err(|error| in_hook(entry.plugin.as_ref(), "before_launch", error))?;
            verify_launch(entry, &before, launch, &mut sealed)?;
        }
        Ok(())
    }

    /// Tells every plugin the browser runs.
    ///
    /// # Errors
    ///
    /// The first hook error, as [`PluginError::Hook`].
    pub async fn on_browser(&self, browser: &dyn BrowserHandle) -> Result<()> {
        for entry in self.ordered() {
            entry
                .plugin
                .on_browser(browser)
                .await
                .map_err(|error| in_hook(entry.plugin.as_ref(), "on_browser", error))?;
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
        for entry in self.ordered() {
            let plugin = &entry.plugin;
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
        for entry in self.ordered() {
            if let Err(error) = entry.plugin.on_close().await {
                failures.push(in_hook(entry.plugin.as_ref(), "on_close", error));
            }
        }
        failures
    }
}

fn denied(plugin: &str, what: impl fmt::Display, reason: &str) -> PluginError {
    PluginError::Capability {
        plugin: plugin.to_owned(),
        capability: what.to_string(),
        reason: reason.to_owned(),
    }
}

/// Checks what one plugin's `before_launch` changed.
fn verify_launch(
    entry: &Entry,
    before: &LaunchSettings,
    after: &LaunchSettings,
    sealed: &mut Vec<(&'static str, String, String)>,
) -> Result<()> {
    let name = entry.plugin.name();
    let meta = entry.plugin.metadata();
    let need = |capability: Capability| -> Result<()> {
        if entry.grants.covers(&capability) {
            Ok(())
        } else {
            Err(denied(
                name,
                capability,
                "it changed a setting without the capability",
            ))
        }
    };
    let grows = |field: &str, old: &[String], new: &[String]| -> Result<()> {
        if old.iter().all(|item| new.contains(item)) {
            Ok(())
        } else {
            Err(denied(
                name,
                field,
                "list settings only grow; it removed an entry",
            ))
        }
    };
    let raw_switches = entry.grants.covers(&Capability::Raw(RawKind::Switches));
    let added = |old: &[String], new: &[String]| -> Vec<String> {
        new.iter()
            .filter(|item| !old.contains(item))
            .cloned()
            .collect()
    };

    grows("args", &before.args, &after.args)?;
    let new_args = added(&before.args, &after.args);
    if !new_args.is_empty() {
        need(Capability::LaunchArgs)?;
        if !raw_switches {
            for arg in &new_args {
                if let Some(reason) = switch_policy::refusal(arg) {
                    return Err(denied(name, "launch.args", &reason));
                }
            }
        }
    }
    for (field, old, new) in [
        (
            "disable_features",
            &before.disable_features,
            &after.disable_features,
        ),
        (
            "enable_features",
            &before.enable_features,
            &after.enable_features,
        ),
    ] {
        grows(field, old, new)?;
        let new_features = added(old, new);
        if !new_features.is_empty() {
            need(Capability::LaunchArgs)?;
            if !raw_switches
                && new_features
                    .iter()
                    .any(|f| switch_policy::feature_refused(f))
            {
                return Err(denied(
                    name,
                    field,
                    "that feature may not be changed by a plugin",
                ));
            }
        }
    }
    grows(
        "host_resolver_rules",
        &before.host_resolver_rules,
        &after.host_resolver_rules,
    )?;
    if before.host_resolver_rules != after.host_resolver_rules
        || before.webrtc_policy != after.webrtc_policy
        || before.disable_quic != after.disable_quic
    {
        need(Capability::LaunchNetwork)?;
    }
    if before.prefs != after.prefs {
        if !before.prefs.keys().all(|key| after.prefs.contains_key(key)) {
            return Err(denied(
                name,
                "prefs",
                "it removed a preference another plugin set",
            ));
        }
        need(Capability::LaunchPrefs)?;
    }
    let old_ext: Vec<String> = before
        .extensions
        .iter()
        .map(|p| p.display().to_string())
        .collect();
    let new_ext: Vec<String> = after
        .extensions
        .iter()
        .map(|p| p.display().to_string())
        .collect();
    grows("extensions", &old_ext, &new_ext)?;
    if old_ext != new_ext {
        need(Capability::LaunchExtensions)?;
    }
    if before.headless != after.headless {
        need(Capability::LaunchHeadless)?;
    }
    if before.proxy != after.proxy {
        need(Capability::LaunchProxy)?;
    }
    if before.profile != after.profile {
        return Err(denied(
            name,
            "profile",
            "the profile is read-only for plugins",
        ));
    }

    // Seals on scalar fields.
    let scalars: [(&'static str, Seals, bool, String); 3] = [
        (
            "proxy",
            Seals::PROXY,
            before.proxy != after.proxy,
            format!("{:?}", after.proxy),
        ),
        (
            "webrtc_policy",
            Seals::WEBRTC,
            before.webrtc_policy != after.webrtc_policy,
            format!("{:?}", after.webrtc_policy),
        ),
        (
            "headless",
            Seals::HEADLESS,
            before.headless != after.headless,
            format!("{:?}", after.headless),
        ),
    ];
    for (field, seal, changed, value) in scalars {
        if !changed {
            continue;
        }
        if let Some((_, owner, held)) = sealed.iter().find(|(f, _, _)| *f == field) {
            if *held != value {
                return Err(PluginError::Sealed {
                    field,
                    a: owner.clone(),
                    b: name.to_owned(),
                });
            }
        } else if meta.seals.contains(seal) {
            sealed.push((field, name.to_owned(), value));
        }
    }
    Ok(())
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
