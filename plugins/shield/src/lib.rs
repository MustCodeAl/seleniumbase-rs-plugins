//! Privacy hardening for the browser seleniumbase-rs starts: shield turns off
//! the browser's own background reporting, keeps WebRTC from leaking the
//! machine's addresses, blocks third-party cookies, refuses to keep a profile
//! on disk, and optionally routes traffic through a local Tor daemon with
//! per-context circuit isolation (`feature = "tor"`).
//!
//! It limits what the user's own browser sends about the user. It does not
//! spoof fingerprints or hide automation; that is the job of
//! [seleniumbase-rs-stealth](https://github.com/MustCodeAl/seleniumbase-rs-stealth).
//!
//! ```
//! use seleniumbase_rs_plugin::PluginSet;
//! use seleniumbase_rs_plugin_shield::{Level, Shield, ShieldConfig};
//!
//! let shield = Shield::new(ShieldConfig::new().level(Level::Strict))?;
//! let plugins = PluginSet::strict().with(shield)?;
//! assert_eq!(plugins.names(), ["shield"]);
//! # Ok::<(), seleniumbase_rs_plugin::PluginError>(())
//! ```

mod config;
pub mod telemetry;
#[cfg(feature = "tor")]
pub mod tor;

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, PoisonError};

use seleniumbase_rs_plugin::{
    Capability, Category, Configurable, HostScope, LaunchSettings, Metadata, Package, PageHandle,
    Plugin, PluginError, ProfileView, Requirements, Result, WebRtcPolicy, async_trait,
};
#[cfg(feature = "tor")]
use seleniumbase_rs_plugin::{
    ContextHandle, ContextId, ContextSettings, NetScope, PathScope, Seals,
};
use serde_json::{Value, json};

pub use config::{Level, ShieldConfig, WebRtcMode};
#[cfg(feature = "tor")]
pub use tor::{
    ControlAuth, Forwarder, Isolation, IsolationToken, Limits as TorLimits, Tor, TorConfig,
};

/// Origins [`Shield::remember_origin`] keeps; later ones are dropped.
const MAX_ORIGINS: usize = 1_024;

/// Makes every `RTCPeerConnection` ask for relay candidates only, so the
/// machine's own addresses are not offered to the other side. Defence in depth
/// beside the browser's IP-handling policy.
const WEBRTC_SHIM: &str = r"(() => {
  const Native = window.RTCPeerConnection;
  if (typeof Native !== 'function') return;
  const Relay = function RTCPeerConnection(configuration, ...rest) {
    const forced = Object.assign({}, configuration || {}, { iceTransportPolicy: 'relay' });
    return new Native(forced, ...rest);
  };
  Relay.prototype = Native.prototype;
  Object.setPrototypeOf(Relay, Native);
  window.RTCPeerConnection = Relay;
  if (typeof window.webkitRTCPeerConnection === 'function') window.webkitRTCPeerConnection = Relay;
})();";

/// The shield privacy plugin. See the [crate documentation](crate).
#[derive(Debug, Default)]
pub struct Shield {
    config: ShieldConfig,
    /// Origins seen (scheme, host and port; never paths, queries or bodies).
    seen: Mutex<Seen>,
    /// Optional embedded Tor router when `config.tor` is enabled.
    #[cfg(feature = "tor")]
    tor: Option<tor::Tor>,
}

/// The origin bookkeeping behind [`Shield::remember_origin`].
#[derive(Debug, Default)]
struct Seen {
    origins: BTreeSet<String>,
    /// Origins that were not kept because the list was full.
    dropped: usize,
}

impl Shield {
    /// A shield with these options.
    ///
    /// # Errors
    ///
    /// [`PluginError::Config`] when a host in `extra_block_hosts` is not a plain
    /// host name or when `tor` options are invalid.
    pub fn new(config: ShieldConfig) -> Result<Self> {
        let config = config.normalized()?;
        #[cfg(feature = "tor")]
        let tor = match &config.tor {
            Some(tor_cfg) => Some(tor::Tor::new(tor_cfg.clone())?),
            None => None,
        };
        Ok(Self {
            config,
            seen: Mutex::default(),
            #[cfg(feature = "tor")]
            tor,
        })
    }

    /// The options, with host names lower-cased.
    #[must_use]
    pub fn config(&self) -> &ShieldConfig {
        &self.config
    }

    /// How many local Tor SOCKS forwarders are alive (`0` when Tor is off).
    #[cfg(feature = "tor")]
    #[must_use]
    pub fn live_tor_forwarders(&self) -> usize {
        self.tor.as_ref().map_or(0, tor::Tor::live_forwarders)
    }

    /// Remembers the origin of `url`: scheme, host and port of an `http` or
    /// `https` URL, lower case, without credentials, path, query, fragment or
    /// default port.
    pub fn remember_origin(&self, url: &str) {
        let Some(origin) = origin_of(url) else {
            return;
        };
        let mut seen = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
        if seen.origins.len() < MAX_ORIGINS || seen.origins.contains(&origin) {
            seen.origins.insert(origin);
        } else {
            seen.dropped = seen.dropped.saturating_add(1);
        }
    }

    /// The remembered origins, sorted, and forgets them.
    pub fn take_origins(&self) -> Vec<String> {
        let mut seen = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
        std::mem::take(&mut *seen).origins.into_iter().collect()
    }

    /// How many origins [`remember_origin`](Self::remember_origin) dropped.
    pub fn dropped_origins(&self) -> usize {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .dropped
    }

    /// The same options and an empty origin list, for one pooled browser.
    fn fresh(&self) -> Self {
        #[cfg(feature = "tor")]
        let tor = self
            .config
            .tor
            .as_ref()
            .and_then(|cfg| tor::Tor::new(cfg.clone()).ok());
        Self {
            config: self.config.clone(),
            seen: Mutex::default(),
            #[cfg(feature = "tor")]
            tor,
        }
    }

    /// The URL patterns of `extra_block_hosts`, for `Network.setBlockedURLs`.
    fn page_patterns(&self) -> Vec<String> {
        self.config
            .extra_block_hosts
            .iter()
            .flat_map(|host| {
                [
                    format!("*://{host}/*"),
                    format!("*://*.{host}/*"),
                    format!("*://{host}:*/*"),
                    format!("*://*.{host}:*/*"),
                ]
            })
            .collect()
    }

    /// The preferences for these options.
    fn prefs(&self) -> Vec<(&'static str, Value)> {
        let mut prefs = vec![
            ("net.network_prediction_options", json!(2)),
            ("search.suggest_enabled", json!(false)),
            ("alternate_error_pages.enabled", json!(false)),
            ("spellcheck.use_spelling_service", json!(false)),
            ("privacy_sandbox.m1.topics_enabled", json!(false)),
            ("privacy_sandbox.m1.fledge_enabled", json!(false)),
            ("privacy_sandbox.m1.ad_measurement_enabled", json!(false)),
        ];
        if self.config.block_third_party_cookies {
            prefs.push(("profile.cookie_controls_mode", json!(1)));
        }
        if !self.config.safe_browsing {
            prefs.push(("safebrowsing.enabled", json!(false)));
        }
        prefs
    }
}

/// Appends the items of `new` that `list` does not have yet.
fn extend_unique(list: &mut Vec<String>, new: impl IntoIterator<Item = String>) {
    for item in new {
        if !list.contains(&item) {
            list.push(item);
        }
    }
}

/// `scheme://host[:port]` of an `http` or `https` URL, lower case, without
/// credentials; `None` for anything else.
fn origin_of(url: &str) -> Option<String> {
    let (scheme, rest) = url.trim().split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return None;
    }
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let valid = !host.is_empty()
        && !host.starts_with(':')
        && host.bytes().all(|b| b.is_ascii_graphic())
        && !host.contains(['\\', '<', '>', '"', '`', '{', '}', '|', '^']);
    if !valid {
        return None;
    }
    let mut host = host.to_ascii_lowercase();
    if let Some(colon) = host.rfind(':').filter(|i| !host[*i..].contains(']')) {
        let default = if scheme == "https" { "443" } else { "80" };
        let port = &host[colon + 1..];
        if port.is_empty() || port == default {
            host.truncate(colon);
        } else if !port.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
    }
    Some(format!("{scheme}://{host}"))
}

impl Configurable for Shield {
    const NAME: &'static str = "shield";

    fn describe() -> Metadata {
        use Capability::{Cdp, LaunchArgs, LaunchNetwork, LaunchPrefs, PageScript};
        let meta = Metadata::new(Category::Privacy)
            .version(env!("CARGO_PKG_VERSION"))
            .summary(
                "Privacy hardening: turns off browser telemetry, WebRTC address leaks and \
                 third-party cookies, keeps profiles ephemeral, and optionally routes traffic \
                 through a local Tor daemon",
            )
            .capabilities([
                LaunchArgs,
                LaunchPrefs,
                LaunchNetwork,
                PageScript(HostScope::Everywhere),
                Cdp("Network".into()),
            ]);
        #[cfg(feature = "tor")]
        let meta = meta
            .optional(Capability::LaunchProxy)
            .optional(Capability::Contexts)
            .optional(Capability::HostNet(NetScope::Loopback))
            .optional(Capability::HostFsRead(PathScope::Declared(Vec::new())));
        meta
    }

    /// Options: see [`ShieldConfig`]. `Value::Null` means the defaults.
    fn configure(options: &Value) -> Result<Self> {
        let config = if options.is_null() {
            ShieldConfig::default()
        } else {
            serde_json::from_value(options.clone())
                .map_err(|error| PluginError::Config(format!("shield: {error}")))?
        };
        Self::new(config)
    }
}

#[async_trait]
impl Plugin for Shield {
    fn name(&self) -> &str {
        Self::NAME
    }

    fn metadata(&self) -> Metadata {
        use Capability::{Cdp, LaunchArgs, LaunchNetwork, LaunchPrefs, PageScript};
        #[cfg_attr(
            not(feature = "tor"),
            expect(unused_mut, reason = "extended when tor feature is enabled")
        )]
        let mut meta = Metadata::new(Category::Privacy)
            .version(env!("CARGO_PKG_VERSION"))
            .summary(
                "Privacy hardening: turns off browser telemetry, WebRTC address leaks and \
                 third-party cookies, keeps profiles ephemeral, and optionally routes traffic \
                 through a local Tor daemon",
            )
            .capabilities([
                LaunchArgs,
                LaunchPrefs,
                LaunchNetwork,
                PageScript(HostScope::Everywhere),
                Cdp("Network".into()),
            ]);

        #[cfg(feature = "tor")]
        if let Some(ref tor_plugin) = self.tor {
            meta = meta
                .capabilities([
                    Capability::LaunchProxy,
                    Capability::Contexts,
                    Capability::HostNet(NetScope::Loopback),
                ])
                .seal(Seals::PROXY | Seals::CONTEXT_PROXY | Seals::WEBRTC);
            let cfg = tor_plugin.config();
            if cfg.require_bootstrapped
                && cfg.control.is_some()
                && let Some(path) = cfg
                    .control_auth
                    .as_ref()
                    .and_then(|auth| auth.cookie_path.clone())
            {
                meta.capabilities
                    .insert(Capability::HostFsRead(PathScope::Declared(vec![path])));
            }
        }
        meta
    }

    fn requirements(&self) -> Requirements {
        #[cfg(feature = "tor")]
        if self.tor.is_some() {
            return Requirements::CHROMIUM_ONLY | Requirements::LAUNCH_ONLY;
        }
        Requirements::CHROMIUM_ONLY
    }

    /// A pooled browser gets its own origin list and Tor forwarders.
    fn per_launch(&self) -> Option<Arc<dyn Plugin>> {
        Some(Arc::new(self.fresh()))
    }

    fn packages(&self) -> Vec<Package> {
        match self.config.webrtc {
            WebRtcMode::RelayOnly => vec![Package::script(WEBRTC_SHIM).everywhere()],
            WebRtcMode::Off | WebRtcMode::Policy => Vec::new(),
        }
    }

    async fn before_launch(&self, launch: &mut LaunchSettings) -> Result<()> {
        if self.config.ephemeral_profile && matches!(launch.profile(), ProfileView::Persistent(_)) {
            return Err(PluginError::other(
                "shield: a persistent profile was set; turn `ephemeral_profile` off to allow it",
            ));
        }

        // Run Tor checks and forwarder setup first so a refusal leaves launch settings unchanged.
        #[cfg(feature = "tor")]
        if let Some(ref tor_plugin) = self.tor {
            tor_plugin.before_launch(launch).await?;
        }

        extend_unique(
            &mut launch.args,
            telemetry::SWITCHES.iter().map(|s| (*s).to_owned()),
        );
        extend_unique(
            &mut launch.disable_features,
            telemetry::FEATURES.iter().map(|s| (*s).to_owned()),
        );
        for (key, value) in self.prefs() {
            launch.prefs.insert(key.to_owned(), value);
        }
        if self.config.webrtc != WebRtcMode::Off {
            launch.webrtc_policy = Some(WebRtcPolicy::DisableNonProxiedUdp);
        }
        if self.config.level == Level::Strict {
            extend_unique(
                &mut launch.host_resolver_rules,
                telemetry::BROWSER_HOSTS
                    .iter()
                    .map(|host| telemetry::resolver_rule(host)),
            );
        }
        Ok(())
    }

    async fn on_page_created(&self, page: &dyn PageHandle) -> Result<()> {
        let patterns = self.page_patterns();
        if patterns.is_empty() {
            return Ok(());
        }
        page.send("Network.enable", json!({})).await?;
        page.send("Network.setBlockedURLs", json!({ "urls": patterns }))
            .await?;
        Ok(())
    }

    #[cfg(feature = "tor")]
    async fn before_context(&self, settings: &mut ContextSettings) -> Result<()> {
        if let Some(ref tor_plugin) = self.tor {
            tor_plugin.before_context(settings).await?;
        }
        Ok(())
    }

    #[cfg(feature = "tor")]
    async fn on_context_created(&self, context: &dyn ContextHandle) -> Result<()> {
        if let Some(ref tor_plugin) = self.tor {
            tor_plugin.on_context_created(context).await?;
        }
        Ok(())
    }

    #[cfg(feature = "tor")]
    async fn on_context_closed(&self, id: &ContextId) -> Result<()> {
        if let Some(ref tor_plugin) = self.tor {
            tor_plugin.on_context_closed(id).await?;
        }
        Ok(())
    }

    #[cfg(feature = "tor")]
    async fn on_close(&self) -> Result<()> {
        if let Some(ref tor_plugin) = self.tor {
            tor_plugin.on_close().await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_per_launch_instance_starts_with_no_origins_and_the_same_options() {
        let shield = Shield::new(ShieldConfig::new().block_hosts(["a.example"])).unwrap();
        shield.remember_origin("https://seen.example/");
        assert_eq!(shield.per_launch().expect("an instance").name(), "shield");
        let fresh = shield.fresh();
        assert_eq!(fresh.config(), shield.config());
        let origins = fresh.take_origins();
        assert!(origins.is_empty(), "{origins:?}");
        assert_eq!(fresh.dropped_origins(), 0);
        assert_eq!(shield.take_origins(), ["https://seen.example"]);
    }

    #[cfg(feature = "tor")]
    #[test]
    fn tor_option_adds_proxy_and_context_capabilities_only_when_enabled() {
        let plain = Shield::new(ShieldConfig::new()).unwrap();
        assert!(
            !plain
                .metadata()
                .capabilities
                .covers(&Capability::LaunchProxy)
        );
        assert!(!plain.metadata().capabilities.covers(&Capability::Contexts));

        let with_tor = Shield::new(ShieldConfig::new().with_tor()).unwrap();
        assert!(
            with_tor
                .metadata()
                .capabilities
                .covers(&Capability::LaunchProxy)
        );
        assert!(
            with_tor
                .metadata()
                .capabilities
                .covers(&Capability::Contexts)
        );
        assert!(with_tor.requirements().contains(Requirements::LAUNCH_ONLY));
    }
}
