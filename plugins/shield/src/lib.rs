//! Privacy hardening for the browser seleniumbase-rs starts: shield turns off
//! the browser's own background reporting, keeps WebRTC from leaking the
//! machine's addresses, blocks third-party cookies and refuses to keep a
//! profile on disk.
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
//!
//! # What it does
//!
//! In [`before_launch`](Plugin::before_launch), in this order:
//!
//! 1. With `ephemeral_profile` (the default) it refuses a launch that set a
//!    persistent profile, before it changes anything.
//! 2. It adds the switches in [`telemetry::SWITCHES`] and disables the features
//!    in [`telemetry::FEATURES`].
//! 3. It sets privacy preferences: no network prediction, search suggestions,
//!    Link Doctor error pages or Google spelling service, and no Privacy
//!    Sandbox ad topics, Protected Audience or ad measurement. With
//!    `block_third_party_cookies` it blocks third-party cookies; with
//!    `safe_browsing = false` (and only then) it turns Safe Browsing off.
//! 4. Unless `webrtc` is `off`, it sets Chrome's `disable_non_proxied_udp`
//!    IP-handling policy.
//! 5. At the `strict` level it makes the hosts in [`telemetry::BROWSER_HOSTS`]
//!    fail to resolve for the browser process.
//!
//! With `webrtc = "relay-only"` (the default) every tab also gets a small page
//! script that forces `RTCPeerConnection` to use relay candidates. A relay
//! needs a TURN server, so calls between peers without one do not connect:
//! choose `policy` if you need them.
//!
//! In [`on_page_created`](Plugin::on_page_created) it blocks the
//! `extra_block_hosts` (and their subdomains) with a raw
//! `Network.setBlockedURLs`.
//!
//! # Not active yet
//!
//! These parts of the design need hooks the plugin API does not have yet. They
//! are not faked:
//!
//! - `clear_between_tests` and the origin list ([`Shield::remember_origin`],
//!   [`Shield::take_origins`]) wait for the response and test-end hooks. The
//!   list is kept and tested, but nothing feeds it yet.
//! - `sweep_stale_profiles` waits for a host file API.
//! - Blocking by the host (`NetworkInterest`) replaces the raw
//!   `Network.setBlockedURLs`. The plugin does not declare the capabilities
//!   these need (`net.observe`, `storage.clear`, `test.hooks`,
//!   `host.fs.write:temp`) until it uses them.
//! - It does not check that the temporary profile is gone at close.
//!
//! Preference keys are written as dotted names (`net.network_prediction_options`),
//! as the plugin API's `LaunchSettings::prefs` documents.

mod config;
pub mod telemetry;

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, PoisonError};

use seleniumbase_rs_plugin::{
    Capability, Category, Configurable, HostScope, LaunchSettings, Metadata, Package, PageHandle,
    Plugin, PluginError, ProfileView, Requirements, Result, WebRtcPolicy, async_trait,
};
use serde_json::{Value, json};

pub use config::{Level, ShieldConfig, WebRtcMode};

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

/// The shield plugin. See the [crate documentation](crate).
#[derive(Debug, Default)]
pub struct Shield {
    config: ShieldConfig,
    /// Origins seen (scheme, host and port; never paths, queries or bodies).
    seen: Mutex<BTreeSet<String>>,
}

impl Shield {
    /// A shield with these options.
    ///
    /// # Errors
    ///
    /// [`PluginError::Config`] when a host in `extra_block_hosts` is not a plain
    /// host name.
    pub fn new(config: ShieldConfig) -> Result<Self> {
        Ok(Self {
            config: config.normalized()?,
            seen: Mutex::default(),
        })
    }

    /// The options, with host names lower-cased.
    #[must_use]
    pub fn config(&self) -> &ShieldConfig {
        &self.config
    }

    /// Remembers the origin of `url`: scheme, host and port of an `http` or
    /// `https` URL, without credentials, path, query or fragment. Anything else
    /// is ignored, and at most 1024 origins are kept.
    ///
    /// Nothing calls this yet: the hook that sees responses is not part of the
    /// plugin API. It is the bookkeeping that `clear_between_tests` will use.
    pub fn remember_origin(&self, url: &str) {
        let Some(origin) = origin_of(url) else {
            return;
        };
        let mut seen = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
        if seen.len() < MAX_ORIGINS || seen.contains(&origin) {
            seen.insert(origin);
        }
    }

    /// The remembered origins, sorted, and forgets them.
    pub fn take_origins(&self) -> Vec<String> {
        let mut seen = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
        std::mem::take(&mut *seen).into_iter().collect()
    }

    /// The URL patterns of `extra_block_hosts`, for `Network.setBlockedURLs`.
    fn page_patterns(&self) -> Vec<String> {
        self.config
            .extra_block_hosts
            .iter()
            .flat_map(|host| [format!("*://{host}/*"), format!("*://*.{host}/*")])
            .collect()
    }

    /// The preferences for these options.
    fn prefs(&self) -> Vec<(&'static str, Value)> {
        // Names and values checked against the Chromium source on 2026-10-17:
        // `net.network_prediction_options` (kNetworkPredictionOptions in
        // chrome/common/pref_names.h; 2 is NetworkPredictionOptions::kDisabled),
        // `search.suggest_enabled` (same file), `alternate_error_pages.enabled`
        // (components/embedder_support/pref_names.h),
        // `spellcheck.use_spelling_service` (components/spellcheck/browser/pref_names.h),
        // `privacy_sandbox.m1.*_enabled` (components/privacy_sandbox/privacy_sandbox_prefs.h),
        // `profile.cookie_controls_mode` (components/content_settings/core/common/pref_names.h;
        // 1 is CookieControlsMode::kBlockThirdParty) and `safebrowsing.enabled`
        // (components/safe_browsing/core/common/safe_browsing_prefs.h).
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
    valid.then(|| format!("{scheme}://{}", host.to_ascii_lowercase()))
}

impl Configurable for Shield {
    const NAME: &'static str = "shield";

    fn describe() -> Metadata {
        use Capability::{Cdp, LaunchArgs, LaunchNetwork, LaunchPrefs, PageScript};
        Metadata::new(Category::Privacy)
            .version(env!("CARGO_PKG_VERSION"))
            .summary(
                "Turns off browser telemetry, WebRTC address leaks and third-party cookies; \
                 keeps no profile",
            )
            .capabilities([
                LaunchArgs,
                LaunchPrefs,
                LaunchNetwork,
                PageScript(HostScope::Everywhere),
                Cdp("Network".into()),
            ])
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
        Self::describe()
    }

    fn requirements(&self) -> Requirements {
        Requirements::CHROMIUM_ONLY
    }

    /// A pooled browser gets its own origin list.
    fn per_launch(&self) -> Option<Arc<dyn Plugin>> {
        Some(Arc::new(Self {
            config: self.config.clone(),
            seen: Mutex::default(),
        }))
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
            // The browser process does not go through `Network.setBlockedURLs`,
            // so these hosts are cut off at its resolver.
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
        // A raw command: the host merges `Network.setBlockedURLs` from several
        // plugins into one list for the session.
        page.send("Network.enable", json!({})).await?;
        page.send("Network.setBlockedURLs", json!({ "urls": patterns }))
            .await?;
        Ok(())
    }
}
