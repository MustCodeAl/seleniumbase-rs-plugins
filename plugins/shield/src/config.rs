//! The options of the shield plugin.

use seleniumbase_rs_plugin::PluginError;
use serde::Deserialize;

#[cfg(feature = "tor")]
use crate::tor::TorConfig;

/// How much of the browser's own background traffic shield cuts off.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Level {
    /// Telemetry switches and features, privacy preferences, the WebRTC policy.
    #[default]
    Basic,
    /// Everything in [`Basic`](Self::Basic), and the browser process can no
    /// longer resolve the hosts it reports to
    /// ([`telemetry::BROWSER_HOSTS`](crate::telemetry::BROWSER_HOSTS)).
    Strict,
}

/// What shield does about WebRTC leaking the machine's addresses.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WebRtcMode {
    /// Leave WebRTC as the browser has it.
    Off,
    /// Set Chrome's `disable_non_proxied_udp` IP-handling policy.
    Policy,
    /// The policy, and a page script that makes every `RTCPeerConnection` use
    /// relay candidates only.
    #[default]
    RelayOnly,
}

/// Deserializes `tor` as `false`/`null` (`None`), `true` (`Some(TorConfig::default())`),
/// or a `[plugins.shield.tor]` table (`Some(TorConfig)`).
#[cfg(feature = "tor")]
fn deserialize_tor<'de, D>(deserializer: D) -> Result<Option<TorConfig>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum TorOption {
        Bool(bool),
        Config(TorConfig),
    }

    match Option::<TorOption>::deserialize(deserializer)? {
        None | Some(TorOption::Bool(false)) => Ok(None),
        Some(TorOption::Bool(true)) => Ok(Some(TorConfig::default())),
        Some(TorOption::Config(cfg)) => Ok(Some(cfg)),
    }
}

/// The options of [`Shield`](crate::Shield): `[plugins.shield]` in a config
/// file, `--plugin-opt 'shield.level="strict"'` on the command line.
///
/// Enable Tor routing with `tor = true` (default local daemon at `127.0.0.1:9050`)
/// or a `[plugins.shield.tor]` table configuring `socks`, `control`,
/// `control_auth`, `isolation`, and `require_bootstrapped`.
///
/// An option that is not listed here is an error, so a typo does not turn a
/// protection off without a word.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
#[non_exhaustive]
pub struct ShieldConfig {
    /// How much background traffic to cut off. Default `basic`.
    pub level: Level,
    /// What to do about WebRTC. Default `relay-only`.
    pub webrtc: WebRtcMode,
    /// Block third-party cookies. Default `true`. `false` leaves the browser's
    /// own setting; it never allows them.
    pub block_third_party_cookies: bool,
    /// Refuse to run with a persistent profile. Default `true`: a launch that
    /// sets one fails with a message instead of keeping state on disk.
    pub ephemeral_profile: bool,
    /// Delete the profile folders of dead browsers that earlier runs left in
    /// the temporary folder. Default `false`. **Not active yet**: `true` is refused.
    pub sweep_stale_profiles: bool,
    /// Clear the storage of every origin a test visited when the test ends.
    /// Default `false`. **Not active yet**: `true` is refused.
    pub clear_between_tests: bool,
    /// Host names whose requests pages may not make, with their subdomains,
    /// such as `tracker.example.com`. Host names only: no scheme, port, path or `*`.
    pub extra_block_hosts: Vec<String>,
    /// Leave Safe Browsing on. Default `true`. Only `false` makes shield turn
    /// it off.
    pub safe_browsing: bool,
    /// Optional Tor SOCKS5 routing and per-context circuit isolation through a
    /// local Tor daemon (`feature = "tor"`). Accepts `true`, `false`, or a
    /// [`TorConfig`] object. Default `None`.
    #[cfg(feature = "tor")]
    #[serde(default, deserialize_with = "deserialize_tor")]
    pub tor: Option<TorConfig>,
}

impl Default for ShieldConfig {
    fn default() -> Self {
        Self {
            level: Level::default(),
            webrtc: WebRtcMode::default(),
            block_third_party_cookies: true,
            ephemeral_profile: true,
            sweep_stale_profiles: false,
            clear_between_tests: false,
            extra_block_hosts: Vec::new(),
            safe_browsing: true,
            #[cfg(feature = "tor")]
            tor: None,
        }
    }
}

impl ShieldConfig {
    /// The default options.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets [`level`](Self::level).
    #[must_use]
    pub fn level(mut self, level: Level) -> Self {
        self.level = level;
        self
    }

    /// Sets [`webrtc`](Self::webrtc).
    #[must_use]
    pub fn webrtc(mut self, webrtc: WebRtcMode) -> Self {
        self.webrtc = webrtc;
        self
    }

    /// Sets [`block_third_party_cookies`](Self::block_third_party_cookies).
    #[must_use]
    pub fn block_third_party_cookies(mut self, block: bool) -> Self {
        self.block_third_party_cookies = block;
        self
    }

    /// Sets [`ephemeral_profile`](Self::ephemeral_profile).
    #[must_use]
    pub fn ephemeral_profile(mut self, ephemeral: bool) -> Self {
        self.ephemeral_profile = ephemeral;
        self
    }

    /// Sets [`safe_browsing`](Self::safe_browsing).
    #[must_use]
    pub fn safe_browsing(mut self, on: bool) -> Self {
        self.safe_browsing = on;
        self
    }

    /// Adds hosts to [`extra_block_hosts`](Self::extra_block_hosts).
    #[must_use]
    pub fn block_hosts<I, S>(mut self, hosts: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.extra_block_hosts
            .extend(hosts.into_iter().map(Into::into));
        self
    }

    /// Enables Tor routing with default local daemon settings (`127.0.0.1:9050`,
    /// per-context circuit isolation).
    #[cfg(feature = "tor")]
    #[must_use]
    pub fn with_tor(mut self) -> Self {
        self.tor = Some(TorConfig::default());
        self
    }

    /// Enables Tor routing with explicit [`TorConfig`] options.
    #[cfg(feature = "tor")]
    #[must_use]
    pub fn tor(mut self, config: TorConfig) -> Self {
        self.tor = Some(config);
        self
    }

    /// Checks the options and lower-cases the host names.
    ///
    /// # Errors
    ///
    /// [`PluginError::Config`] when a host name in `extra_block_hosts` is not a
    /// plain ASCII host name, when `sweep_stale_profiles` or
    /// `clear_between_tests` is on, or when `tor` options are invalid.
    pub(crate) fn normalized(mut self) -> Result<Self, PluginError> {
        for (name, on) in [
            ("sweep_stale_profiles", self.sweep_stale_profiles),
            ("clear_between_tests", self.clear_between_tests),
        ] {
            if on {
                return Err(PluginError::Config(format!(
                    "shield: `{name}` is not implemented yet (the plugin API has no hook for it); \
                     leave it off"
                )));
            }
        }
        for host in &mut self.extra_block_hosts {
            *host = normalize_host(host)?;
        }
        let mut seen = std::collections::BTreeSet::new();
        self.extra_block_hosts
            .retain(|host| seen.insert(host.clone()));
        #[cfg(feature = "tor")]
        if let Some(ref tor) = self.tor {
            tor.validate()?;
        }
        Ok(self)
    }
}

/// A host name as it goes into a URL pattern: ASCII letters, digits, `-` and
/// `.` only, so a value cannot add a wildcard, a scheme or a second rule.
fn normalize_host(raw: &str) -> Result<String, PluginError> {
    let bad =
        |why: &str| PluginError::Config(format!("shield: extra_block_hosts entry {raw:?} {why}"));
    let host = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return Err(bad("is empty"));
    }
    if host.len() > 253 {
        return Err(bad("is longer than 253 characters"));
    }
    for label in host.split('.') {
        let valid = (1..=63).contains(&label.len())
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-');
        if !valid {
            return Err(bad(
                "is not a plain host name (letters, digits and `-` in dot-separated labels; \
                 no scheme, port, path or `*`; write internationalised names as punycode)",
            ));
        }
    }
    Ok(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_are_lowered_and_trimmed() {
        assert_eq!(normalize_host(" Example.COM. ").unwrap(), "example.com");
        assert_eq!(
            normalize_host("xn--bcher-kva.example").unwrap(),
            "xn--bcher-kva.example"
        );
    }

    #[test]
    fn duplicates_are_dropped_in_order() {
        let config = ShieldConfig::new().block_hosts(["b.example", "a.example", "B.example"]);
        assert_eq!(
            config.normalized().unwrap().extra_block_hosts,
            ["b.example", "a.example"]
        );
    }

    #[cfg(feature = "tor")]
    #[test]
    fn tor_deserializes_from_bool_or_object() {
        let off: ShieldConfig =
            serde_json::from_value(serde_json::json!({ "tor": false })).unwrap();
        assert!(off.tor.is_none());

        let default_on: ShieldConfig =
            serde_json::from_value(serde_json::json!({ "tor": true })).unwrap();
        assert_eq!(default_on.tor, Some(TorConfig::default()));

        let custom: ShieldConfig = serde_json::from_value(serde_json::json!({
            "tor": { "socks": "127.0.0.1:9150", "isolation": "browser" }
        }))
        .unwrap();
        let tor = custom.tor.unwrap();
        assert_eq!(tor.socks.port(), 9150);
    }
}
