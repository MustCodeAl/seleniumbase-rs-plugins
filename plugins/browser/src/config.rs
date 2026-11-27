//! Configuration for the containerized persistent `browser` plugin.

use std::fmt;
use std::path::PathBuf;

use seleniumbase_rs_plugin::{PluginError, Result};
use serde::de::{self, Deserializer, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};

use crate::{geo, session};

/// Default folder storing containerized session bundles.
pub(crate) const DEFAULT_SESSION_DIR: &str = "saved_sessions";

/// Default message shown while `interactive` sign-in waits.
pub(crate) const DEFAULT_PAUSE_MESSAGE: &str =
    "Sign in in the browser window, then come back here.";

/// Maximum length of `pause_message` in characters.
const MAX_PAUSE_MESSAGE_CHARS: usize = 500;

/// Maximum `ttl_secs` allowed (30 days).
pub(crate) const MAX_TTL_SECS: u64 = 30 * 24 * 60 * 60;

/// How exit proxies rotate across browser launches and isolated contexts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RotationMode {
    /// Keep one sticky proxy per named container until rotated explicitly.
    #[default]
    Sticky,
    /// Advance to the next proxy on every launch and every new browser context.
    RoundRobin,
    /// Keep the launch proxy for the default context and rotate on each new isolated context.
    PerContext,
}

/// Options for [`BrowserSession`](crate::BrowserSession): `[plugins.browser]` in
/// a settings file or `--plugin-opt 'browser.session="account-a"'`.
///
/// Containerizes browser state (cookies, `localStorage`, `sessionStorage`, open
/// tab URLs, and identity metadata) with optional TTL expiry, geolocation
/// targeting, IP auto-rotation, and interactive / multi-step SPA flow tasks.
#[derive(Clone, Default, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
#[non_exhaustive]
pub struct SessionConfig {
    /// Name of the persistent container (`1..=64` ASCII letters, digits, `.`, `_`, `-`).
    /// Also accepts `"container"` in JSON/TOML.
    #[serde(alias = "container")]
    pub session: Option<String>,
    /// Save cookies, storage, open tabs, and identity before close (`before_close`).
    pub save_on_close: bool,
    /// Folder storing container JSON bundles (default `saved_sessions`).
    pub session_dir: Option<PathBuf>,
    /// Re-open saved `http://`/`https://` tab URLs when restoring a container (default `true`).
    #[serde(default = "default_true")]
    pub restore_tabs: bool,
    /// Container Time-To-Live in seconds (`1..=2_592_000`). Expired containers reset cleanly on load.
    pub ttl_secs: Option<u64>,
    /// Two-letter ISO country code for geolocation targeting (derives default locale, timezone, coords).
    pub country: Option<String>,
    /// Explicit BCP 47 locale override (for example `"de-DE"`).
    pub locale: Option<String>,
    /// Explicit IANA timezone override (for example `"Europe/Berlin"`).
    pub timezone: Option<String>,
    /// Explicit `[latitude, longitude]` geolocation coordinates.
    pub geolocation: Option<[f64; 2]>,
    /// Explicit `User-Agent` override kept with the container identity.
    pub user_agent: Option<String>,
    /// Proxy URLs (`http://`, `https://`, `socks5://`, `socks5h://`) for IP auto-rotation.
    /// Accepts a list or a comma-separated string. Credentials are never printed in `Debug`.
    #[serde(deserialize_with = "string_list")]
    pub proxies: Vec<String>,
    /// Proxy rotation policy across launches and contexts (default `sticky`).
    pub rotation: RotationMode,
    /// Enable interactive manual sign-in capture for `sbrs plugin run browser` (needs headed browser).
    pub interactive: bool,
    /// Prompt shown while waiting during interactive sign-in.
    pub pause_message: Option<String>,
}

const fn default_true() -> bool {
    true
}

impl fmt::Debug for SessionConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let redacted_proxies: Vec<String> = self
            .proxies
            .iter()
            .map(|p| geo::redact_proxy_url(p))
            .collect();
        f.debug_struct("SessionConfig")
            .field("session", &self.session)
            .field("save_on_close", &self.save_on_close)
            .field("session_dir", &self.session_dir)
            .field("restore_tabs", &self.restore_tabs)
            .field("ttl_secs", &self.ttl_secs)
            .field("country", &self.country)
            .field("locale", &self.locale)
            .field("timezone", &self.timezone)
            .field("geolocation", &self.geolocation)
            .field("user_agent", &self.user_agent)
            .field("proxies", &redacted_proxies)
            .field("rotation", &self.rotation)
            .field("interactive", &self.interactive)
            .field("pause_message", &self.pause_message)
            .finish()
    }
}

struct StringList;

impl<'de> Visitor<'de> for StringList {
    type Value = Vec<String>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a comma-separated string or a list of strings")
    }

    fn visit_str<E: de::Error>(self, text: &str) -> std::result::Result<Self::Value, E> {
        let text = text.trim();
        if text.is_empty() {
            return Ok(Vec::new());
        }
        Ok(text.split(',').map(|part| part.trim().to_owned()).collect())
    }

    fn visit_seq<A: SeqAccess<'de>>(
        self,
        mut seq: A,
    ) -> std::result::Result<Self::Value, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element::<String>()? {
            items.push(item);
        }
        Ok(items)
    }
}

fn string_list<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Vec<String>, D::Error> {
    deserializer.deserialize_any(StringList)
}

fn bad(message: impl fmt::Display) -> PluginError {
    PluginError::Config(format!("browser: {message}"))
}

/// Fluent builder for [`SessionConfig`].
#[must_use = "a builder does nothing until `build` is called"]
#[derive(Clone, Debug)]
pub struct SessionConfigBuilder {
    config: SessionConfig,
}

impl Default for SessionConfigBuilder {
    fn default() -> Self {
        Self {
            config: SessionConfig::new(),
        }
    }
}

impl SessionConfigBuilder {
    /// Names the persistent container (`session`).
    #[must_use = "a builder does nothing until `build` is called"]
    pub fn session(mut self, name: impl Into<String>) -> Self {
        self.config.session = Some(name.into());
        self
    }

    /// Alias for [`session`](Self::session).
    #[must_use = "a builder does nothing until `build` is called"]
    pub fn container(self, name: impl Into<String>) -> Self {
        self.session(name)
    }

    /// Enables or disables persisting full state before close.
    #[must_use = "a builder does nothing until `build` is called"]
    pub fn save_on_close(mut self, save: bool) -> Self {
        self.config.save_on_close = save;
        self
    }

    /// Sets the folder storing container state files.
    #[must_use = "a builder does nothing until `build` is called"]
    pub fn session_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.config.session_dir = Some(dir.into());
        self
    }

    /// Enables or disables re-opening persisted tabs on container restore.
    #[must_use = "a builder does nothing until `build` is called"]
    pub fn restore_tabs(mut self, restore: bool) -> Self {
        self.config.restore_tabs = restore;
        self
    }

    /// Sets container Time-To-Live in seconds (`1..=2_592_000`).
    #[must_use = "a builder does nothing until `build` is called"]
    pub fn ttl_secs(mut self, secs: u64) -> Self {
        self.config.ttl_secs = Some(secs);
        self
    }

    /// Sets two-letter ISO country code for geolocation targeting.
    #[must_use = "a builder does nothing until `build` is called"]
    pub fn country(mut self, code: impl Into<String>) -> Self {
        self.config.country = Some(code.into());
        self
    }

    /// Sets an explicit BCP 47 locale override.
    #[must_use = "a builder does nothing until `build` is called"]
    pub fn locale(mut self, locale: impl Into<String>) -> Self {
        self.config.locale = Some(locale.into());
        self
    }

    /// Sets an explicit IANA timezone override.
    #[must_use = "a builder does nothing until `build` is called"]
    pub fn timezone(mut self, tz: impl Into<String>) -> Self {
        self.config.timezone = Some(tz.into());
        self
    }

    /// Sets explicit geolocation coordinates `(latitude, longitude)`.
    #[must_use = "a builder does nothing until `build` is called"]
    pub fn geolocation(mut self, latitude: f64, longitude: f64) -> Self {
        self.config.geolocation = Some([latitude, longitude]);
        self
    }

    /// Sets an explicit `User-Agent` override for this container.
    #[must_use = "a builder does nothing until `build` is called"]
    pub fn user_agent(mut self, ua: impl Into<String>) -> Self {
        self.config.user_agent = Some(ua.into());
        self
    }

    /// Adds a proxy URL to the rotation pool.
    #[must_use = "a builder does nothing until `build` is called"]
    pub fn proxy(mut self, url: impl Into<String>) -> Self {
        self.config.proxies.push(url.into());
        self
    }

    /// Adds multiple proxy URLs to the rotation pool.
    #[must_use = "a builder does nothing until `build` is called"]
    pub fn proxies<I, S>(mut self, urls: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.config.proxies.extend(urls.into_iter().map(Into::into));
        self
    }

    /// Sets the IP rotation mode (`sticky`, `round-robin`, `per-context`).
    #[must_use = "a builder does nothing until `build` is called"]
    pub fn rotation(mut self, mode: RotationMode) -> Self {
        self.config.rotation = mode;
        self
    }

    /// Enables or disables interactive manual sign-in capture.
    #[must_use = "a builder does nothing until `build` is called"]
    pub fn interactive(mut self, interactive: bool) -> Self {
        self.config.interactive = interactive;
        self
    }

    /// Sets the prompt message displayed during interactive sign-in.
    #[must_use = "a builder does nothing until `build` is called"]
    pub fn pause_message(mut self, message: impl Into<String>) -> Self {
        self.config.pause_message = Some(message.into());
        self
    }

    /// Validates all options and builds the [`SessionConfig`].
    ///
    /// # Errors
    ///
    /// [`PluginError::Config`] naming the invalid option.
    pub fn build(mut self) -> Result<SessionConfig> {
        self.config.normalize_and_check()?;
        Ok(self.config)
    }
}

impl SessionConfig {
    /// Default empty session config (`restore_tabs = true`).
    #[must_use]
    pub fn new() -> Self {
        Self {
            restore_tabs: true,
            ..Self::default()
        }
    }

    /// Starts a [`SessionConfigBuilder`].
    #[must_use = "a builder does nothing until `build` is called"]
    pub fn builder() -> SessionConfigBuilder {
        SessionConfigBuilder::default()
    }

    /// Converts this config into a builder.
    #[must_use = "a builder does nothing until `build` is called"]
    pub fn into_builder(self) -> SessionConfigBuilder {
        SessionConfigBuilder { config: self }
    }

    /// Whether this config persists container state to disk.
    #[must_use]
    pub const fn saves(&self) -> bool {
        self.save_on_close || self.interactive
    }

    /// Effective prompt message for interactive sign-in.
    #[must_use]
    pub fn pause_message_or_default(&self) -> &str {
        self.pause_message
            .as_deref()
            .unwrap_or(DEFAULT_PAUSE_MESSAGE)
    }

    /// Effective locale (explicit override or derived from `country`).
    #[must_use]
    pub fn effective_locale(&self) -> Option<&str> {
        self.locale.as_deref().or_else(|| {
            self.country
                .as_deref()
                .and_then(geo::lookup)
                .map(|g| g.locale)
        })
    }

    /// Effective timezone (explicit override or derived from `country`).
    #[must_use]
    pub fn effective_timezone(&self) -> Option<&str> {
        self.timezone.as_deref().or_else(|| {
            self.country
                .as_deref()
                .and_then(geo::lookup)
                .map(|g| g.timezone)
        })
    }

    /// Effective geolocation `(latitude, longitude)` (explicit override or derived from `country`).
    #[must_use]
    pub fn effective_geolocation(&self) -> Option<(f64, f64)> {
        self.geolocation.map(|[lat, lon]| (lat, lon)).or_else(|| {
            self.country
                .as_deref()
                .and_then(geo::lookup)
                .map(|g| (g.latitude, g.longitude))
        })
    }

    /// Normalizes country codes and validates all options.
    ///
    /// # Errors
    ///
    /// [`PluginError::Config`] naming the invalid option.
    pub(crate) fn normalize_and_check(&mut self) -> Result<()> {
        if let Some(ref name) = self.session {
            session::check_name(name).map_err(bad)?;
        }
        if self.save_on_close && self.session.is_none() {
            return Err(bad("`save_on_close` requires `session` (or `container`)"));
        }
        if self.session_dir.is_some() && self.session.is_none() {
            return Err(bad("`session_dir` requires `session` (or `container`)"));
        }
        if self.interactive && self.session.is_none() {
            return Err(bad("`interactive` requires `session` (or `container`)"));
        }
        if let Some(ref dir) = self.session_dir {
            let text = dir.to_string_lossy();
            if text.trim().is_empty() || text.contains('\0') {
                return Err(bad("`session_dir` must be a non-empty path without NUL"));
            }
        }
        if let Some(ttl) = self.ttl_secs {
            if self.session.is_none() {
                return Err(bad("`ttl_secs` requires `session` (or `container`)"));
            }
            if !(1..=MAX_TTL_SECS).contains(&ttl) {
                return Err(bad(format!(
                    "`ttl_secs` must be between 1 and {MAX_TTL_SECS}, got {ttl}"
                )));
            }
        }
        if let Some(ref country) = self.country {
            self.country = Some(geo::normalize_country(country)?);
        }
        if let Some([lat, lon]) = self.geolocation
            && (!lat.is_finite()
                || !lon.is_finite()
                || !(-90.0..=90.0).contains(&lat)
                || !(-180.0..=180.0).contains(&lon))
        {
            return Err(bad(
                "`geolocation` must be finite [latitude, longitude] within [-90, 90] and [-180, 180]",
            ));
        }
        for proxy in &self.proxies {
            geo::validate_proxy_url(proxy)?;
        }
        if let Some(ref msg) = self.pause_message {
            if !self.interactive {
                return Err(bad("`pause_message` requires `interactive = true`"));
            }
            if msg.trim().is_empty() {
                return Err(bad("`pause_message` cannot be empty"));
            }
            if msg.chars().count() > MAX_PAUSE_MESSAGE_CHARS {
                return Err(bad(format!(
                    "`pause_message` cannot exceed {MAX_PAUSE_MESSAGE_CHARS} characters"
                )));
            }
            if msg.chars().any(|c| c.is_control() && c != '\n') {
                return Err(bad(
                    "`pause_message` may not contain control characters other than newline",
                ));
            }
        }
        if self.saves() && !cfg!(unix) {
            return Err(bad(
                "saving a session requires Unix owner-only file permissions",
            ));
        }
        Ok(())
    }
}
