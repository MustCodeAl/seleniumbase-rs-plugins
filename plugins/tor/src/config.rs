//! The options of the tor plugin.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use seleniumbase_rs_plugin::PluginError;
use serde::Deserialize;

/// Whether every browser context gets a circuit of its own.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Isolation {
    /// Every browser context goes through a forwarder of its own, which Tor
    /// puts on its own circuits. The browser's default context and its other
    /// tabs share one more.
    #[default]
    PerContext,
    /// The whole browser goes through one forwarder, so all of it shares
    /// circuits.
    Browser,
}

/// How the plugin proves to Tor's control port that it may read the bootstrap
/// state. Exactly one of the two fields is set.
///
/// A password is never an option value: `password_env` names the environment
/// variable that holds it, and the variable is read when it is needed.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
#[non_exhaustive]
pub struct ControlAuth {
    /// The authentication cookie file of the Tor daemon (`SAFECOOKIE`), such
    /// as `/var/run/tor/control.authcookie`. The plugin reads this one file.
    pub cookie_path: Option<PathBuf>,
    /// The environment variable that holds the control password
    /// (`HASHEDPASSWORD`).
    pub password_env: Option<String>,
}

impl ControlAuth {
    /// Authenticate with the cookie file at `path`.
    #[must_use]
    pub fn cookie(path: impl Into<PathBuf>) -> Self {
        Self {
            cookie_path: Some(path.into()),
            password_env: None,
        }
    }

    /// Authenticate with the password in the environment variable `name`.
    #[must_use]
    pub fn password_env(name: impl Into<String>) -> Self {
        Self {
            cookie_path: None,
            password_env: Some(name.into()),
        }
    }

    /// Checks that exactly one method is named and that the name is usable.
    pub(crate) fn validate(&self) -> Result<(), PluginError> {
        let bad = |what: String| PluginError::Config(format!("tor: {what}"));
        match (&self.cookie_path, &self.password_env) {
            (Some(_), Some(_)) => Err(bad(
                "`control_auth` names both `cookie_path` and `password_env`; name exactly one"
                    .to_owned(),
            )),
            (None, None) => Err(bad(
                "`control_auth` needs `cookie_path` (a cookie file) or `password_env` (the name \
                     of an environment variable that holds the password)"
                    .to_owned(),
            )),
            (Some(path), None) if path.as_os_str().is_empty() => {
                Err(bad("`control_auth.cookie_path` is empty".to_owned()))
            }
            (None, Some(name))
                if name.is_empty()
                    || name.contains(['=', '\0'])
                    || name.chars().any(char::is_whitespace) =>
            {
                Err(bad(format!(
                    "`control_auth.password_env` {name:?} is not an environment variable name"
                )))
            }
            _ => Ok(()),
        }
    }
}

/// The options of [`Tor`](crate::Tor): `[plugins.tor]` in a config file,
/// `--plugin-opt 'tor.socks="127.0.0.1:9150"'` on the command line.
///
/// An option that is not listed here is an error, so a typo does not turn a
/// protection off without a word.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
#[non_exhaustive]
pub struct TorConfig {
    /// Where Tor's SocksPort listens. Default `127.0.0.1:9050`. Only a
    /// loopback address is accepted.
    pub socks: SocketAddr,
    /// Where Tor's control port listens, `127.0.0.1:9051` for a default
    /// daemon. Default none. It is used for one thing: to read whether Tor
    /// finished bootstrapping. Only a loopback address is accepted, and
    /// [`control_auth`](Self::control_auth) is required with it.
    pub control: Option<SocketAddr>,
    /// How to authenticate to the control port. Default none.
    pub control_auth: Option<ControlAuth>,
    /// One circuit set per browser context, or one for the whole browser.
    /// Default `per-context`.
    pub isolation: Isolation,
    /// Refuse to start the browser until Tor reports that it finished
    /// bootstrapping. Default `true`. It needs [`control`](Self::control);
    /// without it the plugin can only check that something answers as a SOCKS5
    /// proxy at [`socks`](Self::socks).
    pub require_bootstrapped: bool,
}

/// Refuses an address that is not on this machine, or that has no port.
fn require_loopback(option: &str, address: SocketAddr) -> Result<(), PluginError> {
    if !address.ip().is_loopback() {
        return Err(PluginError::Config(format!(
            "tor: `{option}` must be a loopback address (127.0.0.1 or ::1), got {address}: the \
             plugin only talks to a Tor daemon on this machine"
        )));
    }
    if address.port() == 0 {
        return Err(PluginError::Config(format!(
            "tor: `{option}` needs a port, got {address}"
        )));
    }
    Ok(())
}

impl Default for TorConfig {
    fn default() -> Self {
        Self {
            socks: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9050),
            control: None,
            control_auth: None,
            isolation: Isolation::default(),
            require_bootstrapped: true,
        }
    }
}

impl TorConfig {
    /// The default options.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets [`socks`](Self::socks).
    #[must_use]
    pub fn socks(mut self, socks: SocketAddr) -> Self {
        self.socks = socks;
        self
    }

    /// Sets [`control`](Self::control) and [`control_auth`](Self::control_auth).
    #[must_use]
    pub fn control(mut self, control: SocketAddr, auth: ControlAuth) -> Self {
        self.control = Some(control);
        self.control_auth = Some(auth);
        self
    }

    /// Sets [`isolation`](Self::isolation).
    #[must_use]
    pub fn isolation(mut self, isolation: Isolation) -> Self {
        self.isolation = isolation;
        self
    }

    /// Sets [`require_bootstrapped`](Self::require_bootstrapped).
    #[must_use]
    pub fn require_bootstrapped(mut self, require: bool) -> Self {
        self.require_bootstrapped = require;
        self
    }

    /// Checks the options.
    ///
    /// # Errors
    ///
    /// [`PluginError::Config`] when `socks` or `control` is not a loopback
    /// address, when `control` has no `control_auth` or the other way round,
    /// or when `control_auth` does not name exactly one method.
    pub fn validate(&self) -> Result<(), PluginError> {
        require_loopback("socks", self.socks)?;
        match (self.control, &self.control_auth) {
            (Some(control), Some(auth)) => {
                require_loopback("control", control)?;
                auth.validate()
            }
            (Some(_), None) => Err(PluginError::Config(
                "tor: `control` needs `control_auth` (`{ cookie_path = \"...\" }` or \
                     `{ password_env = \"...\" }`): the plugin never uses a control port without \
                     authenticating"
                    .to_owned(),
            )),
            (None, Some(_)) => Err(PluginError::Config(
                "tor: `control_auth` is set but `control` is not; set `control` to the control \
                     port address, such as 127.0.0.1:9051"
                    .to_owned(),
            )),
            (None, None) => Ok(()),
        }
    }
}
