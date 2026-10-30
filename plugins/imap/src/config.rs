//! The options of the plugin, and the checks that make a bad one an error at
//! start-up instead of a surprise in the middle of a wait.

use std::fmt;

use seleniumbase_rs_plugin::{PluginError, Result};
use serde::{Deserialize, Serialize};

/// The longest `timeout_secs` accepted.
pub const MAX_TIMEOUT_SECS: u64 = 3_600;

/// The longest `poll_secs` accepted.
pub const MAX_POLL_SECS: u64 = 300;

/// The mailbox to read and how to get into it. The password is never an
/// option: `password_env` names the environment variable that holds it.
///
/// ```
/// use seleniumbase_rs_plugin_imap::ImapConfig;
///
/// let config: ImapConfig = serde_json::from_value(serde_json::json!({
///     "host": "imap.example.com",
///     "user": "me@example.com",
///     "password_env": "MAIL_APP_PASSWORD",
/// }))?;
/// assert_eq!(config.port, 993);
/// assert_eq!(config.mailbox, "INBOX");
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ImapConfig {
    /// The IMAP server, such as `imap.example.com`. The connection is TLS from
    /// the first byte (IMAPS).
    pub host: String,
    /// The IMAPS port.
    pub port: u16,
    /// The login name.
    pub user: String,
    /// The NAME of the environment variable that holds the password or app
    /// password.
    pub password_env: String,
    /// The mailbox to watch.
    pub mailbox: String,
    /// Seconds between two looks at the mailbox.
    pub poll_secs: u64,
    /// Seconds to wait for a matching email before giving up.
    pub timeout_secs: u64,
}

impl Default for ImapConfig {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: 993,
            user: String::new(),
            password_env: String::new(),
            mailbox: "INBOX".into(),
            poll_secs: 5,
            timeout_secs: 120,
        }
    }
}

fn bad(message: String) -> PluginError {
    PluginError::Config(format!("imap: {message}"))
}

impl ImapConfig {
    /// Checks every option; the error names the option.
    pub(crate) fn check(&self) -> Result<()> {
        if self.host.is_empty() {
            return Err(bad("`host` is required".into()));
        }
        if !self
            .host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_'))
        {
            return Err(bad(
                "`host` must be a host name such as imap.example.com".into()
            ));
        }
        if self.port == 0 {
            return Err(bad("`port` must not be 0".into()));
        }
        if self.user.is_empty() || self.user.chars().any(char::is_control) {
            return Err(bad("`user` is required and must be plain text".into()));
        }
        let name = &self.password_env;
        if name.is_empty() {
            return Err(bad(
                "`password_env` is required: the name of the environment variable that holds the password"
                    .into(),
            ));
        }
        if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            || name.starts_with(|c: char| c.is_ascii_digit())
        {
            return Err(bad(
                "`password_env` must be the NAME of an environment variable (letters, digits and `_`), not the password itself"
                    .into(),
            ));
        }
        if self.mailbox.is_empty() || self.mailbox.chars().any(char::is_control) {
            return Err(bad("`mailbox` is required and must be plain text".into()));
        }
        if !(1..=MAX_POLL_SECS).contains(&self.poll_secs) {
            return Err(bad(format!(
                "`poll_secs` must be between 1 and {MAX_POLL_SECS}"
            )));
        }
        if !(1..=MAX_TIMEOUT_SECS).contains(&self.timeout_secs) {
            return Err(bad(format!(
                "`timeout_secs` must be between 1 and {MAX_TIMEOUT_SECS}"
            )));
        }
        Ok(())
    }

    /// The password, read through `get` from the variable `password_env` names.
    pub(crate) fn password_with(&self, get: &dyn Fn(&str) -> Option<String>) -> Result<Secret> {
        get(&self.password_env)
            .filter(|value| !value.is_empty())
            .map(Secret)
            .ok_or_else(|| {
                bad(format!(
                    "the environment variable `{}` named by `password_env` is not set or is empty; it must hold the password or app password",
                    self.password_env
                ))
            })
    }
}

/// A password that cannot be printed by accident.
pub(crate) struct Secret(String);

impl Secret {
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_secret_never_prints() {
        let secret = Secret("hunter2".into());
        assert_eq!(format!("{secret:?}"), "Secret(<redacted>)");
        assert_eq!(secret.expose(), "hunter2");
    }
}
