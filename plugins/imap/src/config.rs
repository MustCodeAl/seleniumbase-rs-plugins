//! The options of the plugin, and the checks that make a bad one an error at
//! start-up instead of a surprise in the middle of a wait.

use std::fmt;

use seleniumbase_rs_plugin::{PluginError, Result};
use serde::{Deserialize, Serialize};

/// The longest `timeout_secs` accepted.
pub const MAX_TIMEOUT_SECS: u64 = 3_600;

/// The longest `poll_secs` accepted.
pub const MAX_POLL_SECS: u64 = 300;

/// The prefixes a `password_env` name must start with. The comparison is
/// case-sensitive.
const PASSWORD_ENV_PREFIXES: [&str; 3] = ["IMAP_", "MAIL_", "SB_"];

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
///
/// `password_env` must start with `IMAP_`, `MAIL_` or `SB_` (capitals, as
/// written). The password is sent to `host`, so a settings file that comes
/// with a cloned project must not be able to point the plugin at a variable
/// that holds some other secret, such as `GITHUB_TOKEN`. Any other name is
/// refused when the plugin is built; the error names the rule and the
/// variable (only when it looks like a variable name: capitals, digits and
/// `_`, so that a password pasted into the option is not printed back), and
/// the variable is not read.
///
/// ```
/// use seleniumbase_rs_plugin_imap::{Imap, ImapConfig};
///
/// let config = ImapConfig {
///     host: "imap.example.com".into(),
///     user: "me@example.com".into(),
///     password_env: "GITHUB_TOKEN".into(),
///     ..ImapConfig::default()
/// };
/// let error = Imap::new_with(config, &|_name| Some("never read".into())).unwrap_err();
/// assert_eq!(
///     error.to_string(),
///     "plugin configuration: imap: `password_env` must name a variable starting with IMAP_, MAIL_ or SB_ (got `GITHUB_TOKEN`)"
/// );
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
    /// The name must start with `IMAP_`, `MAIL_` or `SB_` (see the type's
    /// documentation), and the variable must be set when the plugin is built.
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

/// Whether `name` looks like the name of an environment variable: capital
/// ASCII letters, digits and `_` only. A `password_env` that does not may be a
/// password that someone pasted into the option, so an error never repeats it.
fn looks_like_variable_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
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
        // The password is sent to `host`, so only names meant for this plugin
        // are allowed: a settings file must not be able to point it at a
        // variable that holds some other secret. The name is repeated in the
        // message only when it looks like a variable name (capitals, digits
        // and `_`): anything else may be a password pasted into the option and
        // is not printed back. The variable of a refused name is never read.
        if !PASSWORD_ENV_PREFIXES
            .iter()
            .any(|prefix| name.starts_with(prefix))
        {
            let rule = "`password_env` must name a variable starting with IMAP_, MAIL_ or SB_";
            return Err(bad(if looks_like_variable_name(name) {
                format!("{rule} (got `{name}`)")
            } else {
                rule.into()
            }));
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
                    // Repeated only when it looks like a variable name: anything
                    // else may be a password pasted into the option.
                    let name = if looks_like_variable_name(&self.password_env) {
                        format!(" `{}`", self.password_env)
                    } else {
                        String::new()
                    };
                    bad(format!(
                        "the environment variable{name} named by `password_env` is not set or is empty; it must hold the password or app password"
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
    fn the_refusal_names_every_accepted_prefix() {
        let config = ImapConfig {
            host: "imap.example.com".into(),
            user: "me@example.com".into(),
            password_env: "GITHUB_TOKEN".into(),
            ..ImapConfig::default()
        };
        let message = config.check().unwrap_err().to_string();
        for prefix in PASSWORD_ENV_PREFIXES {
            assert!(message.contains(prefix), "{message}");
        }
    }

    #[test]
    fn only_capitals_digits_and_underscores_look_like_a_variable_name() {
        for name in ["PATH", "GITHUB_TOKEN", "SB_9", "_", "A1"] {
            assert!(looks_like_variable_name(name), "{name}");
        }
        for name in [
            "",
            "path",
            "Path",
            "SB_hunter2",
            "my secret",
            "pa$$word",
            "a=b",
            "ÄB",
        ] {
            assert!(!looks_like_variable_name(name), "{name}");
        }
    }

    #[test]
    fn a_secret_never_prints() {
        let secret = Secret("hunter2".into());
        assert_eq!(format!("{secret:?}"), "Secret(<redacted>)");
        assert_eq!(secret.expose(), "hunter2");
    }
}
