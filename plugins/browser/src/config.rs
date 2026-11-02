//! The options of the plugin, and the checks that make a bad one an error at
//! start-up instead of a surprise at launch.

use std::fmt;
use std::path::PathBuf;

use crate::session;

use seleniumbase_rs_plugin::{PluginError, Result};
use serde::Deserialize;
use serde::de::{self, Deserializer, SeqAccess, Visitor};

/// Which extensions to load. The names are the ones Python SeleniumBase uses
/// for `--extension-zip` and `--extension-dir`.
///
/// Both options take a list of paths or one text with the paths separated by
/// commas, as Python does; an empty text means none.
///
/// ```
/// use seleniumbase_rs_plugin_browser::SessionConfig;
///
/// let config: SessionConfig = serde_json::from_value(serde_json::json!({
///     "extension_zip": "dark-reader.crx, adblock.zip",
///     "extension_dir": ["my-extension"],
/// }))?;
/// assert_eq!(config.extension_zip.len(), 2);
/// assert_eq!(config.extension_dir.len(), 1);
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
#[non_exhaustive]
pub struct SessionConfig {
    /// `.zip` and `.crx` files, unpacked into a temporary folder for each
    /// browser. Handled before `extension_dir`, as Python does.
    #[serde(deserialize_with = "paths")]
    pub extension_zip: Vec<PathBuf>,
    /// Unpacked extension folders, loaded where they are and never changed.
    #[serde(deserialize_with = "paths")]
    pub extension_dir: Vec<PathBuf>,
    /// Wait, once the browser answers, until every extension this plugin
    /// loaded that has a service worker (`background.service_worker` in its
    /// manifest) has a running one. Needs `extension_zip` or `extension_dir`,
    /// and a host that reports extension service workers; a host that does
    /// not makes the launch fail with a message naming this option.
    pub wait_for_workers: bool,
    /// How long `wait_for_workers` waits, from 1 to 30 seconds. The default is
    /// 10. Refused unless `wait_for_workers` is on.
    pub worker_timeout_secs: Option<u64>,
    /// The name of a saved session: the cookies of the browser's default
    /// context, kept in `<session_dir>/<name>.json`. They are put back when
    /// the browser starts; a session that was never saved is a fresh start.
    /// One to 64 letters, digits, `.`, `_` or `-`, starting with a letter or
    /// digit.
    pub session: Option<String>,
    /// Save the cookies under `session` just before the browser closes. Needs
    /// `session`, and a system with Unix file permissions.
    pub save_on_close: bool,
    /// The folder the session files live in. The default is `saved_sessions`
    /// in the working directory of the program, made absolute when the plugin
    /// is built. Needs `session`.
    pub session_dir: Option<PathBuf>,
    /// Offer the task `sbrs plugin run browser`: it opens a tab, waits until a
    /// person has signed in, and saves the session. Needs `session`, a headed
    /// browser and a system with Unix file permissions.
    pub interactive: bool,
    /// What the person is told while the task waits. Needs `interactive`.
    pub pause_message: Option<String>,
}

/// A path, a comma-separated text of paths, or a list of paths.
struct Paths;

impl<'de> Visitor<'de> for Paths {
    type Value = Vec<PathBuf>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a path, a comma-separated text of paths, or a list of paths")
    }

    fn visit_str<E: de::Error>(self, text: &str) -> std::result::Result<Self::Value, E> {
        let text = text.trim();
        if text.is_empty() {
            return Ok(Vec::new());
        }
        Ok(text
            .split(',')
            .map(|part| PathBuf::from(part.trim()))
            .collect())
    }

    fn visit_seq<A: SeqAccess<'de>>(
        self,
        mut seq: A,
    ) -> std::result::Result<Self::Value, A::Error> {
        let mut paths = Vec::new();
        while let Some(path) = seq.next_element::<String>()? {
            paths.push(PathBuf::from(path));
        }
        Ok(paths)
    }
}

fn paths<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Vec<PathBuf>, D::Error> {
    deserializer.deserialize_any(Paths)
}

/// How long `wait_for_workers` waits when `worker_timeout_secs` is not given.
pub(crate) const DEFAULT_WORKER_TIMEOUT_SECS: u64 = 10;

/// The most `worker_timeout_secs` may ask for.
pub(crate) const MAX_WORKER_TIMEOUT_SECS: u64 = 30;

/// The folder the session files live in when `session_dir` is not given.
pub(crate) const DEFAULT_SESSION_DIR: &str = "saved_sessions";

/// What the person is told while the interactive task waits, unless
/// `pause_message` says otherwise.
pub(crate) const DEFAULT_PAUSE_MESSAGE: &str = "Sign in in the browser window, then come back here.";

/// The longest `pause_message`, in characters.
const MAX_PAUSE_MESSAGE_CHARS: usize = 500;


fn bad(message: String) -> PluginError {
    PluginError::Config(format!("browser: {message}"))
}

impl SessionConfig {
    /// No extensions.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a `.zip` or `.crx` file.
    #[must_use]
    pub fn with_zip(mut self, path: impl Into<PathBuf>) -> Self {
        self.extension_zip.push(path.into());
        self
    }

    /// Adds an unpacked extension folder.
    #[must_use]
    pub fn with_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.extension_dir.push(path.into());
        self
    }

    /// Turns `wait_for_workers` on or off.
    #[must_use]
    pub fn with_wait_for_workers(mut self, wait: bool) -> Self {
        self.wait_for_workers = wait;
        self
    }

    /// Sets how many seconds `wait_for_workers` waits.
    #[must_use]
    pub fn with_worker_timeout_secs(mut self, seconds: u64) -> Self {
        self.worker_timeout_secs = Some(seconds);
        self
    }

    /// Names the saved session to restore.
    #[must_use]
    pub fn with_session(mut self, name: impl Into<String>) -> Self {
        self.session = Some(name.into());
        self
    }

    /// Turns `save_on_close` on or off.
    #[must_use]
    pub fn with_save_on_close(mut self, save: bool) -> Self {
        self.save_on_close = save;
        self
    }

    /// Sets the folder the session files live in.
    #[must_use]
    pub fn with_session_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.session_dir = Some(dir.into());
        self
    }

    /// Turns `interactive` on or off.
    #[must_use]
    pub fn with_interactive(mut self, interactive: bool) -> Self {
        self.interactive = interactive;
        self
    }

    /// Sets what the person is told while the interactive task waits.
    #[must_use]
    pub fn with_pause_message(mut self, message: impl Into<String>) -> Self {
        self.pause_message = Some(message.into());

        self
    }

    /// Whether no extension is configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.extension_zip.is_empty() && self.extension_dir.is_empty()
    }

    /// Every configured path: the archives first, then the folders.
    pub(crate) fn sources(&self) -> Vec<PathBuf> {
        let mut all = self.extension_zip.clone();
        all.extend(self.extension_dir.iter().cloned());
        all
    }

    /// Checks every option; the error names the option.
    pub(crate) fn check(&self) -> Result<()> {
            self.check_extensions()?;
            self.check_workers()?;
            self.check_session()?;
            self.check_interactive()
        }
    
        /// The seconds `wait_for_workers` waits: `worker_timeout_secs`, else 10.
        pub(crate) fn worker_timeout_secs_or_default(&self) -> u64 {
            self.worker_timeout_secs
                .unwrap_or(DEFAULT_WORKER_TIMEOUT_SECS)
        }
    
        /// What the interactive task tells the person.
        pub(crate) fn pause_message_or_default(&self) -> &str {
            self.pause_message
                .as_deref()
                .unwrap_or(DEFAULT_PAUSE_MESSAGE)
        }
    
        /// Whether the plugin saves a session: when the browser closes, or in the
        /// interactive task.
        pub(crate) fn saves(&self) -> bool {
            self.save_on_close || self.interactive
        }
    
        fn check_extensions(&self) -> Result<()> {
            for (option, list) in [
                ("extension_zip", &self.extension_zip),
                ("extension_dir", &self.extension_dir),
            ] {
                if list.iter().any(|p| p.to_string_lossy().trim().is_empty()) {
                    return Err(bad(format!("`{option}` has an empty entry")));
                }
            }
            // Chrome takes the folders as one comma-separated list, and the host
            // refuses a folder whose path holds a comma.
            if let Some(path) = self
                .extension_dir
                .iter()
                .find(|p| p.to_string_lossy().contains(','))
            {
                return Err(bad(format!(
                    "`extension_dir` entry `{}` holds a comma, which Chrome's list of extension folders cannot carry; rename the folder",
                    path.display()
                )));
            }
            Ok(())
        }
    
        fn check_workers(&self) -> Result<()> {
            if self.worker_timeout_secs.is_some() && !self.wait_for_workers {
                return Err(bad(
                    "`worker_timeout_secs` needs `wait_for_workers`: there is no wait to limit"
                        .to_owned(),
                ));
            }
            if let Some(seconds) = self.worker_timeout_secs
                && !(1..=MAX_WORKER_TIMEOUT_SECS).contains(&seconds)
            {
                return Err(bad(format!(
                    "`worker_timeout_secs` must be between 1 and {MAX_WORKER_TIMEOUT_SECS}, not {seconds}"
                )));
            }
            if self.wait_for_workers && self.is_empty() {
                return Err(bad(
                    "`wait_for_workers` needs `extension_zip` or `extension_dir`: there is no extension to wait for"
                        .to_owned(),
                ));
            }
            Ok(())
        }
    
        fn check_session(&self) -> Result<()> {
            match &self.session {
                Some(name) if !session::valid_name(name) => {
                    return Err(bad(format!(
                        "`session` {name:?} is not a valid name: use 1 to 64 letters, digits, `.`, `_` or `-`, starting with a letter or a digit"
                    )));
                }
                Some(_) => {}
                None => {
                    for (on, option, why) in [
                        (
                            self.save_on_close,
                            "save_on_close",
                            "there is no name to save the cookies under",
                        ),
                        (
                            self.session_dir.is_some(),
                            "session_dir",
                            "there is no session file to put in it",
                        ),
                        (
                            self.interactive,
                            "interactive",
                            "there is no session to save the sign-in under",
                        ),
                    ] {
                        if on {
                            return Err(bad(format!("`{option}` needs `session`: {why}")));
                        }
                    }
                }
            }
            if let Some(dir) = &self.session_dir {
                let text = dir.to_string_lossy();
                if text.trim().is_empty() || text.contains('\0') {
                    return Err(bad(
                        "`session_dir` is empty or holds a NUL character".to_owned()
                    ));
                }
            }
            // Files are written with mode 0600 through a temporary file, which
            // needs Unix permissions; ACLs are not handled yet.
            if cfg!(not(unix)) && self.saves() {
                return Err(bad(
                    "saving a session (`save_on_close`, `interactive`) needs Unix file permissions, which this system does not have"
                        .to_owned(),
                ));
            }
            Ok(())
        }
    
        fn check_interactive(&self) -> Result<()> {
            let Some(message) = &self.pause_message else {
                return Ok(());
            };
            if !self.interactive {
                return Err(bad(
                    "`pause_message` needs `interactive`: there is no pause to describe".to_owned(),
                ));
            }
            if message.trim().is_empty() {
                return Err(bad("`pause_message` is empty".to_owned()));
            }
            if message.chars().count() > MAX_PAUSE_MESSAGE_CHARS {
                return Err(bad(format!(
                    "`pause_message` is longer than {MAX_PAUSE_MESSAGE_CHARS} characters"
                )));
            }
            if message.chars().any(|c| c.is_control() && c != '\n') {
                return Err(bad(
                    "`pause_message` holds a control character; use plain text".to_owned(),
                ));
            }
            Ok(())
        }
}
