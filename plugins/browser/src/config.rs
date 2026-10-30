//! The options of the plugin, and the checks that make a bad one an error at
//! start-up instead of a surprise at launch.

use std::fmt;
use std::path::PathBuf;

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
}
