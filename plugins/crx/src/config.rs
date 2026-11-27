//! Configuration for the unified `crx` browser-extension plugin.

use std::fmt;
use std::path::PathBuf;

use seleniumbase_rs_plugin::{PluginError, Result};
use serde::Deserialize;
use serde::de::{self, Deserializer, SeqAccess, Visitor};

/// How long `wait_for_workers` waits when `worker_timeout_secs` is unset.
pub(crate) const DEFAULT_WORKER_TIMEOUT_SECS: u64 = 10;

/// Maximum allowed `worker_timeout_secs`.
pub(crate) const MAX_WORKER_TIMEOUT_SECS: u64 = 30;

/// Options for [`CrxExtensions`](crate::CrxExtensions): `[plugins.crx]` in a
/// settings file or `--plugin-opt 'crx.extension_dir=["my-extension"]'`.
///
/// Accepts packed archives via `extension_zip` (or the legacy `files` alias)
/// and unpacked Manifest V3 extension folders via `extension_dir`. Each path
/// option accepts either a JSON/TOML list of paths or a comma-separated string.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
#[non_exhaustive]
pub struct CrxConfig {
    /// Legacy alias for `.crx` / `.zip` archive paths; merged ahead of `extension_zip`.
    #[serde(deserialize_with = "paths")]
    pub files: Vec<PathBuf>,
    /// `.crx` and `.zip` extension archives, unpacked into per-launch temp dirs.
    #[serde(deserialize_with = "paths")]
    pub extension_zip: Vec<PathBuf>,
    /// Unpacked Manifest V3 extension folders, loaded in place without modifying them.
    #[serde(deserialize_with = "paths")]
    pub extension_dir: Vec<PathBuf>,
    /// Wait in `on_browser` until every loaded extension with a
    /// `background.service_worker` reports a running worker.
    pub wait_for_workers: bool,
    /// Timeout in seconds (`1..=30`, default `10`) for `wait_for_workers`.
    pub worker_timeout_secs: Option<u64>,
    /// Enforce `"manifest_version": 3` on every extension (default `true`).
    #[serde(default = "default_true")]
    pub require_manifest_v3: bool,
}

const fn default_true() -> bool {
    true
}

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
        let mut out = Vec::new();
        while let Some(path) = seq.next_element::<String>()? {
            out.push(PathBuf::from(path));
        }
        Ok(out)
    }
}

fn paths<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Vec<PathBuf>, D::Error> {
    deserializer.deserialize_any(Paths)
}

fn bad(message: impl fmt::Display) -> PluginError {
    PluginError::Config(format!("crx: {message}"))
}

/// Fluent builder for [`CrxConfig`].
#[must_use = "a builder does nothing until `build` is called"]
#[derive(Clone, Debug)]
pub struct CrxConfigBuilder {
    config: CrxConfig,
}

impl Default for CrxConfigBuilder {
    fn default() -> Self {
        Self {
            config: CrxConfig::new(),
        }
    }
}

impl CrxConfigBuilder {
    /// Adds a `.crx` or `.zip` archive.
    #[must_use = "a builder does nothing until `build` is called"]
    pub fn zip(mut self, path: impl Into<PathBuf>) -> Self {
        self.config.extension_zip.push(path.into());
        self
    }

    /// Adds an unpacked extension directory.
    #[must_use = "a builder does nothing until `build` is called"]
    pub fn dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.config.extension_dir.push(path.into());
        self
    }

    /// Enables or disables waiting for extension service workers on launch.
    #[must_use = "a builder does nothing until `build` is called"]
    pub fn wait_for_workers(mut self, wait: bool) -> Self {
        self.config.wait_for_workers = wait;
        self
    }

    /// Sets the worker wait timeout in seconds (`1..=30`).
    #[must_use = "a builder does nothing until `build` is called"]
    pub fn worker_timeout_secs(mut self, seconds: u64) -> Self {
        self.config.worker_timeout_secs = Some(seconds);
        self
    }

    /// Sets whether Manifest V3 validation is enforced (`true` by default).
    #[must_use = "a builder does nothing until `build` is called"]
    pub fn require_manifest_v3(mut self, require: bool) -> Self {
        self.config.require_manifest_v3 = require;
        self
    }

    /// Validates options and returns the [`CrxConfig`].
    ///
    /// # Errors
    ///
    /// [`PluginError::Config`] when a path is empty, an unpacked folder path
    /// contains a comma, or worker timeout options are invalid.
    pub fn build(self) -> Result<CrxConfig> {
        self.config.check()?;
        Ok(self.config)
    }
}

impl CrxConfig {
    /// Empty extension config with Manifest V3 enforcement on.
    #[must_use]
    pub fn new() -> Self {
        Self {
            require_manifest_v3: true,
            ..Self::default()
        }
    }

    /// Starts a [`CrxConfigBuilder`].
    #[must_use = "a builder does nothing until `build` is called"]
    pub fn builder() -> CrxConfigBuilder {
        CrxConfigBuilder::default()
    }

    /// Converts this config into a builder.
    #[must_use = "a builder does nothing until `build` is called"]
    pub fn into_builder(self) -> CrxConfigBuilder {
        CrxConfigBuilder { config: self }
    }

    /// All configured archive paths (`files` followed by `extension_zip`).
    pub(crate) fn archives(&self) -> impl Iterator<Item = &PathBuf> {
        self.files.iter().chain(self.extension_zip.iter())
    }

    /// Whether any archive is configured.
    #[must_use]
    pub fn has_archives(&self) -> bool {
        !self.files.is_empty() || !self.extension_zip.is_empty()
    }

    /// Whether no extension is configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        !self.has_archives() && self.extension_dir.is_empty()
    }

    /// All configured source paths for capability declarations.
    pub(crate) fn sources(&self) -> Vec<PathBuf> {
        self.archives()
            .chain(self.extension_dir.iter())
            .cloned()
            .collect()
    }

    /// Effective timeout for `wait_for_workers`.
    #[must_use]
    pub fn worker_timeout_secs_or_default(&self) -> u64 {
        self.worker_timeout_secs
            .unwrap_or(DEFAULT_WORKER_TIMEOUT_SECS)
    }

    /// Validates all options.
    ///
    /// # Errors
    ///
    /// [`PluginError::Config`] naming the invalid option.
    pub(crate) fn check(&self) -> Result<()> {
        for (option, list) in [
            ("files", &self.files),
            ("extension_zip", &self.extension_zip),
            ("extension_dir", &self.extension_dir),
        ] {
            for path in list {
                let text = path.to_string_lossy();
                if text.trim().is_empty() {
                    return Err(bad(format!("`{option}` contains an empty path")));
                }
                if option == "extension_dir" && text.contains(',') {
                    return Err(bad(format!(
                        "`extension_dir` path `{text}` contains a comma, which Chrome splits --load-extension on"
                    )));
                }
            }
        }
        if self.wait_for_workers && self.is_empty() {
            return Err(bad(
                "`wait_for_workers` requires at least one entry in `files`, `extension_zip`, or `extension_dir`",
            ));
        }
        if let Some(secs) = self.worker_timeout_secs {
            if !self.wait_for_workers {
                return Err(bad(
                    "`worker_timeout_secs` requires `wait_for_workers = true`",
                ));
            }
            if !(1..=MAX_WORKER_TIMEOUT_SECS).contains(&secs) {
                return Err(bad(format!(
                    "`worker_timeout_secs` must be between 1 and {MAX_WORKER_TIMEOUT_SECS}, got {secs}"
                )));
            }
        }
        Ok(())
    }
}
