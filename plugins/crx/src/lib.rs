//! The single seleniumbase-rs plugin for loading Chromium browser extensions
//! from `.crx` (CRX3 and CRX2), `.zip`, and unpacked Manifest V3 folders, with
//! optional service-worker readiness waits.
//!
//! Packed archives are unpacked into per-launch temporary directories (prefix
//! `sbrs-crx-`, deleted when the browser closes) with zip-bomb (512 MiB) and
//! path-traversal guards. Unpacked directories are loaded in place and never
//! modified.
//!
//! The cryptographic signature in a `.crx` header is **not** verified: load
//! only extensions you trust.
//!
//! ```no_run
//! use seleniumbase_rs_plugin::PluginSet;
//! use seleniumbase_rs_plugin_crx::{CrxConfig, CrxExtensions};
//!
//! let config = CrxConfig::builder()
//!     .zip("extensions/dark-reader.crx")
//!     .dir("my-unpacked-extension")
//!     .wait_for_workers(true)
//!     .build()?;
//! let plugins = PluginSet::strict().with(CrxExtensions::from_config(config)?)?;
//! assert_eq!(plugins.names(), ["crx"]);
//! # Ok::<(), seleniumbase_rs_plugin::PluginError>(())
//! ```

mod config;
mod source;
mod workers;

use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use seleniumbase_rs_plugin::config::options;
use seleniumbase_rs_plugin::{
    BrowserHandle, Budgets, Capability, Category, Configurable, LaunchSettings, Metadata,
    PathScope, Plugin, PluginError, Requirements, Result, async_trait,
};
use tempfile::TempDir;

pub use config::{CrxConfig, CrxConfigBuilder};

/// Plugin name in [`PluginSet`](seleniumbase_rs_plugin::PluginSet) and CLI flags.
const NAME: &str = "crx";

/// Unpacked archives above this size are refused, as a guard against zip bombs.
const MAX_UNPACKED: u64 = 512 * 1024 * 1024;

fn wait_budgets(seconds: u64) -> Budgets {
    let mut budgets = Budgets::default();
    budgets.other = Some(Duration::from_secs(seconds) + workers::HOOK_HEADROOM);
    budgets
}

fn asks_for_old_headless(args: &[String]) -> bool {
    args.iter()
        .any(|arg| arg.trim_start_matches('-') == "headless=old")
}

/// Loads Chromium extensions from `.crx`, `.zip`, and unpacked folders.
#[derive(Debug)]
pub struct CrxExtensions {
    config: CrxConfig,
    unpacked: Mutex<Vec<TempDir>>,
    workers: Mutex<Vec<source::Worker>>,
}

impl CrxExtensions {
    /// Creates a plugin that loads these `.crx` / `.zip` archive paths.
    ///
    /// Keeps backward compatibility with legacy callers passing `.crx` files
    /// directly (Manifest V3 enforcement is relaxed unless built with
    /// [`from_config`](Self::from_config)).
    pub fn new<I, P>(files: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: Into<PathBuf>,
    {
        let config = CrxConfig {
            files: files.into_iter().map(Into::into).collect(),
            require_manifest_v3: false,
            ..CrxConfig::default()
        };
        Self::checked(config)
    }

    /// Creates a plugin from a validated [`CrxConfig`].
    ///
    /// # Errors
    ///
    /// [`PluginError::Config`] when any option in `config` is invalid.
    pub fn from_config(config: CrxConfig) -> Result<Self> {
        config.check()?;
        Ok(Self::checked(config))
    }

    fn checked(config: CrxConfig) -> Self {
        Self {
            config,
            unpacked: Mutex::new(Vec::new()),
            workers: Mutex::new(Vec::new()),
        }
    }

    /// Returns the configuration this plugin was built with.
    #[must_use]
    pub fn config(&self) -> &CrxConfig {
        &self.config
    }

    fn unpacked(&self) -> MutexGuard<'_, Vec<TempDir>> {
        self.unpacked.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn workers(&self) -> MutexGuard<'_, Vec<source::Worker>> {
        self.workers.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Configurable for CrxExtensions {
    const NAME: &'static str = NAME;

    fn describe() -> Metadata {
        Metadata::new(Category::Extension)
            .version(env!("CARGO_PKG_VERSION"))
            .summary("Loads Chromium extensions from .crx, .zip, and unpacked Manifest V3 folders")
            .capability(Capability::LaunchExtensions)
            .optional(Capability::HostFsWrite(PathScope::Temp))
            .optional(Capability::Clock)
    }

    /// Options: `files`, `extension_zip`, `extension_dir`, `wait_for_workers`,
    /// `worker_timeout_secs`, `require_manifest_v3`. `Value::Null` yields an
    /// empty configuration.
    fn configure(value: &serde_json::Value) -> Result<Self> {
        let config = if value.is_null() {
            CrxConfig::new()
        } else {
            options::<CrxConfig>(NAME, value)?
        };
        Self::from_config(config)
    }
}

#[async_trait]
impl Plugin for CrxExtensions {
    fn name(&self) -> &str {
        NAME
    }

    fn requirements(&self) -> Requirements {
        Requirements::CHROMIUM_ONLY | Requirements::LAUNCH_ONLY
    }

    fn metadata(&self) -> Metadata {
        let mut meta = Metadata::new(Category::Extension)
            .version(env!("CARGO_PKG_VERSION"))
            .summary("Loads Chromium extensions from .crx, .zip, and unpacked Manifest V3 folders")
            .capability(Capability::LaunchExtensions);
        if self.config.has_archives() {
            meta = meta.capability(Capability::HostFsWrite(PathScope::Temp));
        }
        let reads = self.config.sources();
        if !reads.is_empty() {
            meta = meta.capability(Capability::HostFsRead(PathScope::Declared(reads)));
        }
        if self.config.wait_for_workers {
            meta = meta
                .capability(Capability::Clock)
                .budget(wait_budgets(self.config.worker_timeout_secs_or_default()));
        }
        meta
    }

    fn per_launch(&self) -> Option<Arc<dyn Plugin>> {
        Some(Arc::new(Self::checked(self.config.clone())))
    }

    async fn before_launch(&self, launch: &mut LaunchSettings) -> Result<()> {
        if self.config.is_empty() {
            return Ok(());
        }
        if asks_for_old_headless(&launch.args) {
            return Err(PluginError::other(
                "crx: extensions do not load under `--headless=old`; use `--headless=new` or headed mode",
            ));
        }
        let prepared = source::prepare(&self.config, &std::env::temp_dir())?;
        for folder in prepared.folders {
            if !launch.extensions.contains(&folder) {
                launch.extensions.push(folder);
            }
        }
        self.unpacked().extend(prepared.temps);
        *self.workers() = prepared.workers;
        Ok(())
    }

    async fn on_browser(&self, browser: &dyn BrowserHandle) -> Result<()> {
        if !self.config.wait_for_workers {
            return Ok(());
        }
        let wanted = self.workers().clone();
        workers::wait(
            browser,
            &wanted,
            self.config.worker_timeout_secs_or_default(),
        )
        .await
    }

    async fn on_close(&self) -> Result<()> {
        self.unpacked().clear();
        self.workers().clear();
        Ok(())
    }
}

/// Why a file could not be unpacked.
#[derive(Debug)]
#[non_exhaustive]
pub enum CrxError {
    /// The file does not start like a CRX file, or its header is cut short.
    NotCrx(String),
    /// The archive inside could not be read or written out.
    Archive(String),
}

impl std::fmt::Display for CrxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotCrx(why) => write!(f, "not a CRX file: {why}"),
            Self::Archive(why) => write!(f, "cannot unpack the extension: {why}"),
        }
    }
}

impl std::error::Error for CrxError {}

/// The zip archive inside a CRX file (CRX3 or CRX2), without its header.
///
/// # Errors
///
/// [`CrxError::NotCrx`] when the bytes are not a CRX file.
pub fn archive(crx: &[u8]) -> std::result::Result<&[u8], CrxError> {
    let word = |at: usize| -> std::result::Result<usize, CrxError> {
        crx.get(at..at + 4)
            .map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize)
            .ok_or_else(|| CrxError::NotCrx("the header is cut short".into()))
    };
    if crx.get(..4) != Some(b"Cr24") {
        return Err(CrxError::NotCrx("it does not start with `Cr24`".into()));
    }
    let start = match word(4)? {
        3 => 12usize.checked_add(word(8)?),
        2 => 16usize
            .checked_add(word(8)?)
            .and_then(|n| n.checked_add(word(12).ok()?)),
        version => return Err(CrxError::NotCrx(format!("unknown version {version}"))),
    }
    .ok_or_else(|| CrxError::NotCrx("the header lengths overflow".into()))?;
    crx.get(start..)
        .ok_or_else(|| CrxError::NotCrx("the header is longer than the file".into()))
}

/// Unpacks a CRX file into `dest`, refusing entries that would land outside it.
///
/// # Errors
///
/// [`CrxError`] when the file is not a CRX file or its archive cannot be unpacked.
pub fn unpack(crx: &[u8], dest: &Path) -> std::result::Result<(), CrxError> {
    let archive_error = |error: &dyn std::fmt::Display| CrxError::Archive(error.to_string());
    let mut zip =
        zip::ZipArchive::new(Cursor::new(archive(crx)?)).map_err(|error| archive_error(&error))?;
    let mut written = 0u64;
    for index in 0..zip.len() {
        let mut entry = zip.by_index(index).map_err(|error| archive_error(&error))?;
        let Some(relative) = entry.enclosed_name() else {
            return Err(CrxError::Archive(format!(
                "the entry `{}` leaves its folder",
                entry.name().unwrap_or_default()
            )));
        };
        let target = dest.join(relative);
        if entry.is_dir() {
            std::fs::create_dir_all(&target).map_err(|error| archive_error(&error))?;
            continue;
        }
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(|error| archive_error(&error))?;
        }
        let mut bytes = Vec::new();
        (&mut entry)
            .take(MAX_UNPACKED - written + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| archive_error(&error))?;
        written += bytes.len() as u64;
        if written > MAX_UNPACKED {
            return Err(CrxError::Archive("it unpacks to more than 512 MB".into()));
        }
        std::fs::write(&target, &bytes).map_err(|error| archive_error(&error))?;
    }
    if !dest.join("manifest.json").is_file() {
        return Err(CrxError::Archive("it has no manifest.json".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use seleniumbase_rs_plugin_testing::block_on;
    use std::io::Write;
    use zip::write::SimpleFileOptions;

    fn zip_with(entries: &[(&str, &str)]) -> Vec<u8> {
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (name, body) in entries {
            writer
                .start_file(*name, SimpleFileOptions::default())
                .unwrap();
            writer.write_all(body.as_bytes()).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    fn crx3(zip: &[u8]) -> Vec<u8> {
        let header = b"\x12\x03fake-signed-header";
        let mut crx = b"Cr24".to_vec();
        crx.extend(3u32.to_le_bytes());
        crx.extend((header.len() as u32).to_le_bytes());
        crx.extend(header);
        crx.extend(zip);
        crx
    }

    fn crx2(zip: &[u8]) -> Vec<u8> {
        let mut crx = b"Cr24".to_vec();
        crx.extend(2u32.to_le_bytes());
        crx.extend(3u32.to_le_bytes());
        crx.extend(2u32.to_le_bytes());
        crx.extend(b"keysg");
        crx.extend(zip);
        crx
    }

    #[test]
    fn crx3_and_crx2_files_unpack_to_their_manifest() {
        let zip = zip_with(&[("manifest.json", r#"{"name":"x"}"#), ("js/a.js", "1")]);
        for crx in [crx3(&zip), crx2(&zip)] {
            let dir = tempfile::tempdir().unwrap();
            unpack(&crx, dir.path()).unwrap();
            assert!(dir.path().join("manifest.json").is_file());
            assert!(dir.path().join("js/a.js").is_file());
        }
    }

    #[test]
    fn files_that_are_not_crx_or_reach_outside_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            unpack(b"PK\x03\x04", dir.path()),
            Err(CrxError::NotCrx(_))
        ));
        assert!(matches!(
            unpack(b"Cr24\x03\0\0\0\xff\xff\xff\x7f", dir.path()),
            Err(CrxError::NotCrx(_))
        ));
        let escape = crx3(&zip_with(&[("manifest.json", "{}"), ("../evil.txt", "x")]));
        assert!(matches!(
            unpack(&escape, dir.path()),
            Err(CrxError::Archive(_))
        ));
        let no_manifest = crx3(&zip_with(&[("a.js", "1")]));
        assert!(matches!(
            unpack(&no_manifest, tempfile::tempdir().unwrap().path()),
            Err(CrxError::Archive(_))
        ));
    }

    #[test]
    fn loads_crx_zip_and_unpacked_mv3_and_cleans_up_on_close() {
        let source = tempfile::tempdir().unwrap();
        let mv3 = r#"{"manifest_version":3,"name":"demo","version":"1.0"}"#;
        let crx_file = source.path().join("ext.crx");
        std::fs::write(&crx_file, crx3(&zip_with(&[("manifest.json", mv3)]))).unwrap();
        let zip_file = source.path().join("ext.zip");
        std::fs::write(&zip_file, zip_with(&[("manifest.json", mv3)])).unwrap();
        let unpacked_dir = source.path().join("unpacked");
        std::fs::create_dir(&unpacked_dir).unwrap();
        std::fs::write(unpacked_dir.join("manifest.json"), mv3).unwrap();

        let cfg = CrxConfig::builder()
            .zip(&crx_file)
            .zip(&zip_file)
            .dir(&unpacked_dir)
            .build()
            .unwrap();
        let plugin = CrxExtensions::from_config(cfg).unwrap();
        let mut launch = LaunchSettings::default();
        block_on(plugin.before_launch(&mut launch)).unwrap();
        assert_eq!(launch.extensions.len(), 3);
        let temp_a = launch.extensions[0].clone();
        let temp_b = launch.extensions[1].clone();
        assert!(temp_a.join("manifest.json").is_file());
        assert!(temp_b.join("manifest.json").is_file());

        block_on(plugin.on_close()).unwrap();
        assert!(!temp_a.exists());
        assert!(!temp_b.exists());
        assert!(unpacked_dir.exists());
    }

    #[test]
    fn refuses_manifest_v2_when_mv3_required() {
        let source = tempfile::tempdir().unwrap();
        let dir = source.path().join("mv2");
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(
            dir.join("manifest.json"),
            r#"{"manifest_version":2,"name":"old","version":"1.0"}"#,
        )
        .unwrap();

        let cfg = CrxConfig::builder().dir(&dir).build().unwrap();
        let plugin = CrxExtensions::from_config(cfg).unwrap();
        let mut launch = LaunchSettings::default();
        let err = block_on(plugin.before_launch(&mut launch)).unwrap_err();
        assert!(err.to_string().contains("Manifest V3"), "{err}");
    }

    #[test]
    fn legacy_new_still_works_with_crx_files() {
        let source = tempfile::tempdir().unwrap();
        let file = source.path().join("ext.crx");
        std::fs::write(&file, crx3(&zip_with(&[("manifest.json", "{}")]))).unwrap();
        let plugin = CrxExtensions::new([&file]);
        let mut launch = LaunchSettings::default();
        block_on(plugin.before_launch(&mut launch)).unwrap();
        let folder = launch.extensions[0].clone();
        assert!(folder.join("manifest.json").is_file());
        block_on(plugin.on_close()).unwrap();
        assert!(!folder.exists());
    }
}
