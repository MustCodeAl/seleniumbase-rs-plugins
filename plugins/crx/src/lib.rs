//! A seleniumbase-rs plugin that loads packed Chrome extensions (`.crx` files).
//!
//! Chrome only loads unpacked extension folders from the command line. This
//! plugin takes `.crx` files (CRX3, the current format, and the older CRX2),
//! strips the signed header, unpacks the zip into a temporary folder and adds
//! the folder to the browser's start-up settings. The folders are deleted when
//! the browser closes.
//!
//! The signature in the header is **not** verified: load only files you trust,
//! as you would install them by hand.
//!
//! ```no_run
//! use seleniumbase_rs_plugin::PluginSet;
//! use seleniumbase_rs_plugin_crx::CrxExtensions;
//!
//! let plugins = PluginSet::new().with(CrxExtensions::new(["extensions/dark-reader.crx"]))?;
//! # Ok::<(), seleniumbase_rs_plugin::PluginError>(())
//! ```

use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use seleniumbase_rs_plugin::{
    Capability, Category, Configurable, LaunchSettings, Metadata, PathScope, Plugin, PluginError,
    Requirements, Result, async_trait,
};
use tempfile::TempDir;

/// Unpacked archives above this size are refused, as a guard against zip bombs.
const MAX_UNPACKED: u64 = 512 * 1024 * 1024;

impl Configurable for CrxExtensions {
    const NAME: &'static str = "crx";

    fn describe() -> Metadata {
        Metadata::new(Category::Extension)
            .version(env!("CARGO_PKG_VERSION"))
            .summary("Loads .crx extension files into the browser it starts")
            .capability(Capability::LaunchExtensions)
            .capability(Capability::HostFsWrite(PathScope::Temp))
    }

    /// Options: `files`, an array of `.crx` paths.
    fn configure(options: &serde_json::Value) -> Result<Self> {
        let files = options
            .get("files")
            .and_then(serde_json::Value::as_array)
            .and_then(|items| items.iter().map(|v| v.as_str()).collect::<Option<Vec<_>>>())
            .ok_or_else(|| PluginError::Config("`files` must be an array of paths".into()))?;
        Ok(Self::new(files))
    }
}

/// Loads `.crx` files into the browser it starts.
#[derive(Debug)]
pub struct CrxExtensions {
    files: Vec<PathBuf>,
    unpacked: Mutex<Vec<TempDir>>,
}

impl CrxExtensions {
    /// Loads these `.crx` files.
    pub fn new<I, P>(files: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: Into<PathBuf>,
    {
        Self {
            files: files.into_iter().map(Into::into).collect(),
            unpacked: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait]
impl Plugin for CrxExtensions {
    fn name(&self) -> &str {
        "crx"
    }

    fn requirements(&self) -> Requirements {
        Requirements::CHROMIUM_ONLY | Requirements::LAUNCH_ONLY
    }

    fn metadata(&self) -> Metadata {
        Self::describe().capability(Capability::HostFsRead(PathScope::Declared(
            self.files.clone(),
        )))
    }

    /// A fresh instance for each browser, so closing one pooled browser does
    /// not delete the unpacked folders of the others.
    fn per_launch(&self) -> Option<Arc<dyn Plugin>> {
        Some(Arc::new(Self::new(self.files.clone())))
    }

    async fn before_launch(&self, launch: &mut LaunchSettings) -> Result<()> {
        for file in &self.files {
            let bytes = std::fs::read(file).map_err(|error| {
                PluginError::other(format!("cannot read {}: {error}", file.display()))
            })?;
            let dir = tempfile::Builder::new()
                .prefix("sbrs-crx-")
                .tempdir()
                .map_err(|error| {
                    PluginError::other(format!(
                        "cannot make a folder for {}: {error}",
                        file.display()
                    ))
                })?;
            unpack(&bytes, dir.path())
                .map_err(|error| PluginError::other(format!("{}: {error}", file.display())))?;
            launch.extensions.push(dir.path().to_path_buf());
            self.unpacked
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(dir);
        }
        Ok(())
    }

    async fn on_close(&self) -> Result<()> {
        // Dropping the folders deletes them.
        self.unpacked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
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
        // Version 3: one length for the signed header.
        3 => 12usize.checked_add(word(8)?),
        // Version 2: a public key and a signature, each with its length.
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
/// [`CrxError`] when the file is not a CRX file or its archive cannot be
/// unpacked.
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
    fn the_plugin_adds_the_unpacked_folder_and_deletes_it_on_close() {
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
