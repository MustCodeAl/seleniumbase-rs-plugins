//! Turns the configured paths into folders Chrome can load: archives are
//! unpacked into temporary folders, unpacked folders are used where they are,
//! and every folder must hold a Manifest V3 `manifest.json`.

use std::collections::HashSet;
use std::fmt::Display;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use seleniumbase_rs_plugin::{PluginError, Result};
use seleniumbase_rs_plugin_crx::unpack;
use serde_json::Value;
use tempfile::TempDir;

use crate::config::SessionConfig;

/// Archives larger than this are refused before they are read. It is the limit
/// the `crx` plugin puts on the size of what an archive unpacks to.
const MAX_ARCHIVE_BYTES: u64 = 512 * 1024 * 1024;

/// A `manifest.json` larger than this is not a manifest.
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;

/// What a launch needs from the configured paths.
#[derive(Debug, Default)]
pub(crate) struct Prepared {
    /// The folders to load, in order: the archives first, then the folders.
    pub(crate) folders: Vec<PathBuf>,
    /// The temporary folders the archives were unpacked into. Dropping them
    /// deletes the folders.
    pub(crate) temps: Vec<TempDir>,
}

/// The error for the path `given` of the option `option`.
fn problem(option: &str, given: &Path, what: impl Display) -> PluginError {
    PluginError::other(format!("browser: {option} `{}`: {what}", given.display()))
}

/// The real path of `given`, which must exist.
fn resolve(option: &str, given: &Path) -> Result<PathBuf> {
    fs::canonicalize(given).map_err(|error| match error.kind() {
        io::ErrorKind::NotFound => problem(option, given, "does not exist"),
        _ => problem(option, given, format!("cannot be read: {error}")),
    })
}

/// Resolves and unpacks everything `config` names, making the temporary
/// folders inside `temp_root`. Nothing is kept when one of them is refused:
/// the folders made so far are deleted.
///
/// # Errors
///
/// [`PluginError::Other`], naming the option and the path as the user wrote it.
pub(crate) fn prepare(config: &SessionConfig, temp_root: &Path) -> Result<Prepared> {
    let mut prepared = Prepared::default();
    let mut seen = HashSet::new();

    for given in &config.extension_zip {
        let option = "extension_zip";
        let real = resolve(option, given)?;
        let metadata = fs::metadata(&real)
            .map_err(|error| problem(option, given, format!("cannot be read: {error}")))?;
        if metadata.is_dir() {
            return Err(problem(
                option,
                given,
                "is a folder; use extension_dir for an unpacked extension",
            ));
        }
        if !metadata.is_file() {
            return Err(problem(option, given, "is not a regular file"));
        }
        if !seen.insert(real.clone()) {
            continue;
        }
        if metadata.len() > MAX_ARCHIVE_BYTES {
            return Err(problem(option, given, "is larger than 512 MiB"));
        }
        let bytes = fs::read(&real)
            .map_err(|error| problem(option, given, format!("cannot be read: {error}")))?;
        let temp = tempfile::Builder::new()
            .prefix("sbrs-browser-")
            .tempdir_in(temp_root)
            .map_err(|error| problem(option, given, format!("cannot be unpacked: {error}")))?;
        unpack_archive(&bytes, temp.path()).map_err(|what| problem(option, given, what))?;
        check_manifest(temp.path()).map_err(|what| problem(option, given, what))?;
        let folder = fs::canonicalize(temp.path())
            .map_err(|error| problem(option, given, format!("cannot be unpacked: {error}")))?;
        prepared.folders.push(folder);
        prepared.temps.push(temp);
    }

    for given in &config.extension_dir {
        let option = "extension_dir";
        let real = resolve(option, given)?;
        let metadata = fs::metadata(&real)
            .map_err(|error| problem(option, given, format!("cannot be read: {error}")))?;
        if !metadata.is_dir() {
            return Err(problem(
                option,
                given,
                "is a file; use extension_zip for a .zip or .crx file",
            ));
        }
        if !seen.insert(real.clone()) {
            continue;
        }
        check_manifest(&real).map_err(|what| problem(option, given, what))?;
        prepared.folders.push(real);
    }

    Ok(prepared)
}

/// Unpacks a CRX (version 2 or 3) or a plain ZIP file into `dest`. The format
/// is read from the first bytes, not from the file name.
fn unpack_archive(bytes: &[u8], dest: &Path) -> std::result::Result<(), String> {
    if bytes.starts_with(b"Cr24") {
        return unpack(bytes, dest).map_err(|error| error.to_string());
    }
    if bytes.starts_with(b"PK\x03\x04") || bytes.starts_with(b"PK\x05\x06") {
        // The crx plugin's code unpacks the ZIP behind a CRX header, with its
        // checks for entries that leave the folder and for the unpacked size.
        // A plain ZIP gets the smallest CRX3 header: the magic, version 3 and a
        // signed header of length 0.
        let mut wrapped = Vec::with_capacity(bytes.len() + 12);
        wrapped.extend_from_slice(b"Cr24");
        wrapped.extend_from_slice(&3u32.to_le_bytes());
        wrapped.extend_from_slice(&0u32.to_le_bytes());
        wrapped.extend_from_slice(bytes);
        return unpack(&wrapped, dest).map_err(|error| error.to_string());
    }
    Err("is neither a CRX nor a ZIP file".to_owned())
}

/// Checks that `folder` holds a Manifest V3 `manifest.json`.
fn check_manifest(folder: &Path) -> std::result::Result<(), String> {
    let path = folder.join("manifest.json");
    let metadata = fs::metadata(&path)
        .ok()
        .filter(fs::Metadata::is_file)
        .ok_or_else(|| "manifest.json is missing".to_owned())?;
    if metadata.len() > MAX_MANIFEST_BYTES {
        return Err("manifest.json is larger than 1 MiB".to_owned());
    }
    let bytes =
        fs::read(&path).map_err(|error| format!("manifest.json cannot be read: {error}"))?;
    // Chrome accepts a byte order mark; some editors add one.
    let text = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(&bytes);
    let manifest: Value = serde_json::from_slice(text)
        .map_err(|error| format!("manifest.json is not valid JSON: {error}"))?;
    let Some(object) = manifest.as_object() else {
        return Err("manifest.json is not a JSON object".to_owned());
    };
    match object.get("manifest_version") {
        None => Err(
            "manifest.json has no manifest_version; only Manifest V3 extensions are loaded"
                .to_owned(),
        ),
        Some(version) if version.as_u64() == Some(3) => Ok(()),
        Some(version) => Err(format!(
            "manifest_version is {version}; only Manifest V3 extensions are loaded"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};
    use zip::write::SimpleFileOptions;

    fn zip_with(entries: &[(&str, &str)]) -> Vec<u8> {
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (name, body) in entries {
            writer
                .start_file(*name, SimpleFileOptions::default())
                .expect("start a zip entry");
            writer.write_all(body.as_bytes()).expect("write an entry");
        }
        writer.finish().expect("finish the zip").into_inner()
    }

    const MANIFEST: &str = r#"{"manifest_version":3,"name":"x","version":"1"}"#;

    fn entries(temp_root: &Path) -> usize {
        fs::read_dir(temp_root).expect("a readable folder").count()
    }

    #[test]
    fn a_refused_extension_leaves_no_unpacked_folder_behind() {
        let fixtures = tempfile::tempdir().expect("temp dir");
        let temp_root = tempfile::tempdir().expect("temp dir");
        let good = fixtures.path().join("good.zip");
        fs::write(&good, zip_with(&[("manifest.json", MANIFEST)])).expect("write");
        let bad = fixtures.path().join("bad.zip");
        fs::write(&bad, b"PK\x03\x04 cut short").expect("write");

        let config = SessionConfig::new().with_zip(&good).with_zip(&bad);
        let error = prepare(&config, temp_root.path()).expect_err("the second archive is bad");
        assert!(error.to_string().contains("bad.zip"), "{error}");
        assert_eq!(
            entries(temp_root.path()),
            0,
            "the first unpacked folder is deleted"
        );
    }

    #[test]
    fn unpacked_folders_live_in_the_given_root_until_dropped() {
        let fixtures = tempfile::tempdir().expect("temp dir");
        let temp_root = tempfile::tempdir().expect("temp dir");
        let zip = fixtures.path().join("ext.zip");
        fs::write(&zip, zip_with(&[("manifest.json", MANIFEST)])).expect("write");

        let prepared = prepare(&SessionConfig::new().with_zip(&zip), temp_root.path())
            .expect("a good archive");
        assert_eq!(entries(temp_root.path()), 1);
        assert_eq!(prepared.folders.len(), 1);
        assert!(prepared.folders[0].starts_with(fs::canonicalize(temp_root.path()).expect("root")));
        drop(prepared);
        assert_eq!(entries(temp_root.path()), 0);
    }

    #[test]
    fn an_empty_zip_has_no_manifest() {
        let fixtures = tempfile::tempdir().expect("temp dir");
        let temp_root = tempfile::tempdir().expect("temp dir");
        let zip = fixtures.path().join("empty.zip");
        fs::write(&zip, zip_with(&[])).expect("write");
        let error = prepare(&SessionConfig::new().with_zip(&zip), temp_root.path())
            .expect_err("nothing to load");
        assert!(error.to_string().contains("manifest.json"), "{error}");
        assert_eq!(entries(temp_root.path()), 0);
    }
}
