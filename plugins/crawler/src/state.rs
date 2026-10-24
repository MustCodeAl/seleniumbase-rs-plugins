//! The state file: a crawl written down so a later run can go on where it
//! stopped.
//!
//! ```json
//! {"version":1,"config_hash":"…","visited":[…],"frontier":[[url,depth],…],
//!  "edges":[[from,to],…],"broken":[…],"pages":12,"blocked":[…]}
//! ```
//!
//! The file is written to `<name>.tmp` next to it and renamed over it, so a
//! crash never leaves half a file. A run resumes only when `config_hash`
//! equals the hash of the options that decide which pages are crawled; a file
//! of another crawl is ignored, never mixed in.

use std::path::{Path, PathBuf};

use seleniumbase_rs_plugin::{PluginError, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::report::Broken;

/// The version of the file format.
pub(crate) const VERSION: u32 = 1;

/// The largest state file read, in bytes.
const MAX_STATE_BYTES: u64 = 256 * 1024 * 1024;

/// The content of a state file.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct StateFile {
    pub(crate) version: u32,
    pub(crate) config_hash: String,
    /// Normalised addresses already loaded.
    pub(crate) visited: Vec<String>,
    /// Addresses still to load, with their depth.
    pub(crate) frontier: Vec<(String, u32)>,
    /// Links between pages.
    pub(crate) edges: Vec<(String, String)>,
    /// The broken pages found so far, so a resumed run reports them too.
    #[serde(default)]
    pub(crate) broken: Vec<Broken>,
    /// How many pages were loaded.
    #[serde(default)]
    pub(crate) pages: usize,
    /// The addresses robots.txt kept the crawl from.
    #[serde(default)]
    pub(crate) blocked: Vec<String>,
}

/// What reading the state file gave.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Loaded {
    /// There is no file yet.
    Missing,
    /// There is one, but of another crawl or another format; it will be
    /// overwritten.
    Other(&'static str),
    /// A crawl to go on with.
    Resume(StateFile),
}

fn failure(path: &Path, what: &str, error: impl std::fmt::Display) -> PluginError {
    PluginError::other(format!(
        "crawler: cannot {what} the state file `{}`: {error}",
        path.display()
    ))
}

/// Reads the file at `path` for a crawl whose options hash to `hash`.
pub(crate) fn load(path: &Path, hash: &str) -> Result<Loaded> {
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Loaded::Missing),
        Err(error) => return Err(failure(path, "read", error)),
    };
    if metadata.len() > MAX_STATE_BYTES {
        return Err(failure(path, "read", "it is larger than 256 MiB"));
    }
    let text = std::fs::read_to_string(path).map_err(|error| failure(path, "read", error))?;
    let state: StateFile = match serde_json::from_str(&text) {
        Ok(state) => state,
        Err(error) => return Err(failure(path, "parse", error)),
    };
    if state.version != VERSION {
        return Ok(Loaded::Other("it has another format version"));
    }
    if state.config_hash != hash {
        return Ok(Loaded::Other("it belongs to a crawl with other options"));
    }
    Ok(Loaded::Resume(state))
}

/// The sibling the file is written to before it is renamed.
pub(crate) fn temp_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".tmp");
    path.with_file_name(name)
}

/// Writes `state` to `path`, by a temporary file and a rename.
pub(crate) fn save(path: &Path, state: &StateFile) -> Result<()> {
    let bytes = serde_json::to_vec(state).map_err(|error| failure(path, "write", error))?;
    let temp = temp_path(path);
    std::fs::write(&temp, bytes).map_err(|error| failure(path, "write", error))?;
    std::fs::rename(&temp, path).map_err(|error| {
        let _ = std::fs::remove_file(&temp);
        failure(path, "write", error)
    })
}

/// A stable hash of `value`, as 16 hex digits (FNV-1a, 64 bits). It tells two
/// sets of options apart; it is not a security hash.
pub(crate) fn config_hash(value: &Value) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in value.to_string().bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    format!("{hash:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A folder under the system temporary folder, removed when dropped.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(label: &str) -> Self {
            let dir = std::env::temp_dir()
                .join(format!("sbrs-crawler-state-{label}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        fn file(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn sample(hash: &str) -> StateFile {
        StateFile {
            version: VERSION,
            config_hash: hash.into(),
            visited: vec!["https://a.test/".into()],
            frontier: vec![("https://a.test/b".into(), 1)],
            edges: vec![("https://a.test/".into(), "https://a.test/b".into())],
            broken: vec![Broken {
                url: "https://a.test/x".into(),
                from: None,
                status: 404,
            }],
            pages: 1,
            blocked: vec!["https://a.test/private".into()],
        }
    }

    #[test]
    fn a_saved_state_resumes_when_the_hash_matches() {
        let scratch = Scratch::new("resume");
        let path = scratch.file("crawl.json");
        assert_eq!(load(&path, "abc").unwrap(), Loaded::Missing);
        save(&path, &sample("abc")).unwrap();
        assert_eq!(load(&path, "abc").unwrap(), Loaded::Resume(sample("abc")));
        assert!(
            !temp_path(&path).exists(),
            "the temporary file is renamed away"
        );
    }

    #[test]
    fn a_state_of_other_options_or_another_version_is_ignored_not_mixed_in() {
        let scratch = Scratch::new("mismatch");
        let path = scratch.file("crawl.json");
        save(&path, &sample("abc")).unwrap();
        assert!(matches!(
            load(&path, "different").unwrap(),
            Loaded::Other(_)
        ));
        let mut old = sample("abc");
        old.version = 0;
        save(&path, &old).unwrap();
        assert!(matches!(load(&path, "abc").unwrap(), Loaded::Other(_)));
    }

    #[test]
    fn the_file_has_the_documented_keys() {
        let scratch = Scratch::new("keys");
        let path = scratch.file("crawl.json");
        save(&path, &sample("abc")).unwrap();
        let value: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(value["version"], 1);
        assert_eq!(value["config_hash"], "abc");
        assert_eq!(value["visited"], json!(["https://a.test/"]));
        assert_eq!(value["frontier"], json!([["https://a.test/b", 1]]));
        assert_eq!(
            value["edges"],
            json!([["https://a.test/", "https://a.test/b"]])
        );
    }

    #[test]
    fn a_file_that_is_not_a_state_is_an_error_and_is_left_alone() {
        let scratch = Scratch::new("corrupt");
        let path = scratch.file("crawl.json");
        std::fs::write(&path, "not json").unwrap();
        let error = load(&path, "abc").unwrap_err().to_string();
        assert!(error.contains("cannot parse the state file"), "{error}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "not json");
    }

    #[test]
    fn a_folder_that_does_not_exist_is_an_error_naming_the_file() {
        let scratch = Scratch::new("nofolder");
        let path = scratch.file("missing-dir/crawl.json");
        let error = save(&path, &sample("abc")).unwrap_err().to_string();
        assert!(error.contains("cannot write the state file"), "{error}");
        assert!(error.contains("crawl.json"), "{error}");
    }

    #[test]
    fn the_hash_is_stable_and_tells_options_apart() {
        let a = json!({ "start": ["https://a.test/"], "max_depth": 3 });
        assert_eq!(config_hash(&a), config_hash(&a.clone()));
        assert_eq!(config_hash(&a).len(), 16);
        assert_ne!(
            config_hash(&a),
            config_hash(&json!({ "start": ["https://a.test/"], "max_depth": 4 }))
        );
    }
}
