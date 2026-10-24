//! The resume file: one JSON line for each job that finished well, so a second
//! run with the same jobs skips them.
//!
//! A line is `{"key": "<32 hex digits>", "index": 3}`. The key is a hash of the
//! runner and the job (see `job_key`); the file holds no job text. A job that
//! failed is not listed, so a second run tries it again. A line is written
//! after the job's record reached the sink, so a crash between the two runs
//! the job again instead of losing its record.

use std::collections::HashSet;
use std::fmt::Display;
use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};

use seleniumbase_rs_plugin::{PluginError, Result};
use serde::Deserialize;
use serde_json::json;

/// A line of the file. Other fields are allowed and ignored.
#[derive(Debug, Deserialize)]
struct Entry {
    key: String,
}

/// The file, read once and open for appending.
#[derive(Debug)]
pub(crate) struct ResumeLog {
    path: PathBuf,
    done: HashSet<String>,
    file: File,
}

impl ResumeLog {
    /// Reads the file (a missing one is empty), checks that it can be appended
    /// to and creates it if needed.
    ///
    /// A last line cut off by a crash (no line break after it) is dropped from the
    /// file. Any
    /// other line that is not an entry is an error: the file is not ours.
    pub(crate) fn open(path: &Path) -> Result<Self> {
        let cannot = |what: &str, error: &dyn Display| {
            PluginError::Config(format!(
                "batcher: cannot {what} the resume file `{}`: {error}",
                path.display()
            ))
        };
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(error) if error.kind() == ErrorKind::NotFound => String::new(),
            Err(error) => return Err(cannot("read", &error)),
        };
        let complete = text.is_empty() || text.ends_with('\n');
        let count = text.lines().count();
        let mut done = HashSet::new();
        for (position, line) in text.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<Entry>(line) {
                Ok(entry) => {
                    done.insert(entry.key);
                }
                Err(_) if !complete && position + 1 == count => {}
                Err(error) => {
                    return Err(PluginError::Config(format!(
                        "batcher: line {} of the resume file `{}` is not an entry: {error}",
                        position + 1,
                        path.display()
                    )));
                }
            }
        }
        if !complete {
            // Drop the cut-off line, so that the next entry does not follow it.
            let kept = text.trim_end_matches(|c: char| c != char::from(10)).len();
            std::fs::write(path, &text[..kept]).map_err(|error| cannot("write", &error))?;
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|error| cannot("open", &error))?;
        Ok(Self {
            path: path.to_owned(),
            done,
            file,
        })
    }

    /// Whether the job named `key` finished well in an earlier run.
    pub(crate) fn is_done(&self, key: &str) -> bool {
        self.done.contains(key)
    }

    /// How many jobs the file lists.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.done.len()
    }

    /// Writes down that the job named `key`, number `index` of the input,
    /// finished well.
    pub(crate) fn mark(&mut self, key: &str, index: usize) -> Result<()> {
        let line = format!("{}\n", json!({ "key": key, "index": index }));
        self.file.write_all(line.as_bytes()).map_err(|error| {
            PluginError::other(format!(
                "batcher: cannot write the resume file `{}`: {error}",
                self.path.display()
            ))
        })?;
        self.done.insert(key.to_owned());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A path in the temporary folder that no other test uses, and no file.
    fn scratch(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "sbrs-batcher-unit-{}-{name}.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        path
    }

    fn key(n: usize) -> String {
        format!("{n:032x}")
    }

    #[test]
    fn a_missing_file_is_created_empty_and_what_is_marked_is_read_back() {
        let path = scratch("roundtrip");
        let mut log = ResumeLog::open(&path).unwrap();
        assert_eq!(log.len(), 0);
        assert!(path.exists());
        log.mark(&key(1), 0).unwrap();
        log.mark(&key(2), 5).unwrap();
        assert!(log.is_done(&key(1)));
        assert!(!log.is_done(&key(3)));
        drop(log);
        let again = ResumeLog::open(&path).unwrap();
        assert_eq!(again.len(), 2);
        assert!(again.is_done(&key(2)));
        let lines: Vec<serde_json::Value> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(
            lines,
            [
                json!({ "key": key(1), "index": 0 }),
                json!({ "key": key(2), "index": 5 })
            ]
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_last_line_cut_off_by_a_crash_is_dropped_and_not_glued_to_the_next() {
        let path = scratch("torn");
        std::fs::write(&path, format!("{{\"key\":\"{}\"}}\n{{\"key\":\"ab", key(1))).unwrap();
        let mut log = ResumeLog::open(&path).unwrap();
        assert_eq!(log.len(), 1);
        log.mark(&key(2), 1).unwrap();
        drop(log);
        let again = ResumeLog::open(&path).unwrap();
        assert!(again.is_done(&key(1)) && again.is_done(&key(2)));
        assert_eq!(again.len(), 2);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_line_that_is_not_an_entry_is_an_error_that_names_it() {
        let path = scratch("garbage");
        std::fs::write(
            &path,
            format!("{{\"key\":\"{}\"}}\nnot json\n{{\"key\":\"x\"}}\n", key(1)),
        )
        .unwrap();
        let error = ResumeLog::open(&path).unwrap_err().to_string();
        assert!(
            error.contains("line 2") && error.contains("not an entry"),
            "{error}"
        );
        // A complete last line that is garbage is not a torn write either.
        std::fs::write(&path, format!("{{\"key\":\"{}\"}}\ngarbage\n", key(1))).unwrap();
        assert!(ResumeLog::open(&path).is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_path_that_cannot_be_used_is_a_configuration_error() {
        let folder = std::env::temp_dir();
        let error = ResumeLog::open(&folder).unwrap_err().to_string();
        assert!(error.contains("batcher: cannot"), "{error}");
        let nowhere = folder
            .join("sbrs-batcher-no-such-folder")
            .join("done.jsonl");
        assert!(ResumeLog::open(&nowhere).is_err());
    }
}
