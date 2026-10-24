//! The resume file: a second run skips what the first one finished.

mod support;

use std::path::{Path, PathBuf};

use seleniumbase_rs_plugin::{PluginError, Result, Sink};
use serde_json::{Value, json};
use support::{Mode, Rig, Worker, indexes, jobs, set_with};

/// A path in the temporary folder that no other test uses, and no file.
fn scratch(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "sbrs-batcher-it-{}-{name}.jsonl",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    path
}

fn options(path: &Path, runner: &str) -> Value {
    json!({
        "runner": runner,
        "retries": 0,
        "backoff_ms": 0,
        "ordered": true,
        "resume_file": path,
    })
}

fn entries(path: &Path) -> usize {
    std::fs::read_to_string(path).unwrap().lines().count()
}

#[test]
fn a_second_run_skips_the_jobs_the_first_one_finished() {
    let path = scratch("second");
    let input = jobs(6, 0);

    // First run: the odd jobs fail, the even ones are written down.
    let worker = Worker::new("worker", Mode::FailOdd);
    let rig = Rig::new();
    let first = rig
        .run(&set_with(options(&path, "worker"), &[&worker]), &input)
        .unwrap();
    assert_eq!(
        (first["ok"].as_u64(), first["failed"].as_u64()),
        (Some(3), Some(3))
    );
    assert_eq!(entries(&path), 3);

    // Second run: only the odd ones run again, and the even ones are lines
    // that say so, first.
    let worker = Worker::new("worker", Mode::FailOdd);
    let rig = Rig::new();
    let second = rig
        .run(&set_with(options(&path, "worker"), &[&worker]), &input)
        .unwrap();
    assert_eq!(
        second,
        json!({ "total": 6, "ok": 0, "failed": 3, "skipped": 3, "retried": 0, "chunks": 1 })
    );
    assert_eq!(worker.total(), 3);
    let lines = rig.sink.lines();
    assert_eq!(indexes(&lines), [0, 2, 4, 1, 3, 5]);
    for line in &lines[..3] {
        assert_eq!(line["chunk"], Value::Null);
        assert_eq!(line["outcome"], json!({ "status": "skipped" }));
    }
    assert!(
        lines[3..]
            .iter()
            .all(|l| l["outcome"]["status"] == "failed")
    );
    assert_eq!(entries(&path), 3, "a failed job is not written down");

    // Third run: the odd jobs work now.
    let worker = Worker::new("worker", Mode::Echo);
    let rig = Rig::new();
    let third = rig
        .run(&set_with(options(&path, "worker"), &[&worker]), &input)
        .unwrap();
    assert_eq!(
        (third["ok"].as_u64(), third["skipped"].as_u64()),
        (Some(3), Some(3))
    );
    assert_eq!(worker.total(), 3);
    assert_eq!(entries(&path), 6);

    // Fourth run: everything is done, so no context is even made.
    let worker = Worker::new("worker", Mode::Echo);
    let rig = Rig::new();
    let fourth = rig
        .run(&set_with(options(&path, "worker"), &[&worker]), &input)
        .unwrap();
    assert_eq!(
        fourth,
        json!({ "total": 6, "ok": 0, "failed": 0, "skipped": 6, "retried": 0, "chunks": 0 })
    );
    assert_eq!(worker.total(), 0);
    assert_eq!(rig.browser.contexts_made(), 0);
    assert_eq!(rig.sink.lines().len(), 6);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn another_runner_starts_over_because_the_name_of_a_job_includes_its_runner() {
    let path = scratch("runner");
    let input = jobs(4, 0);
    let alpha = Worker::new("alpha", Mode::Echo);
    let first = Rig::new()
        .run(&set_with(options(&path, "alpha"), &[&alpha]), &input)
        .unwrap();
    assert_eq!(first["ok"], 4);
    let beta = Worker::new("beta", Mode::Echo);
    let second = Rig::new()
        .run(&set_with(options(&path, "beta"), &[&beta]), &input)
        .unwrap();
    assert_eq!(
        (second["ok"].as_u64(), second["skipped"].as_u64()),
        (Some(4), Some(0))
    );
    assert_eq!(beta.total(), 4);
    assert_eq!(entries(&path), 8);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn the_file_holds_hashes_and_places_but_no_text_of_a_job() {
    let path = scratch("secret");
    let worker = Worker::new("worker", Mode::Echo);
    let input = json!({ "jobs": [{ "n": 0, "url": "https://a.test/?token=secret-token-123" }] });
    Rig::new()
        .run(&set_with(options(&path, "worker"), &[&worker]), &input)
        .unwrap();
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(
        !text.contains("secret") && !text.contains("a.test"),
        "{text}"
    );
    let entry: Value = serde_json::from_str(text.trim()).unwrap();
    assert_eq!(entry["index"], 0);
    let key = entry["key"].as_str().unwrap();
    assert!(
        key.len() == 32 && key.bytes().all(|b| b.is_ascii_hexdigit()),
        "{key}"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_last_line_cut_off_by_a_crash_does_not_stop_the_next_run() {
    let path = scratch("torn");
    let input = jobs(3, 0);
    let worker = Worker::new("worker", Mode::Echo);
    Rig::new()
        .run(&set_with(options(&path, "worker"), &[&worker]), &input)
        .unwrap();
    let mut text = std::fs::read_to_string(&path).unwrap();
    text.push_str("{\"key\":\"ab");
    std::fs::write(&path, text).unwrap();
    let worker = Worker::new("worker", Mode::Echo);
    let summary = Rig::new()
        .run(&set_with(options(&path, "worker"), &[&worker]), &input)
        .unwrap();
    assert_eq!(summary["skipped"], 3);
    assert_eq!(worker.total(), 0);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_file_that_is_not_ours_stops_the_run_before_any_context_is_made() {
    let path = scratch("foreign");
    std::fs::write(&path, "this is not a resume file\nnor is this\n").unwrap();
    let worker = Worker::new("worker", Mode::Echo);
    let rig = Rig::new();
    let error = rig
        .run(&set_with(options(&path, "worker"), &[&worker]), &jobs(2, 0))
        .unwrap_err();
    assert!(
        matches!(&error, PluginError::Config(m) if m.contains("line 1") && m.contains("resume file")),
        "{error:?}"
    );
    assert_eq!(rig.browser.contexts_made(), 0);
    assert!(rig.sink.lines().is_empty());
    assert_eq!(worker.total(), 0);

    // A folder is no file either.
    let rig = Rig::new();
    let folder = std::env::temp_dir();
    let error = rig
        .run(
            &set_with(options(&folder, "worker"), &[&worker]),
            &jobs(2, 0),
        )
        .unwrap_err();
    assert!(matches!(error, PluginError::Config(_)), "{error:?}");
    let _ = std::fs::remove_file(&path);
}

struct FullDisk;

impl Sink for FullDisk {
    fn record(&self, _line: &Value) -> Result<()> {
        Err(PluginError::other("disk full"))
    }
}

#[test]
fn a_job_is_written_down_only_after_its_record_was_written() {
    let path = scratch("order");
    let input = jobs(3, 0);
    let worker = Worker::new("worker", Mode::Echo);
    let rig = Rig::new();
    let error = rig
        .run_with(
            &set_with(options(&path, "worker"), &[&worker]),
            &input,
            &FullDisk,
        )
        .unwrap_err();
    assert_eq!(error.to_string(), "disk full");
    assert_eq!(entries(&path), 0, "no record, so no entry");
    assert_eq!(rig.browser.live_contexts(), 0);
    assert_eq!(rig.browser.live_pages(), 0);

    // The jobs run again in the next run.
    let worker = Worker::new("worker", Mode::Echo);
    let summary = Rig::new()
        .run(&set_with(options(&path, "worker"), &[&worker]), &input)
        .unwrap();
    assert_eq!(
        (summary["ok"].as_u64(), summary["skipped"].as_u64()),
        (Some(3), Some(0))
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn chunks_are_counted_over_the_jobs_that_run_not_the_jobs_skipped() {
    let path = scratch("chunks");
    let mut config = options(&path, "worker");
    config["chunk_size"] = json!(2);
    let input = jobs(6, 0);
    let worker = Worker::new("worker", Mode::FailOdd);
    let first = Rig::new()
        .run(&set_with(config.clone(), &[&worker]), &input)
        .unwrap();
    assert_eq!(first["chunks"], 3);
    // Three odd jobs are left: two chunks.
    let worker = Worker::new("worker", Mode::FailOdd);
    let rig = Rig::new();
    let second = rig.run(&set_with(config, &[&worker]), &input).unwrap();
    assert_eq!(second["chunks"], 2);
    assert_eq!(rig.browser.contexts_made(), 2);
    let _ = std::fs::remove_file(&path);
}
