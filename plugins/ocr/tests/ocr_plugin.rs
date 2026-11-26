//! Unit tests for `seleniumbase-rs-plugin-ocr`.

use std::sync::Arc;

use seleniumbase_rs_plugin::{
    Capability, Category, Clock, Configurable, NoPrompt, PluginSet, TaskContext,
};
use seleniumbase_rs_plugin_ocr::{NAME, OcrPlugin, sha256_hex, validate_png_header};
use seleniumbase_rs_plugin_testing::{ManualTimer, RecordingBrowser, VecSink, block_on};
use serde_json::{Value, json};

#[test]
fn sha256_and_png_header_validation() {
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert!(validate_png_header(b"not a png").is_err());
    assert!(validate_png_header(b"\x89PNG\r\n\x1a\nrest").is_ok());
}

#[test]
fn ocr_plugin_task_validates_png_and_reports_model_dir() {
    let meta = OcrPlugin::describe();
    assert_eq!(meta.category, Some(Category::Core));
    assert!(meta.capabilities.covers(&Capability::Task));

    let dir = tempfile::tempdir().unwrap();
    let png_path = dir.path().join("shot.png");
    std::fs::write(&png_path, b"\x89PNG\r\n\x1a\nbody").unwrap();

    let plugin = OcrPlugin::configure(&Value::Null).unwrap();
    let set = PluginSet::strict().with(plugin).unwrap();
    let browser = RecordingBrowser::new();
    let sink = VecSink::new();
    let clock = Clock::new(Arc::new(ManualTimer::new()));
    let input = json!({
        "models_dir": dir.path(),
        "image_path": png_path,
    });
    let cx = TaskContext::new(&browser, &input, &sink, &set, &clock, &NoPrompt);
    let out = block_on(set.task(NAME).unwrap().run(&cx)).unwrap();
    assert_eq!(out["png_validated"], true);
    assert_eq!(out["models_present"], false);
    assert_eq!(sink.lines().len(), 1);
}
