//! The browser plugin through its public API: no browser, only the plugin
//! set, a temporary folder per test and archives built in memory.

use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use seleniumbase_rs_plugin::{
    BrowserFamily, Capability, Category, Configurable, Descriptor, Engine, HostInfo, LaunchContext,
    LaunchSettings, Metadata, PathScope, Plugin, PluginError, PluginSet, PluginSpec, Registry,
    Requirements, async_trait,
};
use seleniumbase_rs_plugin::{BrowserHandle, CapabilitySet, ExtensionWorker, LoadedExtension};
use seleniumbase_rs_plugin_browser::{BrowserSession, SessionConfig};
use seleniumbase_rs_plugin_crx::CrxExtensions;
use seleniumbase_rs_plugin_testing::block_on;
use seleniumbase_rs_plugin_testing::{Call, ManualTimer, RecordingBrowser, block_on_advancing};
use std::time::Duration;

use serde_json::{Map, Value, json};
use zip::write::SimpleFileOptions;

// ---- fixtures ----

fn mv3(name: &str) -> String {
    format!(r#"{{"manifest_version":3,"name":"{name}","version":"1.0"}}"#)
}

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

fn crx3(zip: &[u8]) -> Vec<u8> {
    let header = b"\x12\x03fake-signed-header";
    let mut crx = b"Cr24".to_vec();
    crx.extend(3u32.to_le_bytes());
    crx.extend(u32::try_from(header.len()).expect("small").to_le_bytes());
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

/// An extension archive whose manifest says `name`.
fn archive(name: &str) -> Vec<u8> {
    zip_with(&[("manifest.json", &mv3(name)), ("js/a.js", "1")])
}

fn write(dir: &Path, file: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.join(file);
    std::fs::write(&path, bytes).expect("write a fixture");
    path
}

/// An unpacked extension folder called `folder` whose manifest says `name`.
fn unpacked(dir: &Path, folder: &str, name: &str) -> PathBuf {
    let path = dir.join(folder);
    std::fs::create_dir_all(&path).expect("make a folder");
    std::fs::write(path.join("manifest.json"), mv3(name)).expect("write the manifest");
    path
}

fn canonical(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).expect("an existing path")
}

fn name_of(folder: &Path) -> String {
    let bytes = std::fs::read(folder.join("manifest.json")).expect("a manifest");
    let manifest: Value = serde_json::from_slice(&bytes).expect("a JSON manifest");
    manifest["name"].as_str().expect("a name").to_owned()
}

fn names(launch: &LaunchSettings) -> Vec<String> {
    launch.extensions.iter().map(|f| name_of(f)).collect()
}

fn plugin(config: SessionConfig) -> BrowserSession {
    BrowserSession::new(config).expect("valid options")
}

fn launched(plugin: &BrowserSession) -> LaunchSettings {
    let mut launch = LaunchSettings::default();
    block_on(plugin.before_launch(&mut launch)).expect("before_launch");
    launch
}

fn refusal(plugin: &BrowserSession) -> String {
    let mut launch = LaunchSettings::default();
    let error = block_on(plugin.before_launch(&mut launch)).expect_err("a refusal");
    assert!(
        launch.extensions.is_empty(),
        "nothing was added: {launch:?}"
    );
    error.to_string()
}

fn context(headless: bool) -> LaunchContext {
    LaunchContext {
        engine: Engine::Cdp,
        family: BrowserFamily::Chromium,
        headless,
        connecting: false,
    }
}

// ---- config ----

#[test]
fn no_options_load_nothing() {
    assert!(SessionConfig::default().is_empty());
    let plugin = BrowserSession::configure(&Value::Null).expect("no options");
    assert!(plugin.config().is_empty());
    let launch = launched(&plugin);
    assert_eq!(launch, LaunchSettings::default());
}

#[test]
fn lists_and_comma_separated_text_are_both_read() {
    let plugin = BrowserSession::configure(&json!({
        "extension_zip": ["a.zip", "b.crx"],
        "extension_dir": "one, two",
    }))
    .expect("valid options");
    let config = plugin.config();
    assert_eq!(
        config.extension_zip,
        [PathBuf::from("a.zip"), "b.crx".into()]
    );
    assert_eq!(config.extension_dir, [PathBuf::from("one"), "two".into()]);

    let text = BrowserSession::configure(&json!({ "extension_zip": "a.zip,b.crx" }))
        .expect("valid options");
    assert_eq!(
        text.config().extension_zip,
        [PathBuf::from("a.zip"), "b.crx".into()]
    );
}

#[test]
fn an_empty_text_means_no_extension() {
    let plugin = BrowserSession::configure(&json!({ "extension_zip": "", "extension_dir": "  " }))
        .expect("valid options");
    assert!(plugin.config().is_empty());
}

#[test]
fn the_builder_adds_in_order() {
    let config = SessionConfig::new()
        .with_zip("a.zip")
        .with_zip("b.crx")
        .with_dir("dir");
    assert_eq!(
        config.extension_zip,
        [PathBuf::from("a.zip"), "b.crx".into()]
    );
    assert_eq!(config.extension_dir, [PathBuf::from("dir")]);
    assert!(!config.is_empty());
}

#[test]
fn an_unknown_option_is_refused_by_name() {
    // Misspellings of the real options, and one that never existed.
    for option in [
        "extension_zips",
        "wait_for_worker",
        "worker_timeout",
        "sessions",
        "save_on_exit",
        "interactiv",
    ] {
        let mut options = Map::new();
        options.insert(option.to_owned(), json!(true));
        let error =
            BrowserSession::configure(&Value::Object(options)).expect_err("an unknown option");
        assert!(matches!(error, PluginError::Config(_)), "{error:?}");
        assert!(error.to_string().contains(option), "{error}");
    }
}

#[test]
fn a_wrong_type_is_refused() {
    for options in [
        json!({ "extension_zip": 3 }),
        json!({ "extension_dir": [1] }),
        json!({ "extension_dir": { "path": "x" } }),
        json!({ "extension_zip": true }),
    ] {
        let error = BrowserSession::configure(&options).expect_err("a wrong type");
        assert!(
            matches!(error, PluginError::Config(_)),
            "{options}: {error:?}"
        );
        assert!(
            error
                .to_string()
                .starts_with("plugin configuration: browser:"),
            "{error}"
        );
    }
}

#[test]
fn an_empty_entry_is_refused() {
    for (options, option) in [
        (json!({ "extension_zip": ["a.zip", ""] }), "extension_zip"),
        (json!({ "extension_zip": "a.zip,,b.zip" }), "extension_zip"),
        (json!({ "extension_dir": ["  "] }), "extension_dir"),
        (json!({ "extension_dir": "a," }), "extension_dir"),
    ] {
        let error = BrowserSession::configure(&options).expect_err("an empty entry");
        assert!(
            matches!(error, PluginError::Config(_)),
            "{options}: {error:?}"
        );
        assert!(error.to_string().contains(option), "{options}: {error}");
    }
}

#[test]
fn a_comma_in_a_folder_is_refused_because_chrome_splits_its_list_there() {
    let error = BrowserSession::configure(&json!({ "extension_dir": ["my,extension"] }))
        .expect_err("a comma");
    assert!(matches!(error, PluginError::Config(_)), "{error:?}");
    assert!(error.to_string().contains("my,extension"), "{error}");
    assert!(error.to_string().contains("comma"), "{error}");
}

// ---- the options for workers, saved sessions and signing in ----

/// The text of the refusal `options` get: a `Config` error that starts the way
/// every option error of the plugin does.
fn refused(options: &Value) -> String {
    let error = match BrowserSession::configure(options) {
        Ok(_) => panic!("{options} must be refused"),
        Err(error) => error,
    };
    assert!(
        matches!(error, PluginError::Config(_)),
        "{options}: {error:?}"
    );
    let text = error.to_string();
    assert!(
        text.starts_with("plugin configuration: browser:"),
        "{options}: {text}"
    );
    text
}

#[test]
fn the_new_options_are_off_by_default() {
    let plugin = BrowserSession::configure(&Value::Null).expect("no options");
    let config = plugin.config();
    assert!(!config.wait_for_workers);
    assert_eq!(config.worker_timeout_secs, None);
    assert_eq!(config.session, None);
    assert!(!config.save_on_close);
    assert_eq!(config.session_dir, None);
    assert!(!config.interactive);
    assert_eq!(config.pause_message, None);
}

#[cfg(unix)]
#[test]
fn the_new_options_are_read_and_the_builder_sets_the_same_fields() {
    let plugin = BrowserSession::configure(&json!({
        "extension_dir": ["ext"],
        "wait_for_workers": true,
        "worker_timeout_secs": 20,
        "session": "login",
        "save_on_close": true,
        "session_dir": "kept",
        "interactive": true,
        "pause_message": "Sign in now",
    }))
    .expect("valid options");
    let built = SessionConfig::new()
        .with_dir("ext")
        .with_wait_for_workers(true)
        .with_worker_timeout_secs(20)
        .with_session("login")
        .with_save_on_close(true)
        .with_session_dir("kept")
        .with_interactive(true)
        .with_pause_message("Sign in now");
    assert_eq!(plugin.config(), &built);
    assert_eq!(built.worker_timeout_secs, Some(20));
    assert_eq!(built.session.as_deref(), Some("login"));
    assert_eq!(built.session_dir, Some(PathBuf::from("kept")));
    assert_eq!(built.pause_message.as_deref(), Some("Sign in now"));
}

#[test]
fn wait_for_workers_needs_an_extension_to_wait_for() {
    let text = refused(&json!({ "wait_for_workers": true }));
    assert!(text.contains("`wait_for_workers`"), "{text}");
    assert!(
        text.contains("extension_zip") && text.contains("extension_dir"),
        "{text}"
    );
    BrowserSession::configure(&json!({ "wait_for_workers": true, "extension_dir": ["ext"] }))
        .expect("an extension to wait for");
    BrowserSession::configure(&json!({ "wait_for_workers": true, "extension_zip": "a.zip" }))
        .expect("an archive to wait for");
    BrowserSession::configure(&json!({ "wait_for_workers": false })).expect("off needs nothing");
}

#[test]
fn worker_timeout_secs_needs_wait_for_workers_and_a_range() {
    for options in [
        json!({ "extension_dir": ["ext"], "worker_timeout_secs": 5 }),
        json!({ "extension_dir": ["ext"], "wait_for_workers": false, "worker_timeout_secs": 5 }),
    ] {
        let text = refused(&options);
        assert!(
            text.contains("`worker_timeout_secs`") && text.contains("`wait_for_workers`"),
            "the message names both options: {text}"
        );
    }
    for seconds in [0u64, 31, 3600] {
        let text = refused(&json!({
            "extension_dir": ["ext"],
            "wait_for_workers": true,
            "worker_timeout_secs": seconds,
        }));
        assert!(text.contains("`worker_timeout_secs`"), "{text}");
        assert!(text.contains("between 1 and 30"), "{text}");
    }
    for seconds in [1u64, 10, 30] {
        let plugin = BrowserSession::configure(&json!({
            "extension_dir": ["ext"],
            "wait_for_workers": true,
            "worker_timeout_secs": seconds,
        }))
        .expect("in range");
        assert_eq!(plugin.config().worker_timeout_secs, Some(seconds));
    }
}

#[test]
fn a_wrong_type_for_one_of_the_new_options_is_refused() {
    for options in [
        json!({ "wait_for_workers": "yes" }),
        json!({ "worker_timeout_secs": -1 }),
        json!({ "worker_timeout_secs": "ten" }),
        json!({ "worker_timeout_secs": 1.5 }),
        json!({ "session": 5 }),
        json!({ "session": true }),
        json!({ "save_on_close": 1 }),
        json!({ "session_dir": 7 }),
        json!({ "interactive": "yes" }),
        json!({ "pause_message": 3 }),
    ] {
        refused(&options);
    }
}

#[test]
fn a_session_name_is_one_safe_path_component() {
    let too_long = "x".repeat(65);
    for name in [
        "../x",
        "a/b",
        "a\\b",
        ".hidden",
        "",
        "..",
        "a b",
        "tab\there",
        "nul\0byte",
        "é",
        "-dash",
        "_under",
        "/abs",
        too_long.as_str(),
    ] {
        let text = refused(&json!({ "session": name }));
        assert!(text.contains("`session`"), "{name:?}: {text}");
    }
    let longest = "x".repeat(64);
    for name in ["a", "login-1", "A.b_c", "0", "a..b", longest.as_str()] {
        BrowserSession::configure(&json!({ "session": name }))
            .unwrap_or_else(|error| panic!("{name:?} is a good name: {error}"));
    }
}

#[test]
fn the_options_that_belong_to_a_session_need_one() {
    for (options, option) in [
        (json!({ "save_on_close": true }), "save_on_close"),
        (json!({ "session_dir": "kept" }), "session_dir"),
        (json!({ "interactive": true }), "interactive"),
    ] {
        let text = refused(&options);
        assert!(
            text.contains(&format!("`{option}`")) && text.contains("`session`"),
            "the message names both options: {text}"
        );
    }
    // Off needs nothing.
    BrowserSession::configure(&json!({ "save_on_close": false, "interactive": false }))
        .expect("off");
}

#[test]
fn an_empty_session_dir_is_refused() {
    for dir in ["", "   "] {
        let text = refused(&json!({ "session": "s", "session_dir": dir }));
        assert!(text.contains("`session_dir`"), "{text}");
    }
}

#[cfg(unix)]
#[test]
fn pause_message_needs_interactive_and_must_be_plain_text() {
    let text = refused(&json!({ "session": "s", "pause_message": "hello" }));
    assert!(
        text.contains("`pause_message`") && text.contains("`interactive`"),
        "{text}"
    );
    let long = "m".repeat(501);
    for message in ["", "   ", "bell\u{7}", "esc\u{1b}[2J", long.as_str()] {
        let text = refused(&json!({
            "session": "s",
            "interactive": true,
            "pause_message": message,
        }));
        assert!(text.contains("`pause_message`"), "{message:?}: {text}");
    }
    let fine = "m".repeat(500);
    for message in ["Sign in, then press Enter", "two\nlines", fine.as_str()] {
        BrowserSession::configure(&json!({
            "session": "s",
            "interactive": true,
            "pause_message": message,
        }))
        .unwrap_or_else(|error| panic!("{message:?} is a good message: {error}"));
    }
}

#[cfg(not(unix))]
#[test]
fn saving_a_session_is_refused_without_unix_file_permissions() {
    for options in [
        json!({ "session": "s", "save_on_close": true }),
        json!({ "session": "s", "interactive": true }),
    ] {
        let text = refused(&options);
        assert!(text.contains("Unix file permissions"), "{text}");
    }
    // Putting a session back needs no permissions to set.
    BrowserSession::configure(&json!({ "session": "s" })).expect("restoring works anywhere");
}

// ---- unpacking and the launch settings ----

#[test]
fn a_zip_is_unpacked_into_a_folder_with_its_manifest() {
    let fixtures = tempfile::tempdir().expect("temp dir");
    let zip = write(fixtures.path(), "ext.zip", &archive("zipped"));
    let plugin = plugin(SessionConfig::new().with_zip(&zip));
    let launch = launched(&plugin);
    assert_eq!(launch.extensions.len(), 1);
    let folder = &launch.extensions[0];
    assert!(folder.is_absolute(), "{folder:?}");
    assert!(folder.join("manifest.json").is_file());
    assert!(folder.join("js/a.js").is_file());
    assert_eq!(name_of(folder), "zipped");
    assert!(
        !folder.starts_with(fixtures.path()),
        "the archive is not unpacked beside itself: {folder:?}"
    );
}

#[test]
fn crx3_and_crx2_files_unpack_like_a_zip() {
    let fixtures = tempfile::tempdir().expect("temp dir");
    let zip = archive("packed");
    let v3 = write(fixtures.path(), "v3.crx", &crx3(&zip));
    let v2 = write(fixtures.path(), "v2.crx", &crx2(&zip));
    let plugin = plugin(SessionConfig::new().with_zip(&v3).with_zip(&v2));
    let launch = launched(&plugin);
    assert_eq!(names(&launch), ["packed", "packed"]);
    assert_ne!(launch.extensions[0], launch.extensions[1]);
}

#[test]
fn the_format_is_read_from_the_bytes_and_not_from_the_extension() {
    let fixtures = tempfile::tempdir().expect("temp dir");
    let crx_named_zip = write(fixtures.path(), "really-crx.zip", &crx3(&archive("one")));
    let zip_named_crx = write(fixtures.path(), "really-zip.crx", &archive("two"));
    let plugin = plugin(
        SessionConfig::new()
            .with_zip(&crx_named_zip)
            .with_zip(&zip_named_crx),
    );
    assert_eq!(names(&launched(&plugin)), ["one", "two"]);
}

#[test]
fn a_folder_is_loaded_in_place_and_left_alone_on_close() {
    let fixtures = tempfile::tempdir().expect("temp dir");
    let folder = unpacked(fixtures.path(), "ext", "in-place");
    let plugin = plugin(SessionConfig::new().with_dir(&folder));
    let launch = launched(&plugin);
    assert_eq!(launch.extensions, [canonical(&folder)]);
    block_on(plugin.on_close()).expect("on_close");
    assert!(
        folder.join("manifest.json").is_file(),
        "the user's folder survives"
    );
}

#[test]
fn a_relative_folder_becomes_an_absolute_one() {
    // Tests run in the crate's folder; the scratch folder is made there, with a
    // random name, and removed when the test ends.
    let scratch = tempfile::Builder::new()
        .prefix("sbrs-relative-")
        .tempdir_in(".")
        .expect("a folder in the working directory");
    let relative = PathBuf::from(scratch.path().file_name().expect("a folder name"));
    assert!(relative.is_relative(), "{relative:?}");
    std::fs::write(relative.join("manifest.json"), mv3("relative")).expect("write the manifest");
    let plugin = plugin(SessionConfig::new().with_dir(&relative));
    let launch = launched(&plugin);
    assert_eq!(launch.extensions, [canonical(&relative)]);
    assert!(launch.extensions[0].is_absolute());
}

#[test]
fn zips_come_first_then_folders_and_each_list_keeps_its_order() {
    let fixtures = tempfile::tempdir().expect("temp dir");
    let z1 = write(fixtures.path(), "z1.zip", &archive("zip-1"));
    let z2 = write(fixtures.path(), "z2.crx", &crx3(&archive("zip-2")));
    let d1 = unpacked(fixtures.path(), "d1", "dir-1");
    let d2 = unpacked(fixtures.path(), "d2", "dir-2");
    // The folders are added first on purpose: Python handles the zips first.
    let plugin = plugin(
        SessionConfig::new()
            .with_dir(&d1)
            .with_dir(&d2)
            .with_zip(&z1)
            .with_zip(&z2),
    );
    let launch = launched(&plugin);
    assert_eq!(names(&launch), ["zip-1", "zip-2", "dir-1", "dir-2"]);
    assert_eq!(launch.extensions[2], canonical(&d1));
    assert_eq!(launch.extensions[3], canonical(&d2));
}

#[test]
fn folders_another_plugin_added_stay_in_front() {
    let fixtures = tempfile::tempdir().expect("temp dir");
    let folder = unpacked(fixtures.path(), "ext", "mine");
    let plugin = plugin(SessionConfig::new().with_dir(&folder));
    let mut launch = LaunchSettings::default();
    launch.extensions.push(PathBuf::from("/already/there"));
    block_on(plugin.before_launch(&mut launch)).expect("before_launch");
    assert_eq!(
        launch.extensions,
        [PathBuf::from("/already/there"), canonical(&folder)]
    );
}

#[test]
fn only_the_extension_list_changes() {
    // The comma-joined `--load-extension` switch is the host's job, and the
    // switch policy refuses it from a plugin: the plugin hands over folders.
    let fixtures = tempfile::tempdir().expect("temp dir");
    let folder = unpacked(fixtures.path(), "ext", "x");
    let zip = write(fixtures.path(), "e.zip", &archive("y"));
    let plugin = plugin(SessionConfig::new().with_dir(&folder).with_zip(&zip));
    let mut launch = launched(&plugin);
    assert_eq!(launch.extensions.len(), 2);
    launch.extensions.clear();
    assert_eq!(launch, LaunchSettings::default());
}

#[test]
fn the_same_extension_listed_twice_is_loaded_once() {
    let fixtures = tempfile::tempdir().expect("temp dir");
    let folder = unpacked(fixtures.path(), "ext", "once");
    let zip = write(fixtures.path(), "e.zip", &archive("once-zip"));
    let plugin = plugin(
        SessionConfig::new()
            .with_dir(&folder)
            .with_dir(folder.join("."))
            .with_zip(&zip)
            .with_zip(fixtures.path().join("./e.zip")),
    );
    assert_eq!(names(&launched(&plugin)), ["once-zip", "once"]);
}

// ---- headless (Python loads the user's extensions whatever the mode) ----

#[test]
fn a_headless_launch_still_gets_the_extensions() {
    let fixtures = tempfile::tempdir().expect("temp dir");
    let folder = unpacked(fixtures.path(), "ext", "headless");
    let plugin = plugin(SessionConfig::new().with_dir(&folder));
    assert!(!plugin.requirements().contains(Requirements::HEADFUL));
    let set = PluginSet::strict()
        .with(plugin)
        .expect("a strict set takes it");
    set.check(&context(true)).expect("headless is allowed");
    let mut launch = LaunchSettings::default();
    launch.headless = true;
    block_on(set.before_launch(&mut launch)).expect("before_launch");
    assert!(launch.headless);
    assert_eq!(launch.extensions, [canonical(&folder)]);
}

#[test]
fn the_old_headless_mode_cannot_load_extensions_and_is_refused() {
    let fixtures = tempfile::tempdir().expect("temp dir");
    let folder = unpacked(fixtures.path(), "ext", "old");
    let plugin = plugin(SessionConfig::new().with_dir(&folder));
    let mut launch = LaunchSettings::default();
    launch.args.push("--headless=old".to_owned());
    let error = block_on(plugin.before_launch(&mut launch)).expect_err("the old mode");
    assert!(error.to_string().contains("headless"), "{error}");
    assert!(launch.extensions.is_empty());

    // Without extensions there is nothing to refuse.
    let idle = BrowserSession::configure(&Value::Null).expect("no options");
    let mut launch = LaunchSettings::default();
    launch.args.push("--headless=old".to_owned());
    block_on(idle.before_launch(&mut launch)).expect("nothing to load");
}

// ---- errors ----

#[test]
fn a_missing_zip_fails_before_launch_with_its_path() {
    let fixtures = tempfile::tempdir().expect("temp dir");
    let missing = fixtures.path().join("nope.zip");
    let plugin = plugin(SessionConfig::new().with_zip(&missing));
    let set = PluginSet::strict()
        .with(plugin)
        .expect("a strict set takes it");
    let mut launch = LaunchSettings::default();
    let error = block_on(set.before_launch(&mut launch)).expect_err("a missing file");
    let text = error.to_string();
    assert!(text.contains(&missing.display().to_string()), "{text}");
    assert!(text.contains("extension_zip"), "{text}");
    assert!(text.contains("does not exist"), "{text}");
    assert!(launch.extensions.is_empty());
}

#[test]
fn a_missing_folder_fails_before_launch_with_its_path() {
    let fixtures = tempfile::tempdir().expect("temp dir");
    let missing = fixtures.path().join("no-such-folder");
    let text = refusal(&plugin(SessionConfig::new().with_dir(&missing)));
    assert!(text.contains(&missing.display().to_string()), "{text}");
    assert!(text.contains("extension_dir"), "{text}");
    assert!(text.contains("does not exist"), "{text}");
}

#[test]
fn a_good_extension_before_a_bad_one_adds_nothing() {
    let fixtures = tempfile::tempdir().expect("temp dir");
    let good = write(fixtures.path(), "good.zip", &archive("good"));
    let bad = fixtures.path().join("bad.zip");
    let text = refusal(&plugin(SessionConfig::new().with_zip(&good).with_zip(&bad)));
    assert!(text.contains("bad.zip"), "{text}");
}

#[test]
fn the_wrong_kind_of_path_says_which_option_to_use() {
    let fixtures = tempfile::tempdir().expect("temp dir");
    let folder = unpacked(fixtures.path(), "ext", "x");
    let file = write(fixtures.path(), "e.zip", &archive("y"));

    let text = refusal(&plugin(SessionConfig::new().with_zip(&folder)));
    assert!(text.contains("is a folder"), "{text}");
    assert!(text.contains("extension_dir"), "{text}");

    let text = refusal(&plugin(SessionConfig::new().with_dir(&file)));
    assert!(text.contains("is a file"), "{text}");
    assert!(text.contains("extension_zip"), "{text}");
}

#[test]
fn a_file_that_is_neither_crx_nor_zip_is_refused() {
    let fixtures = tempfile::tempdir().expect("temp dir");
    let file = write(fixtures.path(), "notes.zip", b"hello, not an archive");
    let text = refusal(&plugin(SessionConfig::new().with_zip(&file)));
    assert!(text.contains("notes.zip"), "{text}");
    assert!(text.contains("neither a CRX nor a ZIP"), "{text}");
}

#[test]
fn a_cut_short_archive_is_refused() {
    let fixtures = tempfile::tempdir().expect("temp dir");
    let cut = archive("cut");
    let zip = write(fixtures.path(), "cut.zip", &cut[..cut.len() / 2]);
    let crx = write(
        fixtures.path(),
        "cut.crx",
        b"Cr24\x03\0\0\0\xff\xff\xff\x7f",
    );
    for path in [zip, crx] {
        let text = refusal(&plugin(SessionConfig::new().with_zip(&path)));
        assert!(text.contains(&path.display().to_string()), "{text}");
    }
}

#[test]
fn an_archive_with_an_entry_outside_its_folder_is_refused() {
    let fixtures = tempfile::tempdir().expect("temp dir");
    let evil = zip_with(&[("manifest.json", &mv3("evil")), ("../escaped.txt", "x")]);
    let file = write(fixtures.path(), "evil.zip", &evil);
    let text = refusal(&plugin(SessionConfig::new().with_zip(&file)));
    assert!(text.contains("evil.zip"), "{text}");
    assert!(text.contains("leaves its folder"), "{text}");
}

#[test]
fn an_archive_or_folder_without_a_manifest_is_refused() {
    let fixtures = tempfile::tempdir().expect("temp dir");
    let zip = write(fixtures.path(), "bare.zip", &zip_with(&[("a.js", "1")]));
    let text = refusal(&plugin(SessionConfig::new().with_zip(&zip)));
    assert!(text.contains("manifest.json"), "{text}");

    let folder = fixtures.path().join("bare");
    std::fs::create_dir_all(&folder).expect("make a folder");
    let text = refusal(&plugin(SessionConfig::new().with_dir(&folder)));
    assert!(text.contains("manifest.json"), "{text}");
    assert!(text.contains(&folder.display().to_string()), "{text}");
}

#[test]
fn only_manifest_v3_is_accepted_for_folders_and_archives() {
    let fixtures = tempfile::tempdir().expect("temp dir");
    let cases = [
        (
            r#"{"manifest_version":2,"name":"old","version":"1"}"#,
            "manifest_version is 2",
        ),
        (r#"{"name":"none","version":"1"}"#, "no manifest_version"),
        (
            r#"{"manifest_version":"3","name":"text","version":"1"}"#,
            "manifest_version",
        ),
        ("not json at all", "not valid JSON"),
        ("[3]", "not a JSON object"),
    ];
    for (index, (manifest, expected)) in cases.into_iter().enumerate() {
        let folder = fixtures.path().join(format!("dir-{index}"));
        std::fs::create_dir_all(&folder).expect("make a folder");
        std::fs::write(folder.join("manifest.json"), manifest).expect("write the manifest");
        let text = refusal(&plugin(SessionConfig::new().with_dir(&folder)));
        assert!(text.contains(expected), "{manifest}: {text}");
        assert!(text.contains(&folder.display().to_string()), "{text}");

        let zip = write(
            fixtures.path(),
            &format!("zip-{index}.zip"),
            &zip_with(&[("manifest.json", manifest)]),
        );
        let text = refusal(&plugin(SessionConfig::new().with_zip(&zip)));
        assert!(text.contains(expected), "{manifest}: {text}");
        assert!(text.contains(&zip.display().to_string()), "{text}");
    }
}

#[test]
fn a_manifest_with_a_byte_order_mark_is_accepted() {
    let fixtures = tempfile::tempdir().expect("temp dir");
    let folder = fixtures.path().join("bom");
    std::fs::create_dir_all(&folder).expect("make a folder");
    let mut bytes = b"\xEF\xBB\xBF".to_vec();
    bytes.extend(mv3("bom").as_bytes());
    std::fs::write(folder.join("manifest.json"), bytes).expect("write the manifest");
    let launch = launched(&plugin(SessionConfig::new().with_dir(&folder)));
    assert_eq!(launch.extensions, [canonical(&folder)]);
}

// ---- pools: each browser owns its folders ----

#[test]
fn two_pooled_browsers_close_independently() {
    let fixtures = tempfile::tempdir().expect("temp dir");
    let zip = write(fixtures.path(), "ext.zip", &archive("pooled"));
    let folder = unpacked(fixtures.path(), "plain", "plain");
    let template = PluginSet::strict()
        .with(plugin(
            SessionConfig::new().with_zip(&zip).with_dir(&folder),
        ))
        .expect("a strict set takes it");

    let first = template.for_launch();
    let second = template.for_launch();
    let mut one = LaunchSettings::default();
    let mut two = LaunchSettings::default();
    block_on(first.before_launch(&mut one)).expect("first launch");
    block_on(second.before_launch(&mut two)).expect("second launch");
    let (unpacked_one, unpacked_two) = (one.extensions[0].clone(), two.extensions[0].clone());
    assert_ne!(
        unpacked_one, unpacked_two,
        "each browser has its own folder"
    );
    assert!(unpacked_one.join("manifest.json").is_file());
    assert!(unpacked_two.join("manifest.json").is_file());

    assert!(block_on(first.on_close()).is_empty());
    assert!(!unpacked_one.exists(), "the first browser's folder is gone");
    assert!(
        unpacked_two.join("manifest.json").is_file(),
        "the second browser's folder survives"
    );
    assert!(
        folder.join("manifest.json").is_file(),
        "the user's folder survives"
    );

    assert!(block_on(second.on_close()).is_empty());
    assert!(!unpacked_two.exists());
    assert!(folder.join("manifest.json").is_file());
}

#[test]
fn closing_twice_is_harmless() {
    let fixtures = tempfile::tempdir().expect("temp dir");
    let zip = write(fixtures.path(), "ext.zip", &archive("twice"));
    let plugin = plugin(SessionConfig::new().with_zip(&zip));
    let launch = launched(&plugin);
    block_on(plugin.on_close()).expect("first close");
    block_on(plugin.on_close()).expect("second close");
    assert!(!launch.extensions[0].exists());
}

#[test]
fn the_per_launch_copy_has_the_same_name_and_options() {
    let fixtures = tempfile::tempdir().expect("temp dir");
    let folder = unpacked(fixtures.path(), "ext", "copy");
    let original = plugin(SessionConfig::new().with_dir(&folder));
    let copy: Arc<dyn Plugin> = original.per_launch().expect("a fresh instance per browser");
    assert_eq!(copy.name(), "browser");
    let mut launch = LaunchSettings::default();
    block_on(copy.before_launch(&mut launch)).expect("the copy loads the same folder");
    assert_eq!(launch.extensions, [canonical(&folder)]);
}

// ---- what the plugin declares ----

#[test]
fn it_declares_the_extension_category_and_its_capabilities() {
    let meta = BrowserSession::describe();
    assert_eq!(meta.category, Some(Category::Extension));
    assert_eq!(meta.version, env!("CARGO_PKG_VERSION"));
    assert!(!meta.summary.is_empty());
    assert!(meta.capabilities.covers(&Capability::LaunchExtensions));
    assert!(
        meta.capabilities
            .covers(&Capability::HostFsWrite(PathScope::Temp))
    );
    assert!(meta.conflicts.iter().any(|name| name == "crx"));
    assert_eq!(<BrowserSession as Configurable>::NAME, "browser");
}

#[test]
fn the_instance_declares_only_what_its_options_need() {
    let fixtures = tempfile::tempdir().expect("temp dir");
    let zip = write(fixtures.path(), "ext.zip", &archive("a"));
    let folder = unpacked(fixtures.path(), "ext", "b");
    let reads = |meta: &Metadata| {
        meta.capabilities
            .iter()
            .any(|c| matches!(c, Capability::HostFsRead(_)))
    };
    let writes = |meta: &Metadata| {
        meta.capabilities
            .iter()
            .any(|c| matches!(c, Capability::HostFsWrite(_)))
    };

    let idle = BrowserSession::configure(&Value::Null)
        .expect("no options")
        .metadata();
    assert!(idle.capabilities.covers(&Capability::LaunchExtensions));
    assert!(!reads(&idle) && !writes(&idle));

    let folders_only = plugin(SessionConfig::new().with_dir(&folder)).metadata();
    assert!(
        folders_only
            .capabilities
            .covers(&Capability::HostFsRead(PathScope::Declared(vec![
                folder.clone()
            ])))
    );
    assert!(!writes(&folders_only));

    let both = plugin(SessionConfig::new().with_zip(&zip).with_dir(&folder)).metadata();
    assert!(
        both.capabilities
            .covers(&Capability::HostFsRead(PathScope::Declared(vec![
                zip.clone(),
                folder.clone()
            ])))
    );
    assert!(
        both.capabilities
            .covers(&Capability::HostFsWrite(PathScope::Temp))
    );
}

#[test]
fn it_needs_a_chromium_browser_it_starts() {
    let plugin = BrowserSession::configure(&Value::Null).expect("no options");
    let needs = plugin.requirements();
    assert!(needs.contains(Requirements::CHROMIUM_ONLY));
    assert!(needs.contains(Requirements::LAUNCH_ONLY));
    assert!(!needs.contains(Requirements::HEADFUL));

    let set = PluginSet::strict()
        .with(plugin)
        .expect("a strict set takes it");
    set.check(&context(false)).expect("a started Chromium");
    set.check_with(
        &context(true),
        &HostInfo::webdriver(BrowserFamily::Chromium),
    )
    .expect("the WebDriver engine can load extensions too");
    let attached = LaunchContext {
        connecting: true,
        ..context(false)
    };
    assert!(matches!(
        set.check(&attached),
        Err(PluginError::Requirement { .. })
    ));
    let firefox = LaunchContext {
        family: BrowserFamily::Firefox,
        ..context(false)
    };
    assert!(matches!(
        set.check(&firefox),
        Err(PluginError::Requirement { .. })
    ));
}

#[test]
fn it_conflicts_with_the_crx_plugin() {
    let both = PluginSet::strict()
        .with(BrowserSession::configure(&Value::Null).expect("no options"))
        .and_then(|set| set.with(CrxExtensions::new(Vec::<PathBuf>::new())))
        .and_then(|set| set.check(&context(false)));
    assert!(
        matches!(both, Err(PluginError::Conflict { .. })),
        "{both:?}"
    );
}

#[test]
fn the_registry_builds_it_from_options() {
    let registry = Registry::new().with(Descriptor::of::<BrowserSession>());
    assert_eq!(registry.names(), ["browser"]);
    let fixtures = tempfile::tempdir().expect("temp dir");
    let folder = unpacked(fixtures.path(), "ext", "registry");

    let spec = PluginSpec::new("browser").options(json!({ "extension_dir": [&folder] }));
    let set = registry
        .plugin_set(&[spec])
        .expect("a strict set from the registry");
    assert_eq!(set.names(), ["browser"]);
    let mut launch = LaunchSettings::default();
    block_on(set.before_launch(&mut launch)).expect("the granted capabilities are enough");
    assert_eq!(launch.extensions, [canonical(&folder)]);

    let none = registry
        .plugin_set(&[PluginSpec::new("browser")])
        .expect("default options");
    assert_eq!(none.names(), ["browser"]);

    let bad = PluginSpec::new("browser").options(json!({ "extension_zp": [] }));
    assert!(matches!(registry.build(&bad), Err(PluginError::Config(_))));
}

// ---- wait_for_workers ----

/// How often the wait asks the host.
const POLL: Duration = Duration::from_millis(250);

/// An unpacked extension whose manifest names a service worker.
fn unpacked_with_worker(dir: &Path, folder: &str, name: &str) -> PathBuf {
    let path = dir.join(folder);
    std::fs::create_dir_all(&path).expect("make a folder");
    let manifest = format!(
        r#"{{"manifest_version":3,"name":"{name}","version":"1.0","background":{{"service_worker":"sw.js"}}}}"#
    );
    std::fs::write(path.join("manifest.json"), manifest).expect("write the manifest");
    path
}

fn worker_of(id: &str) -> ExtensionWorker {
    ExtensionWorker::new(id, format!("chrome-extension://{id}/sw.js"))
}

/// A strict set around the plugin `config` builds, with a manual timer when
/// `timer` is true, checked and launched: the set, the timer and what
/// `before_launch` produced.
fn launched_set(
    config: SessionConfig,
    timer: bool,
) -> (PluginSet, Arc<ManualTimer>, LaunchSettings) {
    let manual = Arc::new(ManualTimer::new());
    let mut set = PluginSet::strict()
        .with(plugin(config))
        .expect("a strict set takes it");
    if timer {
        set = set.with_timer(manual.clone());
    }
    set.check(&context(true))
        .expect("the grants cover the options");
    let mut launch = LaunchSettings::default();
    block_on(set.before_launch(&mut launch)).expect("before_launch");
    (set, manual, launch)
}

/// Runs `on_browser`, moving the timer on whenever the plugin waits.
fn on_browser(
    set: &PluginSet,
    timer: &ManualTimer,
    browser: &RecordingBrowser,
) -> Result<(), PluginError> {
    block_on_advancing(timer, POLL, set.on_browser(browser))
}

/// The text of the `on_browser` failure of the `browser` plugin.
fn hook_failure(error: PluginError) -> String {
    match error {
        PluginError::Hook {
            plugin,
            hook,
            message,
        } => {
            assert_eq!(plugin, "browser");
            assert_eq!(hook, "on_browser");
            message
        }
        other => panic!("expected a hook failure, got {other:?}"),
    }
}

#[test]
fn it_waits_until_the_worker_shows_up() {
    let fixtures = tempfile::tempdir().expect("temp dir");
    let folder = unpacked_with_worker(fixtures.path(), "ext", "alive");
    let config = SessionConfig::new()
        .with_dir(&folder)
        .with_wait_for_workers(true);
    let (set, timer, launch) = launched_set(config, true);
    let browser = RecordingBrowser::new()
        .with_extensions(vec![LoadedExtension::new(
            "aaaa",
            launch.extensions[0].clone(),
        )])
        .with_workers(vec![vec![], vec![], vec![worker_of("aaaa")]]);

    on_browser(&set, &timer, &browser).expect("the worker shows up");

    assert_eq!(browser.calls(), vec![Call::ExtensionWorkers; 3]);
    assert_eq!(timer.elapsed(), POLL * 2);
}

#[test]
fn a_worker_that_is_already_running_costs_no_waiting() {
    let fixtures = tempfile::tempdir().expect("temp dir");
    let folder = unpacked_with_worker(fixtures.path(), "ext", "ready");
    let config = SessionConfig::new()
        .with_dir(&folder)
        .with_wait_for_workers(true);
    let (set, timer, launch) = launched_set(config, true);
    let browser = RecordingBrowser::new()
        .with_extensions(vec![LoadedExtension::new(
            "aaaa",
            launch.extensions[0].clone(),
        )])
        .with_workers(vec![vec![worker_of("aaaa")]]);
    on_browser(&set, &timer, &browser).expect("already there");
    assert_eq!(browser.calls(), [Call::ExtensionWorkers]);
    assert_eq!(timer.elapsed(), Duration::ZERO);
}

#[test]
fn it_skips_extensions_without_a_worker_and_ones_other_plugins_loaded() {
    let fixtures = tempfile::tempdir().expect("temp dir");
    let with = unpacked_with_worker(fixtures.path(), "with", "with");
    let without = unpacked(fixtures.path(), "without", "without");
    let config = SessionConfig::new()
        .with_dir(&with)
        .with_dir(&without)
        .with_wait_for_workers(true);
    let (set, timer, launch) = launched_set(config, true);
    let browser = RecordingBrowser::new()
        .with_extensions(vec![
            LoadedExtension::new("aaaa", launch.extensions[0].clone()),
            LoadedExtension::new("bbbb", launch.extensions[1].clone()),
            LoadedExtension::new("zzzz", "/elsewhere/foreign"),
        ])
        .with_workers(vec![vec![worker_of("aaaa")]]);
    on_browser(&set, &timer, &browser).expect("only the extension with a worker is awaited");
    assert_eq!(timer.elapsed(), Duration::ZERO);
}

#[test]
fn another_plugins_worker_does_not_stand_in_for_ours() {
    let fixtures = tempfile::tempdir().expect("temp dir");
    let folder = unpacked_with_worker(fixtures.path(), "ext", "mine");
    let config = SessionConfig::new()
        .with_dir(&folder)
        .with_wait_for_workers(true)
        .with_worker_timeout_secs(2);
    let (set, timer, launch) = launched_set(config, true);
    let browser = RecordingBrowser::new()
        .with_extensions(vec![
            LoadedExtension::new("aaaa", launch.extensions[0].clone()),
            LoadedExtension::new("zzzz", "/elsewhere/foreign"),
        ])
        .with_workers(vec![vec![worker_of("zzzz")]]);
    let text = hook_failure(on_browser(&set, &timer, &browser).expect_err("ours never runs"));
    assert!(text.contains("aaaa"), "{text}");
    assert!(!text.contains("zzzz"), "{text}");
}

#[test]
fn it_gives_up_after_the_timeout_naming_the_option_the_extensions_and_the_time() {
    let fixtures = tempfile::tempdir().expect("temp dir");
    let running = unpacked_with_worker(fixtures.path(), "running", "running");
    let stuck = unpacked_with_worker(fixtures.path(), "stuck", "stuck");
    let config = SessionConfig::new()
        .with_dir(&running)
        .with_dir(&stuck)
        .with_wait_for_workers(true)
        .with_worker_timeout_secs(3);
    let (set, timer, launch) = launched_set(config, true);
    let browser = RecordingBrowser::new()
        .with_extensions(vec![
            LoadedExtension::new("aaaa", launch.extensions[0].clone()),
            LoadedExtension::new("bbbb", launch.extensions[1].clone()),
        ])
        .with_workers(vec![vec![worker_of("aaaa")]]);

    let text = hook_failure(on_browser(&set, &timer, &browser).expect_err("bbbb never starts"));

    assert!(text.contains("`wait_for_workers`"), "{text}");
    assert!(text.contains("bbbb"), "{text}");
    assert!(
        text.contains("stuck"),
        "the folder as the user wrote it: {text}"
    );
    assert!(text.contains("after 3 s"), "{text}");
    assert!(
        !text.contains("aaaa"),
        "the running one is not blamed: {text}"
    );
    assert_eq!(timer.elapsed(), Duration::from_secs(3));
}

#[test]
fn the_default_wait_is_ten_seconds_and_the_longest_is_not_cut_by_the_hook_limit() {
    let fixtures = tempfile::tempdir().expect("temp dir");
    let folder = unpacked_with_worker(fixtures.path(), "ext", "slow");
    for (config, seconds) in [
        (
            SessionConfig::new()
                .with_dir(&folder)
                .with_wait_for_workers(true),
            10,
        ),
        (
            SessionConfig::new()
                .with_dir(&folder)
                .with_wait_for_workers(true)
                .with_worker_timeout_secs(30),
            30,
        ),
    ] {
        let (set, timer, launch) = launched_set(config, true);
        let browser = RecordingBrowser::new()
            .with_extensions(vec![LoadedExtension::new(
                "aaaa",
                launch.extensions[0].clone(),
            )])
            .with_workers(vec![vec![]]);
        let error = on_browser(&set, &timer, &browser).expect_err("it never starts");
        // The plugin's own message, not the bare time-out of the set's limit
        // for the hook, which is 10 s unless the plugin asks for more.
        let text = hook_failure(error);
        assert!(
            text.contains("no service worker for extension aaaa"),
            "{text}"
        );
        assert!(text.contains(&format!("after {seconds} s")), "{text}");
        assert_eq!(timer.elapsed(), Duration::from_secs(seconds));
    }
}

#[test]
fn a_host_that_cannot_list_workers_makes_the_launch_fail_naming_the_option() {
    let fixtures = tempfile::tempdir().expect("temp dir");
    let folder = unpacked_with_worker(fixtures.path(), "ext", "needs-host");
    let config = SessionConfig::new()
        .with_dir(&folder)
        .with_wait_for_workers(true);
    let (set, timer, launch) = launched_set(config, true);
    // No script: `extension_workers` answers NotSupported, as the default does.
    let browser = RecordingBrowser::new().with_extensions(vec![LoadedExtension::new(
        "aaaa",
        launch.extensions[0].clone(),
    )]);
    let text = hook_failure(on_browser(&set, &timer, &browser).expect_err("not supported"));
    assert!(text.contains("`wait_for_workers`"), "{text}");
    assert!(text.contains("service workers"), "{text}");
    assert_eq!(browser.calls(), [Call::ExtensionWorkers]);
}

#[test]
fn a_host_that_reports_no_extension_id_makes_the_launch_fail_naming_the_folder() {
    let fixtures = tempfile::tempdir().expect("temp dir");
    let folder = unpacked_with_worker(fixtures.path(), "ext", "no-ids");
    let config = SessionConfig::new()
        .with_dir(&folder)
        .with_wait_for_workers(true);
    let (set, timer, _launch) = launched_set(config, true);
    let browser = RecordingBrowser::new().with_workers(vec![vec![]]);
    let text = hook_failure(on_browser(&set, &timer, &browser).expect_err("no ids"));
    assert!(text.contains("`wait_for_workers`"), "{text}");
    assert!(text.contains(&folder.display().to_string()), "{text}");
    assert!(text.contains("id"), "{text}");
}

#[test]
fn a_set_without_a_timer_cannot_wait_and_says_so() {
    let fixtures = tempfile::tempdir().expect("temp dir");
    let folder = unpacked_with_worker(fixtures.path(), "ext", "no-clock");
    let config = SessionConfig::new()
        .with_dir(&folder)
        .with_wait_for_workers(true);
    let (set, _timer, launch) = launched_set(config, false);
    let browser = RecordingBrowser::new()
        .with_extensions(vec![LoadedExtension::new(
            "aaaa",
            launch.extensions[0].clone(),
        )])
        .with_workers(vec![vec![worker_of("aaaa")]]);
    let text = hook_failure(block_on(set.on_browser(&browser)).expect_err("no clock"));
    assert!(text.contains("`wait_for_workers`"), "{text}");
    assert!(text.contains("clock"), "{text}");
}

#[test]
fn nothing_is_asked_when_no_extension_has_a_worker() {
    let fixtures = tempfile::tempdir().expect("temp dir");
    let folder = unpacked(fixtures.path(), "ext", "no-worker");
    let config = SessionConfig::new()
        .with_dir(&folder)
        .with_wait_for_workers(true);
    let (set, timer, _launch) = launched_set(config, true);
    let browser = RecordingBrowser::new();
    on_browser(&set, &timer, &browser).expect("nothing to wait for");
    assert!(browser.calls().is_empty());
}

#[test]
fn a_failing_host_query_fails_the_hook() {
    let fixtures = tempfile::tempdir().expect("temp dir");
    let folder = unpacked_with_worker(fixtures.path(), "ext", "broken-host");
    let config = SessionConfig::new()
        .with_dir(&folder)
        .with_wait_for_workers(true);
    let (set, timer, launch) = launched_set(config, true);
    let browser = RecordingBrowser::new()
        .with_extensions(vec![LoadedExtension::new(
            "aaaa",
            launch.extensions[0].clone(),
        )])
        .with_workers(vec![vec![]])
        .failing("extension_workers");
    let text = hook_failure(on_browser(&set, &timer, &browser).expect_err("the host fails"));
    assert!(text.contains("extension_workers"), "{text}");
}

#[test]
fn without_wait_for_workers_on_browser_asks_nothing() {
    let fixtures = tempfile::tempdir().expect("temp dir");
    let folder = unpacked_with_worker(fixtures.path(), "ext", "no-wait");
    let (set, timer, _launch) = launched_set(SessionConfig::new().with_dir(&folder), true);
    let browser = RecordingBrowser::new();
    on_browser(&set, &timer, &browser).expect("nothing to do");
    assert!(browser.calls().is_empty());
}

#[test]
fn waiting_asks_for_the_clock_and_a_longer_limit_for_on_browser_only() {
    let fixtures = tempfile::tempdir().expect("temp dir");
    let folder = unpacked_with_worker(fixtures.path(), "ext", "meta");
    let base = || SessionConfig::new().with_dir(&folder);

    let off = plugin(base()).metadata();
    assert!(!off.capabilities.covers(&Capability::Clock));
    assert_eq!(off.budgets.limit_for("on_browser"), Duration::from_secs(10));

    let on = plugin(base().with_wait_for_workers(true)).metadata();
    assert!(on.capabilities.covers(&Capability::Clock));
    assert!(on.capabilities.covers(&Capability::LaunchExtensions));
    assert_eq!(on.budgets.limit_for("on_browser"), Duration::from_secs(15));
    assert_eq!(
        on.budgets.limit_for("before_launch"),
        Duration::from_secs(30)
    );
    assert_eq!(
        on.budgets.limit_for("before_close"),
        Duration::from_secs(10)
    );

    let slow = plugin(
        base()
            .with_wait_for_workers(true)
            .with_worker_timeout_secs(30),
    )
    .metadata();
    assert_eq!(
        slow.budgets.limit_for("on_browser"),
        Duration::from_secs(35)
    );
}

#[test]
fn a_set_that_withholds_the_clock_refuses_the_wait_at_start_up() {
    let fixtures = tempfile::tempdir().expect("temp dir");
    let folder = unpacked_with_worker(fixtures.path(), "ext", "no-grant");
    let waiting = plugin(
        SessionConfig::new()
            .with_dir(&folder)
            .with_wait_for_workers(true),
    );
    let grants: CapabilitySet = waiting
        .metadata()
        .capabilities
        .iter()
        .filter(|capability| **capability != Capability::Clock)
        .cloned()
        .collect();
    let set = PluginSet::strict()
        .with_grants(waiting, grants)
        .expect("a strict set takes it");
    let error = set.check(&context(true)).expect_err("clock is not granted");
    assert!(
        matches!(&error, PluginError::Capability { plugin, capability, .. } if plugin == "browser" && capability == "clock"),
        "{error:?}"
    );
}

// ---- saved sessions (cookies in a file) ----

// Saving needs Unix file permissions (the plugin refuses it elsewhere), and
// these tests use symbolic links and modes.
#[cfg(unix)]
mod sessions {
    use super::*;

    /// A value no error, result, log line or `Debug` output may ever repeat.
    const CANARY: &str = "canary-8f3a2c19-secret";

    /// A browser whose errors repeat the parameters of the command, as a careless
    /// one might.
    struct Leaky;

    #[async_trait]
    impl BrowserHandle for Leaky {
        fn engine(&self) -> Engine {
            Engine::Cdp
        }

        fn family(&self) -> BrowserFamily {
            BrowserFamily::Chromium
        }

        async fn send(&self, method: &str, params: Value) -> seleniumbase_rs_plugin::Result<Value> {
            Err(PluginError::other(format!("{method} failed for {params}")))
        }
    }

    /// `Storage.getCookies` answers, as Chrome words them: extra fields, and
    /// `expires: -1` for a session cookie.
    fn chrome_cookies() -> Value {
        json!({ "cookies": [
        { "name": "sid", "value": CANARY, "domain": ".example.test", "path": "/",
          "expires": 4_102_444_800.0, "size": 30, "httpOnly": true, "secure": true,
          "session": false, "sameSite": "Lax", "priority": "High", "sameParty": false,
          "sourceScheme": "Secure", "sourcePort": 443 },
        { "name": "visit", "value": "1", "domain": "example.test", "path": "/app",
          "expires": -1, "size": 6, "httpOnly": false, "secure": false, "session": true,
          "priority": "Medium", "sameParty": false, "sourceScheme": "NonSecure",
          "sourcePort": 80 },
        { "name": "part", "value": "p", "domain": ".example.test", "path": "/",
          "expires": -1, "size": 5, "httpOnly": false, "secure": true, "session": true,
          "sameSite": "None",
          "partitionKey": { "topLevelSite": "https://top.test", "hasCrossSiteAncestor": false } },
    ] })
    }

    /// What the three cookies of [`chrome_cookies`] become in a session file and
    /// in `Storage.setCookies`: only the fields the plugin keeps, and no expiry
    /// for a session cookie.
    fn kept_cookies() -> Value {
        json!([
            { "name": "sid", "value": CANARY, "domain": ".example.test", "path": "/",
              "expires": 4_102_444_800.0, "httpOnly": true, "secure": true, "sameSite": "Lax",
              "priority": "High", "sourceScheme": "Secure", "sourcePort": 443 },
            { "name": "visit", "value": "1", "domain": "example.test", "path": "/app",
              "httpOnly": false, "secure": false, "priority": "Medium",
              "sourceScheme": "NonSecure", "sourcePort": 80 },
            { "name": "part", "value": "p", "domain": ".example.test", "path": "/",
              "httpOnly": false, "secure": true, "sameSite": "None",
              "partitionKey": { "topLevelSite": "https://top.test", "hasCrossSiteAncestor": false } },
        ])
    }

    /// A session file's text with these cookies.
    fn session_text(cookies: &Value) -> String {
        json!({ "version": 1, "saved_at_ms": 1_767_225_600_000_u64, "cookies": cookies })
            .to_string()
    }

    /// A set around a plugin that restores the session `login` kept in `dir`,
    /// and saves it when the browser closes if `save` is true.
    fn session_set(dir: &Path, save: bool) -> PluginSet {
        let config = SessionConfig::new()
            .with_session("login")
            .with_session_dir(dir)
            .with_save_on_close(save);
        let set = PluginSet::strict()
            .with(plugin(config))
            .expect("a strict set takes it");
        set.check(&context(true))
            .expect("the grants cover the options");
        set
    }

    /// The text of the failure of the `browser` plugin in `hook`, which must not
    /// repeat the canary.
    fn session_failure(error: &PluginError, hook: &str) -> String {
        let PluginError::Hook {
            plugin,
            hook: found,
            message,
        } = error
        else {
            panic!("expected a hook failure, got {error:?}");
        };
        assert_eq!(plugin, "browser");
        assert_eq!(*found, hook);
        assert!(!message.contains(CANARY), "a value leaked: {message}");
        assert!(!format!("{error:?}").contains(CANARY), "a value leaked");
        message.clone()
    }

    fn put_session(dir: &Path, text: &str) {
        std::fs::create_dir_all(dir).expect("make the session folder");
        std::fs::write(dir.join("login.json"), text).expect("write the session file");
    }

    fn sent_cookies(browser: &RecordingBrowser) -> Vec<Value> {
        browser
            .calls()
            .into_iter()
            .filter_map(|call| match call {
                Call::Send(method, params) if method == "Storage.setCookies" => {
                    Some(params["cookies"].clone())
                }
                _ => None,
            })
            .collect()
    }

    #[test]
    fn restore_puts_back_only_the_allowed_fields_of_each_cookie() {
        let fixtures = tempfile::tempdir().expect("temp dir");
        let dir = fixtures.path().join("sessions");
        let mut cookies = chrome_cookies()["cookies"].clone();
        // The file may hold more than the plugin sends: fields the browser added,
        // and ones somebody else did.
        cookies[0]["evil"] = json!("<script>");
        cookies[1]["session"] = json!(true);
        put_session(&dir, &session_text(&cookies));
        let set = session_set(&dir, false);
        let browser = RecordingBrowser::new();

        block_on(set.on_browser(&browser)).expect("a good session file");

        assert_eq!(sent_cookies(&browser), [kept_cookies()]);
        assert_eq!(
            browser.calls().len(),
            1,
            "one command: {:?}",
            browser.calls()
        );
    }

    #[test]
    fn expired_cookies_are_dropped_and_session_cookies_are_kept() {
        let fixtures = tempfile::tempdir().expect("temp dir");
        let dir = fixtures.path().join("sessions");
        let cookie = |name: &str, expires: Option<f64>| {
            let mut cookie = json!({ "name": name, "value": "v", "domain": "a.test", "path": "/" });
            if let Some(expires) = expires {
                cookie["expires"] = json!(expires);
            }
            cookie
        };
        put_session(
            &dir,
            &session_text(&json!([
                cookie("expired", Some(1.0)),
                cookie("later", Some(4_102_444_800.0)),
                cookie("session", None),
                cookie("minus-one", Some(-1.0)),
            ])),
        );
        let browser = RecordingBrowser::new();

        block_on(session_set(&dir, false).on_browser(&browser)).expect("a good session file");

        let sent = sent_cookies(&browser);
        let names: Vec<&str> = sent[0]
            .as_array()
            .expect("a list")
            .iter()
            .map(|c| c["name"].as_str().expect("a name"))
            .collect();
        assert_eq!(names, ["later", "session", "minus-one"]);
        assert_eq!(sent[0][0]["expires"], json!(4_102_444_800.0));
        assert!(sent[0][1].get("expires").is_none());
        assert!(
            sent[0][2].get("expires").is_none(),
            "-1 is a session cookie"
        );
    }

    #[test]
    fn a_session_that_was_never_saved_is_a_fresh_start() {
        let fixtures = tempfile::tempdir().expect("temp dir");
        let dir = fixtures.path().join("not-made-yet");
        let browser = RecordingBrowser::new();
        block_on(session_set(&dir, false).on_browser(&browser)).expect("a missing file is fine");
        assert!(browser.calls().is_empty());
        assert!(!dir.exists(), "restoring makes nothing");
    }

    #[test]
    fn a_session_with_nothing_to_restore_sends_nothing() {
        let fixtures = tempfile::tempdir().expect("temp dir");
        let dir = fixtures.path().join("sessions");
        for cookies in [
            json!([]),
            json!([{ "name": "old", "value": "v", "domain": "a.test", "path": "/", "expires": 1.0 }]),
        ] {
            put_session(&dir, &session_text(&cookies));
            let browser = RecordingBrowser::new();
            block_on(session_set(&dir, false).on_browser(&browser)).expect("nothing to put back");
            assert!(browser.calls().is_empty(), "{cookies}");
        }
    }

    #[test]
    fn a_bad_session_file_is_an_error_naming_the_option_and_never_a_value() {
        let fixtures = tempfile::tempdir().expect("temp dir");
        let dir = fixtures.path().join("sessions");
        let cookie = |field: &str, value: Value| {
            let mut cookie =
                json!({ "name": "sid", "value": "v", "domain": "a.test", "path": "/" });
            cookie[field] = value;
            session_text(&json!([cookie]))
        };
        let texts = [
            // Cut off in the middle of a value: serde would quote the value.
            format!(r#"{{"version":1,"saved_at_ms":1,"cookies":[{{"name":"sid","value":"{CANARY}"#),
            cookie("value", json!([CANARY])),
            cookie("name", json!({ "x": CANARY })),
            cookie("domain", json!(5)),
            cookie("path", json!(CANARY)),
            cookie("sameSite", json!(CANARY)),
            cookie("priority", json!(CANARY)),
            cookie("sourceScheme", json!(CANARY)),
            cookie("sourcePort", json!(CANARY)),
            cookie("httpOnly", json!(CANARY)),
            cookie("secure", json!(CANARY)),
            cookie("expires", json!(CANARY)),
            cookie("partitionKey", json!(7)),
            format!(r#"{{"version":2,"saved_at_ms":1,"cookies":["{CANARY}"]}}"#),
            format!(r#"{{"version":"{CANARY}","cookies":[]}}"#),
            format!(r#"{{"version":1,"cookies":"{CANARY}"}}"#),
            format!(r#"{{"version":1,"cookies":["{CANARY}"]}}"#),
            format!(r#"{{"version":1}} "{CANARY}""#),
            format!(r#"["{CANARY}"]"#),
            format!(r#""{CANARY}""#),
            String::new(),
        ];
        for text in texts {
            put_session(&dir, &text);
            let browser = RecordingBrowser::new();
            let error = block_on(session_set(&dir, false).on_browser(&browser))
                .expect_err("a bad file must be refused");
            let message = session_failure(&error, "on_browser");
            assert!(message.contains("`session`"), "{message}");
            assert!(message.contains("login"), "{message}");
            assert!(browser.calls().is_empty(), "nothing was sent for {text}");
        }
    }

    #[test]
    fn a_syntax_error_says_where_and_not_what() {
        let fixtures = tempfile::tempdir().expect("temp dir");
        let dir = fixtures.path().join("sessions");
        put_session(
            &dir,
            &format!("{{\n  \"version\": 1,\n  \"cookies\": [\"{CANARY}\" 5]\n}}"),
        );
        let error = block_on(session_set(&dir, false).on_browser(&RecordingBrowser::new()))
            .expect_err("not JSON");
        let message = session_failure(&error, "on_browser");
        assert!(message.contains("line 3"), "{message}");
    }

    #[test]
    fn a_session_file_that_is_too_big_or_too_full_is_refused() {
        let fixtures = tempfile::tempdir().expect("temp dir");
        let dir = fixtures.path().join("sessions");
        std::fs::create_dir_all(&dir).expect("make the folder");

        std::fs::write(dir.join("login.json"), vec![b' '; 8 * 1024 * 1024 + 1]).expect("write");
        let error = block_on(session_set(&dir, false).on_browser(&RecordingBrowser::new()))
            .expect_err("too big");
        assert!(session_failure(&error, "on_browser").contains("8 MiB"));

        let cookie = json!({ "name": "c", "value": "v", "domain": "a.test", "path": "/" });
        put_session(&dir, &session_text(&json!(vec![cookie.clone(); 5001])));
        let error = block_on(session_set(&dir, false).on_browser(&RecordingBrowser::new()))
            .expect_err("too many");
        assert!(session_failure(&error, "on_browser").contains("5000"));

        put_session(&dir, &session_text(&json!(vec![cookie; 5000])));
        let browser = RecordingBrowser::new();
        block_on(session_set(&dir, false).on_browser(&browser)).expect("5000 is the limit");
        assert_eq!(
            sent_cookies(&browser)[0].as_array().expect("a list").len(),
            5000
        );
    }

    #[test]
    fn a_symlink_or_a_folder_in_place_of_the_session_file_is_refused_on_restore() {
        let fixtures = tempfile::tempdir().expect("temp dir");
        let dir = fixtures.path().join("sessions");
        std::fs::create_dir_all(&dir).expect("make the folder");
        let elsewhere = fixtures.path().join("elsewhere.json");
        std::fs::write(&elsewhere, session_text(&json!([]))).expect("write");
        std::os::unix::fs::symlink(&elsewhere, dir.join("login.json")).expect("a symlink");
        let error = block_on(session_set(&dir, false).on_browser(&RecordingBrowser::new()))
            .expect_err("a symlink");
        assert!(session_failure(&error, "on_browser").contains("symbolic link"));

        std::fs::remove_file(dir.join("login.json")).expect("remove");
        std::fs::create_dir(dir.join("login.json")).expect("a folder");
        let error = block_on(session_set(&dir, false).on_browser(&RecordingBrowser::new()))
            .expect_err("a folder");
        assert!(session_failure(&error, "on_browser").contains("not a regular file"));
    }

    #[test]
    fn save_on_close_writes_the_cookies_in_before_close() {
        use std::os::unix::fs::PermissionsExt;
        let fixtures = tempfile::tempdir().expect("temp dir");
        let dir = fixtures.path().join("made").join("sessions");
        let set = session_set(&dir, true);
        let browser = RecordingBrowser::new().replying("Storage.getCookies", chrome_cookies());

        block_on(set.on_browser(&browser)).expect("nothing to restore, the folder can be written");
        let failures = block_on(set.before_close(&browser));

        assert!(failures.is_empty(), "{failures:?}");
        assert_eq!(
            browser.calls(),
            [Call::Send("Storage.getCookies".into(), json!({}))]
        );
        let file = dir.join("login.json");
        let saved: Value =
            serde_json::from_slice(&std::fs::read(&file).expect("the file")).expect("JSON");
        assert_eq!(saved["version"], json!(1));
        assert!(saved["saved_at_ms"].as_u64().expect("a time") > 1_767_225_600_000);
        assert_eq!(saved["cookies"], kept_cookies());
        let mode = |path: &Path| {
            std::fs::metadata(path)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777
        };
        assert_eq!(mode(&file), 0o600);
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(dir.parent().expect("parent")), 0o700);
        let names: Vec<_> = std::fs::read_dir(&dir)
            .expect("read")
            .map(|e| e.expect("entry").file_name())
            .collect();
        assert_eq!(names, ["login.json"], "no temporary file is left");
    }

    #[test]
    fn saving_replaces_a_looser_file_and_leaves_no_temporary_file() {
        use std::os::unix::fs::PermissionsExt;
        let fixtures = tempfile::tempdir().expect("temp dir");
        let dir = fixtures.path().join("sessions");
        put_session(&dir, "old content");
        let file = dir.join("login.json");
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).expect("loosen");
        let set = session_set(&dir, true);
        let browser = RecordingBrowser::new().replying("Storage.getCookies", chrome_cookies());

        assert!(block_on(set.before_close(&browser)).is_empty());

        let text = std::fs::read_to_string(&file).expect("the file");
        assert!(text.contains("\"version\""), "{text}");
        assert_eq!(
            std::fs::metadata(&file)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(std::fs::read_dir(&dir).expect("read").count(), 1);
    }

    #[test]
    fn a_symlink_at_the_target_is_not_followed_when_saving() {
        let fixtures = tempfile::tempdir().expect("temp dir");
        let dir = fixtures.path().join("sessions");
        std::fs::create_dir_all(&dir).expect("make the folder");
        let victim = fixtures.path().join("victim.txt");
        std::fs::write(&victim, "untouched").expect("write");
        std::os::unix::fs::symlink(&victim, dir.join("login.json")).expect("a symlink");
        let set = session_set(&dir, true);
        let browser = RecordingBrowser::new().replying("Storage.getCookies", chrome_cookies());

        let failures = block_on(set.before_close(&browser));

        assert_eq!(failures.len(), 1, "{failures:?}");
        let message = session_failure(&failures[0], "before_close");
        assert!(message.contains("symbolic link"), "{message}");
        assert_eq!(std::fs::read_to_string(&victim).expect("read"), "untouched");
        assert_eq!(
            std::fs::read_dir(&dir).expect("read").count(),
            1,
            "no temporary file"
        );
    }

    #[test]
    fn a_save_that_fails_leaves_the_old_file_and_no_temporary_file() {
        let fixtures = tempfile::tempdir().expect("temp dir");
        let dir = fixtures.path().join("sessions");
        put_session(&dir, "the old session");
        let set = session_set(&dir, true);

        // The browser cannot give its cookies.
        let broken = RecordingBrowser::new().failing("Storage.getCookies");
        let failures = block_on(set.before_close(&broken));
        assert_eq!(failures.len(), 1, "{failures:?}");
        session_failure(&failures[0], "before_close");
        assert_eq!(
            std::fs::read_to_string(dir.join("login.json")).expect("read"),
            "the old session"
        );

        // The browser answers something that is not a list of cookies.
        for reply in [
            json!({}),
            json!({ "cookies": "x" }),
            json!({ "cookies": [5] }),
            json!(null),
        ] {
            let odd = RecordingBrowser::new().replying("Storage.getCookies", reply);
            let failures = block_on(set.before_close(&odd));
            assert_eq!(failures.len(), 1, "{failures:?}");
            session_failure(&failures[0], "before_close");
        }
        assert_eq!(
            std::fs::read_to_string(dir.join("login.json")).expect("read"),
            "the old session"
        );

        // Too many cookies to restore later: not saved.
        let cookie = json!({ "name": "c", "value": "v", "domain": "a.test", "path": "/" });
        let many = RecordingBrowser::new().replying(
            "Storage.getCookies",
            json!({ "cookies": vec![cookie; 5001] }),
        );
        let failures = block_on(set.before_close(&many));
        assert!(session_failure(&failures[0], "before_close").contains("5000"));

        // A folder where the file should go.
        std::fs::remove_file(dir.join("login.json")).expect("remove");
        std::fs::create_dir(dir.join("login.json")).expect("a folder");
        let browser = RecordingBrowser::new().replying("Storage.getCookies", chrome_cookies());
        let failures = block_on(set.before_close(&browser));
        assert_eq!(failures.len(), 1, "{failures:?}");
        assert!(session_failure(&failures[0], "before_close").contains("not a regular file"));
        assert_eq!(
            std::fs::read_dir(&dir).expect("read").count(),
            1,
            "no temporary file"
        );
    }

    #[test]
    fn without_save_on_close_before_close_does_nothing() {
        let fixtures = tempfile::tempdir().expect("temp dir");
        let dir = fixtures.path().join("sessions");
        let set = session_set(&dir, false);
        let browser = RecordingBrowser::new().replying("Storage.getCookies", chrome_cookies());
        assert!(block_on(set.before_close(&browser)).is_empty());
        assert!(browser.calls().is_empty());
        assert!(!dir.exists());
    }

    #[test]
    fn a_saved_session_comes_back_in_the_next_browser() {
        let fixtures = tempfile::tempdir().expect("temp dir");
        let dir = fixtures.path().join("sessions");
        let first = session_set(&dir, true);
        let browser = RecordingBrowser::new().replying("Storage.getCookies", chrome_cookies());
        assert!(block_on(first.before_close(&browser)).is_empty());

        // A pool hands the next browser a fresh copy of the same plugin.
        let next = first.for_launch();
        let again = RecordingBrowser::new();
        block_on(next.on_browser(&again)).expect("the session is put back");
        assert_eq!(sent_cookies(&again), [kept_cookies()]);
    }

    #[test]
    fn a_folder_that_cannot_be_written_fails_the_launch_and_not_the_close() {
        use std::os::unix::fs::PermissionsExt;
        let fixtures = tempfile::tempdir().expect("temp dir");
        let locked = fixtures.path().join("locked");
        std::fs::create_dir(&locked).expect("make the folder");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o500)).expect("lock");
        let dir = locked.join("sessions");
        // A process that may write there anyway (root) cannot show the failure.
        if std::fs::create_dir(&dir).is_ok() {
            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700))
                .expect("unlock");
            return;
        }
        let set = session_set(&dir, true);
        let error = block_on(set.on_browser(&RecordingBrowser::new())).expect_err("not writable");
        let message = session_failure(&error, "on_browser");
        assert!(message.contains("`session`"), "{message}");
        assert!(message.contains("save_on_close"), "{message}");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).expect("unlock");
    }

    #[test]
    fn a_browser_message_that_repeats_a_cookie_is_scrubbed() {
        let fixtures = tempfile::tempdir().expect("temp dir");
        let dir = fixtures.path().join("sessions");
        put_session(&dir, &session_text(&chrome_cookies()["cookies"]));
        let set = session_set(&dir, true);
        let error = block_on(set.on_browser(&Leaky)).expect_err("the browser refuses");
        let message = session_failure(&error, "on_browser");
        assert!(message.contains("Storage.setCookies"), "{message}");

        let failures = block_on(set.before_close(&Leaky));
        session_failure(&failures[0], "before_close");
    }

    #[test]
    fn the_instance_declares_the_capabilities_its_session_options_need() {
        let fixtures = tempfile::tempdir().expect("temp dir");
        let dir = fixtures.path().join("sessions");
        let file = dir.join("login.json");
        let has = |meta: &Metadata, capability: &Capability| meta.capabilities.covers(capability);
        let reads_file = Capability::HostFsRead(PathScope::Declared(vec![file.clone()]));
        let writes_dir = Capability::HostFsWrite(PathScope::Declared(vec![dir.clone()]));

        let none = plugin(SessionConfig::new()).metadata();
        for capability in [
            &Capability::CookiesRead,
            &Capability::CookiesWrite,
            &reads_file,
            &writes_dir,
        ] {
            assert!(!has(&none, capability), "{capability}");
        }

        let restore = plugin(
            SessionConfig::new()
                .with_session("login")
                .with_session_dir(&dir),
        )
        .metadata();
        assert!(has(&restore, &Capability::CookiesWrite));
        assert!(has(&restore, &reads_file));
        assert!(!has(&restore, &Capability::CookiesRead));
        assert!(!has(&restore, &writes_dir));

        let saving = plugin(
            SessionConfig::new()
                .with_session("login")
                .with_session_dir(&dir)
                .with_save_on_close(true),
        )
        .metadata();
        assert!(has(&saving, &Capability::CookiesWrite));
        assert!(has(&saving, &Capability::CookiesRead));
        assert!(has(&saving, &reads_file));
        assert!(has(&saving, &writes_dir));
    }

    #[test]
    fn a_set_that_withholds_cookie_access_refuses_the_session_at_start_up() {
        let fixtures = tempfile::tempdir().expect("temp dir");
        let dir = fixtures.path().join("sessions");
        for (missing, expected) in [
            (Capability::CookiesWrite, "cookies.write"),
            (Capability::CookiesRead, "cookies.read"),
        ] {
            let saving = plugin(
                SessionConfig::new()
                    .with_session("login")
                    .with_session_dir(&dir)
                    .with_save_on_close(true),
            );
            let grants: CapabilitySet = saving
                .metadata()
                .capabilities
                .iter()
                .filter(|capability| **capability != missing)
                .cloned()
                .collect();
            let set = PluginSet::strict()
                .with_grants(saving, grants)
                .expect("a strict set takes it");
            let error = set.check(&context(true)).expect_err("not granted");
            assert!(
                matches!(&error, PluginError::Capability { capability, .. } if capability == expected),
                "{error:?}"
            );
        }
    }

    #[test]
    fn the_session_folder_defaults_to_saved_sessions_in_the_working_directory() {
        let here = std::env::current_dir().expect("a working directory");
        let meta = plugin(SessionConfig::new().with_session("login")).metadata();
        let expected = Capability::HostFsRead(PathScope::Declared(vec![
            here.join("saved_sessions").join("login.json"),
        ]));
        assert!(meta.capabilities.covers(&expected), "{meta:?}");

        // A relative folder is made absolute when the plugin is built.
        let meta = plugin(
            SessionConfig::new()
                .with_session("login")
                .with_session_dir("kept"),
        )
        .metadata();
        let expected = Capability::HostFsRead(PathScope::Declared(vec![
            here.join("kept").join("login.json"),
        ]));
        assert!(meta.capabilities.covers(&expected), "{meta:?}");
    }
} // mod sessions

// ---- order against a privacy plugin such as tor (spec 8, question 11) ----

/// Stands in for the tor plugin, which does not exist yet: a privacy plugin.
struct PrivacyStandIn;

#[async_trait]
impl Plugin for PrivacyStandIn {
    fn name(&self) -> &str {
        "tor"
    }

    fn metadata(&self) -> Metadata {
        Metadata::new(Category::Privacy)
            .version("0")
            .summary("stands in for the tor plugin")
    }
}

#[test]
fn a_privacy_plugin_runs_after_the_browser_plugin_whatever_the_insertion_order() {
    // Extension -> Phase::Normal, Privacy -> Phase::Enforce, and an earlier
    // phase runs first: the privacy plugin has the last word.
    assert!(Category::Extension.default_phase() < Category::Privacy.default_phase());

    let browser = || BrowserSession::configure(&Value::Null).expect("no options");
    let tor_first = PluginSet::strict()
        .with(PrivacyStandIn)
        .and_then(|set| set.with(browser()))
        .expect("both fit");
    let browser_first = PluginSet::strict()
        .with(browser())
        .and_then(|set| set.with(PrivacyStandIn))
        .expect("both fit");
    assert_eq!(tor_first.names(), ["browser", "tor"]);
    assert_eq!(browser_first.names(), ["browser", "tor"]);
}
