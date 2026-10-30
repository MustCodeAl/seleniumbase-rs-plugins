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
use seleniumbase_rs_plugin_browser::{BrowserSession, SessionConfig};
use seleniumbase_rs_plugin_crx::CrxExtensions;
use seleniumbase_rs_plugin_testing::block_on;
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
    // `session`, `wait_for_workers` and `interactive` are in the design but not
    // built yet: they are refused instead of accepted and ignored.
    for option in [
        "extension_zips",
        "session",
        "wait_for_workers",
        "interactive",
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
