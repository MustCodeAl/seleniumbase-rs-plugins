//! The options and the declaration of the batcher: no browser.

use std::path::PathBuf;
use std::time::Duration;

use seleniumbase_rs_plugin::{
    BrowserFamily, Capability, Category, Configurable, Descriptor, Engine, LaunchContext,
    PathScope, Plugin, PluginError, PluginSet, PluginSpec, Registry,
};
use seleniumbase_rs_plugin_batcher::{Batcher, BatcherConfig};
use serde_json::{Value, json};

fn config_error(config: Value) -> String {
    match Batcher::configure(&config) {
        Err(PluginError::Config(message)) => message,
        other => panic!("expected a configuration error, got {other:?}"),
    }
}

fn cdp() -> LaunchContext {
    LaunchContext {
        engine: Engine::Cdp,
        family: BrowserFamily::Chromium,
        headless: true,
        connecting: false,
    }
}

#[test]
fn no_options_means_the_defaults() {
    let plugin = Batcher::configure(&Value::Null).unwrap();
    let config = plugin.config();
    assert_eq!(*config, BatcherConfig::default());
    assert_eq!(config.concurrency, 2);
    assert_eq!(config.chunk_size, 25);
    assert_eq!(config.job_timeout_secs, 60);
    assert_eq!(config.retries, 1);
    assert_eq!(config.backoff_ms, 500);
    assert_eq!(config.runner, "open");
    assert_eq!(config.max_jobs, 10_000);
    assert!(!config.ordered);
    assert_eq!(config.warm_up, None);
    assert_eq!(config.resume_file, None);
}

#[test]
fn a_misspelt_option_names_the_plugin_and_the_option() {
    assert_eq!(
        config_error(json!({ "concurency": 4 })),
        "batcher: unknown option `concurency`"
    );
}

#[test]
fn every_limit_is_checked_at_both_ends() {
    for (config, option) in [
        (json!({ "concurrency": 0 }), "concurrency"),
        (json!({ "concurrency": 33 }), "concurrency"),
        (json!({ "chunk_size": 0 }), "chunk_size"),
        (json!({ "chunk_size": 10_001 }), "chunk_size"),
        (json!({ "job_timeout_secs": 0 }), "job_timeout_secs"),
        (json!({ "job_timeout_secs": 3601 }), "job_timeout_secs"),
        (json!({ "retries": 4 }), "retries"),
        (json!({ "backoff_ms": 60_001 }), "backoff_ms"),
        (json!({ "max_jobs": 0 }), "max_jobs"),
        (json!({ "max_jobs": 1_000_001 }), "max_jobs"),
    ] {
        let message = config_error(config.clone());
        assert!(
            message.starts_with("batcher: ") && message.contains(&format!("`{option}`")),
            "{config}: {message}"
        );
    }
    Batcher::configure(&json!({
        "concurrency": 32, "chunk_size": 10_000, "job_timeout_secs": 3600, "retries": 3,
        "backoff_ms": 60_000, "max_jobs": 1_000_000,
    }))
    .unwrap();
    Batcher::configure(
        &json!({ "concurrency": 1, "chunk_size": 1, "job_timeout_secs": 1,
        "retries": 0, "backoff_ms": 0, "max_jobs": 1 }),
    )
    .unwrap();
}

#[test]
fn a_runner_name_must_be_a_plugin_name() {
    for runner in ["", " ", " fetcher", "my fetcher", "batcher"] {
        let message = config_error(json!({ "runner": runner }));
        assert!(message.contains("`runner`"), "{runner:?}: {message}");
    }
    Batcher::configure(&json!({ "runner": "extractor" })).unwrap();
}

#[test]
fn an_empty_resume_file_path_is_refused() {
    assert!(config_error(json!({ "resume_file": "" })).contains("`resume_file`"));
}

#[test]
fn the_backoff_doubles_and_stops_at_a_minute() {
    let config = BatcherConfig {
        backoff_ms: 100,
        ..BatcherConfig::default()
    };
    let waits: Vec<Duration> = (1..=4).map(|attempt| config.backoff(attempt)).collect();
    assert_eq!(
        waits,
        [
            Duration::from_millis(100),
            Duration::from_millis(200),
            Duration::from_millis(400),
            Duration::from_millis(800),
        ]
    );
    let long = BatcherConfig {
        backoff_ms: 40_000,
        ..BatcherConfig::default()
    };
    assert_eq!(long.backoff(2), Duration::from_secs(60));
}

#[test]
fn it_declares_its_category_and_capabilities() {
    let meta = Batcher::describe();
    assert_eq!(meta.category, Some(Category::Environment));
    for needed in [
        Capability::Task,
        Capability::Contexts,
        Capability::PageNavigate,
        Capability::PageEvaluate,
    ] {
        assert!(meta.capabilities.covers(&needed), "{needed}");
    }
    assert!(!meta.capabilities.covers(&Capability::CookiesRead));
    assert!(!meta.capabilities.covers(&Capability::NetSensitive));
    assert!(meta.requires.is_empty());
}

#[test]
fn a_named_runner_becomes_a_dependency() {
    let plugin = Batcher::configure(&json!({ "runner": "fetcher" })).unwrap();
    let meta = plugin.metadata();
    assert_eq!(meta.requires, ["fetcher"]);
    // A set without the runner refuses to start.
    let set = PluginSet::strict().with(plugin).unwrap();
    let error = set.check(&cdp()).unwrap_err();
    assert!(
        matches!(&error, PluginError::MissingDependency { plugin, missing }
            if plugin == "batcher" && missing == "fetcher"),
        "{error:?}"
    );
}

#[test]
fn a_resume_file_is_declared_as_a_file_the_plugin_reads_and_writes() {
    let plugin = Batcher::configure(&json!({ "resume_file": "out/done.jsonl" })).unwrap();
    let scope = PathScope::Declared(vec![PathBuf::from("out/done.jsonl")]);
    let meta = plugin.metadata();
    assert!(
        meta.capabilities
            .covers(&Capability::HostFsRead(scope.clone()))
    );
    assert!(meta.capabilities.covers(&Capability::HostFsWrite(scope)));
    // Without the option the plugin touches no file.
    let plain = Batcher::configure(&Value::Null).unwrap().metadata();
    assert!(
        !plain
            .capabilities
            .covers(&Capability::HostFsWrite(PathScope::Temp))
    );
}

#[test]
fn it_registers_and_runs_on_chromium_over_cdp_only() {
    let registry = Registry::new().with(Descriptor::of::<Batcher>());
    assert_eq!(registry.names(), ["batcher"]);
    let set = registry.plugin_set(&[PluginSpec::new("batcher")]).unwrap();
    set.check(&cdp()).unwrap();
    let firefox = LaunchContext {
        family: BrowserFamily::Firefox,
        ..cdp()
    };
    assert!(set.check(&firefox).is_err());
}
