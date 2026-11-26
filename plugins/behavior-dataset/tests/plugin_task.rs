//! Plugin trait, Configurable/Registry, capability gating, and Task execution tests.
#![cfg(feature = "plugin")]

use std::sync::Arc;

use seleniumbase_rs_plugin::{
    Capability, CapabilitySet, Category, Clock, Configurable, Descriptor, NoPrompt, PluginError,
    PluginSet, Registry, Requirements, TaskContext,
};
use seleniumbase_rs_plugin_behavior_dataset::{
    BehaviorDatasetPlugin, DatasetConfig, DatasetSample, ExportFormat, NAME, PersonaKind,
    ScenarioKind,
};
use seleniumbase_rs_plugin_testing::{ManualTimer, RecordingBrowser, VecSink, block_on};
use serde_json::{Value, json};

fn run_task(
    set: &PluginSet,
    browser: &RecordingBrowser,
    input: &Value,
) -> (seleniumbase_rs_plugin::Result<Value>, Vec<Value>) {
    let sink = VecSink::new();
    let clock = Clock::new(Arc::new(ManualTimer::new()));
    let cx = TaskContext::new(browser, input, &sink, set, &clock, &NoPrompt);
    let summary = block_on(set.task(NAME).unwrap().run(&cx));
    (summary, sink.lines())
}

#[test]
fn plugin_metadata_requirements_and_registry_configuration() {
    let meta = BehaviorDatasetPlugin::describe();
    assert_eq!(meta.category, Some(Category::Core));
    assert!(meta.capabilities.covers(&Capability::Task));
    assert!(meta.capabilities.covers(&Capability::PageEvaluate));
    assert!(meta.capabilities.covers(&Capability::PageNavigate));
    assert!(meta.capabilities.covers(&Capability::Cdp("Input".into())));

    let plugin = BehaviorDatasetPlugin::configure(&Value::Null).unwrap();
    assert_eq!(*plugin.config(), DatasetConfig::default());
    assert_eq!(
        seleniumbase_rs_plugin::Plugin::requirements(&plugin),
        Requirements::empty()
    );

    let registry = Registry::new().with(Descriptor::of::<BehaviorDatasetPlugin>());
    assert_eq!(registry.names(), [NAME]);

    let set = PluginSet::strict().with(plugin).unwrap();
    assert_eq!(set.names(), [NAME]);
    assert_eq!(set.task_names(), [NAME]);

    let err = BehaviorDatasetPlugin::configure(&json!({ "nonexistent_field": 1 })).unwrap_err();
    assert!(
        matches!(err, PluginError::Config(ref msg) if msg.contains("unknown option `nonexistent_field`")),
        "unexpected error: {err}"
    );
}

#[test]
fn task_runs_deterministically_without_live_browser_io_and_records_to_sink() {
    let config = DatasetConfig {
        sample_count: 4,
        base_seed: 123,
        personas: vec![PersonaKind::FastTypist, PersonaKind::CarefulReader],
        scenarios: vec![ScenarioKind::FormEntry, ScenarioKind::TargetApproachClick],
        include_baseline_negatives: true,
        export_format: ExportFormat::CsvFeatures,
        ..DatasetConfig::default()
    };
    let plugin = BehaviorDatasetPlugin::new(config).unwrap();
    let set = PluginSet::strict().with(plugin).unwrap();

    let browser = RecordingBrowser::new();
    let (summary, lines) = run_task(&set, &browser, &Value::Null);
    let summary = summary.unwrap();

    // No tabs, CDP commands, or browser I/O should happen during offline generation.
    assert!(
        browser.calls().is_empty(),
        "unexpected browser calls: {:?}",
        browser.calls()
    );

    assert_eq!(summary["total_samples"], 8);
    assert_eq!(summary["human_samples"], 4);
    assert_eq!(summary["baseline_samples"], 4);
    assert_eq!(summary["base_seed"], 123);
    assert_eq!(summary["include_baseline_negatives"], true);
    assert_eq!(summary["export_format"], "csv_features");
    assert!(summary["human_mean_tremor_energy"].as_f64().unwrap() > 0.0);
    assert!(summary["baseline_mean_tremor_energy"].as_f64().unwrap() < 1e-12);
    assert_eq!(lines.len(), 8);

    for line in &lines {
        let sample: DatasetSample = serde_json::from_value(line.clone()).unwrap();
        assert!(!sample.events.is_empty());
    }

    // Re-running with identical config & input yields exact same sink lines and summary.
    let (summary2, lines2) = run_task(&set, &browser, &Value::Null);
    assert_eq!(summary, summary2.unwrap());
    assert_eq!(lines, lines2);
}

#[test]
fn task_merges_partial_input_overrides_and_optional_export() {
    let config = DatasetConfig {
        sample_count: 10,
        base_seed: 42,
        include_baseline_negatives: false,
        ..DatasetConfig::default()
    };
    let set = PluginSet::strict()
        .with(BehaviorDatasetPlugin::new(config).unwrap())
        .unwrap();
    let browser = RecordingBrowser::new();

    let input = json!({
        "sample_count": 3,
        "include_baseline_negatives": true,
        "export_format": "csv_features",
        "include_export": true
    });
    let (summary, lines) = run_task(&set, &browser, &input);
    let summary = summary.unwrap();

    assert_eq!(summary["total_samples"], 6);
    assert_eq!(summary["base_seed"], 42);
    assert_eq!(lines.len(), 6);

    let exported = summary["exported"].as_str().unwrap();
    assert_eq!(exported.lines().count(), 7);
}

#[test]
fn task_rejects_invalid_input_before_recording_and_enforces_task_capability() {
    let set = PluginSet::strict()
        .with(BehaviorDatasetPlugin::default())
        .unwrap();
    let browser = RecordingBrowser::new();

    for bad in [
        json!({ "sample_count": 0 }),
        json!({ "sample_count": 50_000 }),
        json!({ "unknown_override": true }),
    ] {
        let (res, lines) = run_task(&set, &browser, &bad);
        assert!(matches!(res, Err(PluginError::Config(_))), "{res:?}");
        assert!(lines.is_empty());
    }

    let denied_set = PluginSet::strict()
        .with_grants(BehaviorDatasetPlugin::default(), CapabilitySet::new())
        .unwrap();
    let Err(err) = denied_set.task(NAME) else {
        panic!("expected capability error when Task grant is absent");
    };
    assert!(matches!(err, PluginError::Capability { .. }), "{err:?}");
}
