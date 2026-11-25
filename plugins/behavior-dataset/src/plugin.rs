//! `seleniumbase-rs-plugin` integration for deterministic offline dataset generation tasks.

use std::collections::BTreeSet;

use async_trait::async_trait;
use seleniumbase_rs_plugin::{
    Capability, Category, Configurable, Metadata, Plugin, PluginError, Requirements, Result, Task,
    TaskContext, config::options,
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::dataset::{DatasetBatchGenerator, DatasetConfig, DatasetSample};
use crate::error::DatasetError;
use crate::export::ExportFormat;
use crate::persona::PersonaKind;
use crate::scenario::ScenarioKind;

/// Canonical plugin identifier.
pub const NAME: &str = "behavior-dataset";

/// Plugin and [`Task`] generating synthetic behavioral datasets without Chromium I/O.
#[derive(Debug, Clone, Default)]
pub struct BehaviorDatasetPlugin {
    config: DatasetConfig,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct TaskInputOverride {
    sample_count: Option<usize>,
    base_seed: Option<u64>,
    personas: Option<Vec<PersonaKind>>,
    scenarios: Option<Vec<ScenarioKind>>,
    include_baseline_negatives: Option<bool>,
    export_format: Option<ExportFormat>,
    include_export: Option<bool>,
}

impl BehaviorDatasetPlugin {
    /// Builds a validated [`BehaviorDatasetPlugin`] from `config`.
    ///
    /// # Errors
    ///
    /// Returns [`PluginError::Config`] if `config` fails validation.
    pub fn new(config: DatasetConfig) -> Result<Self> {
        config.validate().map_err(config_err)?;
        Ok(Self { config })
    }

    /// Configured defaults used when [`Task::run`] receives no input overrides.
    #[must_use]
    pub const fn config(&self) -> &DatasetConfig {
        &self.config
    }

    fn resolve_config(&self, input: &Value) -> Result<(DatasetConfig, bool)> {
        let overrides: TaskInputOverride = if input.is_null() {
            TaskInputOverride::default()
        } else {
            options(NAME, input)?
        };
        let mut effective = self.config.clone();
        if let Some(sample_count) = overrides.sample_count {
            effective.sample_count = sample_count;
        }
        if let Some(base_seed) = overrides.base_seed {
            effective.base_seed = base_seed;
        }
        if let Some(personas) = overrides.personas {
            effective.personas = personas;
        }
        if let Some(scenarios) = overrides.scenarios {
            effective.scenarios = scenarios;
        }
        if let Some(include_baseline) = overrides.include_baseline_negatives {
            effective.include_baseline_negatives = include_baseline;
        }
        if let Some(export_format) = overrides.export_format {
            effective.export_format = export_format;
        }
        effective.validate().map_err(config_err)?;
        Ok((effective, overrides.include_export.unwrap_or(false)))
    }
}

#[async_trait]
impl Plugin for BehaviorDatasetPlugin {
    fn name(&self) -> &str {
        NAME
    }

    fn requirements(&self) -> Requirements {
        Requirements::empty()
    }

    fn metadata(&self) -> Metadata {
        Self::describe()
    }

    fn task(&self) -> Option<&dyn Task> {
        Some(self)
    }
}

impl Configurable for BehaviorDatasetPlugin {
    const NAME: &'static str = NAME;

    fn describe() -> Metadata {
        Metadata::new(Category::Core)
            .version(env!("CARGO_PKG_VERSION"))
            .summary("Generates synthetic human-like web behavior batches and ML training datasets")
            .capabilities([Capability::Task])
    }

    fn configure(value: &Value) -> Result<Self> {
        let config: DatasetConfig = options(NAME, value)?;
        Self::new(config)
    }
}

#[async_trait]
impl Task for BehaviorDatasetPlugin {
    /// Generates a deterministic behavioral dataset batch from configured defaults
    /// merged with `cx.input`, records each sample to `cx.sink`, and returns
    /// aggregate batch metrics.
    ///
    /// # Errors
    ///
    /// Returns [`PluginError::Config`] on invalid overrides or bounds, or
    /// [`PluginError`] if `cx.sink.record` fails.
    async fn run(&self, cx: &TaskContext<'_>) -> Result<Value> {
        let (effective, include_export) = self.resolve_config(cx.input)?;
        let generator = DatasetBatchGenerator::new(effective.clone()).map_err(config_err)?;
        let batch = generator.generate().map_err(other_err)?;

        for sample in &batch.samples {
            let line = serde_json::to_value(sample).map_err(other_err)?;
            cx.sink.record(&line)?;
        }

        let personas: Vec<&'static str> = batch
            .samples
            .iter()
            .filter_map(|s| s.summary.persona.map(PersonaKind::as_str))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let scenarios: Vec<&'static str> = batch
            .samples
            .iter()
            .map(|s| s.summary.scenario.as_str())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();

        let human_straight = mean_metric(&batch.samples, true, |s| s.features.straightness_index);
        let baseline_straight =
            mean_metric(&batch.samples, false, |s| s.features.straightness_index);
        let human_tremor =
            mean_metric(&batch.samples, true, |s| s.features.tremor_high_freq_energy);
        let baseline_tremor = mean_metric(&batch.samples, false, |s| {
            s.features.tremor_high_freq_energy
        });
        let human_vel = mean_metric(&batch.samples, true, |s| s.features.mean_velocity_px_s);
        let baseline_vel = mean_metric(&batch.samples, false, |s| s.features.mean_velocity_px_s);

        let mut summary = json!({
            "total_samples": batch.len(),
            "human_samples": batch.human_count(),
            "baseline_samples": batch.baseline_count(),
            "total_events": batch.total_events(),
            "base_seed": effective.base_seed,
            "include_baseline_negatives": effective.include_baseline_negatives,
            "export_format": effective.export_format.as_str(),
            "personas": personas,
            "scenarios": scenarios,
            "human_mean_straightness_index": human_straight,
            "baseline_mean_straightness_index": baseline_straight,
            "human_mean_tremor_energy": human_tremor,
            "baseline_mean_tremor_energy": baseline_tremor,
            "human_mean_velocity_px_s": human_vel,
            "baseline_mean_velocity_px_s": baseline_vel,
        });

        if include_export {
            let exported = batch.export(effective.export_format).map_err(other_err)?;
            if let Some(obj) = summary.as_object_mut() {
                obj.insert("exported".to_owned(), Value::String(exported));
            }
        }

        Ok(summary)
    }
}

fn mean_metric<F>(samples: &[DatasetSample], is_human: bool, extract: F) -> Option<f64>
where
    F: Fn(&DatasetSample) -> f64,
{
    let mut sum = 0.0;
    let mut count = 0usize;
    for sample in samples {
        if sample.summary.is_human == is_human {
            sum += extract(sample);
            count += 1;
        }
    }
    if count == 0 {
        None
    } else {
        #[allow(clippy::cast_precision_loss)]
        Some(sum / count as f64)
    }
}

fn config_err(error: DatasetError) -> PluginError {
    PluginError::Config(format!("{NAME}: {error}"))
}

fn other_err(error: impl std::fmt::Display) -> PluginError {
    PluginError::other(format!("{NAME}: {error}"))
}
