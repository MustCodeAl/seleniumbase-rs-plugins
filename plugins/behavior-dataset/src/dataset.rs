//! Batch dataset configuration, deterministic generator, and batch containers.

use serde::{Deserialize, Serialize};

use crate::error::{DatasetError, Result};
use crate::event::{BehaviorEvent, reconstruct_field_texts};
use crate::export::{ExportFormat, export_batch};
use crate::features::{SessionSummary, TrajectoryFeatures};
use crate::persona::{PersonaKind, PersonaProfile};
use crate::scenario::{ScenarioKind, ScenarioOutput, simulate_linear_baseline, simulate_scenario};

/// Maximum number of human sessions per generated batch.
pub const MAX_SAMPLE_COUNT: usize = 10_000;

/// Configuration for deterministic synthetic behavioral dataset generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DatasetConfig {
    /// Number of human session samples to generate (`1..=10_000`).
    pub sample_count: usize,
    /// Base seed for deterministic persona sampling and simulation.
    pub base_seed: u64,
    /// Personas to cycle through (empty means all six [`PersonaKind::ALL`]).
    pub personas: Vec<PersonaKind>,
    /// Scenarios to cycle through (empty means all five [`ScenarioKind::ALL`]).
    pub scenarios: Vec<ScenarioKind>,
    /// When true, also emit a paired synthetic linear baseline negative
    /// (`is_human = false`, `label = "synthetic_linear_baseline"`) per human sample.
    pub include_baseline_negatives: bool,
    /// Preferred export format for batch serialization.
    pub export_format: ExportFormat,
}

impl Default for DatasetConfig {
    fn default() -> Self {
        Self {
            sample_count: 20,
            base_seed: 42,
            personas: Vec::new(),
            scenarios: Vec::new(),
            include_baseline_negatives: false,
            export_format: ExportFormat::JsonlSamples,
        }
    }
}

impl DatasetConfig {
    /// Validates configuration bounds.
    ///
    /// # Errors
    ///
    /// Returns [`DatasetError::InvalidConfig`] when `sample_count` is `0` or
    /// exceeds [`MAX_SAMPLE_COUNT`].
    pub fn validate(&self) -> Result<()> {
        if !(1..=MAX_SAMPLE_COUNT).contains(&self.sample_count) {
            return Err(DatasetError::InvalidConfig(format!(
                "sample_count must be between 1 and {MAX_SAMPLE_COUNT}, got {}",
                self.sample_count
            )));
        }
        Ok(())
    }

    fn effective_personas(&self) -> Vec<PersonaKind> {
        if self.personas.is_empty() {
            PersonaKind::ALL.to_vec()
        } else {
            self.personas.clone()
        }
    }

    fn effective_scenarios(&self) -> Vec<ScenarioKind> {
        if self.scenarios.is_empty() {
            ScenarioKind::ALL.to_vec()
        } else {
            self.scenarios.clone()
        }
    }
}

/// One simulated session sample with summary, ML feature vector, and event timeline.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DatasetSample {
    /// Unique sample identifier within its batch.
    pub id: String,
    /// High-level session metadata and text reconstruction diagnostics.
    pub summary: SessionSummary,
    /// Extracted kinematic, Fitts's law, and timing feature vector.
    pub features: TrajectoryFeatures,
    /// Full chronological event timeline.
    pub events: Vec<BehaviorEvent>,
}

/// Collection of generated human (and optional synthetic baseline) samples.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DatasetBatch {
    /// Configuration used to generate this batch.
    pub config: DatasetConfig,
    /// Generated samples in deterministic order.
    pub samples: Vec<DatasetSample>,
}

impl DatasetBatch {
    /// Total number of samples in this batch.
    #[must_use]
    pub fn len(&self) -> usize {
        self.samples.len()
    }

    /// Returns true if the batch contains no samples.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    /// Number of human-simulated samples (`is_human == true`).
    #[must_use]
    pub fn human_count(&self) -> usize {
        self.samples.iter().filter(|s| s.summary.is_human).count()
    }

    /// Number of synthetic linear baseline negative samples (`is_human == false`).
    #[must_use]
    pub fn baseline_count(&self) -> usize {
        self.samples.iter().filter(|s| !s.summary.is_human).count()
    }

    /// Total events across every sample in the batch.
    #[must_use]
    pub fn total_events(&self) -> usize {
        self.samples.iter().map(|s| s.events.len()).sum()
    }

    /// Exports the batch in the requested [`ExportFormat`].
    ///
    /// # Errors
    ///
    /// Returns [`DatasetError::Serialization`] or [`DatasetError::Format`] on failure.
    pub fn export(&self, format: ExportFormat) -> Result<String> {
        export_batch(self, format)
    }

    /// Exports the full batch as pretty-printed JSON.
    ///
    /// # Errors
    ///
    /// Returns [`DatasetError::Serialization`] if JSON serialization fails.
    pub fn to_json(&self) -> Result<String> {
        self.export(ExportFormat::Json)
    }

    /// Exports one JSON [`DatasetSample`] per line.
    ///
    /// # Errors
    ///
    /// Returns [`DatasetError::Serialization`] if JSON serialization fails.
    pub fn to_jsonl_samples(&self) -> Result<String> {
        self.export(ExportFormat::JsonlSamples)
    }

    /// Exports one flattened event object per line for streaming ML pipelines.
    ///
    /// # Errors
    ///
    /// Returns [`DatasetError::Serialization`] if JSON serialization fails.
    pub fn to_jsonl_events(&self) -> Result<String> {
        self.export(ExportFormat::JsonlEvents)
    }

    /// Exports a flat 20-column CSV table with one row per event.
    ///
    /// # Errors
    ///
    /// Returns [`DatasetError::Format`] if formatting fails.
    pub fn to_csv_events(&self) -> Result<String> {
        self.export(ExportFormat::CsvEvents)
    }

    /// Exports a 33-column feature matrix CSV with one row per sample.
    ///
    /// # Errors
    ///
    /// Returns [`DatasetError::Format`] if formatting fails.
    pub fn to_csv_features(&self) -> Result<String> {
        self.export(ExportFormat::CsvFeatures)
    }
}

/// Deterministic generator of synthetic human and baseline behavioral batches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatasetBatchGenerator {
    config: DatasetConfig,
}

impl DatasetBatchGenerator {
    /// Creates a validated batch generator from `config`.
    ///
    /// # Errors
    ///
    /// Returns [`DatasetError::InvalidConfig`] if `config` fails validation.
    pub fn new(config: DatasetConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self { config })
    }

    /// Configuration used by this generator.
    #[must_use]
    pub const fn config(&self) -> &DatasetConfig {
        &self.config
    }

    /// Generates the complete [`DatasetBatch`] deterministically from `self.config`.
    ///
    /// # Errors
    ///
    /// Returns [`DatasetError`] if persona profile parameters fail validation.
    pub fn generate(&self) -> Result<DatasetBatch> {
        let personas = self.config.effective_personas();
        let scenarios = self.config.effective_scenarios();
        let p_len = personas.len();
        let s_len = scenarios.len();

        let cap = if self.config.include_baseline_negatives {
            self.config.sample_count * 2
        } else {
            self.config.sample_count
        };
        let mut samples = Vec::with_capacity(cap);

        for idx in 0..self.config.sample_count {
            let persona = personas[idx % p_len];
            let scenario = scenarios[(idx / p_len) % s_len];
            let sample_seed = derive_sample_seed(
                self.config.base_seed,
                u64::try_from(idx).unwrap_or(u64::MAX),
            );

            let human_id = format!("sample_{idx:04}_human");
            let human = self.generate_human_sample(human_id, persona, scenario, sample_seed)?;
            let viewport = human
                .summary
                .profile
                .as_ref()
                .map_or((1440.0, 900.0), PersonaProfile::viewport);
            samples.push(human);

            if self.config.include_baseline_negatives {
                let baseline_id = format!("sample_{idx:04}_baseline");
                samples.push(self.generate_baseline_sample(
                    baseline_id,
                    scenario,
                    viewport,
                    sample_seed,
                ));
            }
        }

        Ok(DatasetBatch {
            config: self.config.clone(),
            samples,
        })
    }

    /// Generates a single labeled human sample for `(persona, scenario, seed)`.
    ///
    /// # Errors
    ///
    /// Returns [`DatasetError::InvalidBehavior`] if sampled behavior validation fails.
    pub fn generate_human_sample(
        &self,
        sample_id: impl Into<String>,
        persona: PersonaKind,
        scenario: ScenarioKind,
        seed: u64,
    ) -> Result<DatasetSample> {
        let profile = PersonaProfile::sample(persona, seed);
        let output = simulate_scenario(&profile, scenario, seed)?;
        Ok(build_sample(
            sample_id.into(),
            true,
            Some(profile),
            scenario,
            seed,
            output,
        ))
    }

    /// Generates a single labeled synthetic linear baseline negative sample.
    #[must_use]
    pub fn generate_baseline_sample(
        &self,
        sample_id: impl Into<String>,
        scenario: ScenarioKind,
        viewport: (f64, f64),
        seed: u64,
    ) -> DatasetSample {
        let output = simulate_linear_baseline(scenario, viewport, seed);
        build_sample(sample_id.into(), false, None, scenario, seed, output)
    }
}

fn build_sample(
    sample_id: String,
    is_human: bool,
    profile: Option<PersonaProfile>,
    scenario: ScenarioKind,
    seed: u64,
    output: ScenarioOutput,
) -> DatasetSample {
    let persona = profile.as_ref().map(|p| p.kind);
    let features = TrajectoryFeatures::extract(
        &output.events,
        &output.stroke_target_widths,
        is_human,
        persona,
        scenario,
        seed,
    );
    let reconstructed_texts = reconstruct_field_texts(&output.events);
    let summary = SessionSummary {
        sample_id: sample_id.clone(),
        is_human,
        label: features.label.clone(),
        persona,
        scenario,
        seed,
        profile,
        total_duration_ms: output.total_duration_ms,
        event_count: output.events.len(),
        pointer_event_count: features.pointer_event_count,
        key_event_count: features.key_event_count,
        scroll_event_count: features.scroll_event_count,
        reconstructed_texts,
        expected_texts: output.expected_texts,
    };

    DatasetSample {
        id: sample_id,
        summary,
        features,
        events: output.events,
    }
}

/// SplitMix64 mixing so `(base_seed, index)` streams remain uncorrelated across adjacent seeds.
fn derive_sample_seed(base_seed: u64, index: u64) -> u64 {
    let mut z = base_seed
        .wrapping_add(index.wrapping_mul(0x9E37_79B9_7F4A_7C15))
        .wrapping_add(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}
