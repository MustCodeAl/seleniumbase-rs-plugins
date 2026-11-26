//! Synthetic human-like web behavior generator and batch ML dataset exporter
//! for `seleniumbase-rs`.
//!
//! Built directly on [`seleniumbase_rs::sb_cdp::human::behavior`] (`Behavior`,
//! `BehaviorBuilder`, `Humanizer`, `KeyAction`, `Keystroke`, `Step`,
//! `WheelNotch`) and [`seleniumbase_rs::sb_cdp::human::humanize::Rng`], this crate
//! synthesizes realistic multi-persona interaction timelines, extracts
//! kinematic and Fitts's-law ML feature vectors, optionally pairs them with
//! synthetic linear baseline negatives, and exports JSON, streaming JSONL,
//! flat event CSV, and feature matrix CSV datasets.
//!
//! # Examples
//!
//! ```
//! use seleniumbase_rs_plugin_behavior_dataset::{
//!     DatasetBatchGenerator, DatasetConfig, ExportFormat,
//! };
//!
//! let config = DatasetConfig {
//!     sample_count: 4,
//!     base_seed: 7,
//!     include_baseline_negatives: true,
//!     ..DatasetConfig::default()
//! };
//! let batch = DatasetBatchGenerator::new(config)?.generate()?;
//! assert_eq!(batch.human_count(), 4);
//! assert_eq!(batch.baseline_count(), 4);
//!
//! let csv = batch.export(ExportFormat::CsvFeatures)?;
//! assert!(csv.lines().count() == 9);
//! # Ok::<(), seleniumbase_rs_plugin_behavior_dataset::DatasetError>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(missing_debug_implementations)]

pub mod dataset;
pub mod error;
pub mod event;
pub mod export;
pub mod features;
pub mod live;
pub mod persona;
pub mod scenario;

#[cfg(feature = "plugin")]
pub mod plugin;

pub use dataset::{
    DEFAULT_TYPING_SAMPLES, DatasetBatch, DatasetBatchGenerator, DatasetConfig, DatasetSample,
    MAX_LIVE_PAGES, MAX_LIVE_STEPS, MAX_SAMPLE_COUNT,
};
pub use error::{DatasetError, Result};
pub use event::{BehaviorEvent, EventKind, reconstruct_field_texts, reconstruct_typed_text};
pub use export::{ExportFormat, JsonlEventRow};
pub use features::{SessionSummary, TrajectoryFeatures};
pub use live::{
    DISCOVER_SITE_ELEMENTS_JS, DiscoveredElement, ElementRole, SiteActionStep,
    SiteExplorationReport, SiteExplorer, SiteVisitSummary,
};
pub use persona::{PersonaKind, PersonaProfile};
pub use scenario::{
    ScenarioKind, ScenarioOutput, simulate_linear_baseline, simulate_linear_target_approach,
    simulate_scenario, simulate_target_approach,
};

#[cfg(feature = "plugin")]
pub use plugin::{BehaviorDatasetPlugin, NAME};
