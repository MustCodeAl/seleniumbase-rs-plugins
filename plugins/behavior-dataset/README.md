# seleniumbase-rs-plugin-behavior-dataset

Deterministic synthetic web behavior generator, kinematic feature extractor, and batch ML dataset exporter built on `seleniumbase-rs`'s `Behavior` and `Humanizer` engine.

## Features

- **Personas (`PersonaKind`, `PersonaProfile`)**: Continuous seeded parameter sampling across six behavioral archetypes (`FastTypist`, `AverageDesktop`, `CarefulReader`, `TrackpadUser`, `MobileTouch`, `DistractedBrowser`), deriving core `Behavior` + dwell/scroll/reading cadence weights.
- **Scenarios (`ScenarioKind`)**: `TargetApproachClick`, `FormEntry`, `ArticleReadingScroll`, `SearchAndBrowse`, and `CheckoutFlow` generating full `BehaviorEvent` timelines (`timestamp_ms`, `dt_ms`, `kind`, `x`, `y`, `dx`, `dy`, `velocity_px_s`, `acceleration_px_s2`, `jerk_px_s3`, `curvature_rad`, `key`, `dwell_ms`, `scroll_dy`).
- **Kinematic Feature Extractor (`TrajectoryFeatures`, `SessionSummary`)**: Path efficiency / straightness index (`euclidean / arc_length`), Fitts index of difficulty (`log2(D / W + 1)`), overshoot count, velocity/acceleration/jerk statistics, curvature, high-frequency hand tremor energy, inter-key interval statistics, typo correction rate, and ground-truth labels (`is_human`, `persona`, `scenario`, `seed`).
- **Synthetic Linear Baselines**: Optional `include_baseline_negatives` emitting paired linear constant-speed pointer interpolation and uniform typing negatives (`is_human: false`, `label: "synthetic_linear_baseline"`).
- **Exporters (`ExportFormat`)**: Pretty JSON (`Json`), sample-level JSONL (`JsonlSamples`), flattened streaming event JSONL (`JsonlEvents`), flat 20-column event CSV (`CsvEvents`), and 33-column feature matrix CSV (`CsvFeatures`).
- **Plugin & Offline Task (`BehaviorDatasetPlugin`)**: Implements `Plugin` (`name = "behavior-dataset"`, `Category::Core`, `Capability::Task`), `Configurable`, and `Task` to generate batches deterministically without live Chromium I/O and stream samples to `TaskContext::sink`.

## Verification

```bash
cargo test --offline -p seleniumbase-rs-plugin-behavior-dataset
cargo clippy --offline -p seleniumbase-rs-plugin-behavior-dataset --all-targets -- -D warnings
```
