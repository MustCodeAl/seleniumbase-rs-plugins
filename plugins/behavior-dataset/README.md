# seleniumbase-rs-plugin-behavior-dataset

Live-site human user journey explorer, synthetic web behavior generator, kinematic feature extractor, and batch ML dataset exporter built on `seleniumbase-rs`'s `Behavior` and `Humanizer` engine.

## Features

- **Live-Site User Journeys (`live`, `SiteExplorer`, `BehaviorDatasetPlugin::explore_page`)**:
  - Evaluates `DISCOVER_SITE_ELEMENTS_JS` on an open `PageHandle` to discover visible links, safe buttons, benign search and text inputs, readable blocks, and interactive controls with real `getBoundingClientRect()` coordinates and CSS selectors.
  - Plans and executes multi-step persona journeys across up to `max_pages` pages (`same_origin_only` by default) and `max_steps` actions: word-count-proportional reading pauses, minimum-jerk curved pointer trajectories with physiological micro-tremor, hover inspections, smooth scroll bursts, realistic keystroke-by-keystroke typing (`typing_samples`), and link navigation.
  - Dispatches live CDP `Input.dispatchMouseEvent` and `Input.dispatchKeyEvent` commands when `dispatch_live_inputs` is `true`, falling back cleanly to safe JavaScript focus, click, input, and scroll helpers on non-CDP handles.
  - Skips `type="password"`, `type="file"`, payment inputs, and destructive buttons at both the DOM query and Rust parser layers.
- **Personas (`PersonaKind`, `PersonaProfile`)**: Continuous seeded parameter sampling across six behavioral archetypes (`FastTypist`, `AverageDesktop`, `CarefulReader`, `TrackpadUser`, `MobileTouch`, `DistractedBrowser`), deriving core `Behavior` plus dwell, scroll, and reading cadence weights.
- **Offline Scenarios (`ScenarioKind`)**: `TargetApproachClick`, `FormEntry`, `ArticleReadingScroll`, `SearchAndBrowse`, and `CheckoutFlow` generating full `BehaviorEvent` timelines when `url` is `None`.
- **Kinematic Feature Extractor (`TrajectoryFeatures`, `SessionSummary`)**: Path efficiency / straightness index (`euclidean / arc_length`), Fitts index of difficulty (`log2(D / W + 1)`), overshoot count, velocity/acceleration/jerk statistics, curvature, high-frequency hand tremor energy, inter-key interval statistics, typo correction rate, and ground-truth labels (`is_human`, `persona`, `scenario`, `seed`), plus live `page_url`, `action_path`, and `target_selectors` fields on `DatasetSample`.
- **Synthetic Linear Baselines**: Optional `include_baseline_negatives` emitting paired linear constant-speed pointer interpolation and uniform typing negatives (`is_human: false`, `label: "synthetic_linear_baseline"`).
- **Exporters (`ExportFormat`)**: Pretty JSON (`Json`), sample-level JSONL (`JsonlSamples`), flattened streaming event JSONL (`JsonlEvents`), flat 20-column event CSV (`CsvEvents`), and 33-column feature matrix CSV (`CsvFeatures`).
- **Plugin & Task (`BehaviorDatasetPlugin`)**: Implements `Plugin` (`name = "behavior-dataset"`, `Category::Core`, capabilities `task`, `page.evaluate`, `page.navigate`, `cdp:Input`), `Configurable`, and `Task`.

## Verification

```bash
cargo test --offline -p seleniumbase-rs-plugin-behavior-dataset
cargo clippy --offline -p seleniumbase-rs-plugin-behavior-dataset --all-targets -- -D warnings
```
