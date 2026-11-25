//! Tests for batch generation, JSON/JSONL/CSV exporters, and human vs
//! synthetic linear baseline ML feature separability.

use seleniumbase_rs_plugin_behavior_dataset::{
    DatasetBatch, DatasetBatchGenerator, DatasetConfig, DatasetSample, ExportFormat, JsonlEventRow,
    MAX_SAMPLE_COUNT, PersonaKind, ScenarioKind,
};

/// Minimal RFC 4180 CSV parser so quoted fields containing commas are split accurately.
fn parse_csv_row(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut chars = line.chars().peekable();
    let mut in_quotes = false;

    while let Some(ch) = chars.next() {
        if in_quotes {
            if ch == '"' {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    current.push('"');
                } else {
                    in_quotes = false;
                }
            } else {
                current.push(ch);
            }
        } else if ch == '"' {
            in_quotes = true;
        } else if ch == ',' {
            fields.push(std::mem::take(&mut current));
        } else {
            current.push(ch);
        }
    }
    assert!(!in_quotes, "unterminated CSV quote in line: {line}");
    fields.push(current);
    fields
}

#[test]
fn dataset_config_rejects_out_of_bounds_sample_counts() {
    for bad in [0, MAX_SAMPLE_COUNT + 1] {
        let cfg = DatasetConfig {
            sample_count: bad,
            ..DatasetConfig::default()
        };
        assert!(DatasetBatchGenerator::new(cfg).is_err());
    }
}

#[test]
fn balanced_batch_covers_all_personas_and_scenarios_with_paired_negatives() {
    let cfg = DatasetConfig {
        sample_count: 30,
        base_seed: 2026,
        include_baseline_negatives: true,
        ..DatasetConfig::default()
    };
    let batch = DatasetBatchGenerator::new(cfg).unwrap().generate().unwrap();

    assert_eq!(batch.len(), 60);
    assert_eq!(batch.human_count(), 30);
    assert_eq!(batch.baseline_count(), 30);

    for human in batch.samples.iter().filter(|s| s.summary.is_human) {
        assert_eq!(human.summary.label, "human");
        assert!(human.summary.persona.is_some());
        assert_eq!(human.features.label, "human");
        assert!(human.features.is_human);
    }
    for bot in batch.samples.iter().filter(|s| !s.summary.is_human) {
        assert_eq!(bot.summary.label, "synthetic_linear_baseline");
        assert!(bot.summary.persona.is_none());
        assert_eq!(bot.features.label, "synthetic_linear_baseline");
        assert!(!bot.features.is_human);
    }

    let seen_personas: std::collections::BTreeSet<_> = batch
        .samples
        .iter()
        .filter_map(|s| s.summary.persona)
        .collect();
    assert_eq!(seen_personas.len(), PersonaKind::ALL.len());

    let seen_scenarios: std::collections::BTreeSet<_> =
        batch.samples.iter().map(|s| s.summary.scenario).collect();
    assert_eq!(seen_scenarios.len(), ScenarioKind::ALL.len());
}

#[test]
fn csv_exports_have_consistent_columns_across_every_row() {
    let cfg = DatasetConfig {
        sample_count: 10,
        base_seed: 55,
        include_baseline_negatives: true,
        ..DatasetConfig::default()
    };
    let batch = DatasetBatchGenerator::new(cfg).unwrap().generate().unwrap();

    let events_csv = batch.export(ExportFormat::CsvEvents).unwrap();
    let event_lines: Vec<&str> = events_csv.lines().collect();
    assert_eq!(event_lines.len(), 1 + batch.total_events());
    let event_header = parse_csv_row(event_lines[0]);
    assert_eq!(event_header.len(), 20);
    for (idx, line) in event_lines.iter().enumerate().skip(1) {
        let cols = parse_csv_row(line);
        assert_eq!(
            cols.len(),
            20,
            "CsvEvents row {idx} column count mismatch: {line}"
        );
    }

    let features_csv = batch.export(ExportFormat::CsvFeatures).unwrap();
    let feature_lines: Vec<&str> = features_csv.lines().collect();
    assert_eq!(feature_lines.len(), 1 + batch.len());
    let feature_header = parse_csv_row(feature_lines[0]);
    assert_eq!(feature_header.len(), 33);
    for (idx, line) in feature_lines.iter().enumerate().skip(1) {
        let cols = parse_csv_row(line);
        assert_eq!(
            cols.len(),
            33,
            "CsvFeatures row {idx} column count mismatch: {line}"
        );
    }
}

#[test]
fn json_and_jsonl_exports_parse_cleanly_line_by_line() {
    let cfg = DatasetConfig {
        sample_count: 6,
        base_seed: 101,
        include_baseline_negatives: true,
        ..DatasetConfig::default()
    };
    let batch = DatasetBatchGenerator::new(cfg).unwrap().generate().unwrap();

    let json_text = batch.to_json().unwrap();
    let parsed_batch: DatasetBatch = serde_json::from_str(&json_text).unwrap();
    assert_eq!(parsed_batch.config, batch.config);
    assert_eq!(parsed_batch.samples.len(), batch.samples.len());
    for (parsed, orig) in parsed_batch.samples.iter().zip(&batch.samples) {
        assert_sample_approx_eq(parsed, orig);
    }

    let jsonl_samples = batch.to_jsonl_samples().unwrap();
    let sample_lines: Vec<&str> = jsonl_samples.lines().collect();
    assert_eq!(sample_lines.len(), batch.len());
    for (idx, line) in sample_lines.iter().enumerate() {
        let sample: DatasetSample = serde_json::from_str(line).unwrap();
        assert_sample_approx_eq(&sample, &batch.samples[idx]);
    }

    let jsonl_events = batch.to_jsonl_events().unwrap();
    let event_lines: Vec<&str> = jsonl_events.lines().collect();
    assert_eq!(event_lines.len(), batch.total_events());
    let mut flat_idx = 0usize;
    for sample in &batch.samples {
        for ev in &sample.events {
            let row: JsonlEventRow = serde_json::from_str(event_lines[flat_idx]).unwrap();
            assert_eq!(row.sample_id, sample.id);
            assert_eq!(row.is_human, sample.summary.is_human);
            assert_eq!(row.label, sample.summary.label);
            assert_eq!(row.persona, sample.summary.persona);
            assert_eq!(row.scenario, sample.summary.scenario);
            assert_eq!(row.seed, sample.summary.seed);
            assert_eq!(row.kind, ev.kind);
            assert_eq!(row.key, ev.key);
            assert_approx(row.timestamp_ms, ev.timestamp_ms);
            assert_approx(row.dt_ms, ev.dt_ms);
            assert_opt_approx(row.x, ev.x);
            assert_opt_approx(row.y, ev.y);
            assert_opt_approx(row.dx, ev.dx);
            assert_opt_approx(row.dy, ev.dy);
            assert_opt_approx(row.velocity_px_s, ev.velocity_px_s);
            assert_opt_approx(row.acceleration_px_s2, ev.acceleration_px_s2);
            assert_opt_approx(row.jerk_px_s3, ev.jerk_px_s3);
            assert_opt_approx(row.curvature_rad, ev.curvature_rad);
            assert_opt_approx(row.dwell_ms, ev.dwell_ms);
            assert_opt_approx(row.scroll_dy, ev.scroll_dy);
            flat_idx += 1;
        }
    }
}

fn assert_approx(actual: f64, expected: f64) {
    assert!(actual.is_finite() && expected.is_finite());
    let tol = 1e-11 * actual.abs().max(expected.abs()).max(1.0);
    assert!(
        (actual - expected).abs() <= tol,
        "float mismatch: actual={actual}, expected={expected}, tol={tol}"
    );
}

fn assert_opt_approx(actual: Option<f64>, expected: Option<f64>) {
    match (actual, expected) {
        (Some(a), Some(e)) => assert_approx(a, e),
        (None, None) => {}
        _ => panic!("option shape mismatch: actual={actual:?}, expected={expected:?}"),
    }
}

fn assert_sample_approx_eq(actual: &DatasetSample, expected: &DatasetSample) {
    assert_eq!(actual.id, expected.id);
    assert_eq!(actual.summary.sample_id, expected.summary.sample_id);
    assert_eq!(actual.summary.is_human, expected.summary.is_human);
    assert_eq!(actual.summary.label, expected.summary.label);
    assert_eq!(actual.summary.persona, expected.summary.persona);
    assert_eq!(actual.summary.scenario, expected.summary.scenario);
    assert_eq!(actual.summary.seed, expected.summary.seed);
    assert_eq!(actual.summary.event_count, expected.summary.event_count);
    assert_eq!(
        actual.summary.pointer_event_count,
        expected.summary.pointer_event_count
    );
    assert_eq!(
        actual.summary.key_event_count,
        expected.summary.key_event_count
    );
    assert_eq!(
        actual.summary.scroll_event_count,
        expected.summary.scroll_event_count
    );
    assert_eq!(
        actual.summary.reconstructed_texts,
        expected.summary.reconstructed_texts
    );
    assert_eq!(
        actual.summary.expected_texts,
        expected.summary.expected_texts
    );
    assert_approx(
        actual.summary.total_duration_ms,
        expected.summary.total_duration_ms,
    );

    assert_eq!(actual.features.is_human, expected.features.is_human);
    assert_eq!(actual.features.label, expected.features.label);
    assert_eq!(actual.features.persona, expected.features.persona);
    assert_eq!(actual.features.scenario, expected.features.scenario);
    assert_eq!(actual.features.seed, expected.features.seed);
    assert_eq!(actual.features.stroke_count, expected.features.stroke_count);
    assert_eq!(
        actual.features.overshoot_count,
        expected.features.overshoot_count
    );
    assert_eq!(
        actual.features.backspace_count,
        expected.features.backspace_count
    );
    assert_approx(
        actual.features.euclidean_distance_px,
        expected.features.euclidean_distance_px,
    );
    assert_approx(
        actual.features.arc_length_px,
        expected.features.arc_length_px,
    );
    assert_approx(
        actual.features.straightness_index,
        expected.features.straightness_index,
    );
    assert_approx(
        actual.features.fitts_index_of_difficulty,
        expected.features.fitts_index_of_difficulty,
    );
    assert_approx(
        actual.features.peak_velocity_px_s,
        expected.features.peak_velocity_px_s,
    );
    assert_approx(
        actual.features.mean_velocity_px_s,
        expected.features.mean_velocity_px_s,
    );
    assert_approx(
        actual.features.std_velocity_px_s,
        expected.features.std_velocity_px_s,
    );
    assert_approx(
        actual.features.mean_abs_curvature_rad,
        expected.features.mean_abs_curvature_rad,
    );
    assert_approx(
        actual.features.tremor_high_freq_energy,
        expected.features.tremor_high_freq_energy,
    );
    assert_approx(
        actual.features.inter_key_mean_ms,
        expected.features.inter_key_mean_ms,
    );
    assert_approx(
        actual.features.inter_key_std_ms,
        expected.features.inter_key_std_ms,
    );
    assert_approx(
        actual.features.typo_correction_rate,
        expected.features.typo_correction_rate,
    );
    assert_approx(
        actual.features.total_scroll_dy,
        expected.features.total_scroll_dy,
    );

    assert_eq!(actual.events.len(), expected.events.len());
    for (a_ev, e_ev) in actual.events.iter().zip(&expected.events) {
        assert_eq!(a_ev.kind, e_ev.kind);
        assert_eq!(a_ev.key, e_ev.key);
        assert_approx(a_ev.timestamp_ms, e_ev.timestamp_ms);
        assert_approx(a_ev.dt_ms, e_ev.dt_ms);
        assert_opt_approx(a_ev.x, e_ev.x);
        assert_opt_approx(a_ev.y, e_ev.y);
        assert_opt_approx(a_ev.dx, e_ev.dx);
        assert_opt_approx(a_ev.dy, e_ev.dy);
        assert_opt_approx(a_ev.velocity_px_s, e_ev.velocity_px_s);
        assert_opt_approx(a_ev.acceleration_px_s2, e_ev.acceleration_px_s2);
        assert_opt_approx(a_ev.jerk_px_s3, e_ev.jerk_px_s3);
        assert_opt_approx(a_ev.curvature_rad, e_ev.curvature_rad);
        assert_opt_approx(a_ev.dwell_ms, e_ev.dwell_ms);
        assert_opt_approx(a_ev.scroll_dy, e_ev.scroll_dy);
    }
}

#[test]
fn human_and_synthetic_linear_batches_are_cleanly_separable_for_ml() {
    let cfg = DatasetConfig {
        sample_count: 30,
        base_seed: 9001,
        include_baseline_negatives: true,
        ..DatasetConfig::default()
    };
    let batch = DatasetBatchGenerator::new(cfg).unwrap().generate().unwrap();

    let humans: Vec<_> = batch
        .samples
        .iter()
        .filter(|s| s.summary.is_human)
        .map(|s| &s.features)
        .collect();
    let bots: Vec<_> = batch
        .samples
        .iter()
        .filter(|s| !s.summary.is_human)
        .map(|s| &s.features)
        .collect();

    let avg = |slice: &[&_],
               f: fn(&seleniumbase_rs_plugin_behavior_dataset::TrajectoryFeatures) -> f64|
     -> f64 { slice.iter().map(|x| f(x)).sum::<f64>() / slice.len() as f64 };

    let h_straight = avg(&humans, |f| f.straightness_index);
    let b_straight = avg(&bots, |f| f.straightness_index);
    assert!(h_straight < 0.995 && (b_straight - 1.0).abs() < 1e-9);

    let h_tremor = avg(&humans, |f| f.tremor_high_freq_energy);
    let b_tremor = avg(&bots, |f| f.tremor_high_freq_energy);
    assert!(h_tremor > 0.05 && b_tremor < 1e-12);

    let h_vel_std = avg(&humans, |f| f.std_velocity_px_s);
    let b_vel_std = avg(&bots, |f| f.std_velocity_px_s);
    assert!(h_vel_std > 100.0 && b_vel_std < 1e-6);

    let h_curv = avg(&humans, |f| f.mean_abs_curvature_rad);
    let b_curv = avg(&bots, |f| f.mean_abs_curvature_rad);
    assert!(h_curv > 0.01 && b_curv < 1e-9);

    let human_typing: Vec<_> = humans
        .iter()
        .copied()
        .filter(|f| f.key_event_count > 1)
        .collect();
    let bot_typing: Vec<_> = bots
        .iter()
        .copied()
        .filter(|f| f.key_event_count > 1)
        .collect();
    let h_iki_std = avg(&human_typing, |f| f.inter_key_std_ms);
    let b_iki_std = avg(&bot_typing, |f| f.inter_key_std_ms);
    assert!(h_iki_std > 20.0 && b_iki_std < 1e-9);

    // Verify per-sample linear rule separation across all 60 samples:
    // every human sample exhibits tremor > 0, std_velocity > 1, or iki_std > 1,
    // whereas every synthetic linear baseline has near-zero values on all three.
    let mut correct = 0usize;
    for sample in &batch.samples {
        let f = &sample.features;
        let predicted_human = f.tremor_high_freq_energy > 1e-4
            || f.std_velocity_px_s > 1.0
            || f.inter_key_std_ms > 1.0;
        if predicted_human == f.is_human {
            correct += 1;
        }
    }
    assert_eq!(correct, batch.len());
}
