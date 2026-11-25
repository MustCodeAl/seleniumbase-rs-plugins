//! Tests for persona archetypes, scenario coverage, typo + backspace text
//! reconstruction, seed determinism, and cross-seed diversity.

use seleniumbase_rs_plugin_behavior_dataset::{
    DatasetBatchGenerator, DatasetConfig, EventKind, ExportFormat, PersonaKind, PersonaProfile,
    ScenarioKind, TrajectoryFeatures, reconstruct_field_texts, reconstruct_typed_text,
    simulate_scenario,
};

#[test]
fn all_personas_and_scenarios_enumerate_parse_and_roundtrip() {
    assert_eq!(PersonaKind::ALL.len(), 6);
    for kind in PersonaKind::ALL {
        let parsed: PersonaKind = kind.to_string().parse().unwrap();
        assert_eq!(parsed, kind);
        let profile = PersonaProfile::sample(kind, 7);
        assert!(profile.to_behavior().is_ok());
    }

    assert_eq!(ScenarioKind::ALL.len(), 5);
    for scenario in ScenarioKind::ALL {
        let parsed: ScenarioKind = scenario.to_string().parse().unwrap();
        assert_eq!(parsed, scenario);
    }

    assert_eq!(ExportFormat::ALL.len(), 5);
    for fmt in ExportFormat::ALL {
        let parsed: ExportFormat = fmt.to_string().parse().unwrap();
        assert_eq!(parsed, fmt);
    }

    assert!("unknown_persona".parse::<PersonaKind>().is_err());
    assert!("unknown_scenario".parse::<ScenarioKind>().is_err());
    assert!("unknown_format".parse::<ExportFormat>().is_err());
}

#[test]
fn personas_exhibit_distinct_behavioral_distributions() {
    let mean_for = |kind: PersonaKind, extract: fn(&PersonaProfile) -> f64| -> f64 {
        let n = 40u64;
        (1..=n)
            .map(|seed| extract(&PersonaProfile::sample(kind, seed)))
            .sum::<f64>()
            / n as f64
    };

    let fast_wpm = mean_for(PersonaKind::FastTypist, |p| p.typing_wpm);
    let careful_wpm = mean_for(PersonaKind::CarefulReader, |p| p.typing_wpm);
    let mobile_wpm = mean_for(PersonaKind::MobileTouch, |p| p.typing_wpm);
    assert!(fast_wpm > careful_wpm * 1.8);
    assert!(fast_wpm > mobile_wpm * 2.0);

    let distracted_var = mean_for(PersonaKind::DistractedBrowser, |p| p.typing_variability);
    let fast_var = mean_for(PersonaKind::FastTypist, |p| p.typing_variability);
    assert!(distracted_var > fast_var * 1.8);

    let trackpad_overshoot = mean_for(PersonaKind::TrackpadUser, |p| p.overshoot);
    let mobile_overshoot = mean_for(PersonaKind::MobileTouch, |p| p.overshoot);
    assert!(trackpad_overshoot > mobile_overshoot * 3.0);

    let mobile = PersonaProfile::sample(PersonaKind::MobileTouch, 12);
    assert!(mobile.is_touch);
    assert!(mobile.viewport_width <= 430.0);
}

#[test]
fn every_persona_and_scenario_combination_simulates_cleanly() {
    for persona in PersonaKind::ALL {
        for scenario in ScenarioKind::ALL {
            let profile = PersonaProfile::sample(persona, 42);
            let out = simulate_scenario(&profile, scenario, 42).unwrap();
            assert!(!out.events.is_empty());
            assert!(out.total_duration_ms > 0.0);

            match scenario {
                ScenarioKind::ArticleReadingScroll => {
                    assert!(out.events.iter().any(|e| e.kind == EventKind::WheelScroll));
                    assert!(out.events.iter().any(|e| e.kind == EventKind::Pause));
                }
                ScenarioKind::FormEntry => {
                    assert_eq!(out.expected_texts.len(), 3);
                    assert_eq!(reconstruct_field_texts(&out.events), out.expected_texts);
                }
                ScenarioKind::SearchAndBrowse => {
                    assert_eq!(out.expected_texts.len(), 1);
                    assert_eq!(reconstruct_field_texts(&out.events), out.expected_texts);
                    assert!(out.events.iter().any(|e| e.key.as_deref() == Some("Enter")));
                    assert!(out.events.iter().any(|e| e.kind == EventKind::WheelScroll));
                }
                ScenarioKind::CheckoutFlow => {
                    assert_eq!(out.expected_texts.len(), 2);
                    assert_eq!(reconstruct_field_texts(&out.events), out.expected_texts);
                    assert!(out.events.iter().any(|e| e.kind == EventKind::WheelScroll));
                }
                ScenarioKind::TargetApproachClick => {
                    assert!(out.events.iter().any(|e| e.kind == EventKind::MouseDown));
                    assert!(out.events.iter().any(|e| e.kind == EventKind::MouseUp));
                }
                _ => unreachable!("unexpected scenario {scenario:?}"),
            }
        }
    }
}

#[test]
fn typos_and_backspaces_reconstruct_exact_original_text() {
    let mut total_backspaces = 0usize;
    for seed in 1..=30 {
        let mut profile = PersonaProfile::sample(PersonaKind::DistractedBrowser, seed);
        profile.typo_rate = 0.2;
        let out = simulate_scenario(&profile, ScenarioKind::FormEntry, seed).unwrap();
        let reconstructed = reconstruct_field_texts(&out.events);
        assert_eq!(reconstructed, out.expected_texts, "seed {seed}");

        let concatenated = reconstruct_typed_text(&out.events);
        assert_eq!(concatenated, out.expected_texts.concat(), "seed {seed}");

        let features = TrajectoryFeatures::extract(
            &out.events,
            &out.stroke_target_widths,
            true,
            Some(profile.kind),
            ScenarioKind::FormEntry,
            seed,
        );
        total_backspaces += features.backspace_count;
        if features.backspace_count > 0 {
            assert!(features.typo_correction_rate > 0.0);
        }
    }
    assert!(
        total_backspaces >= 50,
        "expected >= 50 corrected typos across 30 form runs at 20% typo rate, got {total_backspaces}"
    );
}

#[test]
fn generation_is_deterministic_per_seed_and_diverse_across_seeds() {
    let cfg_a = DatasetConfig {
        sample_count: 12,
        base_seed: 777,
        include_baseline_negatives: true,
        ..DatasetConfig::default()
    };
    let cfg_b = DatasetConfig {
        base_seed: 778,
        ..cfg_a.clone()
    };

    let batch_a1 = DatasetBatchGenerator::new(cfg_a.clone())
        .unwrap()
        .generate()
        .unwrap();
    let batch_a2 = DatasetBatchGenerator::new(cfg_a)
        .unwrap()
        .generate()
        .unwrap();
    let batch_b = DatasetBatchGenerator::new(cfg_b)
        .unwrap()
        .generate()
        .unwrap();

    assert_eq!(batch_a1, batch_a2);
    assert_eq!(
        batch_a1.to_jsonl_events().unwrap(),
        batch_a2.to_jsonl_events().unwrap()
    );
    assert_eq!(
        batch_a1.to_csv_features().unwrap(),
        batch_a2.to_csv_features().unwrap()
    );

    assert_ne!(batch_a1.samples[0].events, batch_b.samples[0].events);
    assert_ne!(batch_a1.samples[0].features, batch_b.samples[0].features);
    assert_ne!(
        batch_a1.samples[0].summary.profile,
        batch_b.samples[0].summary.profile
    );
}
