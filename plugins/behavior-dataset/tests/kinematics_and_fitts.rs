//! Tests for Fitts's law duration scaling, bell-shaped velocity profiles,
//! curved path straightness, overshoot, tremor energy, and timeline invariants.

use seleniumbase_rs::sb_cdp::{Point, Rect};
use seleniumbase_rs_plugin_behavior_dataset::{
    BehaviorEvent, EventKind, PersonaKind, PersonaProfile, ScenarioKind, TrajectoryFeatures,
    simulate_linear_baseline, simulate_linear_target_approach, simulate_scenario,
    simulate_target_approach,
};

fn pointer_speeds(events: &[BehaviorEvent]) -> Vec<f64> {
    events
        .iter()
        .filter(|e| e.kind == EventKind::PointerMove && e.dt_ms > 0.0)
        .filter_map(|e| e.velocity_px_s)
        .collect()
}

fn mean(values: &[f64]) -> f64 {
    assert!(!values.is_empty());
    values.iter().sum::<f64>() / values.len() as f64
}

#[test]
fn fitts_law_duration_increases_monotonically_with_distance() {
    let from = Point::new(80.0, 300.0);
    let distances = [120.0, 420.0, 920.0];
    let mut mean_durations = Vec::new();
    let mut mean_fitts_ids = Vec::new();

    for dist in distances {
        let target = Rect {
            x: from.x + dist - 24.0,
            y: from.y - 18.0,
            width: 48.0,
            height: 36.0,
        };
        let mut durations = Vec::new();
        let mut ids = Vec::new();
        for seed in 1..=25 {
            let mut profile = PersonaProfile::sample(PersonaKind::AverageDesktop, seed);
            profile.pointer_speed = 1.0;
            profile.overshoot = 0.0;
            let out = simulate_target_approach(&profile, from, target).unwrap();
            let move_ms: f64 = out
                .events
                .iter()
                .filter(|e| e.kind == EventKind::PointerMove)
                .map(|e| e.dt_ms)
                .sum();
            let features = TrajectoryFeatures::extract(
                &out.events,
                &out.stroke_target_widths,
                true,
                Some(profile.kind),
                ScenarioKind::TargetApproachClick,
                seed,
            );
            durations.push(move_ms);
            ids.push(features.fitts_index_of_difficulty);
        }
        mean_durations.push(mean(&durations));
        mean_fitts_ids.push(mean(&ids));
    }

    assert!(
        mean_durations[0] < mean_durations[1] && mean_durations[1] < mean_durations[2],
        "expected duration to increase with distance: {mean_durations:?}"
    );
    assert!(
        mean_fitts_ids[0] < mean_fitts_ids[1] && mean_fitts_ids[1] < mean_fitts_ids[2],
        "expected Fitts ID to increase with distance: {mean_fitts_ids:?}"
    );
}

#[test]
fn fitts_law_duration_increases_monotonically_for_smaller_targets() {
    let from = Point::new(100.0, 400.0);
    let widths = [160.0, 48.0, 12.0];
    let mut mean_durations = Vec::new();
    let mut mean_fitts_ids = Vec::new();

    for width in widths {
        let target = Rect {
            x: 700.0 - width * 0.5,
            y: 380.0,
            width,
            height: 32.0,
        };
        let mut durations = Vec::new();
        let mut ids = Vec::new();
        for seed in 10..=34 {
            let mut profile = PersonaProfile::sample(PersonaKind::CarefulReader, seed);
            profile.pointer_speed = 1.0;
            profile.overshoot = 0.0;
            let out = simulate_target_approach(&profile, from, target).unwrap();
            let move_ms: f64 = out
                .events
                .iter()
                .filter(|e| e.kind == EventKind::PointerMove)
                .map(|e| e.dt_ms)
                .sum();
            let features = TrajectoryFeatures::extract(
                &out.events,
                &out.stroke_target_widths,
                true,
                Some(profile.kind),
                ScenarioKind::TargetApproachClick,
                seed,
            );
            durations.push(move_ms);
            ids.push(features.fitts_index_of_difficulty);
        }
        mean_durations.push(mean(&durations));
        mean_fitts_ids.push(mean(&ids));
    }

    assert!(
        mean_durations[0] < mean_durations[1] && mean_durations[1] < mean_durations[2],
        "expected smaller targets to take longer: {mean_durations:?}"
    );
    assert!(
        mean_fitts_ids[0] < mean_fitts_ids[1] && mean_fitts_ids[1] < mean_fitts_ids[2],
        "expected smaller targets to have higher Fitts ID: {mean_fitts_ids:?}"
    );
}

#[test]
fn human_pointer_speed_follows_bell_shaped_profile_while_linear_is_flat() {
    let from = Point::new(60.0, 200.0);
    let target = Rect {
        x: 920.0,
        y: 180.0,
        width: 60.0,
        height: 40.0,
    };

    let mut bell_shaped_count = 0usize;
    for seed in 1..=30 {
        let mut profile = PersonaProfile::sample(PersonaKind::AverageDesktop, seed);
        profile.overshoot = 0.0;
        let out = simulate_target_approach(&profile, from, target).unwrap();
        let speeds = pointer_speeds(&out.events);
        let n = speeds.len();
        assert!(n >= 10, "expected >= 10 pointer steps, got {n}");

        let start = mean(&speeds[..n / 10]);
        let middle = mean(&speeds[n * 2 / 5..n * 3 / 5]);
        let end = mean(&speeds[n - n / 10..]);
        if middle > start * 2.5 && middle > end * 2.5 {
            bell_shaped_count += 1;
        }
    }
    assert!(
        bell_shaped_count >= 28,
        "expected >= 28/30 human approaches to be bell-shaped, got {bell_shaped_count}"
    );

    let linear = simulate_linear_target_approach(from, target, 750.0);
    let linear_speeds = pointer_speeds(&linear.events);
    let n = linear_speeds.len();
    let start = mean(&linear_speeds[..n / 10]);
    let middle = mean(&linear_speeds[n * 2 / 5..n * 3 / 5]);
    let end = mean(&linear_speeds[n - n / 10..]);
    assert!((start - middle).abs() < 1e-6);
    assert!((end - middle).abs() < 1e-6);
}

#[test]
fn human_paths_have_straightness_below_one_and_linear_baseline_equals_one() {
    for scenario in [
        ScenarioKind::TargetApproachClick,
        ScenarioKind::FormEntry,
        ScenarioKind::SearchAndBrowse,
        ScenarioKind::CheckoutFlow,
    ] {
        let mut curved = 0usize;
        for seed in 1..=15 {
            let profile = PersonaProfile::sample(PersonaKind::AverageDesktop, seed);
            let human = simulate_scenario(&profile, scenario, seed).unwrap();
            let human_feat = TrajectoryFeatures::extract(
                &human.events,
                &human.stroke_target_widths,
                true,
                Some(profile.kind),
                scenario,
                seed,
            );
            if human_feat.straightness_index < 0.999 {
                curved += 1;
            }
            assert!(
                human_feat.tremor_high_freq_energy > 0.0,
                "human trajectory should have non-zero tremor energy"
            );
            assert!(human_feat.mean_abs_curvature_rad > 0.0);
            assert!(human_feat.std_velocity_px_s > 0.0);

            let bot = simulate_linear_baseline(scenario, profile.viewport(), seed);
            let bot_feat = TrajectoryFeatures::extract(
                &bot.events,
                &bot.stroke_target_widths,
                false,
                None,
                scenario,
                seed,
            );
            assert!(
                (bot_feat.straightness_index - 1.0).abs() < 1e-9,
                "linear baseline straightness must be 1.0, got {} for {scenario:?}",
                bot_feat.straightness_index
            );
            assert!(
                bot_feat.tremor_high_freq_energy < 1e-12,
                "linear baseline tremor should be zero, got {}",
                bot_feat.tremor_high_freq_energy
            );
            assert!(bot_feat.std_velocity_px_s < 1e-6);
            assert!(bot_feat.mean_abs_curvature_rad < 1e-9);
            assert_eq!(bot_feat.overshoot_count, 0);
        }
        assert!(
            curved >= 14,
            "expected curved paths for {scenario:?}, got {curved}/15"
        );
    }
}

#[test]
fn high_overshoot_profile_produces_measurable_overshoots_on_long_targets() {
    let from = Point::new(50.0, 300.0);
    let target = Rect {
        x: 950.0,
        y: 280.0,
        width: 48.0,
        height: 40.0,
    };

    let mut total_overshoots = 0usize;
    for seed in 1..=20 {
        let mut profile = PersonaProfile::sample(PersonaKind::TrackpadUser, seed);
        profile.overshoot = 1.0;
        let out = simulate_target_approach(&profile, from, target).unwrap();
        let feat = TrajectoryFeatures::extract(
            &out.events,
            &out.stroke_target_widths,
            true,
            Some(profile.kind),
            ScenarioKind::TargetApproachClick,
            seed,
        );
        total_overshoots += feat.overshoot_count;
    }
    assert!(
        total_overshoots >= 16,
        "expected >= 16 overshoots across 20 forced-overshoot paths, got {total_overshoots}"
    );
}

#[test]
fn timeline_timestamps_are_monotonic_and_all_fields_finite() {
    for persona in PersonaKind::ALL {
        for scenario in ScenarioKind::ALL {
            let profile = PersonaProfile::sample(persona, 99);
            let out = simulate_scenario(&profile, scenario, 99).unwrap();
            assert!(!out.events.is_empty());

            let mut expected_t = 0.0;
            for ev in &out.events {
                assert!(ev.dt_ms.is_finite() && ev.dt_ms >= 0.0);
                assert!(ev.timestamp_ms.is_finite());
                expected_t += ev.dt_ms;
                assert!(
                    (ev.timestamp_ms - expected_t).abs() < 1e-6,
                    "timestamp drift: {} vs {expected_t}",
                    ev.timestamp_ms
                );
                for opt in [
                    ev.x,
                    ev.y,
                    ev.dx,
                    ev.dy,
                    ev.velocity_px_s,
                    ev.acceleration_px_s2,
                    ev.jerk_px_s3,
                    ev.curvature_rad,
                    ev.dwell_ms,
                    ev.scroll_dy,
                ]
                .into_iter()
                .flatten()
                {
                    assert!(opt.is_finite(), "non-finite event field in {ev:?}");
                }
            }
            assert!((out.total_duration_ms - expected_t).abs() < 1e-6);
        }
    }
}
