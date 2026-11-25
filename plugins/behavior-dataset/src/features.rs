//! Kinematic, Fitts's law, and timing feature extraction for ML training.

use serde::{Deserialize, Serialize};

use crate::event::{BehaviorEvent, EventKind};
use crate::persona::{PersonaKind, PersonaProfile};
use crate::scenario::ScenarioKind;

const DEFAULT_TARGET_WIDTH_PX: f64 = 48.0;
const OVERSHOOT_MIN_DISTANCE_PX: f64 = 50.0;
const OVERSHOOT_THRESHOLD_PX: f64 = 2.0;

/// Extracted ML feature vector and ground-truth labels for one behavioral session.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrajectoryFeatures {
    /// True for human-simulated sessions, false for synthetic linear bot baselines.
    pub is_human: bool,
    /// Classification label (`"human"` or `"synthetic_linear_baseline"`).
    pub label: String,
    /// Sampled persona archetype when `is_human` is true.
    pub persona: Option<PersonaKind>,
    /// Simulated scenario workflow.
    pub scenario: ScenarioKind,
    /// Deterministic seed used to generate this episode.
    pub seed: u64,
    /// Total elapsed session duration in milliseconds.
    pub total_duration_ms: f64,
    /// Total number of events in the timeline.
    pub event_count: usize,
    /// Number of pointer movement samples.
    pub pointer_event_count: usize,
    /// Number of distinct pointer movement strokes.
    pub stroke_count: usize,
    /// Number of keystroke events.
    pub key_event_count: usize,
    /// Number of scroll notch events.
    pub scroll_event_count: usize,
    /// Sum of per-stroke straight-line Euclidean distances in pixels.
    pub euclidean_distance_px: f64,
    /// Sum of per-stroke actual pointer path arc lengths in pixels.
    pub arc_length_px: f64,
    /// Path efficiency / straightness index (`euclidean_distance_px / arc_length_px`).
    pub straightness_index: f64,
    /// Mean Fitts index of difficulty `log2(D / W + 1)` across pointer strokes.
    pub fitts_index_of_difficulty: f64,
    /// Count of strokes whose path overshot the target along the approach axis.
    pub overshoot_count: usize,
    /// Maximum instantaneous pointer speed in pixels per second.
    pub peak_velocity_px_s: f64,
    /// Mean pointer speed across moving samples in pixels per second.
    pub mean_velocity_px_s: f64,
    /// Standard deviation of pointer speed in pixels per second.
    pub std_velocity_px_s: f64,
    /// Mean tangential acceleration in pixels per second squared.
    pub mean_acceleration_px_s2: f64,
    /// Standard deviation of tangential acceleration in pixels per second squared.
    pub std_acceleration_px_s2: f64,
    /// Peak absolute tangential jerk in pixels per second cubed.
    pub peak_jerk_px_s3: f64,
    /// Mean absolute turning angle between consecutive pointer segments in radians.
    pub mean_abs_curvature_rad: f64,
    /// Standard deviation of absolute turning angle in radians.
    pub std_curvature_rad: f64,
    /// High-frequency hand tremor energy (mean squared midpoint residual in px^2).
    pub tremor_high_freq_energy: f64,
    /// Mean inter-key interval in milliseconds.
    pub inter_key_mean_ms: f64,
    /// Standard deviation of inter-key intervals in milliseconds.
    pub inter_key_std_ms: f64,
    /// Mean key hold dwell duration in milliseconds.
    pub mean_key_dwell_ms: f64,
    /// Total backspace correction events.
    pub backspace_count: usize,
    /// Ratio of backspace corrections to total keystroke events.
    pub typo_correction_rate: f64,
    /// Mean mouse button press dwell duration in milliseconds.
    pub mean_click_dwell_ms: f64,
    /// Sum of absolute vertical scroll deltas in pixels.
    pub total_scroll_dy: f64,
}

impl TrajectoryFeatures {
    /// Extracts all kinematic and timing features from an event timeline.
    #[must_use]
    pub fn extract(
        events: &[BehaviorEvent],
        target_widths: &[f64],
        is_human: bool,
        persona: Option<PersonaKind>,
        scenario: ScenarioKind,
        seed: u64,
    ) -> Self {
        let label = if is_human {
            "human".to_owned()
        } else {
            "synthetic_linear_baseline".to_owned()
        };

        let mut acc = FeatureAccumulator::default();
        for event in events {
            acc.visit(event);
        }
        acc.flush_stroke();

        let metrics = acc.finalize(target_widths);
        let total_duration_ms = events.last().map_or(0.0, |e| e.timestamp_ms);

        Self {
            is_human,
            label,
            persona,
            scenario,
            seed,
            total_duration_ms,
            event_count: events.len(),
            pointer_event_count: acc.pointer_event_count,
            stroke_count: metrics.stroke_count,
            key_event_count: acc.key_dts.len(),
            scroll_event_count: acc.scroll_event_count,
            euclidean_distance_px: metrics.euclidean_distance_px,
            arc_length_px: metrics.arc_length_px,
            straightness_index: metrics.straightness_index,
            fitts_index_of_difficulty: metrics.fitts_index_of_difficulty,
            overshoot_count: metrics.overshoot_count,
            peak_velocity_px_s: metrics.peak_velocity_px_s,
            mean_velocity_px_s: metrics.mean_velocity_px_s,
            std_velocity_px_s: metrics.std_velocity_px_s,
            mean_acceleration_px_s2: metrics.mean_acceleration_px_s2,
            std_acceleration_px_s2: metrics.std_acceleration_px_s2,
            peak_jerk_px_s3: metrics.peak_jerk_px_s3,
            mean_abs_curvature_rad: metrics.mean_abs_curvature_rad,
            std_curvature_rad: metrics.std_curvature_rad,
            tremor_high_freq_energy: metrics.tremor_high_freq_energy,
            inter_key_mean_ms: metrics.inter_key_mean_ms,
            inter_key_std_ms: metrics.inter_key_std_ms,
            mean_key_dwell_ms: metrics.mean_key_dwell_ms,
            backspace_count: acc.backspace_count,
            typo_correction_rate: metrics.typo_correction_rate,
            mean_click_dwell_ms: metrics.mean_click_dwell_ms,
            total_scroll_dy: acc.total_scroll_dy,
        }
    }

    /// Alias for [`Self::straightness_index`] (`euclidean_distance_px / arc_length_px`).
    #[must_use]
    pub const fn path_efficiency(&self) -> f64 {
        self.straightness_index
    }
}

/// High-level session metadata and aggregate statistics for a generated sample.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionSummary {
    /// Unique sample identifier within the batch.
    pub sample_id: String,
    /// True for human-simulated sessions, false for synthetic linear bot baselines.
    pub is_human: bool,
    /// Ground-truth classification label (`"human"` or `"synthetic_linear_baseline"`).
    pub label: String,
    /// Sampled persona archetype when `is_human` is true.
    pub persona: Option<PersonaKind>,
    /// Simulated scenario workflow.
    pub scenario: ScenarioKind,
    /// Deterministic seed for this episode.
    pub seed: u64,
    /// Full sampled persona profile when `is_human` is true.
    pub profile: Option<PersonaProfile>,
    /// Total elapsed session duration in milliseconds.
    pub total_duration_ms: f64,
    /// Total events in the timeline.
    pub event_count: usize,
    /// Count of pointer move events.
    pub pointer_event_count: usize,
    /// Count of keystroke events.
    pub key_event_count: usize,
    /// Count of scroll notch events.
    pub scroll_event_count: usize,
    /// Texts reconstructed by applying keystrokes and backspaces from the event stream.
    pub reconstructed_texts: Vec<String>,
    /// Ground-truth target texts supplied to the scenario.
    pub expected_texts: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
struct StrokePoint {
    x: f64,
    y: f64,
    t_ms: f64,
}

#[derive(Debug, Default)]
struct FeatureAccumulator {
    pointer_event_count: usize,
    scroll_event_count: usize,
    current_stroke: Vec<StrokePoint>,
    strokes: Vec<Vec<StrokePoint>>,
    velocities: Vec<f64>,
    accelerations: Vec<f64>,
    jerks: Vec<f64>,
    abs_curvatures: Vec<f64>,
    key_dts: Vec<f64>,
    key_dwells: Vec<f64>,
    backspace_count: usize,
    click_dwells: Vec<f64>,
    total_scroll_dy: f64,
}

impl FeatureAccumulator {
    fn visit(&mut self, event: &BehaviorEvent) {
        match event.kind {
            EventKind::PointerMove => {
                self.pointer_event_count += 1;
                if let (Some(x), Some(y)) = (event.x, event.y) {
                    let dx = event.dx.unwrap_or(0.0);
                    let dy = event.dy.unwrap_or(0.0);
                    if self.current_stroke.is_empty() && (dx.abs() > 1e-9 || dy.abs() > 1e-9) {
                        self.current_stroke.push(StrokePoint {
                            x: x - dx,
                            y: y - dy,
                            t_ms: (event.timestamp_ms - event.dt_ms).max(0.0),
                        });
                    }
                    self.current_stroke.push(StrokePoint {
                        x,
                        y,
                        t_ms: event.timestamp_ms,
                    });
                }
                if event.dt_ms > 0.0 {
                    if let Some(v) = event.velocity_px_s {
                        self.velocities.push(v);
                    }
                    if let Some(a) = event.acceleration_px_s2 {
                        self.accelerations.push(a);
                    }
                    if let Some(j) = event.jerk_px_s3 {
                        self.jerks.push(j.abs());
                    }
                    if let Some(c) = event.curvature_rad {
                        self.abs_curvatures.push(c.abs());
                    }
                }
            }
            EventKind::MouseDown => {
                self.flush_stroke();
            }
            EventKind::MouseUp => {
                self.flush_stroke();
                if let Some(dwell) = event.dwell_ms {
                    self.click_dwells.push(dwell);
                }
            }
            EventKind::KeyPress => {
                self.flush_stroke();
                self.key_dts.push(event.dt_ms);
                if let Some(dwell) = event.dwell_ms {
                    self.key_dwells.push(dwell);
                }
                if event.key.as_deref() == Some("Backspace") {
                    self.backspace_count += 1;
                }
            }
            EventKind::WheelScroll => {
                self.flush_stroke();
                self.scroll_event_count += 1;
                if let Some(dy) = event.scroll_dy {
                    self.total_scroll_dy += dy.abs();
                }
            }
            EventKind::Pause => {
                self.flush_stroke();
            }
        }
    }

    fn flush_stroke(&mut self) {
        if self.current_stroke.len() >= 2 {
            let stroke = std::mem::take(&mut self.current_stroke);
            let arc = stroke_arc_length(&stroke);
            if arc > 1e-9 {
                self.strokes.push(stroke);
            }
        } else {
            self.current_stroke.clear();
        }
    }

    fn finalize(&self, target_widths: &[f64]) -> FinalizedMetrics {
        let mut euclidean_sum = 0.0;
        let mut arc_sum = 0.0;
        let mut fitts_sum = 0.0;
        let mut overshoot_count = 0usize;
        let mut tremor_sum = 0.0;
        let mut tremor_samples = 0usize;

        for (idx, stroke) in self.strokes.iter().enumerate() {
            let Some(first) = stroke.first() else {
                continue;
            };
            let Some(last) = stroke.last() else {
                continue;
            };
            let euclid = (last.x - first.x).hypot(last.y - first.y);
            let arc = stroke_arc_length(stroke);
            euclidean_sum += euclid;
            arc_sum += arc;

            let width = target_widths
                .get(idx)
                .copied()
                .unwrap_or(DEFAULT_TARGET_WIDTH_PX)
                .max(4.0);
            fitts_sum += (euclid / width + 1.0).log2();

            if stroke_overshoots(stroke, euclid) {
                overshoot_count += 1;
            }

            let (energy, count) = stroke_tremor_energy(stroke);
            tremor_sum += energy;
            tremor_samples += count;
        }

        let stroke_count = self.strokes.len();
        let straightness_index = if arc_sum > 1e-9 {
            (euclidean_sum / arc_sum).clamp(0.0, 1.0)
        } else {
            1.0
        };
        #[allow(clippy::cast_precision_loss)]
        let fitts_index_of_difficulty = if stroke_count > 0 {
            fitts_sum / stroke_count as f64
        } else {
            0.0
        };
        #[allow(clippy::cast_precision_loss)]
        let tremor_high_freq_energy = if tremor_samples > 0 {
            tremor_sum / tremor_samples as f64
        } else {
            0.0
        };

        let (mean_velocity_px_s, std_velocity_px_s) = mean_std(&self.velocities);
        let peak_velocity_px_s = self.velocities.iter().copied().fold(0.0, f64::max);
        let (mean_acceleration_px_s2, std_acceleration_px_s2) = mean_std(&self.accelerations);
        let peak_jerk_px_s3 = self.jerks.iter().copied().fold(0.0, f64::max);
        let (mean_abs_curvature_rad, std_curvature_rad) = mean_std(&self.abs_curvatures);
        let (inter_key_mean_ms, inter_key_std_ms) = mean_std(&self.key_dts);
        let (mean_key_dwell_ms, _) = mean_std(&self.key_dwells);
        let (mean_click_dwell_ms, _) = mean_std(&self.click_dwells);
        #[allow(clippy::cast_precision_loss)]
        let typo_correction_rate = if self.key_dts.is_empty() {
            0.0
        } else {
            self.backspace_count as f64 / self.key_dts.len() as f64
        };

        FinalizedMetrics {
            stroke_count,
            euclidean_distance_px: euclidean_sum,
            arc_length_px: arc_sum,
            straightness_index,
            fitts_index_of_difficulty,
            overshoot_count,
            peak_velocity_px_s,
            mean_velocity_px_s,
            std_velocity_px_s,
            mean_acceleration_px_s2,
            std_acceleration_px_s2,
            peak_jerk_px_s3,
            mean_abs_curvature_rad,
            std_curvature_rad,
            tremor_high_freq_energy,
            inter_key_mean_ms,
            inter_key_std_ms,
            mean_key_dwell_ms,
            typo_correction_rate,
            mean_click_dwell_ms,
        }
    }
}

struct FinalizedMetrics {
    stroke_count: usize,
    euclidean_distance_px: f64,
    arc_length_px: f64,
    straightness_index: f64,
    fitts_index_of_difficulty: f64,
    overshoot_count: usize,
    peak_velocity_px_s: f64,
    mean_velocity_px_s: f64,
    std_velocity_px_s: f64,
    mean_acceleration_px_s2: f64,
    std_acceleration_px_s2: f64,
    peak_jerk_px_s3: f64,
    mean_abs_curvature_rad: f64,
    std_curvature_rad: f64,
    tremor_high_freq_energy: f64,
    inter_key_mean_ms: f64,
    inter_key_std_ms: f64,
    mean_key_dwell_ms: f64,
    typo_correction_rate: f64,
    mean_click_dwell_ms: f64,
}

fn stroke_arc_length(stroke: &[StrokePoint]) -> f64 {
    stroke
        .windows(2)
        .map(|pair| (pair[1].x - pair[0].x).hypot(pair[1].y - pair[0].y))
        .sum()
}

fn stroke_overshoots(stroke: &[StrokePoint], euclidean: f64) -> bool {
    if euclidean < OVERSHOOT_MIN_DISTANCE_PX {
        return false;
    }
    let Some(first) = stroke.first() else {
        return false;
    };
    let Some(last) = stroke.last() else {
        return false;
    };
    let ux = (last.x - first.x) / euclidean;
    let uy = (last.y - first.y) / euclidean;

    let max_excess = stroke
        .iter()
        .map(|pt| (pt.x - first.x) * ux + (pt.y - first.y) * uy - euclidean)
        .fold(0.0, f64::max);
    max_excess > OVERSHOOT_THRESHOLD_PX
}

fn stroke_tremor_energy(stroke: &[StrokePoint]) -> (f64, usize) {
    let mut sum = 0.0;
    let mut count = 0usize;
    for win in stroke.windows(3) {
        let dt1 = (win[1].t_ms - win[0].t_ms).max(0.0);
        let dt2 = (win[2].t_ms - win[1].t_ms).max(0.0);
        let span = dt1 + dt2;
        if span <= 1e-6 {
            continue;
        }
        let alpha = dt1 / span;
        let pred_x = win[0].x + (win[2].x - win[0].x) * alpha;
        let pred_y = win[0].y + (win[2].y - win[0].y) * alpha;
        let err_sq = (win[1].x - pred_x).powi(2) + (win[1].y - pred_y).powi(2);
        sum += err_sq;
        count += 1;
    }
    (sum, count)
}

fn mean_std(values: &[f64]) -> (f64, f64) {
    if values.is_empty() {
        return (0.0, 0.0);
    }
    #[allow(clippy::cast_precision_loss)]
    let n = values.len() as f64;
    let mean = values.iter().sum::<f64>() / n;
    let variance = values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / n;
    (mean, variance.sqrt())
}
