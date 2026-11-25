//! Dataset exporters for JSON, streaming JSONL, flat event CSV, and feature matrix CSV.

use std::fmt::{self, Write as _};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::dataset::DatasetBatch;
use crate::error::{DatasetError, Result};
use crate::event::EventKind;
use crate::persona::PersonaKind;
use crate::scenario::ScenarioKind;

/// Output serialization format for a generated [`DatasetBatch`].
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ExportFormat {
    /// Pretty-printed JSON containing the full [`DatasetBatch`].
    Json,
    /// JSON Lines with one complete [`DatasetSample`](crate::dataset::DatasetSample) per line.
    #[default]
    JsonlSamples,
    /// JSON Lines with one flattened [`JsonlEventRow`] per line for event-stream training.
    JsonlEvents,
    /// Flat CSV table with one row per [`BehaviorEvent`](crate::event::BehaviorEvent) (20 columns).
    CsvEvents,
    /// Feature matrix CSV with one row per sample (33 columns).
    CsvFeatures,
}

impl ExportFormat {
    /// All five supported export formats.
    pub const ALL: [Self; 5] = [
        Self::Json,
        Self::JsonlSamples,
        Self::JsonlEvents,
        Self::CsvEvents,
        Self::CsvFeatures,
    ];

    /// Canonical snake_case format name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::JsonlSamples => "jsonl_samples",
            Self::JsonlEvents => "jsonl_events",
            Self::CsvEvents => "csv_events",
            Self::CsvFeatures => "csv_features",
        }
    }
}

impl fmt::Display for ExportFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ExportFormat {
    type Err = DatasetError;

    fn from_str(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "json" => Ok(Self::Json),
            "jsonl_samples" | "jsonl" => Ok(Self::JsonlSamples),
            "jsonl_events" => Ok(Self::JsonlEvents),
            "csv_events" => Ok(Self::CsvEvents),
            "csv_features" | "csv" => Ok(Self::CsvFeatures),
            _ => Err(DatasetError::Parse {
                kind: "ExportFormat",
                value: s.to_owned(),
            }),
        }
    }
}

/// Flattened event record emitted by [`ExportFormat::JsonlEvents`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JsonlEventRow {
    /// Parent sample identifier.
    pub sample_id: String,
    /// True for human-simulated sessions, false for synthetic linear bot baselines.
    pub is_human: bool,
    /// Ground-truth classification label.
    pub label: String,
    /// Sampled persona archetype when `is_human` is true.
    pub persona: Option<PersonaKind>,
    /// Simulated scenario workflow.
    pub scenario: ScenarioKind,
    /// Sample seed.
    pub seed: u64,
    /// Cumulative elapsed session time in milliseconds.
    pub timestamp_ms: f64,
    /// Elapsed milliseconds since the preceding event.
    pub dt_ms: f64,
    /// Interaction category.
    pub kind: EventKind,
    /// Pointer X coordinate in CSS pixels.
    pub x: Option<f64>,
    /// Pointer Y coordinate in CSS pixels.
    pub y: Option<f64>,
    /// Horizontal pointer displacement in CSS pixels.
    pub dx: Option<f64>,
    /// Vertical pointer displacement in CSS pixels.
    pub dy: Option<f64>,
    /// Instantaneous pointer speed in pixels per second.
    pub velocity_px_s: Option<f64>,
    /// Tangential pointer acceleration in pixels per second squared.
    pub acceleration_px_s2: Option<f64>,
    /// Tangential pointer jerk in pixels per second cubed.
    pub jerk_px_s3: Option<f64>,
    /// Signed turning angle in radians.
    pub curvature_rad: Option<f64>,
    /// Key label for keystroke events.
    pub key: Option<String>,
    /// Hold or pause dwell duration in milliseconds.
    pub dwell_ms: Option<f64>,
    /// Vertical scroll delta in pixels.
    pub scroll_dy: Option<f64>,
}

const CSV_EVENTS_HEADER: &str = "sample_id,is_human,label,persona,scenario,seed,timestamp_ms,dt_ms,kind,x,y,dx,dy,velocity_px_s,acceleration_px_s2,jerk_px_s3,curvature_rad,key,dwell_ms,scroll_dy";
const CSV_FEATURES_HEADER: &str = "sample_id,is_human,label,persona,scenario,seed,total_duration_ms,event_count,pointer_event_count,stroke_count,key_event_count,scroll_event_count,euclidean_distance_px,arc_length_px,straightness_index,fitts_index_of_difficulty,overshoot_count,peak_velocity_px_s,mean_velocity_px_s,std_velocity_px_s,mean_acceleration_px_s2,std_acceleration_px_s2,peak_jerk_px_s3,mean_abs_curvature_rad,std_curvature_rad,tremor_high_freq_energy,inter_key_mean_ms,inter_key_std_ms,mean_key_dwell_ms,backspace_count,typo_correction_rate,mean_click_dwell_ms,total_scroll_dy";

pub(crate) fn export_batch(batch: &DatasetBatch, format: ExportFormat) -> Result<String> {
    match format {
        ExportFormat::Json => Ok(serde_json::to_string_pretty(batch)?),
        ExportFormat::JsonlSamples => export_jsonl_samples(batch),
        ExportFormat::JsonlEvents => export_jsonl_events(batch),
        ExportFormat::CsvEvents => export_csv_events(batch),
        ExportFormat::CsvFeatures => export_csv_features(batch),
    }
}

fn export_jsonl_samples(batch: &DatasetBatch) -> Result<String> {
    let mut out = String::new();
    for (idx, sample) in batch.samples.iter().enumerate() {
        if idx > 0 {
            out.push('\n');
        }
        out.push_str(&serde_json::to_string(sample)?);
    }
    Ok(out)
}

fn export_jsonl_events(batch: &DatasetBatch) -> Result<String> {
    let mut out = String::new();
    let mut first = true;
    for sample in &batch.samples {
        for event in &sample.events {
            if !first {
                out.push('\n');
            }
            first = false;
            let row = JsonlEventRow {
                sample_id: sample.id.clone(),
                is_human: sample.summary.is_human,
                label: sample.summary.label.clone(),
                persona: sample.summary.persona,
                scenario: sample.summary.scenario,
                seed: sample.summary.seed,
                timestamp_ms: event.timestamp_ms,
                dt_ms: event.dt_ms,
                kind: event.kind,
                x: event.x,
                y: event.y,
                dx: event.dx,
                dy: event.dy,
                velocity_px_s: event.velocity_px_s,
                acceleration_px_s2: event.acceleration_px_s2,
                jerk_px_s3: event.jerk_px_s3,
                curvature_rad: event.curvature_rad,
                key: event.key.clone(),
                dwell_ms: event.dwell_ms,
                scroll_dy: event.scroll_dy,
            };
            out.push_str(&serde_json::to_string(&row)?);
        }
    }
    Ok(out)
}

fn export_csv_events(batch: &DatasetBatch) -> Result<String> {
    let mut out = String::from(CSV_EVENTS_HEADER);
    for sample in &batch.samples {
        let sum = &sample.summary;
        let persona = sum.persona.map_or("", PersonaKind::as_str);
        for ev in &sample.events {
            out.push('\n');
            push_csv_field(&mut out, &sample.id);
            write!(
                out,
                ",{},{},{},{},{},{:.4},{:.4},{}",
                sum.is_human,
                sum.label,
                persona,
                sum.scenario.as_str(),
                sum.seed,
                ev.timestamp_ms,
                ev.dt_ms,
                ev.kind.as_str()
            )?;
            push_opt_f64(&mut out, ev.x, 4)?;
            push_opt_f64(&mut out, ev.y, 4)?;
            push_opt_f64(&mut out, ev.dx, 4)?;
            push_opt_f64(&mut out, ev.dy, 4)?;
            push_opt_f64(&mut out, ev.velocity_px_s, 4)?;
            push_opt_f64(&mut out, ev.acceleration_px_s2, 4)?;
            push_opt_f64(&mut out, ev.jerk_px_s3, 4)?;
            push_opt_f64(&mut out, ev.curvature_rad, 6)?;
            out.push(',');
            if let Some(key) = ev.key.as_deref() {
                push_csv_field(&mut out, key);
            }
            push_opt_f64(&mut out, ev.dwell_ms, 4)?;
            push_opt_f64(&mut out, ev.scroll_dy, 4)?;
        }
    }
    Ok(out)
}

fn export_csv_features(batch: &DatasetBatch) -> Result<String> {
    let mut out = String::from(CSV_FEATURES_HEADER);
    for sample in &batch.samples {
        let f = &sample.features;
        let persona = f.persona.map_or("", PersonaKind::as_str);
        out.push('\n');
        push_csv_field(&mut out, &sample.id);
        write!(
            out,
            ",{},{},{},{},{},{:.4},{},{},{},{},{},{:.4},{:.4},{:.6},{:.6},{},{:.4},{:.4},{:.4},{:.4},{:.4},{:.4},{:.6},{:.6},{:.6},{:.4},{:.4},{:.4},{},{:.6},{:.4},{:.4}",
            f.is_human,
            f.label,
            persona,
            f.scenario.as_str(),
            f.seed,
            f.total_duration_ms,
            f.event_count,
            f.pointer_event_count,
            f.stroke_count,
            f.key_event_count,
            f.scroll_event_count,
            f.euclidean_distance_px,
            f.arc_length_px,
            f.straightness_index,
            f.fitts_index_of_difficulty,
            f.overshoot_count,
            f.peak_velocity_px_s,
            f.mean_velocity_px_s,
            f.std_velocity_px_s,
            f.mean_acceleration_px_s2,
            f.std_acceleration_px_s2,
            f.peak_jerk_px_s3,
            f.mean_abs_curvature_rad,
            f.std_curvature_rad,
            f.tremor_high_freq_energy,
            f.inter_key_mean_ms,
            f.inter_key_std_ms,
            f.mean_key_dwell_ms,
            f.backspace_count,
            f.typo_correction_rate,
            f.mean_click_dwell_ms,
            f.total_scroll_dy,
        )?;
    }
    Ok(out)
}

fn push_opt_f64(out: &mut String, value: Option<f64>, decimals: usize) -> fmt::Result {
    out.push(',');
    if let Some(v) = value
        && v.is_finite()
    {
        write!(out, "{v:.decimals$}")?;
    }
    Ok(())
}

fn push_csv_field(out: &mut String, value: &str) {
    if value.contains([',', '"', '\n', '\r']) {
        out.push('"');
        for ch in value.chars() {
            if ch == '"' {
                out.push_str("\"\"");
            } else {
                out.push(ch);
            }
        }
        out.push('"');
    } else {
        out.push_str(value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_escaping_handles_plain_quotes_commas_and_newlines() {
        let mut buf = String::new();
        push_csv_field(&mut buf, "plain");
        assert_eq!(buf, "plain");

        buf.clear();
        push_csv_field(&mut buf, "hello, \"world\"\nnext");
        assert_eq!(buf, "\"hello, \"\"world\"\"\nnext\"");
    }

    #[test]
    fn empty_batch_exports_headers_only_for_csv_and_empty_for_jsonl() {
        let empty = DatasetBatch {
            config: crate::dataset::DatasetConfig::default(),
            samples: Vec::new(),
        };
        assert_eq!(empty.to_jsonl_samples().unwrap(), "");
        assert_eq!(empty.to_jsonl_events().unwrap(), "");
        assert_eq!(empty.to_csv_events().unwrap(), CSV_EVENTS_HEADER);
        assert_eq!(empty.to_csv_features().unwrap(), CSV_FEATURES_HEADER);
    }
}
