//! Event schema, kinematic timeline emitter, and keystroke reconstruction.

use std::fmt;

use seleniumbase_rs::sb_cdp::Point;
use serde::{Deserialize, Serialize};

/// Discrete interaction event types recorded in a behavioral timeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum EventKind {
    /// Pointer movement sample along a trajectory.
    PointerMove,
    /// Primary mouse button press or touch contact start.
    MouseDown,
    /// Primary mouse button release or touch contact end.
    MouseUp,
    /// Key press event (typing character, backspace, or enter).
    KeyPress,
    /// Mouse wheel or touch scroll notch.
    WheelScroll,
    /// Cognitive reaction, reading dwell, or distraction pause.
    Pause,
}

impl EventKind {
    /// Canonical snake_case event name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PointerMove => "pointer_move",
            Self::MouseDown => "mouse_down",
            Self::MouseUp => "mouse_up",
            Self::KeyPress => "key_press",
            Self::WheelScroll => "wheel_scroll",
            Self::Pause => "pause",
        }
    }
}

impl fmt::Display for EventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One timestamped event with derived pointer kinematics and input attributes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BehaviorEvent {
    /// Cumulative elapsed session time in milliseconds.
    pub timestamp_ms: f64,
    /// Elapsed milliseconds since the preceding event.
    pub dt_ms: f64,
    /// Interaction category.
    pub kind: EventKind,
    /// Pointer horizontal position in CSS pixels, when applicable.
    pub x: Option<f64>,
    /// Pointer vertical position in CSS pixels, when applicable.
    pub y: Option<f64>,
    /// Horizontal displacement from previous pointer position, when applicable.
    pub dx: Option<f64>,
    /// Vertical displacement from previous pointer position, when applicable.
    pub dy: Option<f64>,
    /// Instantaneous pointer speed in pixels per second.
    pub velocity_px_s: Option<f64>,
    /// Tangential pointer acceleration in pixels per second squared.
    pub acceleration_px_s2: Option<f64>,
    /// Tangential pointer jerk in pixels per second cubed.
    pub jerk_px_s3: Option<f64>,
    /// Signed turning angle in radians relative to the previous segment.
    pub curvature_rad: Option<f64>,
    /// Key label (`"a"`, `"Backspace"`, `"Enter"`, etc.) for key events.
    pub key: Option<String>,
    /// Press hold duration or pause dwell duration in milliseconds.
    pub dwell_ms: Option<f64>,
    /// Vertical scroll delta in pixels for scroll events.
    pub scroll_dy: Option<f64>,
}

/// Stateful timeline builder that converts raw plans into [`BehaviorEvent`]s
/// while computing finite pointer kinematics per stroke.
#[derive(Debug, Clone)]
pub(crate) struct TimelineBuilder {
    timestamp_ms: f64,
    events: Vec<BehaviorEvent>,
    cursor: Option<Point>,
    stroke_state: StrokeKinematics,
}

#[derive(Debug, Clone, Default)]
struct StrokeKinematics {
    samples_in_stroke: usize,
    prev_velocity: Option<f64>,
    prev_accel: Option<f64>,
    prev_vec: Option<(f64, f64)>,
}

impl TimelineBuilder {
    pub(crate) fn new() -> Self {
        Self {
            timestamp_ms: 0.0,
            events: Vec::new(),
            cursor: None,
            stroke_state: StrokeKinematics::default(),
        }
    }

    pub(crate) fn cursor(&self) -> Option<Point> {
        self.cursor
    }

    pub(crate) fn timestamp_ms(&self) -> f64 {
        self.timestamp_ms
    }

    pub(crate) fn event_count(&self) -> usize {
        self.events.len()
    }

    pub(crate) fn finish(self) -> Vec<BehaviorEvent> {
        self.events
    }

    pub(crate) fn reset_stroke(&mut self) {
        self.stroke_state = StrokeKinematics::default();
    }

    /// Emits an anchor pointer sample without advancing time if cursor is unset.
    pub(crate) fn anchor_at(&mut self, pt: Point) {
        self.reset_stroke();
        self.cursor = Some(pt);
        self.events.push(BehaviorEvent {
            timestamp_ms: self.timestamp_ms,
            dt_ms: 0.0,
            kind: EventKind::PointerMove,
            x: Some(pt.x),
            y: Some(pt.y),
            dx: Some(0.0),
            dy: Some(0.0),
            velocity_px_s: Some(0.0),
            acceleration_px_s2: Some(0.0),
            jerk_px_s3: Some(0.0),
            curvature_rad: Some(0.0),
            key: None,
            dwell_ms: None,
            scroll_dy: None,
        });
    }

    /// Records one pointer movement step to `to` after `dt_ms` milliseconds.
    pub(crate) fn push_move(&mut self, to: Point, dt_ms: f64) {
        let dt_ms = finite_non_neg(dt_ms);
        self.timestamp_ms += dt_ms;
        let prev = self.cursor.unwrap_or(to);
        let dx = to.x - prev.x;
        let dy = to.y - prev.y;
        let ds = dx.hypot(dy);
        let dt_s = dt_ms / 1000.0;

        let velocity = if dt_s > 1e-6 { ds / dt_s } else { 0.0 };

        let (accel, jerk, curvature) = if dt_s > 1e-6 && self.stroke_state.samples_in_stroke > 0 {
            let accel = self
                .stroke_state
                .prev_velocity
                .map_or(0.0, |v0| (velocity - v0) / dt_s);
            let jerk = self
                .stroke_state
                .prev_accel
                .map_or(0.0, |a0| (accel - a0) / dt_s);
            let curvature = self
                .stroke_state
                .prev_vec
                .map_or(0.0, |v0| turning_angle(v0, (dx, dy)));

            self.stroke_state.prev_accel = Some(accel);
            (accel, jerk, curvature)
        } else {
            (0.0, 0.0, 0.0)
        };

        if dt_s > 1e-6 {
            self.stroke_state.samples_in_stroke += 1;
            self.stroke_state.prev_velocity = Some(velocity);
            if ds > 1e-9 {
                self.stroke_state.prev_vec = Some((dx, dy));
            }
        }
        self.cursor = Some(to);

        self.events.push(BehaviorEvent {
            timestamp_ms: self.timestamp_ms,
            dt_ms,
            kind: EventKind::PointerMove,
            x: Some(to.x),
            y: Some(to.y),
            dx: Some(dx),
            dy: Some(dy),
            velocity_px_s: Some(velocity),
            acceleration_px_s2: Some(accel),
            jerk_px_s3: Some(jerk),
            curvature_rad: Some(curvature),
            key: None,
            dwell_ms: None,
            scroll_dy: None,
        });
    }

    pub(crate) fn push_click(&mut self, at: Point, settle_ms: f64, dwell_ms: f64) {
        self.reset_stroke();
        let settle_ms = finite_non_neg(settle_ms);
        let dwell_ms = finite_non_neg(dwell_ms);
        self.cursor = Some(at);

        self.timestamp_ms += settle_ms;
        self.events.push(BehaviorEvent {
            timestamp_ms: self.timestamp_ms,
            dt_ms: settle_ms,
            kind: EventKind::MouseDown,
            x: Some(at.x),
            y: Some(at.y),
            dx: None,
            dy: None,
            velocity_px_s: None,
            acceleration_px_s2: None,
            jerk_px_s3: None,
            curvature_rad: None,
            key: None,
            dwell_ms: None,
            scroll_dy: None,
        });

        self.timestamp_ms += dwell_ms;
        self.events.push(BehaviorEvent {
            timestamp_ms: self.timestamp_ms,
            dt_ms: dwell_ms,
            kind: EventKind::MouseUp,
            x: Some(at.x),
            y: Some(at.y),
            dx: None,
            dy: None,
            velocity_px_s: None,
            acceleration_px_s2: None,
            jerk_px_s3: None,
            curvature_rad: None,
            key: None,
            dwell_ms: Some(dwell_ms),
            scroll_dy: None,
        });
    }

    pub(crate) fn push_key(&mut self, key: String, dt_ms: f64, dwell_ms: f64) {
        self.reset_stroke();
        let dt_ms = finite_non_neg(dt_ms);
        let dwell_ms = finite_non_neg(dwell_ms);
        self.timestamp_ms += dt_ms;
        self.events.push(BehaviorEvent {
            timestamp_ms: self.timestamp_ms,
            dt_ms,
            kind: EventKind::KeyPress,
            x: None,
            y: None,
            dx: None,
            dy: None,
            velocity_px_s: None,
            acceleration_px_s2: None,
            jerk_px_s3: None,
            curvature_rad: None,
            key: Some(key),
            dwell_ms: Some(dwell_ms),
            scroll_dy: None,
        });
    }

    pub(crate) fn push_scroll(&mut self, dy: f64, dt_ms: f64) {
        self.reset_stroke();
        let dt_ms = finite_non_neg(dt_ms);
        self.timestamp_ms += dt_ms;
        let pos = self.cursor;
        self.events.push(BehaviorEvent {
            timestamp_ms: self.timestamp_ms,
            dt_ms,
            kind: EventKind::WheelScroll,
            x: pos.map(|p| p.x),
            y: pos.map(|p| p.y),
            dx: None,
            dy: None,
            velocity_px_s: None,
            acceleration_px_s2: None,
            jerk_px_s3: None,
            curvature_rad: None,
            key: None,
            dwell_ms: None,
            scroll_dy: Some(dy),
        });
    }

    pub(crate) fn push_pause(&mut self, duration_ms: f64) {
        self.reset_stroke();
        let duration_ms = finite_non_neg(duration_ms);
        if duration_ms <= 0.0 {
            return;
        }
        self.timestamp_ms += duration_ms;
        let pos = self.cursor;
        self.events.push(BehaviorEvent {
            timestamp_ms: self.timestamp_ms,
            dt_ms: duration_ms,
            kind: EventKind::Pause,
            x: pos.map(|p| p.x),
            y: pos.map(|p| p.y),
            dx: None,
            dy: None,
            velocity_px_s: None,
            acceleration_px_s2: None,
            jerk_px_s3: None,
            curvature_rad: None,
            key: None,
            dwell_ms: Some(duration_ms),
            scroll_dy: None,
        });
    }
}

fn finite_non_neg(value: f64) -> f64 {
    if value.is_finite() {
        value.max(0.0)
    } else {
        0.0
    }
}

/// Signed turning angle in `[-pi, pi]` between vectors `a` and `b`.
fn turning_angle(a: (f64, f64), b: (f64, f64)) -> f64 {
    let mag_a = a.0.hypot(a.1);
    let mag_b = b.0.hypot(b.1);
    if mag_a <= 1e-9 || mag_b <= 1e-9 {
        return 0.0;
    }
    let cross = a.0 * b.1 - a.1 * b.0;
    let dot = a.0 * b.0 + a.1 * b.1;
    cross.atan2(dot)
}

/// Reconstructs the final typed string across all keystroke events in `events`,
/// applying `"Backspace"` deletions and ignoring non-character control keys like `"Enter"`.
#[must_use]
pub fn reconstruct_typed_text(events: &[BehaviorEvent]) -> String {
    let mut out = String::new();
    for event in events {
        if event.kind != EventKind::KeyPress {
            continue;
        }
        let Some(key) = event.key.as_deref() else {
            continue;
        };
        if key == "Backspace" {
            out.pop();
        } else if key != "Enter" {
            out.push_str(key);
        }
    }
    out
}

/// Reconstructs per-field typed strings by splitting on clicks or `"Enter"` submissions.
#[must_use]
pub fn reconstruct_field_texts(events: &[BehaviorEvent]) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut has_typing = false;

    for event in events {
        match event.kind {
            EventKind::KeyPress => {
                let Some(key) = event.key.as_deref() else {
                    continue;
                };
                if key == "Enter" {
                    if has_typing {
                        fields.push(std::mem::take(&mut current));
                        has_typing = false;
                    }
                } else if key == "Backspace" {
                    current.pop();
                    has_typing = true;
                } else {
                    current.push_str(key);
                    has_typing = true;
                }
            }
            EventKind::MouseDown => {
                if has_typing {
                    fields.push(std::mem::take(&mut current));
                    has_typing = false;
                }
            }
            EventKind::PointerMove
            | EventKind::MouseUp
            | EventKind::WheelScroll
            | EventKind::Pause => {}
        }
    }
    if has_typing {
        fields.push(current);
    }
    fields
}

#[cfg(test)]
mod tests {
    use std::f64::consts::FRAC_PI_2;

    use super::*;

    #[test]
    fn turning_angle_measures_orthogonal_and_collinear_turns() {
        assert!((turning_angle((1.0, 0.0), (1.0, 0.0))).abs() < 1e-12);
        assert!((turning_angle((1.0, 0.0), (0.0, 1.0)) - FRAC_PI_2).abs() < 1e-12);
        assert!((turning_angle((1.0, 0.0), (0.0, -1.0)) + FRAC_PI_2).abs() < 1e-12);
        assert_eq!(turning_angle((0.0, 0.0), (1.0, 0.0)), 0.0);
    }

    #[test]
    fn reconstruction_handles_backspaces_beyond_empty_and_enter() {
        let mut tl = TimelineBuilder::new();
        tl.push_key("Backspace".into(), 50.0, 30.0);
        tl.push_key("a".into(), 50.0, 30.0);
        tl.push_key("x".into(), 50.0, 30.0);
        tl.push_key("Backspace".into(), 50.0, 30.0);
        tl.push_key("b".into(), 50.0, 30.0);
        tl.push_key("Enter".into(), 50.0, 30.0);
        tl.push_key("c".into(), 50.0, 30.0);
        let events = tl.finish();
        assert_eq!(reconstruct_typed_text(&events), "abc");
        assert_eq!(reconstruct_field_texts(&events), vec!["ab", "c"]);
    }
}
