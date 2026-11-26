//! Web interaction scenario simulation using core `Humanizer` and linear baselines.

use std::fmt;
use std::str::FromStr;

use seleniumbase_rs::sb_cdp::human::behavior::{Humanizer, KeyAction};
use seleniumbase_rs::sb_cdp::human::humanize::Rng;
use seleniumbase_rs::sb_cdp::{Point, Rect};
use serde::{Deserialize, Serialize};

use crate::error::{DatasetError, Result};
use crate::event::{BehaviorEvent, TimelineBuilder};
use crate::persona::PersonaProfile;

const SEARCH_QUERIES: [&str; 6] = [
    "ergonomic mechanical keyboard wireless",
    "rust async stream processing guide",
    "noise cancelling headphones review 2026",
    "best espresso grinder for pour over",
    "synthetic behavioral dataset generation",
    "modular standing desk cable tray",
];

const FULL_NAMES: [&str; 6] = [
    "Ada Lovelace",
    "Grace Hopper",
    "Alan Turing",
    "Margaret Hamilton",
    "Tim Berners-Lee",
    "Barbara Liskov",
];

const EMAILS: [&str; 6] = [
    "ada.lovelace@example.org",
    "grace.hopper@example.com",
    "alan.turing@example.net",
    "m.hamilton@example.io",
    "tim.bl@example.org",
    "b.liskov@example.com",
];

const DELIVERY_NOTES: [&str; 6] = [
    "Please leave the parcel by the side porch, and ring the bell once.",
    "Deliver after 2pm if possible. The gate code is 4829, thank you!",
    "Kindly handle with care; contact me by phone upon arrival.",
    "Leave at the reception desk, suite 304. No signature required.",
    "If nobody answers, please place it behind the planter by the steps.",
    "Morning delivery preferred! Please knock loudly on the front door.",
];

const PROMO_CODES: [&str; 5] = ["SAVE20", "WELCOME10", "SPRING26", "VIPDEAL", "FREESHIP"];

/// Simulated browser workflow classes.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ScenarioKind {
    /// Single Fitts's-law pointer approach from a resting position to a target button click.
    #[default]
    TargetApproachClick,
    /// Multi-field form fill with reaction pauses, typing cadence, typos, and submit click.
    FormEntry,
    /// Long-form reading pauses interleaved with eased scroll wheel notches.
    ArticleReadingScroll,
    /// Search bar focus, query typing, submit, scroll results, and result click.
    SearchAndBrowse,
    /// E-commerce add-to-cart, scroll, address/promo entry, and checkout click.
    CheckoutFlow,
}

impl ScenarioKind {
    /// All five supported interaction scenarios.
    pub const ALL: [Self; 5] = [
        Self::TargetApproachClick,
        Self::FormEntry,
        Self::ArticleReadingScroll,
        Self::SearchAndBrowse,
        Self::CheckoutFlow,
    ];

    /// Canonical snake_case identifier for this scenario.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TargetApproachClick => "target_approach_click",
            Self::FormEntry => "form_entry",
            Self::ArticleReadingScroll => "article_reading_scroll",
            Self::SearchAndBrowse => "search_and_browse",
            Self::CheckoutFlow => "checkout_flow",
        }
    }
}

impl fmt::Display for ScenarioKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ScenarioKind {
    type Err = DatasetError;

    fn from_str(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "target_approach_click" | "targetapproachclick" => Ok(Self::TargetApproachClick),
            "form_entry" | "formentry" => Ok(Self::FormEntry),
            "article_reading_scroll" | "articlereadingscroll" => Ok(Self::ArticleReadingScroll),
            "search_and_browse" | "searchandbrowse" => Ok(Self::SearchAndBrowse),
            "checkout_flow" | "checkoutflow" => Ok(Self::CheckoutFlow),
            _ => Err(DatasetError::Parse {
                kind: "ScenarioKind",
                value: s.to_owned(),
            }),
        }
    }
}

/// Result of simulating one behavioral scenario episode.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScenarioOutput {
    /// Ordered event timeline.
    pub events: Vec<BehaviorEvent>,
    /// Target element widths in CSS pixels for each pointer movement stroke.
    pub stroke_target_widths: Vec<f64>,
    /// Ground-truth texts intended for typed fields in this episode.
    pub expected_texts: Vec<String>,
    /// Total elapsed duration of the timeline in milliseconds.
    pub total_duration_ms: f64,
}

enum PlanStep {
    MoveAndClick { target: Rect },
    MoveHover { target: Rect },
    Type { text: String, submit_enter: bool },
    Scroll { dy: f64 },
    Read { words: f64 },
}

struct ScenarioPlan {
    start: Point,
    steps: Vec<PlanStep>,
}

fn rect_in_viewport(vw: f64, vh: f64, rx: f64, ry: f64, rw: f64, rh: f64) -> Rect {
    let width = (vw * rw).clamp(24.0, (vw - 32.0).max(24.0));
    let height = (vh * rh).clamp(20.0, (vh - 32.0).max(20.0));
    let x = (vw * rx).clamp(16.0, (vw - width - 16.0).max(16.0));
    let y = (vh * ry).clamp(16.0, (vh - height - 16.0).max(16.0));
    Rect {
        x,
        y,
        width,
        height,
    }
}

fn build_plan(scenario: ScenarioKind, viewport: (f64, f64), seed: u64) -> ScenarioPlan {
    let mut rng = Rng::new(seed ^ 0xA24B_AED4_963E_E407);
    let (vw, vh) = (viewport.0.max(320.0), viewport.1.max(480.0));

    match scenario {
        ScenarioKind::TargetApproachClick => {
            let left_to_right = rng.chance(0.5);
            let start_x = if left_to_right {
                vw * rng.range(0.10, 0.28)
            } else {
                vw * rng.range(0.72, 0.90)
            };
            let start = Point::new(start_x, vh * rng.range(0.20, 0.80));
            let target_rx = if left_to_right {
                rng.range(0.58, 0.82)
            } else {
                rng.range(0.08, 0.30)
            };
            let target = rect_in_viewport(
                vw,
                vh,
                target_rx,
                rng.range(0.18, 0.76),
                rng.range(0.08, 0.16),
                rng.range(0.05, 0.08),
            );
            ScenarioPlan {
                start,
                steps: vec![PlanStep::MoveAndClick { target }],
            }
        }
        ScenarioKind::FormEntry => {
            let start = Point::new(vw * rng.range(0.20, 0.80), vh * rng.range(0.10, 0.25));
            let name = (*rng.pick(&FULL_NAMES)).to_owned();
            let email = (*rng.pick(&EMAILS)).to_owned();
            let note = (*rng.pick(&DELIVERY_NOTES)).to_owned();

            let f1 = rect_in_viewport(vw, vh, 0.22, 0.24, 0.50, 0.055);
            let f2 = rect_in_viewport(vw, vh, 0.22, 0.36, 0.50, 0.055);
            let f3 = rect_in_viewport(vw, vh, 0.22, 0.49, 0.52, 0.13);
            let submit = rect_in_viewport(vw, vh, 0.36, 0.70, 0.22, 0.06);

            ScenarioPlan {
                start,
                steps: vec![
                    PlanStep::MoveAndClick { target: f1 },
                    PlanStep::Type {
                        text: name,
                        submit_enter: false,
                    },
                    PlanStep::MoveAndClick { target: f2 },
                    PlanStep::Type {
                        text: email,
                        submit_enter: false,
                    },
                    PlanStep::MoveAndClick { target: f3 },
                    PlanStep::Type {
                        text: note,
                        submit_enter: false,
                    },
                    PlanStep::MoveAndClick { target: submit },
                ],
            }
        }
        ScenarioKind::ArticleReadingScroll => {
            let start = Point::new(vw * rng.range(0.35, 0.65), vh * rng.range(0.25, 0.45));
            let chunks = if rng.chance(0.5) { 4 } else { 5 };
            let mut steps = vec![PlanStep::MoveHover {
                target: rect_in_viewport(vw, vh, 0.30, 0.35, 0.40, 0.20),
            }];
            for idx in 0..chunks {
                steps.push(PlanStep::Read {
                    words: rng.range(24.0, 62.0),
                });
                let down = rng.range(360.0, 760.0);
                steps.push(PlanStep::Scroll { dy: down });
                if idx == 1 && rng.chance(0.4) {
                    steps.push(PlanStep::Scroll {
                        dy: -rng.range(120.0, 220.0),
                    });
                }
            }
            steps.push(PlanStep::Read {
                words: rng.range(16.0, 35.0),
            });
            ScenarioPlan { start, steps }
        }
        ScenarioKind::SearchAndBrowse => {
            let start = Point::new(vw * rng.range(0.15, 0.85), vh * rng.range(0.40, 0.80));
            let query = (*rng.pick(&SEARCH_QUERIES)).to_owned();
            let search_box = rect_in_viewport(vw, vh, 0.20, 0.14, 0.56, 0.06);
            let result_card = rect_in_viewport(
                vw,
                vh,
                0.18,
                rng.range(0.36, 0.66),
                0.55,
                rng.range(0.08, 0.12),
            );
            ScenarioPlan {
                start,
                steps: vec![
                    PlanStep::MoveAndClick { target: search_box },
                    PlanStep::Type {
                        text: query,
                        submit_enter: true,
                    },
                    PlanStep::Read {
                        words: rng.range(12.0, 24.0),
                    },
                    PlanStep::Scroll {
                        dy: rng.range(320.0, 680.0),
                    },
                    PlanStep::MoveAndClick {
                        target: result_card,
                    },
                    PlanStep::Read {
                        words: rng.range(18.0, 42.0),
                    },
                ],
            }
        }
        ScenarioKind::CheckoutFlow => {
            let start = Point::new(vw * rng.range(0.12, 0.45), vh * rng.range(0.20, 0.45));
            let add_cart = rect_in_viewport(vw, vh, 0.60, 0.34, 0.24, 0.065);
            let promo_field = rect_in_viewport(vw, vh, 0.22, 0.44, 0.35, 0.055);
            let note_field = rect_in_viewport(vw, vh, 0.22, 0.56, 0.48, 0.08);
            let place_order = rect_in_viewport(vw, vh, 0.56, 0.74, 0.26, 0.07);
            let promo = (*rng.pick(&PROMO_CODES)).to_owned();
            let note = (*rng.pick(&DELIVERY_NOTES)).to_owned();

            ScenarioPlan {
                start,
                steps: vec![
                    PlanStep::MoveAndClick { target: add_cart },
                    PlanStep::Read {
                        words: rng.range(8.0, 18.0),
                    },
                    PlanStep::Scroll {
                        dy: rng.range(280.0, 520.0),
                    },
                    PlanStep::MoveAndClick {
                        target: promo_field,
                    },
                    PlanStep::Type {
                        text: promo,
                        submit_enter: false,
                    },
                    PlanStep::MoveAndClick { target: note_field },
                    PlanStep::Type {
                        text: note,
                        submit_enter: false,
                    },
                    PlanStep::MoveAndClick {
                        target: place_order,
                    },
                ],
            }
        }
    }
}

/// Simulates a single human pointer approach and click using `profile` and core `Humanizer`.
///
/// # Errors
///
/// Returns [`DatasetError::InvalidBehavior`] if `profile` parameters fail validation.
pub fn simulate_target_approach(
    profile: &PersonaProfile,
    from: Point,
    target: Rect,
) -> Result<ScenarioOutput> {
    let mut humanizer = profile.humanizer()?;
    let mut rng = Rng::new(profile.seed ^ 0xD1B5_4A32_D192_ED03);
    let mut timeline = TimelineBuilder::new();
    let mut target_widths = Vec::new();

    timeline.anchor_at(from);
    emit_human_move(
        &mut humanizer,
        profile,
        &mut rng,
        &mut timeline,
        &mut target_widths,
        target,
        true,
    );

    let total_duration_ms = timeline.timestamp_ms();
    Ok(ScenarioOutput {
        events: timeline.finish(),
        stroke_target_widths: target_widths,
        expected_texts: Vec::new(),
        total_duration_ms,
    })
}

/// Simulates a linear constant-speed pointer approach and click (bot baseline).
#[must_use]
pub fn simulate_linear_target_approach(
    from: Point,
    target: Rect,
    speed_px_s: f64,
) -> ScenarioOutput {
    let mut timeline = TimelineBuilder::new();
    let mut target_widths = Vec::new();
    timeline.anchor_at(from);
    emit_linear_move(&mut timeline, &mut target_widths, target, speed_px_s, true);
    let total_duration_ms = timeline.timestamp_ms();
    ScenarioOutput {
        events: timeline.finish(),
        stroke_target_widths: target_widths,
        expected_texts: Vec::new(),
        total_duration_ms,
    }
}

/// Simulates a complete human interaction scenario using `profile` and core `Humanizer`.
///
/// # Errors
///
/// Returns [`DatasetError::InvalidBehavior`] if `profile` parameters fail validation.
pub fn simulate_scenario(
    profile: &PersonaProfile,
    scenario: ScenarioKind,
    seed: u64,
) -> Result<ScenarioOutput> {
    let plan = build_plan(scenario, profile.viewport(), seed);
    let mut humanizer = profile.humanizer()?;
    let mut rng = Rng::new(seed ^ 0x94D0_49BB_1331_11EB);
    let mut timeline = TimelineBuilder::new();
    let mut target_widths = Vec::new();
    let mut expected_texts = Vec::new();

    timeline.anchor_at(plan.start);

    for step in plan.steps {
        if rng.chance(profile.distraction_prob * 0.45) {
            let pause = rng.gaussian(900.0, 260.0).clamp(350.0, 2400.0);
            timeline.push_pause(pause);
        }

        match step {
            PlanStep::MoveAndClick { target } => {
                emit_human_move(
                    &mut humanizer,
                    profile,
                    &mut rng,
                    &mut timeline,
                    &mut target_widths,
                    target,
                    true,
                );
            }
            PlanStep::MoveHover { target } => {
                emit_human_move(
                    &mut humanizer,
                    profile,
                    &mut rng,
                    &mut timeline,
                    &mut target_widths,
                    target,
                    false,
                );
            }
            PlanStep::Type { text, submit_enter } => {
                expected_texts.push(text.clone());
                let reaction_ms =
                    humanizer.reaction().as_secs_f64() * 1000.0 * profile.reaction_scale;
                timeline.push_pause(reaction_ms);

                for keystroke in humanizer.typing_plan(&text) {
                    let wait_ms = keystroke.wait.as_secs_f64() * 1000.0;
                    let dwell_ms =
                        rng.gaussian(82.0, 22.0).clamp(28.0, 180.0) * profile.dwell_scale;
                    let label = match keystroke.action {
                        KeyAction::Type(ch) => ch.to_string(),
                        KeyAction::Backspace => "Backspace".to_owned(),
                        _ => String::new(),
                    };
                    if !label.is_empty() {
                        timeline.push_key(label, wait_ms, dwell_ms);
                    }
                }
                if submit_enter {
                    let enter_wait = rng.gaussian(190.0, 55.0).clamp(80.0, 420.0);
                    let enter_dwell = rng.gaussian(75.0, 18.0).clamp(30.0, 150.0);
                    timeline.push_key("Enter".to_owned(), enter_wait, enter_dwell);
                }
            }
            PlanStep::Scroll { dy } => {
                let pace = profile.scroll_pace.max(0.2);
                for notch in humanizer.scroll_plan(dy) {
                    let wait_ms = notch.wait.as_secs_f64() * 1000.0 / pace;
                    timeline.push_scroll(notch.dy, wait_ms);
                }
            }
            PlanStep::Read { words } => {
                let wpm = profile.reading_wpm.max(40.0);
                let base_ms = (words / wpm) * 60_000.0;
                let jitter = rng.range(0.75, 1.30);
                timeline.push_pause((base_ms * jitter).clamp(300.0, 5000.0));
            }
        }
    }

    let total_duration_ms = timeline.timestamp_ms();
    Ok(ScenarioOutput {
        events: timeline.finish(),
        stroke_target_widths: target_widths,
        expected_texts,
        total_duration_ms,
    })
}

/// Simulates the synthetic linear constant-speed baseline for `scenario` (negative class).
#[must_use]
pub fn simulate_linear_baseline(
    scenario: ScenarioKind,
    viewport: (f64, f64),
    seed: u64,
) -> ScenarioOutput {
    let plan = build_plan(scenario, viewport, seed);
    let mut timeline = TimelineBuilder::new();
    let mut target_widths = Vec::new();
    let mut expected_texts = Vec::new();

    timeline.anchor_at(plan.start);

    for step in plan.steps {
        match step {
            PlanStep::MoveAndClick { target } => {
                emit_linear_move(&mut timeline, &mut target_widths, target, 750.0, true);
            }
            PlanStep::MoveHover { target } => {
                emit_linear_move(&mut timeline, &mut target_widths, target, 750.0, false);
            }
            PlanStep::Type { text, submit_enter } => {
                expected_texts.push(text.clone());
                timeline.push_pause(100.0);
                for ch in text.chars() {
                    timeline.push_key(ch.to_string(), 110.0, 40.0);
                }
                if submit_enter {
                    timeline.push_key("Enter".to_owned(), 110.0, 40.0);
                }
            }
            PlanStep::Scroll { dy } => {
                let total = dy.abs();
                let sign = dy.signum();
                let mut done = 0.0;
                while done < total {
                    let step_dy = (total - done).min(100.0);
                    done += step_dy;
                    timeline.push_scroll(sign * step_dy, 50.0);
                }
            }
            PlanStep::Read { words } => {
                let fixed_ms = (words * 12.0).clamp(250.0, 1200.0);
                timeline.push_pause(fixed_ms);
            }
        }
    }

    let total_duration_ms = timeline.timestamp_ms();
    ScenarioOutput {
        events: timeline.finish(),
        stroke_target_widths: target_widths,
        expected_texts,
        total_duration_ms,
    }
}

fn emit_human_move(
    humanizer: &mut Humanizer,
    profile: &PersonaProfile,
    rng: &mut Rng,
    timeline: &mut TimelineBuilder,
    target_widths: &mut Vec<f64>,
    target: Rect,
    click: bool,
) {
    let from = timeline
        .cursor()
        .unwrap_or_else(|| Point::new(target.x, target.y));
    let to = humanizer.target_point(target);
    let path = humanizer.mouse_path(from, to, target.width);
    for step in path {
        timeline.push_move(step.at, step.wait.as_secs_f64() * 1000.0);
    }
    target_widths.push(target.width.max(4.0));
    if click {
        let settle_ms = rng.range(8.0, 35.0) * profile.dwell_scale;
        let dwell_ms = humanizer.click_dwell().as_secs_f64() * 1000.0 * profile.dwell_scale;
        timeline.push_click(to, settle_ms, dwell_ms);
    } else {
        timeline.reset_stroke();
    }
}

fn emit_linear_move(
    timeline: &mut TimelineBuilder,
    target_widths: &mut Vec<f64>,
    target: Rect,
    speed_px_s: f64,
    click: bool,
) {
    let center = Point::new(
        target.x + target.width * 0.5,
        target.y + target.height * 0.5,
    );
    let from = timeline.cursor().unwrap_or(center);
    let distance = (center.x - from.x).hypot(center.y - from.y);
    target_widths.push(target.width.max(4.0));

    if distance < 1.0 {
        timeline.push_move(center, 0.0);
    } else {
        let speed = speed_px_s.max(50.0);
        let total_ms = (distance / speed) * 1000.0;
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let count = ((total_ms / 12.0).ceil() as usize).max(2);
        #[allow(clippy::cast_precision_loss)]
        let dt_ms = total_ms / count as f64;

        for idx in 1..=count {
            #[allow(clippy::cast_precision_loss)]
            let t = idx as f64 / count as f64;
            let pt = Point::new(
                from.x + (center.x - from.x) * t,
                from.y + (center.y - from.y) * t,
            );
            timeline.push_move(pt, dt_ms);
        }
    }

    if click {
        timeline.push_click(center, 10.0, 50.0);
    } else {
        timeline.reset_stroke();
    }
}
