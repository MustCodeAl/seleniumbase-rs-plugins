//! Behavioral persona archetypes and continuous seeded parameter sampling.

use std::fmt;
use std::str::FromStr;

use seleniumbase_rs::sb_cdp::human::behavior::{Behavior, Humanizer};
use seleniumbase_rs::sb_cdp::human::humanize::Rng;
use serde::{Deserialize, Serialize};

use crate::error::{DatasetError, Result};

/// Archetypal human browsing persona classes.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PersonaKind {
    /// Rapid touch-typist with quick pointer navigation and low dwell times.
    FastTypist,
    /// Typical desktop mouse-and-keyboard user.
    #[default]
    AverageDesktop,
    /// Deliberate reader with slower scroll cadence, low typo rate, and longer pauses.
    CarefulReader,
    /// Laptop trackpad user with slightly slower pointer speed and more overshoot.
    TrackpadUser,
    /// Mobile touchscreen user with narrow viewport, thumb typing, and quick taps.
    MobileTouch,
    /// Multitasking browser user with high typing variability and frequent distractions.
    DistractedBrowser,
}

impl PersonaKind {
    /// All six supported human persona archetypes.
    pub const ALL: [Self; 6] = [
        Self::FastTypist,
        Self::AverageDesktop,
        Self::CarefulReader,
        Self::TrackpadUser,
        Self::MobileTouch,
        Self::DistractedBrowser,
    ];

    /// Canonical snake_case identifier for this persona.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FastTypist => "fast_typist",
            Self::AverageDesktop => "average_desktop",
            Self::CarefulReader => "careful_reader",
            Self::TrackpadUser => "trackpad_user",
            Self::MobileTouch => "mobile_touch",
            Self::DistractedBrowser => "distracted_browser",
        }
    }
}

impl fmt::Display for PersonaKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for PersonaKind {
    type Err = DatasetError;

    fn from_str(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "fast_typist" | "fasttypist" => Ok(Self::FastTypist),
            "average_desktop" | "averagedesktop" => Ok(Self::AverageDesktop),
            "careful_reader" | "carefulreader" => Ok(Self::CarefulReader),
            "trackpad_user" | "trackpaduser" => Ok(Self::TrackpadUser),
            "mobile_touch" | "mobiletouch" => Ok(Self::MobileTouch),
            "distracted_browser" | "distractedbrowser" => Ok(Self::DistractedBrowser),
            _ => Err(DatasetError::Parse {
                kind: "PersonaKind",
                value: s.to_owned(),
            }),
        }
    }
}

/// Parameter ranges for continuous persona sampling.
struct PersonaBounds {
    wpm: (f64, f64),
    variability: (f64, f64),
    typo_rate: (f64, f64),
    pointer_speed: (f64, f64),
    overshoot: (f64, f64),
    dwell_scale: (f64, f64),
    scroll_pace: (f64, f64),
    reading_wpm: (f64, f64),
    reaction_scale: (f64, f64),
    distraction_prob: (f64, f64),
    viewport_w: (f64, f64),
    viewport_h: (f64, f64),
    is_touch: bool,
}

impl PersonaKind {
    const fn bounds(self) -> PersonaBounds {
        match self {
            Self::FastTypist => PersonaBounds {
                wpm: (85.0, 130.0),
                variability: (0.18, 0.32),
                typo_rate: (0.015, 0.045),
                pointer_speed: (1.20, 1.75),
                overshoot: (0.12, 0.30),
                dwell_scale: (0.65, 0.95),
                scroll_pace: (1.10, 1.50),
                reading_wpm: (240.0, 340.0),
                reaction_scale: (0.65, 0.95),
                distraction_prob: (0.01, 0.05),
                viewport_w: (1440.0, 1920.0),
                viewport_h: (900.0, 1080.0),
                is_touch: false,
            },
            Self::AverageDesktop => PersonaBounds {
                wpm: (45.0, 70.0),
                variability: (0.28, 0.45),
                typo_rate: (0.02, 0.06),
                pointer_speed: (0.85, 1.25),
                overshoot: (0.15, 0.35),
                dwell_scale: (0.85, 1.15),
                scroll_pace: (0.85, 1.15),
                reading_wpm: (180.0, 260.0),
                reaction_scale: (0.85, 1.20),
                distraction_prob: (0.03, 0.10),
                viewport_w: (1280.0, 1920.0),
                viewport_h: (720.0, 1080.0),
                is_touch: false,
            },
            Self::CarefulReader => PersonaBounds {
                wpm: (28.0, 48.0),
                variability: (0.25, 0.42),
                typo_rate: (0.005, 0.025),
                pointer_speed: (0.65, 0.95),
                overshoot: (0.05, 0.18),
                dwell_scale: (1.10, 1.50),
                scroll_pace: (0.55, 0.85),
                reading_wpm: (120.0, 185.0),
                reaction_scale: (1.20, 1.75),
                distraction_prob: (0.04, 0.12),
                viewport_w: (1280.0, 1680.0),
                viewport_h: (800.0, 1050.0),
                is_touch: false,
            },
            Self::TrackpadUser => PersonaBounds {
                wpm: (50.0, 78.0),
                variability: (0.26, 0.42),
                typo_rate: (0.02, 0.055),
                pointer_speed: (0.70, 1.05),
                overshoot: (0.22, 0.45),
                dwell_scale: (0.90, 1.25),
                scroll_pace: (0.90, 1.35),
                reading_wpm: (190.0, 270.0),
                reaction_scale: (0.90, 1.25),
                distraction_prob: (0.03, 0.10),
                viewport_w: (1280.0, 1512.0),
                viewport_h: (800.0, 982.0),
                is_touch: false,
            },
            Self::MobileTouch => PersonaBounds {
                wpm: (22.0, 42.0),
                variability: (0.35, 0.58),
                typo_rate: (0.04, 0.10),
                pointer_speed: (1.30, 2.10),
                overshoot: (0.02, 0.10),
                dwell_scale: (0.70, 1.10),
                scroll_pace: (1.00, 1.60),
                reading_wpm: (160.0, 240.0),
                reaction_scale: (0.95, 1.40),
                distraction_prob: (0.05, 0.15),
                viewport_w: (375.0, 430.0),
                viewport_h: (667.0, 932.0),
                is_touch: true,
            },
            Self::DistractedBrowser => PersonaBounds {
                wpm: (32.0, 65.0),
                variability: (0.48, 0.85),
                typo_rate: (0.04, 0.12),
                pointer_speed: (0.60, 1.35),
                overshoot: (0.25, 0.55),
                dwell_scale: (1.15, 1.85),
                scroll_pace: (0.70, 1.50),
                reading_wpm: (140.0, 230.0),
                reaction_scale: (1.30, 2.40),
                distraction_prob: (0.18, 0.40),
                viewport_w: (1280.0, 1920.0),
                viewport_h: (720.0, 1080.0),
                is_touch: false,
            },
        }
    }
}

/// Continuously sampled behavioral parameters for one simulated user session.
///
/// Converts directly into core [`Behavior`] and [`Humanizer`] instances while
/// retaining dwell, scroll cadence, reading speed, and viewport traits.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PersonaProfile {
    /// Archetype this profile was sampled from.
    pub kind: PersonaKind,
    /// Seed used for both profile sampling and downstream [`Humanizer`] calls.
    pub seed: u64,
    /// Typing speed in words per minute (five characters per word).
    pub typing_wpm: f64,
    /// Relative standard deviation of inter-key intervals.
    pub typing_variability: f64,
    /// Probability per alphabetic letter of a corrected typo.
    pub typo_rate: f64,
    /// Pointer movement speed multiplier relative to baseline.
    pub pointer_speed: f64,
    /// Probability that long pointer moves overshoot and correct.
    pub overshoot: f64,
    /// Multiplier applied to click and key press dwell times.
    pub dwell_scale: f64,
    /// Multiplier applied to scroll wheel notch cadence (`> 1` scrolls faster).
    pub scroll_pace: f64,
    /// Reading speed in words per minute during article reading pauses.
    pub reading_wpm: f64,
    /// Multiplier applied to inter-action reaction delays.
    pub reaction_scale: f64,
    /// Probability of inserting a longer distraction pause between sub-tasks.
    pub distraction_prob: f64,
    /// Simulated viewport width in CSS pixels.
    pub viewport_width: f64,
    /// Simulated viewport height in CSS pixels.
    pub viewport_height: f64,
    /// Whether this profile models a touch-screen device.
    pub is_touch: bool,
}

impl PersonaProfile {
    /// Deterministically samples a continuous profile for `kind` from `seed`.
    #[must_use]
    pub fn sample(kind: PersonaKind, seed: u64) -> Self {
        let mut rng = Rng::new(seed ^ 0x517C_C1B7_2722_0A95);
        Self::sample_with_rng(kind, seed, &mut rng)
    }

    /// Samples a continuous profile using `rng` while recording `seed` on the profile.
    #[must_use]
    pub fn sample_with_rng(kind: PersonaKind, seed: u64, rng: &mut Rng) -> Self {
        let b = kind.bounds();
        // Truncated normal centered in each persona band keeps samples realistic
        // while still exhibiting continuous diversity across seeds.
        let sample_band = |rng: &mut Rng, (lo, hi): (f64, f64)| -> f64 {
            let mid = (lo + hi) * 0.5;
            let sigma = (hi - lo) * 0.28;
            rng.gaussian(mid, sigma).clamp(lo, hi)
        };

        Self {
            kind,
            seed,
            typing_wpm: sample_band(rng, b.wpm).clamp(5.0, 400.0),
            typing_variability: sample_band(rng, b.variability).clamp(0.0, 1.5),
            typo_rate: sample_band(rng, b.typo_rate).clamp(0.0, 0.2),
            pointer_speed: sample_band(rng, b.pointer_speed).clamp(0.1, 5.0),
            overshoot: sample_band(rng, b.overshoot).clamp(0.0, 1.0),
            dwell_scale: sample_band(rng, b.dwell_scale),
            scroll_pace: sample_band(rng, b.scroll_pace),
            reading_wpm: sample_band(rng, b.reading_wpm),
            reaction_scale: sample_band(rng, b.reaction_scale),
            distraction_prob: sample_band(rng, b.distraction_prob).clamp(0.0, 1.0),
            viewport_width: rng.range(b.viewport_w.0, b.viewport_w.1).round(),
            viewport_height: rng.range(b.viewport_h.0, b.viewport_h.1).round(),
            is_touch: b.is_touch,
        }
    }

    /// Derives a core [`Behavior`] from this profile's motor and typing parameters.
    ///
    /// # Errors
    ///
    /// Returns [`DatasetError::InvalidBehavior`] if any numeric parameter falls
    /// outside [`BehaviorBuilder`](seleniumbase_rs::sb_cdp::human::behavior::BehaviorBuilder)'s bounds.
    pub fn to_behavior(&self) -> Result<Behavior> {
        let behavior = Behavior::builder()
            .typing_wpm(self.typing_wpm)
            .typing_variability(self.typing_variability)
            .typo_rate(self.typo_rate)
            .pointer_speed(self.pointer_speed)
            .overshoot(self.overshoot)
            .seed(self.seed)
            .build()?;
        Ok(behavior)
    }

    /// Creates a core [`Humanizer`] configured from this profile.
    ///
    /// # Errors
    ///
    /// Returns [`DatasetError::InvalidBehavior`] if [`Self::to_behavior`] fails validation.
    pub fn humanizer(&self) -> Result<Humanizer> {
        Ok(Humanizer::new(self.to_behavior()?))
    }

    /// Viewport dimensions `(width, height)` in CSS pixels.
    #[must_use]
    pub const fn viewport(&self) -> (f64, f64) {
        (self.viewport_width, self.viewport_height)
    }
}
