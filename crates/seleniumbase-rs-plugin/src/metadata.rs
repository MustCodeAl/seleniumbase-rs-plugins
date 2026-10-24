//! Declarative plugin metadata: category, phase, capabilities, ordering edges, seals.

use std::borrow::Cow;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::capability::{Capability, CapabilitySet};

/// What kind of job a plugin does.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum Category {
    /// Presets, runtime, switches, proxies, headless.
    Environment,
    /// Assertions, lifecycle, reporters, recording fakes.
    Testing,
    /// Extensions and their workers.
    Extension,
    /// Interception, network logging, resource blocking.
    Core,
    /// Hardening, telemetry, WebRTC, cookie isolation.
    Privacy,
}

impl Category {
    /// The phase plugins of this category run in unless they say otherwise.
    #[must_use]
    pub fn default_phase(self) -> Phase {
        match self {
            Self::Environment => Phase::Prepare,
            Self::Extension | Self::Core => Phase::Normal,
            Self::Privacy => Phase::Enforce,
            Self::Testing => Phase::Observe,
        }
    }
}

/// When, relative to other plugins, a plugin runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Phase {
    /// First: set the environment up.
    Prepare,
    /// The default.
    Normal,
    /// After the others, so a privacy plugin has the last word.
    Enforce,
    /// Only watches the result.
    Observe,
    /// Last.
    Last,
}

/// The scalar launch fields a plugin may seal against later change.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Seals(u8);

impl Seals {
    /// The proxy.
    pub const PROXY: Self = Self(1);
    /// The proxy of new contexts.
    pub const CONTEXT_PROXY: Self = Self(1 << 1);
    /// The WebRTC policy.
    pub const WEBRTC: Self = Self(1 << 2);
    /// Headless mode.
    pub const HEADLESS: Self = Self(1 << 3);
    /// The one plugin that answers requests.
    pub const FULFILL: Self = Self(1 << 4);

    /// No seals.
    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Whether every seal of `other` is set.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl std::ops::BitOr for Seals {
    type Output = Self;

    fn bitor(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// Time limits a plugin asks for, per hook. A set that has a timer gives each hook the limit here, or [`Budgets::default_for`] when the field is `None`, and raises no limit above [`Budgets::MAX_FACTOR`] times that default. A set without a timer applies none of them.
///
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Budgets {
    /// For `before_launch`.
    pub before_launch: Option<Duration>,
    /// For `on_page_created`.
    pub on_page_created: Option<Duration>,
    /// For `before_navigate`.
    pub before_navigate: Option<Duration>,
    /// For `on_request`.
    pub on_request: Option<Duration>,
    /// For `on_test_end`.
    pub on_test_end: Option<Duration>,
    /// For `before_close`.
    pub before_close: Option<Duration>,
    /// For `on_close`.
    pub on_close: Option<Duration>,
    /// For every hook not named above.
    pub other: Option<Duration>,
}

impl Budgets {
    /// A plugin's request is raised no higher than this many times the default
    /// limit of the hook.
    pub const MAX_FACTOR: u32 = 4;

    /// The limit a set gives `hook` when the plugin asks for nothing:
    /// `before_launch` and `on_test_end` 30 s, `before_navigate` 5 s,
    /// `on_request` 2 s, every other hook 10 s.
    #[must_use]
    pub fn default_for(hook: &str) -> Duration {
        Duration::from_secs(match hook {
            "before_launch" | "on_test_end" => 30,
            "before_navigate" => 5,
            "on_request" => 2,
            _ => 10,
        })
    }

    /// The limit for `hook`: what the plugin asked for (zero counts as not
    /// asking), at most [`MAX_FACTOR`](Self::MAX_FACTOR) times the default,
    /// else the default.
    #[must_use]
    pub fn limit_for(&self, hook: &str) -> Duration {
        let requested = match hook {
            "before_launch" => self.before_launch,
            "on_page_created" => self.on_page_created,
            "before_navigate" => self.before_navigate,
            "on_request" => self.on_request,
            "on_test_end" => self.on_test_end,
            "before_close" => self.before_close,
            "on_close" => self.on_close,
            _ => self.other,
        };
        let default = Self::default_for(hook);
        requested
            .filter(|asked| !asked.is_zero())
            .map_or(default, |asked| asked.min(default * Self::MAX_FACTOR))
    }
}

/// What a plugin declares about itself.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Metadata {
    /// `None` for a legacy plugin.
    pub category: Option<Category>,
    /// The plugin's version.
    pub version: Cow<'static, str>,
    /// One line about what it does.
    pub summary: Cow<'static, str>,
    /// What it needs.
    pub capabilities: CapabilitySet,
    /// What it uses when granted.
    pub optional: CapabilitySet,
    /// Plugins that must be in the set and run before it.
    pub requires: Vec<Cow<'static, str>>,
    /// Plugins that may not be in the set.
    pub conflicts: Vec<Cow<'static, str>>,
    /// Plugins it runs after, when they are present.
    pub after: Vec<Cow<'static, str>>,
    /// Plugins it runs before, when they are present.
    pub before: Vec<Cow<'static, str>>,
    /// `None`: from the category.
    pub phase: Option<Phase>,
    /// Scalar fields it seals.
    pub seals: Seals,
    /// Time limits.
    pub budgets: Budgets,
}

impl Metadata {
    /// A declared plugin of `category`.
    #[must_use]
    pub fn new(category: Category) -> Self {
        Self {
            category: Some(category),
            version: Cow::Borrowed(""),
            summary: Cow::Borrowed(""),
            capabilities: CapabilitySet::new(),
            optional: CapabilitySet::new(),
            requires: Vec::new(),
            conflicts: Vec::new(),
            after: Vec::new(),
            before: Vec::new(),
            phase: None,
            seals: Seals::empty(),
            budgets: Budgets::default(),
        }
    }

    /// An undeclared plugin: the legacy capability set and no category.
    #[must_use]
    pub fn legacy() -> Self {
        let mut meta = Self::new(Category::Core);
        meta.category = None;
        meta.capabilities = CapabilitySet::legacy();
        meta
    }

    /// Whether the plugin declared its metadata.
    #[must_use]
    pub fn is_declared(&self) -> bool {
        self.category.is_some()
    }

    /// Sets the version.
    #[must_use]
    pub fn version(mut self, version: impl Into<Cow<'static, str>>) -> Self {
        self.version = version.into();
        self
    }

    /// Sets the summary.
    #[must_use]
    pub fn summary(mut self, summary: impl Into<Cow<'static, str>>) -> Self {
        self.summary = summary.into();
        self
    }

    /// Requires a capability.
    #[must_use]
    pub fn capability(mut self, capability: Capability) -> Self {
        self.capabilities.insert(capability);
        self
    }

    /// Requires several capabilities.
    #[must_use]
    pub fn capabilities(mut self, capabilities: impl IntoIterator<Item = Capability>) -> Self {
        for capability in capabilities {
            self.capabilities.insert(capability);
        }
        self
    }

    /// Uses a capability if granted.
    #[must_use]
    pub fn optional(mut self, capability: Capability) -> Self {
        self.optional.insert(capability);
        self
    }

    /// Requires a plugin.
    #[must_use]
    pub fn requires(mut self, name: impl Into<Cow<'static, str>>) -> Self {
        self.requires.push(name.into());
        self
    }

    /// Cannot be combined with a plugin.
    #[must_use]
    pub fn conflicts_with(mut self, name: impl Into<Cow<'static, str>>) -> Self {
        self.conflicts.push(name.into());
        self
    }

    /// Runs after a plugin.
    #[must_use]
    pub fn after(mut self, name: impl Into<Cow<'static, str>>) -> Self {
        self.after.push(name.into());
        self
    }

    /// Runs before a plugin.
    #[must_use]
    pub fn before(mut self, name: impl Into<Cow<'static, str>>) -> Self {
        self.before.push(name.into());
        self
    }

    /// Sets the phase.
    #[must_use]
    pub fn phase(mut self, phase: Phase) -> Self {
        self.phase = Some(phase);
        self
    }

    /// Seals scalar fields.
    #[must_use]
    pub fn seal(mut self, seals: Seals) -> Self {
        self.seals = self.seals | seals;
        self
    }

    /// Sets the time limits.
    #[must_use]
    pub fn budget(mut self, budgets: Budgets) -> Self {
        self.budgets = budgets;
        self
    }
}
