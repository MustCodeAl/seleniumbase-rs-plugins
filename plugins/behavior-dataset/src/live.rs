//! Live-site DOM target discovery, multi-step human journey planning, CDP input
//! dispatch, and interaction telemetry capture.

use std::fmt;
use std::str::FromStr;

use seleniumbase_rs::evasion::behavior::{Humanizer, KeyAction};
use seleniumbase_rs::evasion::humanize::Rng;
use seleniumbase_rs::sb_cdp::{Point, Rect};
#[cfg(feature = "plugin")]
use seleniumbase_rs_plugin::{Engine, PageHandle, PluginError, Result as PluginResult};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::dataset::{DEFAULT_TYPING_SAMPLES, DatasetConfig, DatasetSample, build_live_sample};
use crate::error::{DatasetError, Result};
use crate::event::TimelineBuilder;
use crate::persona::{PersonaKind, PersonaProfile};
use crate::scenario::{ScenarioKind, ScenarioOutput};

/// Read-only DOM element discovery script evaluated on live pages via `PageHandle::evaluate`.
///
/// Collects visible links, safe buttons, benign text/search inputs, readable content
/// blocks, interactive controls, bounding boxes, concise CSS selectors, and viewport
/// geometry without reading sensitive input values or mutating page state.
pub const DISCOVER_SITE_ELEMENTS_JS: &str = r##"(() => {
  const MAX_ELEMENTS = 240;
  const vw = Math.max(Number(window.innerWidth || document.documentElement?.clientWidth || 1280), 1);
  const vh = Math.max(Number(window.innerHeight || document.documentElement?.clientHeight || 800), 1);
  const scrollHeight = Math.max(
    Number(document.documentElement?.scrollHeight || 0),
    Number(document.body?.scrollHeight || 0),
    vh
  );
  const pageUrl = typeof location !== "undefined" ? String(location.href || "") : "";
  const pageOrigin = typeof location !== "undefined" ? String(location.origin || "") : "";
  const title = typeof document !== "undefined" ? String(document.title || "").slice(0, 160) : "";

  const unsafeHint = (text) => {
    const s = String(text || "").toLowerCase();
    return /(password|passwd|passcode|credit|card|cvv|cvc|iban|routing|ssn|secret|token|delete|remove|destroy|logout|sign[\s_-]*out|pay\b|purchase|checkout|place[\s_-]*order|transfer)/.test(s);
  };

  const cssEscape = (raw) => {
    if (typeof CSS !== "undefined" && typeof CSS.escape === "function") {
      return CSS.escape(raw);
    }
    return String(raw).replace(/[^a-zA-Z0-9_-]/g, "\\$&");
  };

  const selectorFor = (el) => {
    const tag = (el.tagName || "div").toLowerCase();
    if (el.id && typeof el.id === "string" && el.id.trim().length > 0 && el.id.length <= 64) {
      return "#" + cssEscape(el.id.trim());
    }
    const testId = el.getAttribute("data-testid") || el.getAttribute("data-test");
    if (testId && testId.length <= 64) {
      return tag + '[data-testid="' + testId.replace(/"/g, '\\"') + '"]';
    }
    const name = el.getAttribute("name");
    if (name && name.length <= 64) {
      return tag + '[name="' + name.replace(/"/g, '\\"') + '"]';
    }
    let idx = 1;
    let prev = el.previousElementSibling;
    while (prev) {
      if (prev.tagName === el.tagName) idx += 1;
      prev = prev.previousElementSibling;
    }
    const parent = el.parentElement;
    if (parent && parent.id && parent.id.length <= 48) {
      return "#" + cssEscape(parent.id) + " > " + tag + ":nth-of-type(" + idx + ")";
    }
    return tag + ":nth-of-type(" + idx + ")";
  };

  const isVisible = (el, rect) => {
    if (!rect || rect.width < 6 || rect.height < 6) return false;
    if (rect.bottom < 0 || rect.right < 0 || rect.left > vw * 1.5) return false;
    try {
      const style = window.getComputedStyle(el);
      if (!style) return true;
      if (style.display === "none" || style.visibility === "hidden" || Number(style.opacity) === 0) {
        return false;
      }
    } catch (_) {}
    return true;
  };

  const wordCountOf = (text) => {
    const trimmed = String(text || "").trim();
    if (!trimmed) return 0;
    return trimmed.split(/\s+/).filter(Boolean).length;
  };

  const selectorQuery = [
    "a[href]",
    "button",
    "input",
    "textarea",
    "[role='button']",
    "[role='tab']",
    "summary",
    "h1",
    "h2",
    "h3",
    "p",
    "article"
  ].join(",");

  const nodes = Array.from(document.querySelectorAll(selectorQuery));
  const elements = [];

  for (const el of nodes) {
    if (elements.length >= MAX_ELEMENTS) break;
    const rect = el.getBoundingClientRect();
    if (!isVisible(el, rect)) continue;

    const tag = (el.tagName || "").toLowerCase();
    const roleAttr = (el.getAttribute("role") || "").toLowerCase();
    const inputType = tag === "input" ? (el.getAttribute("type") || "text").toLowerCase() : null;
    const attrSummary = [
      el.id || "",
      el.getAttribute("name") || "",
      el.getAttribute("placeholder") || "",
      el.getAttribute("aria-label") || "",
      el.getAttribute("autocomplete") || ""
    ].join(" ");

    let role = null;
    let href = null;
    let sameOrigin = false;
    let words = 0;
    let label = "";

    if (tag === "a") {
      const rawHref = el.getAttribute("href") || "";
      if (!rawHref || rawHref.startsWith("#") || rawHref.startsWith("javascript:") || rawHref.startsWith("mailto:") || rawHref.startsWith("tel:")) {
        continue;
      }
      try {
        const resolved = new URL(rawHref, pageUrl || "https://localhost/");
        if (resolved.protocol !== "http:" && resolved.protocol !== "https:") continue;
        href = resolved.href;
        sameOrigin = pageOrigin.length > 0 && resolved.origin === pageOrigin;
      } catch (_) {
        continue;
      }
      label = String(el.innerText || el.textContent || el.getAttribute("aria-label") || "").trim().slice(0, 80);
      if (unsafeHint(label) || unsafeHint(href)) continue;
      role = "link";
      words = wordCountOf(label);
    } else if (tag === "input" || tag === "textarea") {
      if (el.disabled || el.readOnly) continue;
      if (tag === "input") {
        const allowed = ["text", "search", ""];
        if (!allowed.includes(inputType || "")) continue;
      }
      if (unsafeHint(attrSummary)) continue;
      label = String(el.getAttribute("placeholder") || el.getAttribute("aria-label") || el.getAttribute("name") || tag).trim().slice(0, 80);
      role = "text_input";
    } else if (tag === "button" || roleAttr === "button") {
      if (el.disabled) continue;
      const btnType = (el.getAttribute("type") || "").toLowerCase();
      label = String(el.innerText || el.textContent || el.getAttribute("aria-label") || "button").trim().slice(0, 80);
      if (btnType === "submit" || btnType === "reset" || unsafeHint(label) || unsafeHint(attrSummary)) {
        continue;
      }
      role = "button";
      words = wordCountOf(label);
    } else if (roleAttr === "tab" || tag === "summary") {
      label = String(el.innerText || el.textContent || el.getAttribute("aria-label") || tag).trim().slice(0, 80);
      if (unsafeHint(label)) continue;
      role = "interactive_control";
      words = wordCountOf(label);
    } else {
      const text = String(el.innerText || el.textContent || "").trim();
      words = wordCountOf(text);
      if (words < 5) continue;
      label = text.slice(0, 80);
      role = "readable_block";
    }

    elements.push({
      selector: selectorFor(el),
      role,
      tag,
      inputType,
      x: Number(rect.left || rect.x || 0),
      y: Number(rect.top || rect.y || 0),
      width: Number(rect.width || 0),
      height: Number(rect.height || 0),
      href,
      sameOrigin,
      wordCount: words,
      label
    });
  }

  return {
    marker: "__sbrs_discover_site_elements__",
    url: pageUrl,
    title,
    viewportWidth: vw,
    viewportHeight: vh,
    scrollHeight,
    elements
  };
})()"##;

/// Semantic interaction role of a DOM element discovered on a live page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ElementRole {
    /// Hyperlink (`a[href]`) eligible for hover inspection or navigation.
    Link,
    /// Non-destructive button (`button`, `[role="button"]`).
    Button,
    /// Benign text or search input (`input[type="text"|"search"]`, `textarea`).
    TextInput,
    /// Paragraph, heading, or article text block with measurable word count.
    ReadableBlock,
    /// Tab, disclosure summary, or auxiliary interactive widget.
    InteractiveControl,
}

impl ElementRole {
    /// Canonical snake_case role identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Link => "link",
            Self::Button => "button",
            Self::TextInput => "text_input",
            Self::ReadableBlock => "readable_block",
            Self::InteractiveControl => "interactive_control",
        }
    }
}

impl fmt::Display for ElementRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ElementRole {
    type Err = DatasetError;

    fn from_str(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "link" => Ok(Self::Link),
            "button" => Ok(Self::Button),
            "text_input" | "textinput" | "input" => Ok(Self::TextInput),
            "readable_block" | "readableblock" | "readable" => Ok(Self::ReadableBlock),
            "interactive_control" | "interactivecontrol" | "control" => {
                Ok(Self::InteractiveControl)
            }
            _ => Err(DatasetError::Parse {
                kind: "ElementRole",
                value: s.to_owned(),
            }),
        }
    }
}

/// One visible DOM target discovered during live page inspection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DiscoveredElement {
    /// Concise CSS selector addressing this element on the page.
    pub selector: String,
    /// Classified semantic role.
    pub role: ElementRole,
    /// Lowercase HTML tag name.
    pub tag: String,
    /// Lowercase `<input type="...">` attribute when `tag` is `"input"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_type: Option<String>,
    /// Viewport-relative bounding box left coordinate in CSS pixels.
    pub x: f64,
    /// Viewport-relative bounding box top coordinate in CSS pixels.
    pub y: f64,
    /// Bounding box width in CSS pixels.
    pub width: f64,
    /// Bounding box height in CSS pixels.
    pub height: f64,
    /// Resolved destination URL when `role` is [`ElementRole::Link`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub href: Option<String>,
    /// True when `href` shares the current document's origin.
    pub same_origin: bool,
    /// Approximate visible word count for reading dwell estimation.
    pub word_count: usize,
    /// Truncated visible label, placeholder, or accessible name (never an input value).
    pub label: String,
}

impl DiscoveredElement {
    /// Bounding rectangle in CSS viewport coordinates.
    #[must_use]
    pub const fn rect(&self) -> Rect {
        Rect {
            x: self.x,
            y: self.y,
            width: self.width,
            height: self.height,
        }
    }
}

/// Telemetry for one executed user action step during a live-site journey.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SiteActionStep {
    /// Zero-based step index across the journey.
    pub step_index: usize,
    /// URL of the page where the step started.
    pub page_url: String,
    /// Action category (`"read"`, `"hover"`, `"type"`, `"scroll"`, `"click"`, `"navigate"`).
    pub action_kind: String,
    /// CSS selector of the interacted DOM element, if applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_selector: Option<String>,
    /// Semantic role of the interacted DOM element, if applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_role: Option<ElementRole>,
    /// Benign sample phrase typed during `"type"` actions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub typed_text: Option<String>,
    /// Net vertical scroll delta in CSS pixels during `"scroll"` actions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scroll_dy: Option<f64>,
    /// Destination URL when the step navigated to a linked page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub navigated_to: Option<String>,
    /// True when CDP `Input.*` commands were dispatched to the browser tab.
    pub used_cdp_input: bool,
    /// Number of low-level [`BehaviorEvent`](crate::event::BehaviorEvent)s emitted by this step.
    pub event_count: usize,
    /// Simulated human duration of this step in milliseconds.
    pub duration_ms: f64,
}

/// Per-page discovery and interaction summary within a live-site journey.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SiteVisitSummary {
    /// Page URL inspected.
    pub url: String,
    /// Document title observed during discovery.
    pub title: String,
    /// Viewport width in CSS pixels.
    pub viewport_width: f64,
    /// Viewport height in CSS pixels.
    pub viewport_height: f64,
    /// Total scrollable document height in CSS pixels.
    pub scroll_height: f64,
    /// Count of safe visible elements discovered on this page.
    pub discovered_elements: usize,
    /// Count of journey steps executed on this page.
    pub actions_taken: usize,
}

/// Complete telemetry report produced by [`SiteExplorer::explore_page`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SiteExplorationReport {
    /// Seed used for persona sampling and trajectory synthesis.
    pub seed: u64,
    /// Sampled persona archetype driving the journey.
    pub persona: PersonaKind,
    /// Initial page URL where exploration began.
    pub start_url: String,
    /// Ordered list of distinct page URLs visited during the journey.
    pub visited_urls: Vec<String>,
    /// Per-page discovery and action summaries.
    pub visits: Vec<SiteVisitSummary>,
    /// Ordered step-by-step action log.
    pub steps: Vec<SiteActionStep>,
    /// Compact action path descriptors (for example `"type:#search"` or `"navigate:https://..."`).
    pub action_path: Vec<String>,
    /// Ordered list of CSS selectors targeted across the journey.
    pub target_selectors: Vec<String>,
    /// True if at least one live CDP `Input.*` event was dispatched without fallback.
    pub cdp_input_dispatched: bool,
    /// Full labeled [`DatasetSample`] with kinematic features and event timeline.
    pub sample: DatasetSample,
}

#[derive(Debug, Clone)]
struct ParsedPageDiscovery {
    url: String,
    title: String,
    viewport_width: f64,
    viewport_height: f64,
    scroll_height: f64,
    elements: Vec<DiscoveredElement>,
}

/// Planner and executor that drives realistic, non-destructive multi-step user journeys
/// across live pages while recording kinematic [`DatasetSample`] telemetry.
#[derive(Debug, Clone)]
pub struct SiteExplorer {
    config: DatasetConfig,
}

impl SiteExplorer {
    /// Creates a validated [`SiteExplorer`] from `config`.
    ///
    /// # Errors
    ///
    /// Returns [`DatasetError::InvalidConfig`] if `config` fails validation.
    pub fn new(config: DatasetConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self { config })
    }

    /// Configuration governing step limits, origin scope, and input dispatch.
    #[must_use]
    pub const fn config(&self) -> &DatasetConfig {
        &self.config
    }

    /// Parses raw JSON returned by [`DISCOVER_SITE_ELEMENTS_JS`], applying defense-in-depth
    /// safety filtering to exclude password, file, payment, and destructive controls.
    #[must_use]
    pub fn parse_discovery(fallback_url: &str, value: &Value) -> Vec<DiscoveredElement> {
        parse_page_discovery(fallback_url, value).elements
    }

    /// Inspects `page`, plans a seeded multi-step persona journey across up to
    /// `config.max_pages` pages and `config.max_steps` steps, dispatches live inputs
    /// when enabled, and compiles a [`SiteExplorationReport`].
    ///
    /// # Errors
    ///
    /// Returns [`PluginError`] if page evaluation, navigation, or capability checks fail.
    #[cfg(feature = "plugin")]
    pub async fn explore_page(&self, page: &dyn PageHandle) -> PluginResult<SiteExplorationReport> {
        let seed = self.config.base_seed;
        let persona_kind = if self.config.personas.is_empty() {
            let idx = usize::try_from(seed % (PersonaKind::ALL.len() as u64)).unwrap_or(0);
            PersonaKind::ALL[idx]
        } else {
            let idx = usize::try_from(seed % (self.config.personas.len() as u64)).unwrap_or(0);
            self.config.personas[idx]
        };

        let profile = PersonaProfile::sample(persona_kind, seed);
        let mut humanizer = profile
            .humanizer()
            .map_err(|e| PluginError::Config(format!("behavior-dataset: {e}")))?;
        let mut rng = Rng::new(seed ^ 0xA5A5_5A5A_F0F0_0F0F);

        let max_steps = self.config.max_steps.max(1);
        let max_pages = self.config.max_pages.max(1);

        let mut timeline = TimelineBuilder::new();
        let mut target_widths: Vec<f64> = Vec::new();
        let mut expected_texts: Vec<String> = Vec::new();
        let mut visited_urls: Vec<String> = Vec::new();
        let mut visits: Vec<SiteVisitSummary> = Vec::new();
        let mut steps: Vec<SiteActionStep> = Vec::new();
        let mut action_path: Vec<String> = Vec::new();
        let mut target_selectors: Vec<String> = Vec::new();

        let mut cdp_supported = page.engine() == Engine::Cdp;
        let mut cdp_input_dispatched = false;
        let mut anchored = false;

        let initial_url = resolve_page_url(page, self.config.url.as_deref()).await;
        let start_origin = url_origin(&initial_url);

        for _page_idx in 0..max_pages {
            if steps.len() >= max_steps {
                break;
            }

            let current_hint =
                resolve_page_url(page, visited_urls.last().map(String::as_str)).await;
            let eval_expr = discovery_expression(&current_hint);
            let raw_dom = page.evaluate(&eval_expr).await?;
            let discovery = parse_page_discovery(&current_hint, &raw_dom);
            let page_url = discovery.url.clone();

            if !visited_urls.iter().any(|u| u == &page_url) {
                visited_urls.push(page_url.clone());
            }

            if !anchored {
                let start_pt =
                    humanizer.resting_point(discovery.viewport_width, discovery.viewport_height);
                timeline.anchor_at(start_pt);
                anchored = true;
            }

            let mut page_actions = 0usize;
            let mut navigated_next: Option<String> = None;

            // 1. Word-count-proportional reading pause on a visible readable block.
            if steps.len() < max_steps
                && let Some(readable) =
                    pick_element(&discovery.elements, ElementRole::ReadableBlock, &mut rng)
            {
                let (ev_before, t_before) = (timeline.event_count(), timeline.timestamp_ms());
                #[allow(clippy::cast_precision_loss)]
                let words = (readable.word_count.max(6) as f64).min(120.0);
                let wpm = profile.reading_wpm.max(45.0);
                let dwell_ms =
                    ((words / wpm) * 60_000.0 * rng.range(0.75, 1.25)).clamp(240.0, 4200.0);
                timeline.push_pause(dwell_ms);

                record_selector(&mut target_selectors, &readable.selector);
                action_path.push(format!("read:{}", readable.selector));
                steps.push(SiteActionStep {
                    step_index: steps.len(),
                    page_url: page_url.clone(),
                    action_kind: "read".to_owned(),
                    target_selector: Some(readable.selector.clone()),
                    target_role: Some(ElementRole::ReadableBlock),
                    typed_text: None,
                    scroll_dy: None,
                    navigated_to: None,
                    used_cdp_input: false,
                    event_count: timeline.event_count().saturating_sub(ev_before),
                    duration_ms: timeline.timestamp_ms() - t_before,
                });
                page_actions += 1;
            }

            // 2. Hover inspection over an interactive control, button, or link.
            if steps.len() < max_steps
                && let Some(hover_el) = discovery.elements.iter().find(|el| {
                    matches!(
                        el.role,
                        ElementRole::InteractiveControl | ElementRole::Button | ElementRole::Link
                    )
                })
            {
                let (ev_before, t_before) = (timeline.event_count(), timeline.timestamp_ms());
                let used_cdp = dispatch_pointer_approach(
                    page,
                    &mut humanizer,
                    &profile,
                    &mut rng,
                    &mut timeline,
                    &mut target_widths,
                    hover_el,
                    false,
                    self.config.dispatch_live_inputs,
                    &mut cdp_supported,
                )
                .await?;
                cdp_input_dispatched |= used_cdp;
                timeline.push_pause(rng.range(90.0, 260.0) * profile.dwell_scale);

                record_selector(&mut target_selectors, &hover_el.selector);
                action_path.push(format!("hover:{}", hover_el.selector));
                steps.push(SiteActionStep {
                    step_index: steps.len(),
                    page_url: page_url.clone(),
                    action_kind: "hover".to_owned(),
                    target_selector: Some(hover_el.selector.clone()),
                    target_role: Some(hover_el.role),
                    typed_text: None,
                    scroll_dy: None,
                    navigated_to: None,
                    used_cdp_input: used_cdp,
                    event_count: timeline.event_count().saturating_sub(ev_before),
                    duration_ms: timeline.timestamp_ms() - t_before,
                });
                page_actions += 1;
            }

            // 3. Focus and type a benign phrase into a discovered text/search input.
            if steps.len() < max_steps
                && let Some(input_el) =
                    pick_element(&discovery.elements, ElementRole::TextInput, &mut rng)
            {
                let (ev_before, t_before) = (timeline.event_count(), timeline.timestamp_ms());
                let click_cdp = dispatch_pointer_approach(
                    page,
                    &mut humanizer,
                    &profile,
                    &mut rng,
                    &mut timeline,
                    &mut target_widths,
                    input_el,
                    true,
                    self.config.dispatch_live_inputs,
                    &mut cdp_supported,
                )
                .await?;

                let phrase = pick_typing_phrase(&self.config.typing_samples, &mut rng);
                expected_texts.push(phrase.clone());
                let type_cdp = dispatch_typing_sequence(
                    page,
                    &mut humanizer,
                    &profile,
                    &mut rng,
                    &mut timeline,
                    &input_el.selector,
                    &phrase,
                    self.config.dispatch_live_inputs,
                    &mut cdp_supported,
                )
                .await?;
                let used_cdp = click_cdp || type_cdp;
                cdp_input_dispatched |= used_cdp;

                record_selector(&mut target_selectors, &input_el.selector);
                action_path.push(format!("type:{}", input_el.selector));
                steps.push(SiteActionStep {
                    step_index: steps.len(),
                    page_url: page_url.clone(),
                    action_kind: "type".to_owned(),
                    target_selector: Some(input_el.selector.clone()),
                    target_role: Some(ElementRole::TextInput),
                    typed_text: Some(phrase),
                    scroll_dy: None,
                    navigated_to: None,
                    used_cdp_input: used_cdp,
                    event_count: timeline.event_count().saturating_sub(ev_before),
                    duration_ms: timeline.timestamp_ms() - t_before,
                });
                page_actions += 1;
            }

            // 4. Smooth scroll burst when scrollable content exists beyond the viewport.
            if steps.len() < max_steps && discovery.scroll_height > discovery.viewport_height + 24.0
            {
                let (ev_before, t_before) = (timeline.event_count(), timeline.timestamp_ms());
                let max_scrollable =
                    (discovery.scroll_height - discovery.viewport_height).min(720.0);
                let dy = rng.range(160.0, max_scrollable.max(180.0));
                let used_cdp = dispatch_scroll_burst(
                    page,
                    &mut humanizer,
                    &profile,
                    &mut timeline,
                    dy,
                    self.config.dispatch_live_inputs,
                    &mut cdp_supported,
                )
                .await?;
                cdp_input_dispatched |= used_cdp;

                action_path.push(format!("scroll:{dy:.0}"));
                steps.push(SiteActionStep {
                    step_index: steps.len(),
                    page_url: page_url.clone(),
                    action_kind: "scroll".to_owned(),
                    target_selector: None,
                    target_role: None,
                    typed_text: None,
                    scroll_dy: Some(dy),
                    navigated_to: None,
                    used_cdp_input: used_cdp,
                    event_count: timeline.event_count().saturating_sub(ev_before),
                    duration_ms: timeline.timestamp_ms() - t_before,
                });
                page_actions += 1;
            }

            // 5. Click a non-destructive UI button or interactive control if steps remain.
            if steps.len() < max_steps
                && let Some(btn_el) = discovery.elements.iter().find(|el| {
                    matches!(
                        el.role,
                        ElementRole::Button | ElementRole::InteractiveControl
                    )
                })
            {
                let (ev_before, t_before) = (timeline.event_count(), timeline.timestamp_ms());
                let used_cdp = dispatch_pointer_approach(
                    page,
                    &mut humanizer,
                    &profile,
                    &mut rng,
                    &mut timeline,
                    &mut target_widths,
                    btn_el,
                    true,
                    self.config.dispatch_live_inputs,
                    &mut cdp_supported,
                )
                .await?;
                cdp_input_dispatched |= used_cdp;

                record_selector(&mut target_selectors, &btn_el.selector);
                action_path.push(format!("click:{}", btn_el.selector));
                steps.push(SiteActionStep {
                    step_index: steps.len(),
                    page_url: page_url.clone(),
                    action_kind: "click".to_owned(),
                    target_selector: Some(btn_el.selector.clone()),
                    target_role: Some(btn_el.role),
                    typed_text: None,
                    scroll_dy: None,
                    navigated_to: None,
                    used_cdp_input: used_cdp,
                    event_count: timeline.event_count().saturating_sub(ev_before),
                    duration_ms: timeline.timestamp_ms() - t_before,
                });
                page_actions += 1;
            }

            // 6. Follow an unvisited link if page and step budgets allow.
            if steps.len() < max_steps && visits.len() + 1 < max_pages {
                let candidate_link = discovery.elements.iter().find(|el| {
                    if el.role != ElementRole::Link {
                        return false;
                    }
                    let Some(href) = el.href.as_deref() else {
                        return false;
                    };
                    if visited_urls.iter().any(|visited| visited == href) {
                        return false;
                    }
                    if self.config.same_origin_only {
                        let same_by_origin = match (&start_origin, url_origin(href)) {
                            (Some(a), Some(b)) => *a == b,
                            _ => el.same_origin,
                        };
                        return el.same_origin && same_by_origin;
                    }
                    true
                });

                if let Some(link_el) = candidate_link
                    && let Some(href) = link_el.href.clone()
                {
                    let (ev_before, t_before) = (timeline.event_count(), timeline.timestamp_ms());
                    let used_cdp = dispatch_pointer_approach(
                        page,
                        &mut humanizer,
                        &profile,
                        &mut rng,
                        &mut timeline,
                        &mut target_widths,
                        link_el,
                        true,
                        self.config.dispatch_live_inputs,
                        &mut cdp_supported,
                    )
                    .await?;
                    cdp_input_dispatched |= used_cdp;

                    page.navigate(&href).await?;
                    timeline.push_pause(rng.range(180.0, 480.0) * profile.reaction_scale);

                    record_selector(&mut target_selectors, &link_el.selector);
                    action_path.push(format!("navigate:{href}"));
                    steps.push(SiteActionStep {
                        step_index: steps.len(),
                        page_url: page_url.clone(),
                        action_kind: "navigate".to_owned(),
                        target_selector: Some(link_el.selector.clone()),
                        target_role: Some(ElementRole::Link),
                        typed_text: None,
                        scroll_dy: None,
                        navigated_to: Some(href.clone()),
                        used_cdp_input: used_cdp,
                        event_count: timeline.event_count().saturating_sub(ev_before),
                        duration_ms: timeline.timestamp_ms() - t_before,
                    });
                    page_actions += 1;
                    navigated_next = Some(href);
                }
            }

            visits.push(SiteVisitSummary {
                url: page_url,
                title: discovery.title,
                viewport_width: discovery.viewport_width,
                viewport_height: discovery.viewport_height,
                scroll_height: discovery.scroll_height,
                discovered_elements: discovery.elements.len(),
                actions_taken: page_actions,
            });

            if navigated_next.is_none() {
                break;
            }
        }

        let start_url = visited_urls.first().cloned().unwrap_or(initial_url);
        let scenario = infer_journey_scenario(&steps);
        let total_duration_ms = timeline.timestamp_ms();
        let output = ScenarioOutput {
            events: timeline.finish(),
            stroke_target_widths: target_widths,
            expected_texts,
            total_duration_ms,
        };

        let sample = build_live_sample(
            format!("live_{seed:08x}_human"),
            profile,
            scenario,
            seed,
            output,
            Some(start_url.clone()),
            action_path.clone(),
            target_selectors.clone(),
        );

        Ok(SiteExplorationReport {
            seed,
            persona: persona_kind,
            start_url,
            visited_urls,
            visits,
            steps,
            action_path,
            target_selectors,
            cdp_input_dispatched,
            sample,
        })
    }
}

#[cfg(feature = "plugin")]
async fn resolve_page_url(page: &dyn PageHandle, fallback: Option<&str>) -> String {
    match page.url().await {
        Ok(url) if !url.trim().is_empty() && url != "about:blank" => url,
        _ => fallback.unwrap_or("about:blank").to_owned(),
    }
}

#[cfg(feature = "plugin")]
fn discovery_expression(url_hint: &str) -> String {
    let safe_hint: String = url_hint
        .chars()
        .filter(|ch| *ch != '\n' && *ch != '\r' && *ch != '*')
        .take(200)
        .collect();
    format!("/* __sbrs_discover_site_elements__ url={safe_hint} */\n{DISCOVER_SITE_ELEMENTS_JS}")
}

fn parse_page_discovery(fallback_url: &str, value: &Value) -> ParsedPageDiscovery {
    let url = value
        .get("url")
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .unwrap_or(fallback_url)
        .to_owned();
    let title = value
        .get("title")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let viewport_width = value
        .get("viewportWidth")
        .or_else(|| value.get("viewport_width"))
        .and_then(Value::as_f64)
        .filter(|v| v.is_finite() && *v > 0.0)
        .unwrap_or(1366.0);
    let viewport_height = value
        .get("viewportHeight")
        .or_else(|| value.get("viewport_height"))
        .and_then(Value::as_f64)
        .filter(|v| v.is_finite() && *v > 0.0)
        .unwrap_or(820.0);
    let scroll_height = value
        .get("scrollHeight")
        .or_else(|| value.get("scroll_height"))
        .and_then(Value::as_f64)
        .filter(|v| v.is_finite() && *v > 0.0)
        .unwrap_or(viewport_height);

    let mut elements = Vec::new();
    if let Some(arr) = value.get("elements").and_then(Value::as_array) {
        for item in arr {
            if let Some(parsed) = parse_single_element(item) {
                elements.push(parsed);
            }
        }
    }

    ParsedPageDiscovery {
        url,
        title,
        viewport_width,
        viewport_height,
        scroll_height,
        elements,
    }
}

fn parse_single_element(item: &Value) -> Option<DiscoveredElement> {
    let selector = item.get("selector")?.as_str()?.trim();
    if selector.is_empty() {
        return None;
    }
    let role_str = item.get("role")?.as_str()?;
    let role = ElementRole::from_str(role_str).ok()?;
    let tag = item
        .get("tag")
        .and_then(Value::as_str)
        .unwrap_or("div")
        .to_ascii_lowercase();
    let input_type = item
        .get("inputType")
        .or_else(|| item.get("input_type"))
        .and_then(Value::as_str)
        .map(str::to_ascii_lowercase);
    let label = item
        .get("label")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let href = item
        .get("href")
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .map(str::to_owned);

    // Defense-in-depth safety check: refuse password, file, payment, or destructive targets.
    if is_unsafe_element(
        role,
        &tag,
        input_type.as_deref(),
        selector,
        &label,
        href.as_deref(),
    ) {
        return None;
    }

    let x = item.get("x").and_then(Value::as_f64).unwrap_or(0.0);
    let y = item.get("y").and_then(Value::as_f64).unwrap_or(0.0);
    let width = item.get("width").and_then(Value::as_f64).unwrap_or(0.0);
    let height = item.get("height").and_then(Value::as_f64).unwrap_or(0.0);
    if !x.is_finite() || !y.is_finite() || width < 4.0 || height < 4.0 {
        return None;
    }

    let same_origin = item
        .get("sameOrigin")
        .or_else(|| item.get("same_origin"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let word_count = item
        .get("wordCount")
        .or_else(|| item.get("word_count"))
        .and_then(Value::as_u64)
        .and_then(|n| usize::try_from(n).ok())
        .unwrap_or(0);

    Some(DiscoveredElement {
        selector: selector.to_owned(),
        role,
        tag,
        input_type,
        x,
        y,
        width,
        height,
        href,
        same_origin,
        word_count,
        label,
    })
}

fn is_unsafe_element(
    role: ElementRole,
    tag: &str,
    input_type: Option<&str>,
    selector: &str,
    label: &str,
    href: Option<&str>,
) -> bool {
    const UNSAFE_TOKENS: &[&str] = &[
        "password",
        "passwd",
        "passcode",
        "credit",
        "card",
        "cvv",
        "cvc",
        "iban",
        "routing",
        "ssn",
        "secret",
        "delete",
        "remove",
        "destroy",
        "logout",
        "signout",
        "sign-out",
        "sign out",
        "purchase",
        "checkout",
        "place-order",
        "place order",
        "payment",
    ];

    if role == ElementRole::TextInput
        && tag == "input"
        && let Some(t) = input_type
        && !matches!(t, "text" | "search" | "")
    {
        return true;
    }

    if role == ElementRole::Link
        && let Some(h) = href
    {
        let lower_href = h.trim().to_ascii_lowercase();
        if !lower_href.starts_with("http://") && !lower_href.starts_with("https://") {
            return true;
        }
    }

    if role != ElementRole::ReadableBlock {
        let combined = format!(
            "{} {} {}",
            selector.to_ascii_lowercase(),
            label.to_ascii_lowercase(),
            href.unwrap_or_default().to_ascii_lowercase()
        );
        if UNSAFE_TOKENS.iter().any(|tok| combined.contains(tok)) {
            return true;
        }
    }

    false
}

#[cfg(feature = "plugin")]
fn pick_element<'a>(
    elements: &'a [DiscoveredElement],
    role: ElementRole,
    rng: &mut Rng,
) -> Option<&'a DiscoveredElement> {
    let matching: Vec<&DiscoveredElement> = elements.iter().filter(|e| e.role == role).collect();
    if matching.is_empty() {
        None
    } else {
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            clippy::cast_precision_loss
        )]
        let idx = (rng.range(0.0, matching.len() as f64) as usize).min(matching.len() - 1);
        Some(matching[idx])
    }
}

#[cfg(feature = "plugin")]
fn pick_typing_phrase(samples: &[String], rng: &mut Rng) -> String {
    let non_empty: Vec<&str> = samples
        .iter()
        .map(String::as_str)
        .filter(|s| !s.trim().is_empty())
        .collect();
    if non_empty.is_empty() {
        (*rng.pick(&DEFAULT_TYPING_SAMPLES)).to_owned()
    } else {
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            clippy::cast_precision_loss
        )]
        let idx = (rng.range(0.0, non_empty.len() as f64) as usize).min(non_empty.len() - 1);
        non_empty[idx].to_owned()
    }
}

#[cfg(feature = "plugin")]
#[allow(clippy::too_many_arguments)]
async fn dispatch_pointer_approach(
    page: &dyn PageHandle,
    humanizer: &mut Humanizer,
    profile: &PersonaProfile,
    rng: &mut Rng,
    timeline: &mut TimelineBuilder,
    target_widths: &mut Vec<f64>,
    element: &DiscoveredElement,
    click: bool,
    dispatch_live: bool,
    cdp_supported: &mut bool,
) -> PluginResult<bool> {
    let rect = element.rect();
    let from = timeline
        .cursor()
        .unwrap_or_else(|| Point::new(rect.x, rect.y));
    let to = humanizer.target_point(rect);
    let path = humanizer.mouse_path(from, to, rect.width);

    let mut used_cdp = false;
    for step in &path {
        timeline.push_move(step.at, step.wait.as_secs_f64() * 1000.0);
        if dispatch_live && *cdp_supported {
            match page
                .send(
                    "Input.dispatchMouseEvent",
                    json!({
                        "type": "mouseMoved",
                        "x": step.at.x,
                        "y": step.at.y,
                    }),
                )
                .await
            {
                Ok(_) => used_cdp = true,
                Err(PluginError::NotSupported(_)) => {
                    *cdp_supported = false;
                }
                Err(err) => return Err(err),
            }
        }
    }

    target_widths.push(rect.width.max(4.0));

    if click {
        let settle_ms = rng.range(8.0, 35.0) * profile.dwell_scale;
        let dwell_ms = humanizer.click_dwell().as_secs_f64() * 1000.0 * profile.dwell_scale;
        timeline.push_click(to, settle_ms, dwell_ms);

        if dispatch_live {
            if *cdp_supported {
                for event_type in ["mousePressed", "mouseReleased"] {
                    match page
                        .send(
                            "Input.dispatchMouseEvent",
                            json!({
                                "type": event_type,
                                "x": to.x,
                                "y": to.y,
                                "button": "left",
                                "clickCount": 1,
                            }),
                        )
                        .await
                    {
                        Ok(_) => used_cdp = true,
                        Err(PluginError::NotSupported(_)) => {
                            *cdp_supported = false;
                            break;
                        }
                        Err(err) => return Err(err),
                    }
                }
            }
            if !*cdp_supported {
                let sel_json = serde_json::to_string(&element.selector)
                    .unwrap_or_else(|_| "\"body\"".to_owned());
                let fallback_js = format!(
                    "(() => {{ const el = document.querySelector({sel_json}); if (el) {{ if (typeof el.focus === 'function') el.focus(); if (typeof el.click === 'function') el.click(); }} return true; }})()"
                );
                let _ = page.evaluate(&fallback_js).await?;
            }
        }
    } else {
        timeline.reset_stroke();
        if dispatch_live && !*cdp_supported {
            let sel_json =
                serde_json::to_string(&element.selector).unwrap_or_else(|_| "\"body\"".to_owned());
            let fallback_js = format!(
                "(() => {{ const el = document.querySelector({sel_json}); if (el) el.dispatchEvent(new MouseEvent('mouseover', {{ bubbles: true }})); return true; }})()"
            );
            let _ = page.evaluate(&fallback_js).await?;
        }
    }

    Ok(used_cdp)
}

#[cfg(feature = "plugin")]
#[allow(clippy::too_many_arguments)]
async fn dispatch_typing_sequence(
    page: &dyn PageHandle,
    humanizer: &mut Humanizer,
    profile: &PersonaProfile,
    rng: &mut Rng,
    timeline: &mut TimelineBuilder,
    selector: &str,
    phrase: &str,
    dispatch_live: bool,
    cdp_supported: &mut bool,
) -> PluginResult<bool> {
    let reaction_ms = humanizer.reaction().as_secs_f64() * 1000.0 * profile.reaction_scale;
    timeline.push_pause(reaction_ms);

    let mut used_cdp = false;
    for keystroke in humanizer.typing_plan(phrase) {
        let wait_ms = keystroke.wait.as_secs_f64() * 1000.0;
        let dwell_ms = rng.gaussian(80.0, 20.0).clamp(28.0, 175.0) * profile.dwell_scale;
        let (label, key_params) = match keystroke.action {
            KeyAction::Type(ch) => {
                let text = ch.to_string();
                (
                    text.clone(),
                    Some((
                        json!({ "type": "keyDown", "key": text, "text": text }),
                        json!({ "type": "keyUp", "key": text }),
                    )),
                )
            }
            KeyAction::Backspace => (
                "Backspace".to_owned(),
                Some((
                    json!({
                        "type": "keyDown",
                        "key": "Backspace",
                        "code": "Backspace",
                        "windowsVirtualKeyCode": 8,
                        "nativeVirtualKeyCode": 8,
                    }),
                    json!({
                        "type": "keyUp",
                        "key": "Backspace",
                        "code": "Backspace",
                        "windowsVirtualKeyCode": 8,
                        "nativeVirtualKeyCode": 8,
                    }),
                )),
            ),
            _ => (String::new(), None),
        };

        if label.is_empty() {
            continue;
        }
        timeline.push_key(label, wait_ms, dwell_ms);

        if dispatch_live
            && *cdp_supported
            && let Some((down, up)) = key_params
        {
            for payload in [down, up] {
                match page.send("Input.dispatchKeyEvent", payload).await {
                    Ok(_) => used_cdp = true,
                    Err(PluginError::NotSupported(_)) => {
                        *cdp_supported = false;
                        break;
                    }
                    Err(err) => return Err(err),
                }
            }
        }
    }

    if dispatch_live && !*cdp_supported {
        let sel_json = serde_json::to_string(selector).unwrap_or_else(|_| "\"input\"".to_owned());
        let val_json = serde_json::to_string(phrase).unwrap_or_else(|_| "\"\"".to_owned());
        let fallback_js = format!(
            "(() => {{ const el = document.querySelector({sel_json}); if (el && 'value' in el) {{ el.value = {val_json}; el.dispatchEvent(new Event('input', {{ bubbles: true }})); }} return true; }})()"
        );
        let _ = page.evaluate(&fallback_js).await?;
    }

    Ok(used_cdp)
}

#[cfg(feature = "plugin")]
async fn dispatch_scroll_burst(
    page: &dyn PageHandle,
    humanizer: &mut Humanizer,
    profile: &PersonaProfile,
    timeline: &mut TimelineBuilder,
    dy: f64,
    dispatch_live: bool,
    cdp_supported: &mut bool,
) -> PluginResult<bool> {
    let pace = profile.scroll_pace.max(0.2);
    let cursor = timeline
        .cursor()
        .unwrap_or_else(|| Point::new(400.0, 320.0));
    let mut used_cdp = false;

    for notch in humanizer.scroll_plan(dy) {
        let wait_ms = notch.wait.as_secs_f64() * 1000.0 / pace;
        timeline.push_scroll(notch.dy, wait_ms);

        if dispatch_live && *cdp_supported {
            match page
                .send(
                    "Input.dispatchMouseEvent",
                    json!({
                        "type": "mouseWheel",
                        "x": cursor.x,
                        "y": cursor.y,
                        "deltaX": 0.0,
                        "deltaY": notch.dy,
                    }),
                )
                .await
            {
                Ok(_) => used_cdp = true,
                Err(PluginError::NotSupported(_)) => {
                    *cdp_supported = false;
                }
                Err(err) => return Err(err),
            }
        }
    }

    if dispatch_live && !*cdp_supported {
        let fallback_js = format!("(() => {{ window.scrollBy(0, {dy:.2}); return true; }})()");
        let _ = page.evaluate(&fallback_js).await?;
    }

    Ok(used_cdp)
}

#[cfg(feature = "plugin")]
fn record_selector(selectors: &mut Vec<String>, selector: &str) {
    if !selectors.iter().any(|existing| existing == selector) {
        selectors.push(selector.to_owned());
    }
}

#[cfg(feature = "plugin")]
fn infer_journey_scenario(steps: &[SiteActionStep]) -> ScenarioKind {
    let has_type = steps.iter().any(|s| s.action_kind == "type");
    let has_scroll = steps.iter().any(|s| s.action_kind == "scroll");
    let has_nav_or_click = steps
        .iter()
        .any(|s| s.action_kind == "navigate" || s.action_kind == "click");

    if has_type && (has_scroll || has_nav_or_click) {
        ScenarioKind::SearchAndBrowse
    } else if has_type {
        ScenarioKind::FormEntry
    } else if has_scroll {
        ScenarioKind::ArticleReadingScroll
    } else {
        ScenarioKind::TargetApproachClick
    }
}

#[cfg(feature = "plugin")]
fn url_origin(url: &str) -> Option<String> {
    let (scheme, rest) = url.trim().split_once("://")?;
    let scheme_lower = scheme.to_ascii_lowercase();
    if scheme_lower != "http" && scheme_lower != "https" {
        return None;
    }
    let authority = rest.split(['/', '?', '#']).next()?;
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, h)| h)
        .to_ascii_lowercase();
    if host_port.is_empty() {
        return None;
    }
    Some(format!("{scheme_lower}://{host_port}"))
}
