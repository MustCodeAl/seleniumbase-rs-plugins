//! `OwaspPlugin`, thread-safe `AuditSession`, passive network observer, and `Task` runner.

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use async_trait::async_trait;
use seleniumbase_rs_plugin::{
    BrowserHandle, Capability, Category, Configurable, JobRunner, LaunchSettings, Metadata,
    NetworkInterest, PageHandle, PathScope, Plugin, PluginError, ProtocolEvent, RequestFilter,
    Requirements, ResourceKind, ResponseView, Result as PluginResult, Task, TaskContext,
    config::options,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::auditors::cookies::{CookieAuditContext, CookieInput, audit_cookies, audit_set_cookie};
use crate::auditors::dom::{DomAuditOptions, DomSnapshot, audit_dom};
use crate::auditors::forms::{audit_forms, parse_forms_from_value};
use crate::auditors::headers::{HeaderAuditContext, audit_headers};
use crate::auditors::sca::{DetectedComponent, audit_sca};
use crate::error::{OwaspError, Result};
use crate::ptk::{PtkAgentSnapshot, PtkExtensionConfig, PtkExtensionStatus};
use crate::report::OwaspAuditReport;
use crate::types::{AuditorKind, Finding};

/// Plugin identifier name.
pub const NAME: &str = "owasp";

/// Maximum observed HTTP responses kept in memory by default.
pub const DEFAULT_MAX_OBSERVED_RESPONSES: usize = 1_024;
/// Maximum passive findings kept in memory per session by default.
pub const DEFAULT_MAX_FINDINGS: usize = 2_048;

/// Read-only async browser page snapshot script evaluated via [`PageHandle::evaluate`].
/// Collects URL, DOM element inventories, `<form>`/`<input>` posture metadata, HTML comments,
/// storage entries, cookies, runtime JS library globals, and awaits async `window.PTK_AGENT`
/// bridge methods (`scanStatus` / `getScanStatus`, `getFindings`, `exportFullReport`).
const PAGE_AUDIT_JS: &str = r#"(async () => {
  const MAX_ITEMS = 500;
  const MAX_CODE = 32768;
  const url = typeof location !== "undefined" ? String(location.href || "") : "";
  const safeStr = (v, limit) => {
    if (v === null || v === undefined) return null;
    const s = String(v);
    return limit && s.length > limit ? s.slice(0, limit) : s;
  };
  const scripts = [];
  for (const el of Array.from(document.querySelectorAll("script")).slice(0, MAX_ITEMS)) {
    const src = el.getAttribute("src");
    scripts.push({
      src: src || null,
      integrity: el.getAttribute("integrity") || null,
      crossorigin: el.getAttribute("crossorigin") || null,
      inline: src ? null : safeStr(el.textContent || "", MAX_CODE),
    });
  }
  const stylesheets = [];
  for (const el of Array.from(document.querySelectorAll("link[rel~='stylesheet']")).slice(0, MAX_ITEMS)) {
    const href = el.getAttribute("href");
    if (href) {
      stylesheets.push({
        href,
        integrity: el.getAttribute("integrity") || null,
        crossorigin: el.getAttribute("crossorigin") || null,
      });
    }
  }
  const links = [];
  for (const el of Array.from(document.querySelectorAll("a, area")).slice(0, MAX_ITEMS)) {
    links.push({
      href: el.getAttribute("href") || "",
      target: el.getAttribute("target") || null,
      rel: el.getAttribute("rel") || null,
    });
  }
  const active_elements = [];
  for (const [sel, attr] of [["iframe", "src"], ["embed", "src"], ["object", "data"], ["form", "action"]]) {
    for (const el of Array.from(document.querySelectorAll(sel)).slice(0, MAX_ITEMS)) {
      const val = el.getAttribute(attr);
      if (val) active_elements.push({ tag: sel, attr, url: val });
    }
  }
  const passive_elements = [];
  for (const sel of ["img", "audio", "video", "source"]) {
    for (const el of Array.from(document.querySelectorAll(sel)).slice(0, MAX_ITEMS)) {
      const val = el.getAttribute("src");
      if (val) passive_elements.push({ tag: sel, attr: "src", url: val });
    }
  }
  const comments = [];
  try {
    const walker = document.createTreeWalker(document, NodeFilter.SHOW_COMMENT);
    let node;
    while ((node = walker.nextNode()) && comments.length < MAX_ITEMS) {
      comments.push(safeStr(node.nodeValue || "", 4096) || "");
    }
  } catch (_) {}
  const readStorage = (store) => {
    const out = {};
    try {
      const len = Math.min(store.length, MAX_ITEMS);
      for (let i = 0; i < len; i++) {
        const k = store.key(i);
        if (k !== null) out[k] = safeStr(store.getItem(k) || "", 4096) || "";
      }
    } catch (_) {}
    return out;
  };
  const globals = {
    jquery: (window.jQuery && window.jQuery.fn && window.jQuery.fn.jquery) || (window.$ && window.$.fn && window.$.fn.jquery) || null,
    angular: (window.angular && window.angular.version && window.angular.version.full) || null,
    ng_version: (document.querySelector("[ng-version]") && document.querySelector("[ng-version]").getAttribute("ng-version")) || null,
    react: (window.React && window.React.version) || null,
    lodash: (window._ && window._.VERSION) || null,
    bootstrap: (window.bootstrap && window.bootstrap.Tooltip && window.bootstrap.Tooltip.VERSION) || (window.jQuery && window.jQuery.fn && window.jQuery.fn.tooltip && window.jQuery.fn.tooltip.Constructor && window.jQuery.fn.tooltip.Constructor.VERSION) || null,
    vue: (window.Vue && window.Vue.version) || null,
  };
  const forms = [];
  for (const formEl of Array.from(document.querySelectorAll("form")).slice(0, MAX_ITEMS)) {
    const inputs = [];
    for (const inEl of Array.from(formEl.querySelectorAll("input, textarea")).slice(0, MAX_ITEMS)) {
      inputs.push({
        type: (inEl.tagName === "TEXTAREA" ? "textarea" : (inEl.getAttribute("type") || "text")).toLowerCase(),
        name: inEl.getAttribute("name") || null,
        id: inEl.getAttribute("id") || null,
        autocomplete: inEl.getAttribute("autocomplete") || null,
      });
    }
    forms.push({
      action: formEl.getAttribute("action") || null,
      method: (formEl.getAttribute("method") || "GET").toUpperCase(),
      id: formEl.getAttribute("id") || null,
      name: formEl.getAttribute("name") || null,
      inputs,
    });
  }
  let ptkAgent = null;
  try {
    const agent = window.PTK_AGENT;
    if (agent) {
      const statusFn = typeof agent.scanStatus === "function"
        ? agent.scanStatus.bind(agent)
        : (typeof agent.getScanStatus === "function" ? agent.getScanStatus.bind(agent) : null);
      if (statusFn) {
        const scanStatus = await Promise.resolve(statusFn({}));
        const findingsResponse = typeof agent.getFindings === "function"
          ? await Promise.resolve(agent.getFindings({ limit: 200 }))
          : null;
        let exportPlan = null;
        if (typeof agent.exportFullReport === "function") {
          try {
            exportPlan = await Promise.resolve(agent.exportFullReport({ engine: "ALL", transfer: "retrieval-plan" }));
          } catch (_) {}
        }
        ptkAgent = { scanStatus, findingsResponse, exportPlan };
      }
    }
  } catch (_) {}
  let documentCookie = "";
  try { documentCookie = String(document.cookie || ""); } catch (_) {}
  return {
    marker: "__sbrs_owasp_audit__",
    url,
    html: document.documentElement ? safeStr(document.documentElement.outerHTML, 262144) : "",
    documentCookie,
    scripts,
    stylesheets,
    links,
    active_elements,
    passive_elements,
    forms,
    comments,
    localStorage: readStorage(window.localStorage),
    sessionStorage: readStorage(window.sessionStorage),
    globals,
    ptkAgent,
  };
})()"#;

/// Configuration for [`OwaspPlugin`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OwaspConfig {
    /// Enable passive HTTP header, CSP, CORS, HSTS, and server banner auditing.
    pub headers: bool,
    /// Enable passive `Set-Cookie` and `document.cookie` attribute auditing.
    pub cookies: bool,
    /// Enable passive Base64URL JWT header/claims auditing.
    pub jwt: bool,
    /// Enable passive DOM, mixed content, SRI, storage, and `postMessage` auditing.
    pub dom: bool,
    /// Enable passive `<form>` and `<input>` posture auditing (transport, method, CSRF token, autocomplete).
    pub forms: bool,
    /// Enable passive client-side SCA library/version and EOL auditing.
    pub sca: bool,
    /// Optional OWASP PTK extension and `modules.json` configuration.
    pub ptk: Option<PtkExtensionConfig>,
    /// URL glob filters passed to [`NetworkInterest::observe`] (empty observes all URLs).
    pub observe_urls: Vec<String>,
    /// Maximum observed response metadata records kept in [`AuditSession`].
    pub max_observed_responses: usize,
    /// Maximum passive findings kept in [`AuditSession`].
    pub max_findings: usize,
    /// Deduplicate identical findings when compiling [`OwaspAuditReport`].
    pub deduplicate: bool,
    /// Emit informational DOM sink inventory findings for inline scripts.
    pub inventory_dom_sinks: bool,
}

impl Default for OwaspConfig {
    fn default() -> Self {
        Self {
            headers: true,
            cookies: true,
            jwt: true,
            dom: true,
            forms: true,
            sca: true,
            ptk: None,
            observe_urls: Vec::new(),
            max_observed_responses: DEFAULT_MAX_OBSERVED_RESPONSES,
            max_findings: DEFAULT_MAX_FINDINGS,
            deduplicate: true,
            inventory_dom_sinks: true,
        }
    }
}

impl OwaspConfig {
    /// Creates a new configuration with all passive auditors enabled.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Configures optional OWASP PTK extension & `modules.json` integration.
    #[must_use]
    pub fn ptk(mut self, ptk: PtkExtensionConfig) -> Self {
        self.ptk = Some(ptk);
        self
    }

    /// Restricts passive `on_response` observation to matching URL globs.
    #[must_use]
    pub fn observe_urls<I, S>(mut self, urls: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.observe_urls = urls.into_iter().map(Into::into).collect();
        self
    }

    /// Enables or disables header/CSP/CORS auditing.
    #[must_use]
    pub fn headers(mut self, enabled: bool) -> Self {
        self.headers = enabled;
        self
    }

    /// Enables or disables cookie auditing.
    #[must_use]
    pub fn cookies(mut self, enabled: bool) -> Self {
        self.cookies = enabled;
        self
    }

    /// Enables or disables passive JWT auditing.
    #[must_use]
    pub fn jwt(mut self, enabled: bool) -> Self {
        self.jwt = enabled;
        self
    }

    /// Enables or disables passive DOM/storage auditing.
    #[must_use]
    pub fn dom(mut self, enabled: bool) -> Self {
        self.dom = enabled;
        self
    }

    /// Enables or disables passive `<form>` and `<input>` posture auditing.
    #[must_use]
    pub fn forms(mut self, enabled: bool) -> Self {
        self.forms = enabled;
        self
    }

    /// Enables or disables passive client-side SCA auditing.
    #[must_use]
    pub fn sca(mut self, enabled: bool) -> Self {
        self.sca = enabled;
        self
    }

    /// Controls finding deduplication during report generation.
    #[must_use]
    pub fn deduplicate(mut self, deduplicate: bool) -> Self {
        self.deduplicate = deduplicate;
        self
    }

    /// Validates configuration invariants before building [`OwaspPlugin`].
    fn check(&self) -> PluginResult<()> {
        if !(1..=100_000).contains(&self.max_observed_responses) {
            return Err(PluginError::Config(
                "owasp: `max_observed_responses` must be 1 to 100000".to_owned(),
            ));
        }
        if !(1..=100_000).contains(&self.max_findings) {
            return Err(PluginError::Config(
                "owasp: `max_findings` must be 1 to 100000".to_owned(),
            ));
        }
        if self.observe_urls.iter().any(|u| u.trim().is_empty()) {
            return Err(PluginError::Config(
                "owasp: `observe_urls` entries cannot be empty".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Passive HTTP response metadata recorded by [`OwaspPlugin::on_response`] or protocol events.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ObservedResponse {
    /// Request URL.
    pub url: String,
    /// HTTP status code (`0` when blocked/failed before response).
    pub status: u16,
    /// Response MIME type.
    pub mime: String,
    /// Observed headers (`name`, `value`).
    pub headers: Vec<(String, String)>,
}

/// Thread-safe collector accumulating passive network observations and findings across hooks.
#[derive(Debug)]
pub struct AuditSession {
    max_responses: usize,
    max_findings: usize,
    responses: Mutex<VecDeque<ObservedResponse>>,
    findings: Mutex<Vec<Finding>>,
    components: Mutex<Vec<DetectedComponent>>,
    observed_count: AtomicUsize,
    dropped_findings: AtomicUsize,
    ptk_modules_loaded: AtomicUsize,
    last_target_url: Mutex<Option<String>>,
}

impl Default for AuditSession {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_OBSERVED_RESPONSES, DEFAULT_MAX_FINDINGS)
    }
}

impl AuditSession {
    /// Creates a bounded thread-safe audit session collector.
    #[must_use]
    pub fn new(max_responses: usize, max_findings: usize) -> Self {
        Self {
            max_responses: max_responses.max(1),
            max_findings: max_findings.max(1),
            responses: Mutex::new(VecDeque::new()),
            findings: Mutex::new(Vec::new()),
            components: Mutex::new(Vec::new()),
            observed_count: AtomicUsize::new(0),
            dropped_findings: AtomicUsize::new(0),
            ptk_modules_loaded: AtomicUsize::new(0),
            last_target_url: Mutex::new(None),
        }
    }

    fn responses_lock(&self) -> MutexGuard<'_, VecDeque<ObservedResponse>> {
        self.responses
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn findings_lock(&self) -> MutexGuard<'_, Vec<Finding>> {
        self.findings.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn components_lock(&self) -> MutexGuard<'_, Vec<DetectedComponent>> {
        self.components
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Records a passively observed HTTP response and updates `last_target_url`.
    pub fn record_response(
        &self,
        url: String,
        status: u16,
        mime: String,
        headers: Vec<(String, String)>,
    ) {
        self.observed_count.fetch_add(1, Ordering::Relaxed);
        {
            let mut last = self
                .last_target_url
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if last.is_none() || mime.to_ascii_lowercase().contains("html") {
                *last = Some(url.clone());
            }
        }
        let mut guard = self.responses_lock();
        while guard.len() >= self.max_responses {
            guard.pop_front();
        }
        guard.push_back(ObservedResponse {
            url,
            status,
            mime,
            headers,
        });
    }

    /// Appends passive findings up to the configured session limit.
    pub fn record_findings(&self, new_findings: impl IntoIterator<Item = Finding>) {
        let mut guard = self.findings_lock();
        for finding in new_findings {
            if guard.len() < self.max_findings {
                guard.push(finding);
            } else {
                self.dropped_findings.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Records passively detected SCA components.
    pub fn record_components(&self, new_components: impl IntoIterator<Item = DetectedComponent>) {
        let mut guard = self.components_lock();
        for comp in new_components {
            if !guard
                .iter()
                .any(|c| c.name == comp.name && c.version == comp.version)
            {
                guard.push(comp);
            }
        }
    }

    /// Snapshot of all findings accumulated in this session.
    #[must_use]
    pub fn findings(&self) -> Vec<Finding> {
        self.findings_lock().clone()
    }

    /// Drains and returns all findings accumulated in this session.
    #[must_use]
    pub fn take_findings(&self) -> Vec<Finding> {
        std::mem::take(&mut *self.findings_lock())
    }

    /// Snapshot of all observed response metadata.
    #[must_use]
    pub fn observed_responses(&self) -> Vec<ObservedResponse> {
        self.responses_lock().iter().cloned().collect()
    }

    /// Total number of responses observed during this session.
    #[must_use]
    pub fn observed_count(&self) -> usize {
        self.observed_count.load(Ordering::Relaxed)
    }

    /// Count of findings dropped after reaching `max_findings`.
    #[must_use]
    pub fn dropped_findings(&self) -> usize {
        self.dropped_findings.load(Ordering::Relaxed)
    }

    /// Records the number of passive PTK modules loaded from `modules.json`.
    pub fn set_ptk_modules_loaded(&self, count: usize) {
        self.ptk_modules_loaded.store(count, Ordering::Relaxed);
    }

    /// Number of passive PTK modules loaded.
    #[must_use]
    pub fn ptk_modules_loaded(&self) -> usize {
        self.ptk_modules_loaded.load(Ordering::Relaxed)
    }

    /// Clears collected responses, findings, and components.
    pub fn clear(&self) {
        self.responses_lock().clear();
        self.findings_lock().clear();
        self.components_lock().clear();
        self.observed_count.store(0, Ordering::Relaxed);
        self.dropped_findings.store(0, Ordering::Relaxed);
        *self
            .last_target_url
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = None;
    }

    /// Compiles an [`OwaspAuditReport`] from the current session state.
    #[must_use]
    pub fn build_report(&self, target_url: Option<String>, deduplicate: bool) -> OwaspAuditReport {
        let resolved_target = target_url.or_else(|| {
            self.last_target_url
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        });
        OwaspAuditReport::from_parts(
            resolved_target,
            self.findings(),
            self.components_lock().clone(),
            self.observed_count(),
            self.ptk_modules_loaded(),
            None,
            deduplicate,
        )
    }
}

/// Optional input accepted by [`OwaspPlugin`] `Task` and `JobRunner`.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct AuditTaskInput {
    /// Optional URL to navigate to before running the active page audit.
    #[serde(alias = "target_url")]
    url: Option<String>,
    /// Optional HTTP response headers supplied directly alongside page inspection.
    headers: Option<BTreeMap<String, String>>,
    /// Optional `Set-Cookie` header lines supplied directly.
    set_cookies: Vec<String>,
    /// Optional HTML override used only when the page returns no HTML.
    html: Option<String>,
}

/// Defensive OWASP passive security auditing and OWASP PTK integration plugin.
#[derive(Debug)]
pub struct OwaspPlugin {
    config: OwaspConfig,
    interest: NetworkInterest,
    session: Arc<AuditSession>,
    ptk_status: Mutex<Option<PtkExtensionStatus>>,
}

impl Default for OwaspPlugin {
    fn default() -> Self {
        Self {
            config: OwaspConfig::default(),
            interest: NetworkInterest::none().observe(RequestFilter::any()),
            session: Arc::new(AuditSession::default()),
            ptk_status: Mutex::new(None),
        }
    }
}

impl OwaspPlugin {
    /// Builds an [`OwaspPlugin`] from `config`.
    ///
    /// # Errors
    ///
    /// Returns [`PluginError::Config`] when bounds or URL filters are invalid.
    pub fn new(config: OwaspConfig) -> PluginResult<Self> {
        config.check()?;
        let mut interest = NetworkInterest::none();
        if config.observe_urls.is_empty() {
            interest = interest.observe(RequestFilter::any());
        } else {
            for glob in &config.observe_urls {
                interest = interest.observe(RequestFilter::any().url(glob.as_str()));
            }
        }
        let session = Arc::new(AuditSession::new(
            config.max_observed_responses,
            config.max_findings,
        ));
        Ok(Self {
            config,
            interest,
            session,
            ptk_status: Mutex::new(None),
        })
    }

    /// Returns the plugin's configuration.
    #[must_use]
    pub fn config(&self) -> &OwaspConfig {
        &self.config
    }

    /// Returns the thread-safe passive [`AuditSession`] collector.
    #[must_use]
    pub fn session(&self) -> &AuditSession {
        &self.session
    }

    /// Returns the validated PTK extension status once `before_launch` or
    /// [`Self::validate_ptk`] has run.
    #[must_use]
    pub fn ptk_status(&self) -> Option<PtkExtensionStatus> {
        self.ptk_status
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Validates configured PTK extension directory/archive and `modules.json` catalog.
    ///
    /// # Errors
    ///
    /// Returns [`OwaspError`] if extension validation or catalog parsing fails.
    pub fn validate_ptk(&self) -> Result<Option<PtkExtensionStatus>> {
        let Some(ptk) = &self.config.ptk else {
            return Ok(None);
        };
        let status = ptk.validate()?;
        if let Some(catalog) = &status.catalog {
            self.session
                .set_ptk_modules_loaded(catalog.passive_modules().len());
        }
        *self
            .ptk_status
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(status.clone());
        Ok(Some(status))
    }

    /// Passively inspects an open [`PageHandle`] via [`PageHandle::evaluate`], runs all enabled
    /// auditors, merges passive network findings from [`Self::session`], and returns a complete
    /// [`OwaspAuditReport`].
    ///
    /// # Errors
    ///
    /// Returns [`OwaspError::Plugin`] if evaluating JavaScript on the page fails or lacks
    /// [`Capability::PageEvaluate`].
    pub async fn audit_page(&self, page: &dyn PageHandle) -> Result<OwaspAuditReport> {
        self.audit_page_with_input(page, &AuditTaskInput::default())
            .await
    }

    async fn audit_page_with_input(
        &self,
        page: &dyn PageHandle,
        input: &AuditTaskInput,
    ) -> Result<OwaspAuditReport> {
        let eval_reply = page.evaluate(PAGE_AUDIT_JS).await?;
        let page_url = eval_reply
            .get("url")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .or_else(|| input.url.clone());

        let resolved_url = match page_url {
            Some(u) => u,
            None => page
                .url()
                .await
                .unwrap_or_else(|_| "about:blank".to_owned()),
        };

        let mut snapshot = if eval_reply.is_object() {
            DomSnapshot::from_value(&resolved_url, &eval_reply)
        } else if let Some(html) = &input.html {
            DomSnapshot::from_html(resolved_url.clone(), html.clone())
        } else {
            DomSnapshot::new(resolved_url.clone())
        };
        if snapshot.html.is_empty()
            && let Some(html) = &input.html
        {
            let fallback = DomSnapshot::from_html(resolved_url.clone(), html.clone());
            if snapshot.scripts.is_empty() {
                snapshot.scripts = fallback.scripts;
            }
            if snapshot.stylesheets.is_empty() {
                snapshot.stylesheets = fallback.stylesheets;
            }
            if snapshot.links.is_empty() {
                snapshot.links = fallback.links;
            }
            if snapshot.comments.is_empty() {
                snapshot.comments = fallback.comments;
            }
            if snapshot.active_elements.is_empty() {
                snapshot.active_elements = fallback.active_elements;
            }
            if snapshot.passive_elements.is_empty() {
                snapshot.passive_elements = fallback.passive_elements;
            }
            if snapshot.password_inputs.is_empty() {
                snapshot.password_inputs = fallback.password_inputs;
            }
        }

        let mut findings = self.session.findings();
        let mut components = self.session.components_lock().clone();

        // Collect headers associated with this URL from passive network observation + optional input.
        let mut combined_headers: Vec<(String, String)> = Vec::new();
        for resp in self.session.observed_responses() {
            if resp.url == resolved_url {
                combined_headers.extend(resp.headers);
            }
        }
        if let Some(extra_headers) = &input.headers {
            for (k, v) in extra_headers {
                combined_headers.push((k.clone(), v.clone()));
            }
            let pairs: Vec<(String, String)> = extra_headers
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            self.run_header_pipeline(&resolved_url, 200, "text/html", true, &pairs, &mut findings);
        }
        for sc in &input.set_cookies {
            if self.config.cookies {
                let ctx = CookieAuditContext::from_url(Some(&resolved_url));
                findings.extend(audit_set_cookie(sc, &ctx));
            }
        }

        // Cookies from `document.cookie`
        if self.config.cookies
            && let Some(cookie_str) = eval_reply.get("documentCookie").and_then(Value::as_str)
            && !cookie_str.trim().is_empty()
        {
            let parsed_cookies = parse_document_cookie_str(cookie_str);
            let ctx = CookieAuditContext::from_url(Some(&resolved_url));
            findings.extend(audit_cookies(&parsed_cookies, &ctx));
        }

        // Passive DOM, storage, SRI, mixed-content, tabnabbing, postMessage audit
        if self.config.dom {
            let dom_opts = DomAuditOptions {
                inventory_dom_sinks: self.config.inventory_dom_sinks,
                audit_storage: true,
            };
            findings.extend(audit_dom(&snapshot, &dom_opts));
        }

        // Passive `<form>` and `<input>` posture audit
        if self.config.forms {
            let forms = parse_forms_from_value(&eval_reply);
            if !forms.is_empty() {
                findings.extend(audit_forms(&resolved_url, &forms));
            }
        }

        // Passive SCA library/version & EOL advisory audit
        if self.config.sca {
            let sca_res = audit_sca(&snapshot, &combined_headers);
            findings.extend(sca_res.findings);
            for comp in sca_res.components {
                if !components
                    .iter()
                    .any(|c| c.name == comp.name && c.version == comp.version)
                {
                    components.push(comp);
                }
            }
        }

        // Optional passive PTK page bridge (`window.PTK_AGENT`) findings
        let ptk_agent = if let Some(agent_val) = eval_reply.get("ptkAgent").filter(|v| !v.is_null())
        {
            let parsed = PtkAgentSnapshot::from_value(agent_val)?;
            findings.extend(parsed.to_findings());
            Some(parsed)
        } else {
            None
        };

        if !self.config.jwt {
            findings.retain(|f| f.auditor != AuditorKind::Jwt);
        }

        Ok(OwaspAuditReport::from_parts(
            Some(resolved_url),
            findings,
            components,
            self.session.observed_count(),
            self.session.ptk_modules_loaded(),
            ptk_agent,
            self.config.deduplicate,
        ))
    }

    fn run_header_pipeline(
        &self,
        url: &str,
        status: u16,
        mime: &str,
        is_document: bool,
        headers: &[(String, String)],
        out: &mut Vec<Finding>,
    ) {
        if self.config.headers {
            let req_origin = headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("origin"))
                .map(|(_, v)| v.as_str());
            let mut hdr_findings = audit_headers(&HeaderAuditContext {
                url,
                status,
                mime,
                is_document,
                headers,
                request_origin: req_origin,
            });
            if !self.config.cookies {
                hdr_findings.retain(|f| f.auditor != AuditorKind::Cookies);
            }
            if !self.config.jwt {
                hdr_findings.retain(|f| f.auditor != AuditorKind::Jwt);
            }
            out.extend(hdr_findings);
        } else if self.config.cookies {
            let cookie_ctx = CookieAuditContext::from_url(Some(url));
            for (k, v) in headers {
                if k.eq_ignore_ascii_case("set-cookie") {
                    out.extend(audit_set_cookie(v, &cookie_ctx));
                }
            }
        }
    }

    fn fresh(&self) -> Self {
        let mut ptk_modules = 0;
        if let Some(status) = self.ptk_status()
            && let Some(cat) = status.catalog
        {
            ptk_modules = cat.passive_modules().len();
        }
        let session = Arc::new(AuditSession::new(
            self.config.max_observed_responses,
            self.config.max_findings,
        ));
        session.set_ptk_modules_loaded(ptk_modules);
        Self {
            config: self.config.clone(),
            interest: self.interest.clone(),
            session,
            ptk_status: Mutex::new(self.ptk_status()),
        }
    }
}

impl Configurable for OwaspPlugin {
    const NAME: &'static str = NAME;

    fn describe() -> Metadata {
        Metadata::new(Category::Core)
            .version(env!("CARGO_PKG_VERSION"))
            .summary(
                "Defensive passive OWASP security auditing (headers, CSP, CORS, cookies, JWT, DOM, SCA) and OWASP PTK integration",
            )
            .capabilities([
                Capability::NetObserve,
                Capability::PageEvaluate,
                Capability::Task,
            ])
            .optional(Capability::NetSensitive)
            .optional(Capability::NetBodies)
            .optional(Capability::LaunchExtensions)
            .optional(Capability::PageNavigate)
            .optional(Capability::Cdp("Network".into()))
    }

    fn configure(value: &Value) -> PluginResult<Self> {
        Self::new(options::<OwaspConfig>(NAME, value)?)
    }
}

#[async_trait]
impl Plugin for OwaspPlugin {
    fn name(&self) -> &str {
        NAME
    }

    fn requirements(&self) -> Requirements {
        if self
            .config
            .ptk
            .as_ref()
            .is_some_and(|p| p.extension_dir.is_some())
        {
            Requirements::CHROMIUM_ONLY | Requirements::LAUNCH_ONLY
        } else {
            Requirements::CHROMIUM_ONLY
        }
    }

    fn metadata(&self) -> Metadata {
        let mut meta = Self::describe();
        if let Some(ptk) = &self.config.ptk {
            if ptk.extension_dir.is_some() {
                meta = meta.capability(Capability::LaunchExtensions);
            }
            let paths = ptk.declared_paths();
            if !paths.is_empty() {
                meta = meta.capability(Capability::HostFsRead(PathScope::Declared(paths)));
            }
        }
        meta
    }

    fn per_launch(&self) -> Option<Arc<dyn Plugin>> {
        Some(Arc::new(self.fresh()))
    }

    fn network(&self) -> NetworkInterest {
        self.interest.clone()
    }

    fn protocol_events(&self) -> &[&str] {
        &[
            "Network.responseReceived",
            "Network.responseReceivedExtraInfo",
        ]
    }

    fn task(&self) -> Option<&dyn Task> {
        Some(self)
    }

    fn job_runner(&self) -> Option<&dyn JobRunner> {
        Some(self)
    }

    async fn before_launch(&self, launch: &mut LaunchSettings) -> PluginResult<()> {
        let Some(ptk) = &self.config.ptk else {
            return Ok(());
        };
        if ptk.extension_dir.is_some() && asks_for_old_headless(&launch.args) {
            return Err(PluginError::other(
                "owasp: PTK extension cannot be loaded in Chrome's old headless mode (--headless=old)",
            ));
        }
        let status = ptk
            .validate_for_launch()
            .map_err(|err| PluginError::other(format!("owasp: {err}")))?;
        if let Some(dir) = &status.extension_dir
            && !launch.extensions.contains(dir)
        {
            launch.extensions.push(dir.clone());
        }
        if let Some(catalog) = &status.catalog {
            self.session
                .set_ptk_modules_loaded(catalog.passive_modules().len());
        }
        *self
            .ptk_status
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(status);
        Ok(())
    }

    async fn on_response(&self, response: &ResponseView<'_>) -> PluginResult<()> {
        let pairs: Vec<(String, String)> = response
            .request
            .headers
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        self.session.record_response(
            response.request.url.clone(),
            response.status,
            response.mime.to_owned(),
            pairs.clone(),
        );

        let mut findings = Vec::new();
        let is_document = response.request.kind == ResourceKind::Document;
        self.run_header_pipeline(
            &response.request.url,
            response.status,
            response.mime,
            is_document,
            &pairs,
            &mut findings,
        );

        if self.config.sca && !pairs.is_empty() {
            let empty_snap = DomSnapshot::new(response.request.url.clone());
            let sca_res = audit_sca(&empty_snap, &pairs);
            findings.extend(sca_res.findings);
            self.session.record_components(sca_res.components);
        }

        if !self.config.jwt {
            findings.retain(|f| f.auditor != AuditorKind::Jwt);
        }
        self.session.record_findings(findings);
        Ok(())
    }

    async fn on_protocol_event(
        &self,
        _browser: &dyn BrowserHandle,
        event: &ProtocolEvent,
    ) -> PluginResult<()> {
        match event.method.as_str() {
            "Network.responseReceived" => {
                let resp = &event.params["response"];
                let Some(url) = resp["url"].as_str() else {
                    return Ok(());
                };
                let status = resp["status"]
                    .as_u64()
                    .and_then(|s| u16::try_from(s).ok())
                    .unwrap_or(0);
                let mime = resp["mimeType"].as_str().unwrap_or("");
                let is_document = event.params["type"]
                    .as_str()
                    .is_some_and(|t| t.eq_ignore_ascii_case("Document"));
                let headers = extract_cdp_header_pairs(&resp["headers"]);
                self.session.record_response(
                    url.to_owned(),
                    status,
                    mime.to_owned(),
                    headers.clone(),
                );
                let mut findings = Vec::new();
                self.run_header_pipeline(url, status, mime, is_document, &headers, &mut findings);
                self.session.record_findings(findings);
            }
            "Network.responseReceivedExtraInfo" => {
                let headers = extract_cdp_header_pairs(&event.params["headers"]);
                if headers.is_empty() {
                    return Ok(());
                }
                let url = self
                    .session
                    .last_target_url
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .clone();
                if self.config.cookies {
                    let ctx = CookieAuditContext::from_url(url.as_deref());
                    let mut findings = Vec::new();
                    for (k, v) in &headers {
                        if k.eq_ignore_ascii_case("set-cookie") {
                            for line in v.lines() {
                                if !line.trim().is_empty() {
                                    findings.extend(audit_set_cookie(line, &ctx));
                                }
                            }
                        }
                    }
                    self.session.record_findings(findings);
                }
            }
            _ => {}
        }
        Ok(())
    }
}

#[async_trait]
impl JobRunner for OwaspPlugin {
    async fn run_job(&self, page: &dyn PageHandle, job: &Value) -> PluginResult<Value> {
        let input = parse_task_input(job)?;
        if let Some(url) = &input.url {
            page.navigate(url).await?;
        }
        let report = self
            .audit_page_with_input(page, &input)
            .await
            .map_err(to_plugin_error)?;
        serde_json::to_value(&report)
            .map_err(|err| PluginError::other(format!("owasp: failed to serialize report: {err}")))
    }
}

#[async_trait]
impl Task for OwaspPlugin {
    async fn run(&self, cx: &TaskContext<'_>) -> PluginResult<Value> {
        let input = parse_task_input(cx.input)?;
        let browser = cx.plugins.guarded_browser(NAME, cx.browser)?;
        let page = browser.new_page(None).await?;

        let audit_res = async {
            if let Some(url) = &input.url {
                page.navigate(url).await?;
            }
            self.audit_page_with_input(&*page, &input)
                .await
                .map_err(to_plugin_error)
        }
        .await;

        let _ = page.close().await;
        let report = audit_res?;

        for finding in &report.findings {
            let line = serde_json::to_value(finding).map_err(|err| {
                PluginError::other(format!("owasp: failed to serialize finding: {err}"))
            })?;
            cx.sink.record(&line)?;
        }

        serde_json::to_value(&report)
            .map_err(|err| PluginError::other(format!("owasp: failed to serialize report: {err}")))
    }
}

fn parse_task_input(value: &Value) -> PluginResult<AuditTaskInput> {
    if value.is_null() {
        return Ok(AuditTaskInput::default());
    }
    let input: AuditTaskInput = options(NAME, value)?;
    if let Some(url) = &input.url {
        let lower = url.trim().to_ascii_lowercase();
        if !lower.starts_with("http://") && !lower.starts_with("https://") {
            return Err(PluginError::Config(format!(
                "owasp: `url` must use http:// or https://, got `{url}`"
            )));
        }
    }
    Ok(input)
}

fn to_plugin_error(err: OwaspError) -> PluginError {
    match err {
        OwaspError::Plugin(p) => p,
        OwaspError::Config(msg) => PluginError::Config(msg),
        other => PluginError::other(format!("owasp: {other}")),
    }
}

fn asks_for_old_headless(args: &[String]) -> bool {
    args.iter()
        .any(|arg| arg.trim_start_matches('-') == "headless=old")
}

fn parse_document_cookie_str(raw: &str) -> Vec<CookieInput> {
    raw.split(';')
        .filter_map(|pair| {
            let trimmed = pair.trim();
            let (name, value) = trimmed.split_once('=')?;
            let clean_name = name.trim();
            if clean_name.is_empty() {
                return None;
            }
            Some(CookieInput::from_document_cookie(clean_name, value.trim()))
        })
        .collect()
}

fn extract_cdp_header_pairs(headers_val: &Value) -> Vec<(String, String)> {
    let Some(obj) = headers_val.as_object() else {
        return Vec::new();
    };
    let mut pairs = Vec::new();
    for (k, v) in obj {
        if let Some(s) = v.as_str() {
            if k.eq_ignore_ascii_case("set-cookie") && s.contains('\n') {
                for line in s.lines() {
                    if !line.trim().is_empty() {
                        pairs.push((k.clone(), line.trim().to_owned()));
                    }
                }
            } else {
                pairs.push((k.clone(), s.to_owned()));
            }
        }
    }
    pairs
}
