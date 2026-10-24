//! Network hooks: what a plugin declares about requests, and the views it gets.
//!
//! The host owns interception. A plugin states what it cares about in
//! [`Plugin::network`](crate::Plugin::network) as a [`NetworkInterest`]:
//!
//! - `rules` are run by the host and the plugin is never called: block a URL,
//!   or add request headers. They are the cheap way and the only way a plugin
//!   written without code can use.
//! - `observe` filters name the responses [`Plugin::on_response`](crate::Plugin::on_response)
//!   sees. It never changes anything.
//! - `intercept` filters name the requests [`Plugin::on_request`](crate::Plugin::on_request)
//!   may block.
//!
//! The host asks [`PluginSet::interest`] which requests to pause at all, so
//! Chrome stops only the matching ones. What a plugin may declare follows its
//! capabilities: rules and intercept filters need [`Capability::NetIntercept`],
//! observe filters [`Capability::NetObserve`], response bodies
//! [`Capability::NetBodies`], and `Cookie`, `Authorization`,
//! `Proxy-Authorization` and `Set-Cookie` headers [`Capability::NetSensitive`];
//! without it their values read `[redacted]`.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use crate::{BrowserHandle, Capability, ContextId, Entry, PageId, PluginError, PluginSet, Risk};

/// What a request is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ResourceKind {
    /// A page or frame.
    Document,
    /// A stylesheet.
    Stylesheet,
    /// An image.
    Image,
    /// Audio or video.
    Media,
    /// A web font.
    Font,
    /// A script.
    Script,
    /// An `XMLHttpRequest`.
    Xhr,
    /// A `fetch()` call.
    Fetch,
    /// A WebSocket handshake.
    WebSocket,
    /// Anything else.
    Other,
}

/// Which requests a rule or a hook is for. A filter that says nothing matches
/// every request; each field that is set narrows it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct RequestFilter {
    /// A glob over the whole URL: `*` matches any run of characters and `?`
    /// one character. `None` matches every URL.
    pub url: Option<String>,
    /// The kinds of resource; empty matches every kind.
    pub kinds: Vec<ResourceKind>,
    /// The HTTP methods, compared without regard to case; empty matches all.
    pub methods: Vec<String>,
    /// For `observe` filters: the most response-body bytes the plugin wants.
    /// `None` means no body. It only matters to plugins that hold
    /// [`Capability::NetBodies`].
    pub max_body: Option<usize>,
}

impl RequestFilter {
    /// A filter that matches every request.
    #[must_use]
    pub fn any() -> Self {
        Self::default()
    }

    /// Narrows the filter to URLs that match `glob`.
    #[must_use]
    pub fn url(mut self, glob: impl Into<String>) -> Self {
        self.url = Some(glob.into());
        self
    }

    /// Narrows the filter to these kinds of resource.
    #[must_use]
    pub fn kinds(mut self, kinds: impl IntoIterator<Item = ResourceKind>) -> Self {
        self.kinds = kinds.into_iter().collect();
        self
    }

    /// Narrows the filter to these HTTP methods.
    #[must_use]
    pub fn methods<I, S>(mut self, methods: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.methods = methods.into_iter().map(Into::into).collect();
        self
    }

    /// Asks for up to `bytes` of each response body.
    #[must_use]
    pub fn max_body(mut self, bytes: usize) -> Self {
        self.max_body = Some(bytes);
        self
    }

    /// Whether `request` is one the filter selects.
    #[must_use]
    pub fn matches(&self, request: &RequestView) -> bool {
        self.url
            .as_deref()
            .is_none_or(|glob| glob_match(glob, &request.url))
            && (self.kinds.is_empty() || self.kinds.contains(&request.kind))
            && (self.methods.is_empty()
                || self
                    .methods
                    .iter()
                    .any(|method| method.eq_ignore_ascii_case(&request.method)))
    }
}

/// What the host does with a request a rule matches.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RuleAction {
    /// Fail the request.
    Block,
    /// Add these headers to the request.
    SetHeaders(BTreeMap<String, String>),
}

/// A rule the host runs without calling the plugin.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct NetRule {
    /// The requests it applies to.
    pub filter: RequestFilter,
    /// What to do with them.
    pub action: RuleAction,
}

impl NetRule {
    /// A rule that blocks the requests `filter` selects.
    #[must_use]
    pub fn block(filter: RequestFilter) -> Self {
        Self {
            filter,
            action: RuleAction::Block,
        }
    }

    /// A rule that adds `headers` to the requests `filter` selects.
    #[must_use]
    pub fn set_headers<I, K, V>(filter: RequestFilter, headers: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        Self {
            filter,
            action: RuleAction::SetHeaders(
                headers
                    .into_iter()
                    .map(|(k, v)| (k.into(), v.into()))
                    .collect(),
            ),
        }
    }
}

/// What a plugin wants to know about the network.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct NetworkInterest {
    /// Rules the host runs; the plugin is never called for them.
    pub rules: Vec<NetRule>,
    /// Requests whose responses go to [`Plugin::on_response`](crate::Plugin::on_response).
    pub observe: Vec<RequestFilter>,
    /// Requests that go to [`Plugin::on_request`](crate::Plugin::on_request).
    pub intercept: Vec<RequestFilter>,
}

impl NetworkInterest {
    /// No interest in the network. This is the default.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// Whether nothing is declared.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty() && self.observe.is_empty() && self.intercept.is_empty()
    }

    /// Adds a rule.
    #[must_use]
    pub fn rule(mut self, rule: NetRule) -> Self {
        self.rules.push(rule);
        self
    }

    /// Adds a filter for the responses to observe.
    #[must_use]
    pub fn observe(mut self, filter: RequestFilter) -> Self {
        self.observe.push(filter);
        self
    }

    /// Adds a filter for the requests to intercept.
    #[must_use]
    pub fn intercept(mut self, filter: RequestFilter) -> Self {
        self.intercept.push(filter);
        self
    }
}

/// A request, as a plugin sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct RequestView {
    /// The address.
    pub url: String,
    /// The HTTP method, such as `GET`.
    pub method: String,
    /// What the request is for.
    pub kind: ResourceKind,
    /// The request headers. Sensitive ones are redacted unless the plugin holds
    /// [`Capability::NetSensitive`].
    pub headers: BTreeMap<String, String>,
    /// Whether the request loads a document the page navigates to.
    pub navigation: bool,
    /// The tab that sent it, when the host knows.
    pub page: Option<PageId>,
    /// The context of that tab, when it has one.
    pub context: Option<ContextId>,
}

/// The value that stands in for a header the plugin may not read.
pub const REDACTED: &str = "[redacted]";

const SENSITIVE_HEADERS: [&str; 4] = [
    "cookie",
    "authorization",
    "proxy-authorization",
    "set-cookie",
];

impl RequestView {
    /// A `GET`-style request for `url` of `kind`, with no headers.
    #[must_use]
    pub fn new(url: impl Into<String>, method: impl Into<String>, kind: ResourceKind) -> Self {
        Self {
            url: url.into(),
            method: method.into(),
            kind,
            headers: BTreeMap::new(),
            navigation: false,
            page: None,
            context: None,
        }
    }

    /// Adds a header.
    #[must_use]
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(name.into(), value.into());
        self
    }

    /// Marks the request as a navigation.
    #[must_use]
    pub fn navigation(mut self, navigation: bool) -> Self {
        self.navigation = navigation;
        self
    }

    /// Sets the tab that sent it.
    #[must_use]
    pub fn page(mut self, page: PageId) -> Self {
        self.page = Some(page);
        self
    }

    /// Sets the context of the tab.
    #[must_use]
    pub fn context(mut self, context: ContextId) -> Self {
        self.context = Some(context);
        self
    }

    /// A copy whose sensitive header values read [`REDACTED`].
    #[must_use]
    pub fn redacted(&self) -> Self {
        let mut copy = self.clone();
        for (name, value) in &mut copy.headers {
            if is_sensitive(name) {
                REDACTED.clone_into(value);
            }
        }
        copy
    }

    fn has_sensitive_headers(&self) -> bool {
        self.headers.keys().any(|name| is_sensitive(name))
    }
}

fn is_sensitive(name: &str) -> bool {
    SENSITIVE_HEADERS
        .iter()
        .any(|sensitive| sensitive.eq_ignore_ascii_case(name))
}

/// The request as `entry` may see it.
fn view_for<'a>(entry: &Entry, request: &'a RequestView) -> Cow<'a, RequestView> {
    if entry.grants.covers(&Capability::NetSensitive) || !request.has_sensitive_headers() {
        Cow::Borrowed(request)
    } else {
        Cow::Owned(request.redacted())
    }
}

/// What a plugin decides about a request.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RequestDecision {
    /// Let it go.
    Continue,
    /// Fail the request; the message says why.
    Block(String),
}

/// How a request ended.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Outcome {
    /// It got a response.
    Ok,
    /// The network failed it.
    Failed,
    /// A plugin or the host blocked it.
    Blocked {
        /// Who blocked it.
        by: String,
    },
}

/// A response, as a plugin sees it.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ResponseView<'a> {
    /// The request it answers.
    pub request: &'a RequestView,
    /// The HTTP status; `0` when there was no response.
    pub status: u16,
    /// The MIME type, such as `text/html`.
    pub mime: &'a str,
    /// The body, only for a plugin that holds [`Capability::NetBodies`] and an
    /// observe filter with a `max_body`, and cut to that size.
    pub body: Option<&'a [u8]>,
    /// Whether the body was cut.
    pub truncated: bool,
    /// How the request ended.
    pub outcome: Outcome,
}

impl<'a> ResponseView<'a> {
    /// A response with `status` and `mime` type to `request`, with no body.
    #[must_use]
    pub fn new(request: &'a RequestView, status: u16, mime: &'a str) -> Self {
        Self {
            request,
            status,
            mime,
            body: None,
            truncated: false,
            outcome: Outcome::Ok,
        }
    }

    /// Sets the body the host read.
    #[must_use]
    pub fn body(mut self, body: &'a [u8]) -> Self {
        self.body = Some(body);
        self
    }

    /// Marks the body as already cut by the host.
    #[must_use]
    pub fn truncated(mut self, truncated: bool) -> Self {
        self.truncated = truncated;
        self
    }

    /// Sets how the request ended.
    #[must_use]
    pub fn outcome(mut self, outcome: Outcome) -> Self {
        self.outcome = outcome;
        self
    }
}

/// A Chrome DevTools Protocol event, for the plugins that asked for its name in
/// [`Plugin::protocol_events`](crate::Plugin::protocol_events).
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct ProtocolEvent {
    /// The event name, such as `Log.entryAdded`.
    pub method: String,
    /// Its parameters.
    pub params: Value,
}

impl ProtocolEvent {
    /// The event `method` with `params`.
    #[must_use]
    pub fn new(method: impl Into<String>, params: Value) -> Self {
        Self {
            method: method.into(),
            params,
        }
    }
}

/// Whether `entry` may receive events named `method`. Events of the `Target`
/// and `Browser` domains name other tabs and need the matching capability.
fn event_allowed(entry: &Entry, method: &str) -> bool {
    let domain = method.split('.').next().unwrap_or_default();
    let capability = Capability::Cdp(Cow::Owned(domain.to_owned()));
    capability.risk() != Risk::Critical || entry.grants.covers(&capability)
}

impl PluginSet {
    /// What the host has to watch for: the plugins' declarations merged, in run
    /// order, and cut down to what each plugin may use.
    ///
    /// - `rules` are those of plugins that hold [`Capability::NetIntercept`],
    ///   blocking rules first.
    /// - `intercept` filters are those of the same plugins.
    /// - `observe` filters are those of plugins that hold
    ///   [`Capability::NetObserve`]; the `max_body` of a plugin without
    ///   [`Capability::NetBodies`] is dropped.
    #[must_use]
    pub fn interest(&self) -> NetworkInterest {
        let mut blocking = Vec::new();
        let mut other = Vec::new();
        let mut merged = NetworkInterest::none();
        for entry in self.ordered() {
            let declared = &entry.interest;
            if entry.grants.covers(&Capability::NetIntercept) {
                for rule in &declared.rules {
                    if matches!(rule.action, RuleAction::Block) {
                        blocking.push(rule.clone());
                    } else {
                        other.push(rule.clone());
                    }
                }
                merged.intercept.extend(declared.intercept.iter().cloned());
            }
            if entry.grants.covers(&Capability::NetObserve) {
                let bodies = entry.grants.covers(&Capability::NetBodies);
                for filter in &declared.observe {
                    let mut filter = filter.clone();
                    if !bodies {
                        filter.max_body = None;
                    }
                    merged.observe.push(filter);
                }
            }
        }
        blocking.append(&mut other);
        merged.rules = blocking;
        merged
    }

    /// The event names the host has to deliver: those the plugins asked for in
    /// [`Plugin::protocol_events`](crate::Plugin::protocol_events), sorted,
    /// without the `Target` and `Browser` events of a plugin that does not hold
    /// the matching `cdp:` capability.
    #[must_use]
    pub fn protocol_events(&self) -> Vec<String> {
        let mut names = BTreeSet::new();
        for entry in self.ordered() {
            for name in entry.plugin.protocol_events() {
                if event_allowed(entry, name) {
                    names.insert((*name).to_owned());
                }
            }
        }
        names.into_iter().collect()
    }

    /// Decides what happens to a request the host paused. Deny overrides: any
    /// block wins, whatever the order, so the result does not depend on it.
    ///
    /// For each plugin that holds [`Capability::NetIntercept`], in run order, a
    /// blocking rule that matches blocks the request, and so does
    /// [`Plugin::on_request`](crate::Plugin::on_request) when one of the
    /// plugin's `intercept` filters matches. A hook that fails blocks too: the
    /// request does not go through a plugin that could not look at it. The
    /// message of the [`RequestDecision::Block`] starts with the name of the
    /// first plugin, in run order, that blocked.
    pub async fn on_request(&self, request: &RequestView) -> RequestDecision {
        let mut blocked: Option<String> = None;
        for entry in self.holding(&Capability::NetIntercept) {
            let name = entry.plugin.name();
            let by_rule = entry.interest.rules.iter().any(|rule| {
                matches!(rule.action, RuleAction::Block) && rule.filter.matches(request)
            });
            if by_rule && blocked.is_none() {
                blocked = Some(format!("{name}: blocked by a network rule"));
            }
            if entry.interest.intercept.iter().any(|f| f.matches(request)) {
                let view = view_for(entry, request);
                let result = self
                    .run_hook(entry, "on_request", entry.plugin.on_request(&view))
                    .await;
                let reason = match result {
                    Ok(RequestDecision::Continue) => None,
                    Ok(RequestDecision::Block(reason)) => Some(format!("{name}: {reason}")),
                    Err(error) => Some(error.to_string()),
                };
                if blocked.is_none() {
                    blocked = reason;
                }
            }
        }
        blocked.map_or(RequestDecision::Continue, RequestDecision::Block)
    }

    /// The headers the `SetHeaders` rules of plugins that hold
    /// [`Capability::NetIntercept`] add to a request. A later plugin's value
    /// wins over an earlier one's for the same name.
    #[must_use]
    pub fn extra_headers(&self, request: &RequestView) -> BTreeMap<String, String> {
        let mut headers = BTreeMap::new();
        for entry in self.holding(&Capability::NetIntercept) {
            for rule in &entry.interest.rules {
                if let RuleAction::SetHeaders(set) = &rule.action
                    && rule.filter.matches(request)
                {
                    headers.extend(set.iter().map(|(k, v)| (k.clone(), v.clone())));
                }
            }
        }
        headers
    }

    /// Gives a response to each plugin that holds [`Capability::NetObserve`]
    /// and has an `observe` filter that matches its request. The body reaches
    /// only plugins that hold [`Capability::NetBodies`], cut to the largest
    /// `max_body` of the filters that matched. Every plugin runs even when one
    /// fails; the failures are returned for the caller to log.
    pub async fn on_response(&self, response: &ResponseView<'_>) -> Vec<PluginError> {
        let mut failures = Vec::new();
        for entry in self.holding(&Capability::NetObserve) {
            let wanted: Vec<&RequestFilter> = entry
                .interest
                .observe
                .iter()
                .filter(|filter| filter.matches(response.request))
                .collect();
            if wanted.is_empty() {
                continue;
            }
            let cap = if entry.grants.covers(&Capability::NetBodies) {
                wanted.iter().filter_map(|filter| filter.max_body).max()
            } else {
                None
            };
            let (body, truncated) = match (response.body, cap) {
                (Some(body), Some(max)) if body.len() > max => (Some(&body[..max]), true),
                (Some(body), Some(_)) => (Some(body), response.truncated),
                _ => (None, false),
            };
            let request = view_for(entry, response.request);
            let view = ResponseView {
                request: &request,
                status: response.status,
                mime: response.mime,
                body,
                truncated,
                outcome: response.outcome.clone(),
            };
            if let Err(error) = self
                .run_hook(entry, "on_response", entry.plugin.on_response(&view))
                .await
            {
                failures.push(error);
            }
        }
        failures
    }

    /// Gives a protocol event to each plugin that asked for its name. Every
    /// plugin runs even when one fails; the failures are returned for the
    /// caller to log.
    pub async fn on_protocol_event(
        &self,
        browser: &dyn BrowserHandle,
        event: &ProtocolEvent,
    ) -> Vec<PluginError> {
        let mut failures = Vec::new();
        for entry in self.ordered() {
            if !entry
                .plugin
                .protocol_events()
                .contains(&event.method.as_str())
                || !event_allowed(entry, &event.method)
            {
                continue;
            }
            if let Err(error) = self
                .run_hook(
                    entry,
                    "on_protocol_event",
                    entry.plugin.on_protocol_event(browser, event),
                )
                .await
            {
                failures.push(error);
            }
        }
        failures
    }
}

/// Whether `text` matches `pattern`, where `*` stands for any run of
/// characters (also none) and `?` for exactly one.
fn glob_match(pattern: &str, text: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let text: Vec<char> = text.chars().collect();
    let (mut p, mut t) = (0, 0);
    let mut star: Option<usize> = None;
    let mut mark = 0;
    while t < text.len() {
        if p < pattern.len() && (pattern[p] == '?' || pattern[p] == text[t]) {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star = Some(p);
            mark = t;
            p += 1;
        } else if let Some(s) = star {
            p = s + 1;
            mark += 1;
            t = mark;
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|c| *c == '*')
}

#[cfg(test)]
mod tests {
    use super::glob_match;

    #[test]
    fn globs_match_stars_and_question_marks() {
        for (pattern, text, expected) in [
            ("*", "", true),
            ("*", "https://a.test/x", true),
            ("https://a.test/*", "https://a.test/x/y", true),
            ("https://a.test/*", "https://b.test/x", false),
            ("*.png", "https://a.test/i.png", true),
            ("*.png", "https://a.test/i.png?x=1", false),
            ("*.png*", "https://a.test/i.png?x=1", true),
            ("a?c", "abc", true),
            ("a?c", "ac", false),
            ("a*b*c", "aXbYbZc", true),
            ("a*b*c", "aXbYbZ", false),
            ("", "", true),
            ("", "a", false),
            ("**", "a", true),
        ] {
            assert_eq!(glob_match(pattern, text), expected, "{pattern} vs {text}");
        }
    }
}
