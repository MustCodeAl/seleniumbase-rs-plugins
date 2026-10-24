//! Network declarations and the request and response hooks.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use seleniumbase_rs_plugin::{
    BrowserFamily, Capability, Category, Engine, HostInfo, LaunchContext, Metadata, NetRule,
    NetworkInterest, Outcome, Plugin, PluginError, PluginSet, REDACTED, RequestDecision,
    RequestFilter, RequestView, ResourceKind, ResponseView, Result, async_trait,
};
use seleniumbase_rs_plugin_testing::{block_on, drive_request, drive_response};

type Log = Arc<Mutex<Vec<String>>>;

/// A plugin with a network declaration and canned answers.
struct Net {
    name: &'static str,
    caps: Vec<Capability>,
    interest: NetworkInterest,
    decision: RequestDecision,
    fail: bool,
    log: Log,
}

impl Net {
    fn new(name: &'static str, log: &Log) -> Self {
        Self {
            name,
            caps: Vec::new(),
            interest: NetworkInterest::none(),
            decision: RequestDecision::Continue,
            fail: false,
            log: Arc::clone(log),
        }
    }

    fn caps(mut self, caps: impl IntoIterator<Item = Capability>) -> Self {
        self.caps.extend(caps);
        self
    }

    fn interest(mut self, interest: NetworkInterest) -> Self {
        self.interest = interest;
        self
    }

    fn decide(mut self, decision: RequestDecision) -> Self {
        self.decision = decision;
        self
    }
}

#[async_trait]
impl Plugin for Net {
    fn name(&self) -> &str {
        self.name
    }
    fn metadata(&self) -> Metadata {
        Metadata::new(Category::Core).capabilities(self.caps.clone())
    }
    fn network(&self) -> NetworkInterest {
        self.interest.clone()
    }
    async fn on_request(&self, request: &RequestView) -> Result<RequestDecision> {
        let cookie = request.headers.get("Cookie").cloned().unwrap_or_default();
        self.log.lock().unwrap().push(format!(
            "{}:request {} cookie={cookie}",
            self.name, request.url
        ));
        if self.fail {
            return Err(PluginError::other("could not look"));
        }
        Ok(self.decision.clone())
    }
    async fn on_response(&self, response: &ResponseView<'_>) -> Result<()> {
        let body = response.body.map_or_else(
            || "none".to_owned(),
            |b| String::from_utf8_lossy(b).into_owned(),
        );
        self.log.lock().unwrap().push(format!(
            "{}:response {} body={body} truncated={} cookie={}",
            self.name,
            response.status,
            response.truncated,
            response
                .request
                .headers
                .get("Cookie")
                .cloned()
                .unwrap_or_default()
        ));
        if self.fail {
            return Err(PluginError::other("could not read"));
        }
        Ok(())
    }
}

fn log() -> Log {
    Log::default()
}

fn entries(log: &Log) -> Vec<String> {
    log.lock().unwrap().clone()
}

fn get(url: &str) -> RequestView {
    RequestView::new(url, "GET", ResourceKind::Document)
}

fn intercept_all() -> NetworkInterest {
    NetworkInterest::none().intercept(RequestFilter::any())
}

// ---- filters ------------------------------------------------------------

#[test]
fn a_filter_that_says_nothing_matches_everything_and_each_field_narrows_it() {
    let image = RequestView::new("https://a.test/i.png", "get", ResourceKind::Image);
    assert!(RequestFilter::any().matches(&image));
    assert!(RequestFilter::any().url("https://a.test/*").matches(&image));
    assert!(!RequestFilter::any().url("https://b.test/*").matches(&image));
    assert!(
        RequestFilter::any()
            .kinds([ResourceKind::Image])
            .matches(&image)
    );
    assert!(
        !RequestFilter::any()
            .kinds([ResourceKind::Script, ResourceKind::Font])
            .matches(&image)
    );
    // Methods compare without regard to case.
    assert!(RequestFilter::any().methods(["GET"]).matches(&image));
    assert!(!RequestFilter::any().methods(["POST"]).matches(&image));
    assert!(
        RequestFilter::any()
            .url("*.png")
            .kinds([ResourceKind::Image])
            .methods(["get", "head"])
            .matches(&image)
    );
}

#[test]
fn sensitive_headers_are_redacted_by_name_without_regard_to_case() {
    let view = get("https://a.test/")
        .header("cookie", "sid=1")
        .header("Authorization", "Bearer x")
        .header("PROXY-AUTHORIZATION", "Basic y")
        .header("Set-Cookie", "a=b")
        .header("Accept", "text/html")
        .redacted();
    assert_eq!(view.headers["cookie"], REDACTED);
    assert_eq!(view.headers["Authorization"], REDACTED);
    assert_eq!(view.headers["PROXY-AUTHORIZATION"], REDACTED);
    assert_eq!(view.headers["Set-Cookie"], REDACTED);
    assert_eq!(view.headers["Accept"], "text/html");
}

// ---- interest -----------------------------------------------------------

fn full_interest() -> NetworkInterest {
    NetworkInterest::none()
        .rule(NetRule::set_headers(
            RequestFilter::any(),
            [("X-Test", "1")],
        ))
        .rule(NetRule::block(RequestFilter::any().url("*.gif")))
        .observe(
            RequestFilter::any()
                .kinds([ResourceKind::Document])
                .max_body(64),
        )
        .intercept(RequestFilter::any().url("https://api.test/*"))
}

#[test]
fn interest_is_merged_with_blocking_rules_first() {
    let log = log();
    let rules = |name, url| {
        Net::new(name, &log)
            .caps([Capability::NetIntercept])
            .interest(NetworkInterest::none().rule(NetRule::block(RequestFilter::any().url(url))))
    };
    let set = PluginSet::new()
        .with(
            Net::new("headers", &log)
                .caps([Capability::NetIntercept])
                .interest(
                    NetworkInterest::none()
                        .rule(NetRule::set_headers(RequestFilter::any(), [("X", "1")])),
                ),
        )
        .unwrap()
        .with(rules("a", "*.png"))
        .unwrap()
        .with(rules("b", "*.gif"))
        .unwrap();
    let merged = set.interest();
    assert_eq!(merged.rules.len(), 3);
    let urls: Vec<_> = merged
        .rules
        .iter()
        .map(|rule| rule.filter.url.clone())
        .collect();
    assert_eq!(
        urls,
        [Some("*.png".to_owned()), Some("*.gif".to_owned()), None]
    );
}

#[test]
fn interest_is_cut_down_to_what_each_plugin_may_use() {
    let log = log();
    let set = PluginSet::new()
        // Nothing granted: nothing declared counts.
        .with(Net::new("none", &log).interest(full_interest()))
        .unwrap()
        // Observe only, no bodies.
        .with(
            Net::new("observer", &log)
                .caps([Capability::NetObserve])
                .interest(full_interest()),
        )
        .unwrap()
        // Observe with bodies.
        .with(
            Net::new("reader", &log)
                .caps([Capability::NetObserve, Capability::NetBodies])
                .interest(full_interest()),
        )
        .unwrap();
    let merged = set.interest();
    assert!(merged.rules.is_empty() && merged.intercept.is_empty());
    let bodies: Vec<_> = merged.observe.iter().map(|f| f.max_body).collect();
    assert_eq!(bodies, [None, Some(64)]);
}

#[test]
fn a_plugin_with_intercept_contributes_rules_and_filters() {
    let log = log();
    let set = PluginSet::new()
        .with(
            Net::new("fetcher", &log)
                .caps([Capability::NetIntercept])
                .interest(full_interest()),
        )
        .unwrap();
    let merged = set.interest();
    assert_eq!(merged.rules.len(), 2);
    assert_eq!(merged.intercept.len(), 1);
    assert!(merged.observe.is_empty());
}

#[test]
fn check_refuses_declarations_the_plugin_may_not_make() {
    let launch = LaunchContext {
        engine: Engine::Cdp,
        family: BrowserFamily::Chromium,
        headless: true,
        connecting: false,
    };
    let log = log();
    let observing = NetworkInterest::none().observe(RequestFilter::any());
    let intercepting = NetworkInterest::none().rule(NetRule::block(RequestFilter::any()));
    for (interest, needed) in [(observing, "net.observe"), (intercepting, "net.intercept")] {
        // Declared in `network()` but not in the metadata, so not granted.
        let set = PluginSet::new()
            .with(Net::new("sneaky", &log).interest(interest.clone()))
            .unwrap();
        let error = set.check(&launch).unwrap_err();
        assert!(
            matches!(&error, PluginError::Capability { capability, .. } if capability == needed),
            "{needed}: {error:?}"
        );
        // Declared and granted: fine on CDP, refused on WebDriver.
        let capability: Capability = needed.parse().unwrap();
        let set = PluginSet::new()
            .with(
                Net::new("honest", &log)
                    .caps([capability])
                    .interest(interest),
            )
            .unwrap();
        set.check(&launch).unwrap();
        let error = set
            .check_with(&launch, &HostInfo::webdriver(BrowserFamily::Chromium))
            .unwrap_err();
        assert!(
            matches!(error, PluginError::Unsupported { .. }),
            "{error:?}"
        );
    }
}

// ---- on_request ---------------------------------------------------------

#[test]
fn a_request_goes_through_when_no_plugin_blocks_it() {
    let log = log();
    let set = PluginSet::new()
        .with(
            Net::new("a", &log)
                .caps([Capability::NetIntercept])
                .interest(intercept_all()),
        )
        .unwrap();
    assert_eq!(
        drive_request(&set, get("https://x.test/")),
        RequestDecision::Continue
    );
    assert_eq!(entries(&log), ["a:request https://x.test/ cookie="]);
}

#[test]
fn any_block_wins_whatever_the_order_and_names_the_first_plugin_that_blocked() {
    for blocker_first in [true, false] {
        let log = log();
        let blocker = |name| {
            Net::new(name, &log)
                .caps([Capability::NetIntercept])
                .interest(intercept_all())
                .decide(RequestDecision::Block("no ads".into()))
        };
        let allower = Net::new("allower", &log)
            .caps([Capability::NetIntercept])
            .interest(intercept_all());
        let set = if blocker_first {
            PluginSet::new()
                .with(blocker("blocker"))
                .unwrap()
                .with(allower)
                .unwrap()
        } else {
            PluginSet::new()
                .with(allower)
                .unwrap()
                .with(blocker("blocker"))
                .unwrap()
        };
        assert_eq!(
            drive_request(&set, get("https://x.test/")),
            RequestDecision::Block("blocker: no ads".into()),
            "blocker_first = {blocker_first}"
        );
        // Everyone is asked, so observers do not miss requests.
        assert_eq!(entries(&log).len(), 2);
    }
}

#[test]
fn a_hook_that_fails_blocks_the_request() {
    let log = log();
    let mut failing = Net::new("flaky", &log)
        .caps([Capability::NetIntercept])
        .interest(intercept_all());
    failing.fail = true;
    let set = PluginSet::new().with(failing).unwrap();
    let RequestDecision::Block(reason) = drive_request(&set, get("https://x.test/")) else {
        panic!("a failing on_request must block");
    };
    assert!(
        reason.contains("flaky")
            && reason.contains("on_request")
            && reason.contains("could not look"),
        "{reason}"
    );
}

#[test]
fn a_blocking_rule_blocks_without_calling_the_plugin() {
    let log = log();
    let set = PluginSet::new()
        .with(
            Net::new("rules", &log)
                .caps([Capability::NetIntercept])
                .interest(
                    NetworkInterest::none().rule(NetRule::block(RequestFilter::any().url("*.gif"))),
                ),
        )
        .unwrap();
    assert_eq!(
        drive_request(&set, get("https://x.test/a.gif")),
        RequestDecision::Block("rules: blocked by a network rule".into())
    );
    assert_eq!(
        drive_request(&set, get("https://x.test/a.png")),
        RequestDecision::Continue
    );
    assert!(entries(&log).is_empty());
}

#[test]
fn only_plugins_whose_intercept_filter_matches_are_asked() {
    let log = log();
    let set = PluginSet::new()
        .with(
            Net::new("api", &log)
                .caps([Capability::NetIntercept])
                .interest(
                    NetworkInterest::none()
                        .intercept(RequestFilter::any().url("https://api.test/*")),
                ),
        )
        .unwrap()
        .with(
            Net::new("images", &log)
                .caps([Capability::NetIntercept])
                .interest(
                    NetworkInterest::none()
                        .intercept(RequestFilter::any().kinds([ResourceKind::Image])),
                ),
        )
        .unwrap();
    let _ = drive_request(&set, get("https://api.test/v1"));
    assert_eq!(entries(&log), ["api:request https://api.test/v1 cookie="]);
}

#[test]
fn a_plugin_without_net_intercept_is_never_asked_and_cannot_block() {
    let log = log();
    let set = PluginSet::new()
        .with(
            Net::new("blocked-in-theory", &log)
                .caps([Capability::NetObserve])
                .interest(intercept_all())
                .decide(RequestDecision::Block("x".into())),
        )
        .unwrap();
    assert_eq!(
        drive_request(&set, get("https://x.test/")),
        RequestDecision::Continue
    );
    assert!(entries(&log).is_empty());
}

#[test]
fn cookies_are_redacted_unless_the_plugin_holds_net_sensitive() {
    let log = log();
    let set = PluginSet::new()
        .with(
            Net::new("plain", &log)
                .caps([Capability::NetIntercept])
                .interest(intercept_all()),
        )
        .unwrap()
        .with(
            Net::new("trusted", &log)
                .caps([Capability::NetIntercept, Capability::NetSensitive])
                .interest(intercept_all()),
        )
        .unwrap();
    let _ = drive_request(&set, get("https://x.test/").header("Cookie", "sid=secret"));
    assert_eq!(
        entries(&log),
        [
            format!("plain:request https://x.test/ cookie={REDACTED}"),
            "trusted:request https://x.test/ cookie=sid=secret".to_owned()
        ]
    );
}

#[test]
fn set_headers_rules_are_merged_in_run_order() {
    let log = log();
    let headers = |name, pairs: [(&str, &str); 1], url: &str| {
        Net::new(name, &log)
            .caps([Capability::NetIntercept])
            .interest(
                NetworkInterest::none()
                    .rule(NetRule::set_headers(RequestFilter::any().url(url), pairs)),
            )
    };
    let set = PluginSet::new()
        .with(headers("a", [("X-Mode", "a")], "*"))
        .unwrap()
        .with(headers("b", [("X-Mode", "b")], "https://x.test/*"))
        .unwrap()
        .with(headers("c", [("X-Other", "c")], "https://y.test/*"))
        .unwrap();
    let got = set.extra_headers(&get("https://x.test/"));
    assert_eq!(got, BTreeMap::from([("X-Mode".to_owned(), "b".to_owned())]));
}

// ---- on_response --------------------------------------------------------

fn observer(name: &'static str, log: &Log, caps: &[Capability], max: Option<usize>) -> Net {
    let mut filter = RequestFilter::any().kinds([ResourceKind::Document]);
    filter.max_body = max;
    Net::new(name, log)
        .caps(caps.iter().cloned())
        .interest(NetworkInterest::none().observe(filter))
}

#[test]
fn a_response_reaches_matching_observers_only() {
    let log = log();
    let set = PluginSet::new()
        .with(observer("docs", &log, &[Capability::NetObserve], None))
        .unwrap()
        .with(observer("blind", &log, &[], None))
        .unwrap();
    let doc = get("https://x.test/");
    let image = RequestView::new("https://x.test/i.png", "GET", ResourceKind::Image);
    assert!(drive_response(&set, ResponseView::new(&doc, 200, "text/html")).is_empty());
    assert!(drive_response(&set, ResponseView::new(&image, 200, "image/png")).is_empty());
    assert_eq!(
        entries(&log),
        ["docs:response 200 body=none truncated=false cookie="]
    );
}

#[test]
fn bodies_need_net_bodies_and_a_max_and_are_cut_to_it() {
    let log = log();
    let all = [Capability::NetObserve, Capability::NetBodies];
    let set = PluginSet::new()
        .with(observer("no-cap", &log, &[Capability::NetObserve], Some(4)))
        .unwrap()
        .with(observer("no-max", &log, &all, None))
        .unwrap()
        .with(observer("cut", &log, &all, Some(4)))
        .unwrap()
        .with(observer("whole", &log, &all, Some(100)))
        .unwrap();
    let doc = get("https://x.test/");
    let _ = drive_response(
        &set,
        ResponseView::new(&doc, 200, "text/plain").body(b"abcdefgh"),
    );
    assert_eq!(
        entries(&log),
        [
            "no-cap:response 200 body=none truncated=false cookie=",
            "no-max:response 200 body=none truncated=false cookie=",
            "cut:response 200 body=abcd truncated=true cookie=",
            "whole:response 200 body=abcdefgh truncated=false cookie=",
        ]
    );
}

#[test]
fn a_body_the_host_already_cut_stays_marked_as_cut() {
    let log = log();
    let all = [Capability::NetObserve, Capability::NetBodies];
    let set = PluginSet::new()
        .with(observer("whole", &log, &all, Some(100)))
        .unwrap();
    let doc = get("https://x.test/");
    let _ = drive_response(
        &set,
        ResponseView::new(&doc, 200, "text/plain")
            .body(b"ab")
            .truncated(true),
    );
    assert_eq!(
        entries(&log),
        ["whole:response 200 body=ab truncated=true cookie="]
    );
}

#[test]
fn response_hooks_see_redacted_requests_and_errors_are_collected() {
    let log = log();
    let mut failing = observer("flaky", &log, &[Capability::NetObserve], None);
    failing.fail = true;
    let set = PluginSet::new()
        .with(failing)
        .unwrap()
        .with(observer("ok", &log, &[Capability::NetObserve], None))
        .unwrap();
    let doc = get("https://x.test/").header("Cookie", "sid=secret");
    let response = ResponseView::new(&doc, 502, "text/html").outcome(Outcome::Blocked {
        by: "shield".into(),
    });
    let failures = block_on(set.on_response(&response));
    assert_eq!(failures.len(), 1);
    assert!(failures[0].to_string().contains("on_response"));
    assert_eq!(
        entries(&log),
        [
            format!("flaky:response 502 body=none truncated=false cookie={REDACTED}"),
            format!("ok:response 502 body=none truncated=false cookie={REDACTED}")
        ]
    );
}
