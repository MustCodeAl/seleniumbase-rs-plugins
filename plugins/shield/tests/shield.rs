//! The shield plugin through its public API, with the recording fakes: no browser.

use seleniumbase_rs_plugin::{
    BrowserFamily, Capability, Category, Configurable, Descriptor, Engine, HostInfo, LaunchContext,
    LaunchSettings, Plugin, PluginError, PluginSet, PluginSpec, ProfileView, Registry,
    Requirements, WebRtcPolicy, switch_policy,
};
use seleniumbase_rs_plugin_shield::{Level, Shield, ShieldConfig, WebRtcMode, telemetry};
use seleniumbase_rs_plugin_testing::{Call, RecordingPage, block_on};
use serde_json::{Value, json};

fn shield(options: &Value) -> Shield {
    Shield::configure(options).expect("valid options")
}

fn launched(options: &Value) -> LaunchSettings {
    let mut launch = LaunchSettings::default();
    block_on(shield(options).before_launch(&mut launch)).expect("before_launch");
    launch
}

fn context(family: BrowserFamily) -> LaunchContext {
    LaunchContext {
        engine: Engine::Cdp,
        family,
        headless: true,
        connecting: false,
    }
}

// ---- config ----

#[test]
fn defaults_match_the_design() {
    let config = ShieldConfig::default();
    assert_eq!(config.level, Level::Basic);
    assert_eq!(config.webrtc, WebRtcMode::RelayOnly);
    assert!(config.block_third_party_cookies);
    assert!(config.ephemeral_profile);
    assert!(!config.sweep_stale_profiles);
    // Off until the hooks it needs exist: a default must not promise what is not done.
    assert!(!config.clear_between_tests);
    assert!(config.extra_block_hosts.is_empty());
    assert!(config.safe_browsing);
}

#[test]
fn no_options_and_empty_options_are_the_defaults() {
    assert_eq!(shield(&Value::Null).config(), &ShieldConfig::default());
    assert_eq!(shield(&json!({})).config(), &ShieldConfig::default());
}

#[test]
fn options_are_read_with_kebab_case_names() {
    let shield = shield(&json!({
        "level": "strict",
        "webrtc": "relay-only",
        "block_third_party_cookies": false,
        "extra_block_hosts": ["Tracker.Example.com"],
    }));
    let config = shield.config();
    assert_eq!(config.level, Level::Strict);
    assert_eq!(config.webrtc, WebRtcMode::RelayOnly);
    assert!(!config.block_third_party_cookies);
    // Host names are stored lower case.
    assert_eq!(config.extra_block_hosts, ["tracker.example.com"]);
}

#[test]
fn an_unknown_option_is_refused() {
    let error = Shield::configure(&json!({ "levle": "strict" })).unwrap_err();
    assert!(matches!(error, PluginError::Config(_)), "{error:?}");
    assert!(error.to_string().contains("levle"), "{error}");
}

#[test]
fn a_wrong_value_is_refused() {
    for options in [
        json!({ "level": "paranoid" }),
        json!({ "webrtc": "yes" }),
        json!({ "safe_browsing": "off" }),
        json!("strict"),
    ] {
        let error = Shield::configure(&options).unwrap_err();
        assert!(
            matches!(error, PluginError::Config(_)),
            "{options}: {error:?}"
        );
    }
}

#[test]
fn the_options_that_do_nothing_yet_are_refused_when_turned_on() {
    for option in ["sweep_stale_profiles", "clear_between_tests"] {
        let error = Shield::configure(&json!({ option: true })).unwrap_err();
        assert!(
            matches!(error, PluginError::Config(_)),
            "{option}: {error:?}"
        );
        assert!(error.to_string().contains(option), "{error}");
        // Off is the same as not saying it.
        assert_eq!(
            shield(&json!({ option: false })).config(),
            &ShieldConfig::default()
        );
    }
}

#[test]
fn bad_block_hosts_are_refused() {
    for host in [
        "",
        "  ",
        "a b.com",
        "https://a.com",
        "a.com/path",
        "a.com:8080",
        "*.a.com",
        "a,b.com",
        "-a.com",
        "a..com",
        "bücher.example",
    ] {
        let error = Shield::configure(&json!({ "extra_block_hosts": [host] })).unwrap_err();
        assert!(
            matches!(error, PluginError::Config(_)),
            "{host:?}: {error:?}"
        );
    }
}

// ---- metadata and the set ----

#[test]
fn metadata_is_declared_and_describe_matches() {
    let meta = Shield::describe();
    assert_eq!(meta.category, Some(Category::Privacy));
    assert!(meta.is_declared());
    assert_eq!(meta.version, env!("CARGO_PKG_VERSION"));
    assert!(!meta.summary.is_empty());
    assert_eq!(Shield::NAME, "shield");
    let shield = shield(&Value::Null);
    assert_eq!(shield.name(), Shield::NAME);
    assert_eq!(shield.metadata().summary, meta.summary);
    assert_eq!(shield.metadata().capabilities, meta.capabilities);
    for capability in [
        Capability::LaunchArgs,
        Capability::LaunchPrefs,
        Capability::LaunchNetwork,
        Capability::Cdp("Network".into()),
    ] {
        assert!(meta.capabilities.covers(&capability), "{capability}");
    }
}

#[test]
fn it_needs_a_chromium_browser() {
    assert!(
        shield(&Value::Null)
            .requirements()
            .contains(Requirements::CHROMIUM_ONLY)
    );
    let set = PluginSet::strict().with(shield(&Value::Null)).unwrap();
    set.check(&context(BrowserFamily::Chromium)).unwrap();
    let error = set.check(&context(BrowserFamily::Firefox)).unwrap_err();
    assert!(
        matches!(error, PluginError::Requirement { .. }),
        "{error:?}"
    );
    set.check_with(
        &context(BrowserFamily::Chromium),
        &HostInfo::webdriver(BrowserFamily::Chromium),
    )
    .unwrap();
}

#[test]
fn a_strict_set_accepts_every_level_and_webrtc_mode() {
    for level in ["basic", "strict"] {
        for webrtc in ["off", "policy", "relay-only"] {
            let options = json!({ "level": level, "webrtc": webrtc });
            let set = PluginSet::strict().with(shield(&options)).unwrap();
            set.check(&context(BrowserFamily::Chromium)).unwrap();
            // The set verifies every change against the capabilities the plugin declares.
            let mut launch = LaunchSettings::default();
            block_on(set.before_launch(&mut launch)).unwrap_or_else(|e| panic!("{options}: {e}"));
        }
    }
}

#[test]
fn the_registry_builds_it_by_name() {
    let registry = Registry::new().with(Descriptor::of::<Shield>());
    assert_eq!(registry.names(), ["shield"]);
    let set = registry
        .plugin_set(&[PluginSpec::new("shield").options(json!({ "level": "strict" }))])
        .unwrap();
    assert_eq!(set.names(), ["shield"]);
    let Err(error) = registry.build(&PluginSpec::new("shield").options(json!({ "nope": 1 })))
    else {
        panic!("an unknown option must fail");
    };
    assert!(matches!(error, PluginError::Config(_)));
}

#[test]
fn a_pooled_browser_gets_its_own_instance() {
    // That the fresh instance starts with no origins is a unit test in `src/lib.rs`.
    let shield = shield(&Value::Null);
    let set = PluginSet::strict().with(shield).unwrap();
    assert_eq!(set.for_launch().names(), ["shield"]);
}

// ---- before_launch ----

#[test]
fn every_switch_feature_and_host_is_allowed_by_the_switch_policy() {
    for switch in telemetry::SWITCHES {
        assert!(switch.starts_with("--"), "{switch}");
        assert_eq!(switch_policy::refusal(switch), None, "{switch}");
        let name = switch_policy::switch_name(switch).unwrap();
        assert!(
            !switch_policy::REFUSED_SWITCHES.contains(&name.as_str()),
            "{switch}"
        );
    }
    for feature in telemetry::FEATURES {
        assert!(!switch_policy::feature_refused(feature), "{feature}");
    }
    assert!(!telemetry::SWITCHES.is_empty());
    assert!(!telemetry::FEATURES.is_empty());
    assert!(!telemetry::BROWSER_HOSTS.is_empty());
}

#[test]
fn the_telemetry_lists_have_no_duplicates_and_hosts_are_bare_names() {
    for list in [
        telemetry::SWITCHES,
        telemetry::FEATURES,
        telemetry::BROWSER_HOSTS,
    ] {
        let mut sorted = list.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), list.len());
    }
    for host in telemetry::BROWSER_HOSTS {
        assert!(
            host.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-'),
            "{host}"
        );
    }
}

#[test]
fn basic_sets_switches_features_prefs_and_the_webrtc_policy_but_no_host_rules() {
    let launch = launched(&json!({ "level": "basic" }));
    for switch in telemetry::SWITCHES {
        assert!(launch.args.iter().any(|a| a == switch), "{switch}");
    }
    assert_eq!(launch.disable_features, telemetry::FEATURES);
    assert_eq!(
        launch.webrtc_policy,
        Some(WebRtcPolicy::DisableNonProxiedUdp)
    );
    assert!(launch.host_resolver_rules.is_empty());
    assert_eq!(launch.prefs["net.network_prediction_options"], json!(2));
    assert_eq!(launch.prefs["search.suggest_enabled"], json!(false));
    assert_eq!(launch.prefs["alternate_error_pages.enabled"], json!(false));
    assert_eq!(
        launch.prefs["spellcheck.use_spelling_service"],
        json!(false)
    );
    for key in [
        "privacy_sandbox.m1.topics_enabled",
        "privacy_sandbox.m1.fledge_enabled",
        "privacy_sandbox.m1.ad_measurement_enabled",
    ] {
        assert_eq!(launch.prefs[key], json!(false), "{key}");
    }
    // 1 is CookieControlsMode::kBlockThirdParty.
    assert_eq!(launch.prefs["profile.cookie_controls_mode"], json!(1));
    // Basic sets no Safe Browsing preference or rule (what Chromium's own
    // `--disable-background-networking` does to it is not verified), and it does not set the
    // proxy or headless mode.
    assert!(!launch.prefs.contains_key("safebrowsing.enabled"));
    assert_eq!(launch.proxy, None);
    assert!(!launch.headless);
}

#[test]
fn strict_adds_one_resolver_rule_per_browser_host() {
    let launch = launched(&json!({ "level": "strict" }));
    let expected: Vec<String> = telemetry::BROWSER_HOSTS
        .iter()
        .map(|h| format!("MAP {h} ^NOTFOUND"))
        .collect();
    assert_eq!(launch.host_resolver_rules, expected);
    // Safe Browsing is not blocked by a level.
    assert!(
        launch
            .host_resolver_rules
            .iter()
            .all(|r| !r.contains("safebrowsing"))
    );
    // The rules go through the structured field; the plugin never writes the raw switch.
    assert!(
        launch
            .args
            .iter()
            .all(|a| !a.starts_with("--host-resolver-rules")),
        "{:?}",
        launch.args
    );
}

#[test]
fn webrtc_modes() {
    let off = launched(&json!({ "webrtc": "off" }));
    assert_eq!(off.webrtc_policy, None);
    assert!(shield(&json!({ "webrtc": "off" })).packages().is_empty());

    let policy = launched(&json!({ "webrtc": "policy" }));
    assert_eq!(
        policy.webrtc_policy,
        Some(WebRtcPolicy::DisableNonProxiedUdp)
    );
    assert!(shield(&json!({ "webrtc": "policy" })).packages().is_empty());

    let relay = launched(&json!({ "webrtc": "relay-only" }));
    assert_eq!(
        relay.webrtc_policy,
        Some(WebRtcPolicy::DisableNonProxiedUdp)
    );
    let packages = shield(&json!({ "webrtc": "relay-only" })).packages();
    assert_eq!(packages.len(), 1);
    let script = packages[0].init_script().expect("says where it loads");
    assert!(script.contains("iceTransportPolicy"), "{script}");
    assert!(script.contains("relay"), "{script}");
}

#[test]
fn cookies_and_safe_browsing_options() {
    let off = launched(&json!({ "block_third_party_cookies": false }));
    assert!(!off.prefs.contains_key("profile.cookie_controls_mode"));

    let no_safe = launched(&json!({ "safe_browsing": false }));
    assert_eq!(no_safe.prefs["safebrowsing.enabled"], json!(false));
}

#[test]
fn it_keeps_what_other_plugins_set() {
    let mut launch = LaunchSettings::default();
    launch.args.push("--lang=de".into());
    launch.args.push(telemetry::SWITCHES[0].into());
    launch.disable_features.push("Translate".into());
    launch
        .prefs
        .insert("intl.accept_languages".into(), json!("de"));
    block_on(shield(&Value::Null).before_launch(&mut launch)).unwrap();
    assert!(launch.args.contains(&"--lang=de".to_owned()));
    // A switch that was already there is not added twice.
    assert_eq!(
        launch
            .args
            .iter()
            .filter(|a| *a == telemetry::SWITCHES[0])
            .count(),
        1
    );
    assert_eq!(launch.disable_features[0], "Translate");
    assert_eq!(launch.prefs["intl.accept_languages"], json!("de"));

    // Running twice adds nothing new.
    let once = launch.clone();
    block_on(shield(&Value::Null).before_launch(&mut launch)).unwrap();
    assert_eq!(launch, once);
}

#[test]
fn a_persistent_profile_is_refused() {
    let mut launch = LaunchSettings::default();
    launch.set_profile(ProfileView::Persistent("/tmp/my-profile".into()));
    let error = block_on(shield(&Value::Null).before_launch(&mut launch)).unwrap_err();
    assert!(error.to_string().contains("persistent profile"), "{error}");
    // It refused before it changed anything.
    assert_eq!(launch.args, Vec::<String>::new());

    let set = PluginSet::strict().with(shield(&Value::Null)).unwrap();
    let error = block_on(set.before_launch(&mut launch)).unwrap_err();
    assert!(matches!(error, PluginError::Hook { .. }), "{error:?}");
}

#[test]
fn a_persistent_profile_is_allowed_when_ephemeral_profile_is_off() {
    let mut launch = LaunchSettings::default();
    launch.set_profile(ProfileView::Persistent("/tmp/my-profile".into()));
    block_on(shield(&json!({ "ephemeral_profile": false })).before_launch(&mut launch)).unwrap();
    assert!(!launch.args.is_empty());
}

// ---- tabs ----

#[test]
fn a_tab_blocks_the_extra_hosts_through_the_raw_protocol() {
    let page = RecordingPage::new();
    let shield = shield(&json!({ "extra_block_hosts": ["tracker.example.com"] }));
    block_on(shield.on_page_created(&page)).unwrap();
    assert_eq!(
        page.calls(),
        [
            Call::Send("Network.enable".into(), json!({})),
            Call::Send(
                "Network.setBlockedURLs".into(),
                json!({ "urls": [
                    "*://tracker.example.com/*",
                    "*://*.tracker.example.com/*",
                    "*://tracker.example.com:*/*",
                    "*://*.tracker.example.com:*/*",
                ] })
            ),
        ]
    );
}

/// `*` matches any run of characters, as in a `Network.setBlockedURLs` pattern.
fn wildcard_match(pattern: &str, text: &str) -> bool {
    match pattern.split_once('*') {
        None => pattern == text,
        Some((head, tail)) => text.strip_prefix(head).is_some_and(|rest| {
            (0..=rest.len())
                .filter(|i| rest.is_char_boundary(*i))
                .any(|i| wildcard_match(tail, &rest[i..]))
        }),
    }
}

#[test]
fn the_block_patterns_cover_ports_and_subdomains_but_not_look_alikes() {
    let page = RecordingPage::new();
    let shield = shield(&json!({ "extra_block_hosts": ["tracker.example.com"] }));
    block_on(shield.on_page_created(&page)).unwrap();
    let Some(Call::Send(_, params)) = page.calls().pop() else {
        panic!("no blocked-URL command");
    };
    let patterns: Vec<String> = params["urls"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p.as_str().unwrap().to_owned())
        .collect();
    let blocked = |url: &str| patterns.iter().any(|p| wildcard_match(p, url));
    for url in [
        "https://tracker.example.com/x",
        "http://tracker.example.com/",
        "https://tracker.example.com:8443/x",
        "https://a.b.tracker.example.com/x",
        "https://cdn.tracker.example.com:8443/x?y=1",
        "wss://tracker.example.com:9000/socket",
    ] {
        assert!(blocked(url), "{url}");
    }
    for url in [
        "https://nottracker.example.com/x",
        "https://nottracker.example.com:8443/x",
        "https://example.com/tracker.example.com/",
    ] {
        assert!(!blocked(url), "{url}");
    }
}

#[test]
fn a_tab_without_extra_hosts_is_left_alone() {
    let page = RecordingPage::new();
    block_on(shield(&Value::Null).on_page_created(&page)).unwrap();
    assert_eq!(page.calls(), []);
}

#[test]
fn a_failing_protocol_command_stops_the_tab() {
    let page = RecordingPage::new().failing("Network.setBlockedURLs");
    let shield = shield(&json!({ "extra_block_hosts": ["a.example"] }));
    assert!(block_on(shield.on_page_created(&page)).is_err());
}

// ---- origin bookkeeping ----

#[test]
fn origins_are_remembered_without_paths_or_credentials() {
    let shield = shield(&Value::Null);
    for url in [
        "https://User:Secret@Example.com:8443/a/b?token=1#frag",
        "http://example.com/",
        "https://example.com",
        "https://example.com/other",
        "http://[::1]:3000/x",
        "data:text/html,hi",
        "about:blank",
        "file:///etc/passwd",
        "not a url",
        "https://",
    ] {
        shield.remember_origin(url);
    }
    assert_eq!(
        shield.take_origins(),
        [
            "http://[::1]:3000",
            "http://example.com",
            "https://example.com",
            "https://example.com:8443",
        ]
    );
    // Taking them empties the list.
    assert!(shield.take_origins().is_empty());
}

#[test]
fn an_origin_has_one_spelling_whatever_the_default_port() {
    let shield = shield(&Value::Null);
    for url in [
        "https://example.com:443/",
        "https://example.com/",
        "HTTPS://EXAMPLE.COM:443",
        "http://example.com:80/x",
        "http://example.com/",
        "http://example.com:8080/",
        // An empty port is the default port.
        "https://example.com:/",
    ] {
        shield.remember_origin(url);
    }
    assert_eq!(
        shield.take_origins(),
        [
            "http://example.com",
            "http://example.com:8080",
            "https://example.com",
        ]
    );
}

#[test]
fn the_origin_list_is_bounded() {
    let shield = shield(&Value::Null);
    for i in 0..5_000 {
        shield.remember_origin(&format!("https://h{i}.example/"));
    }
    assert!(shield.dropped_origins() >= 5_000 - 1_024);
    assert!(shield.take_origins().len() <= 1_024);
    // Taking the origins starts the count again.
    assert_eq!(shield.dropped_origins(), 0);
}
