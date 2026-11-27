//! Integration tests for containerized persistent `browser` sessions.

use std::sync::Arc;

use seleniumbase_rs_plugin::{
    BrowserFamily, Configurable, ContextSettings, Engine, HostInfo, LaunchContext, LaunchSettings,
    NavOutcome, Plugin, PluginSet,
};
use seleniumbase_rs_plugin_browser::{BrowserSession, RotationMode, SessionConfig};
use seleniumbase_rs_plugin_testing::{Call, RecordingBrowser, RecordingPage, block_on};
use serde_json::json;

fn cdp_ctx() -> LaunchContext {
    LaunchContext {
        engine: Engine::Cdp,
        family: BrowserFamily::Chromium,
        headless: true,
        connecting: false,
    }
}

#[test]
fn one_line_container_and_country_constructors_build_strict_sets() {
    let a = BrowserSession::container("acct-1").unwrap();
    let set = PluginSet::strict().with(a).unwrap();
    set.check(&cdp_ctx()).unwrap();
    assert_eq!(set.names(), ["browser"]);

    let b = BrowserSession::for_country("acct-de", "de").unwrap();
    assert_eq!(b.config().country.as_deref(), Some("DE"));
    assert_eq!(b.config().effective_locale(), Some("de-DE"));
    assert_eq!(b.config().effective_timezone(), Some("Europe/Berlin"));
    assert!(b.config().effective_geolocation().is_some());
}

#[test]
fn container_persists_and_restores_cookies_storage_tabs_and_identity() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = SessionConfig::builder()
        .container("shop-user")
        .session_dir(dir.path())
        .save_on_close(true)
        .restore_tabs(true)
        .country("DE")
        .user_agent("Mozilla/5.0 TestAgent")
        .build()
        .unwrap();

    // Run 1: navigate, capture cookies + storage + open tabs, and persist on before_close.
    let plugin1 = BrowserSession::new(cfg.clone()).unwrap();
    let mut launch1 = LaunchSettings::default();
    block_on(plugin1.before_launch(&mut launch1)).unwrap();
    assert!(launch1.args.iter().any(|a| a == "--lang=de-DE"));

    let browser1 = RecordingBrowser::new().replying(
        "Storage.getCookies",
        json!({
            "cookies": [{
                "name": "sid",
                "value": "super-secret-cookie",
                "domain": "shop.example",
                "path": "/",
                "httpOnly": true,
                "secure": true,
                "sameSite": "Lax"
            }]
        }),
    );
    let page1 = RecordingPage::new()
        .at("https://shop.example/cart")
        .evaluating(
            "localStorage",
            json!({
                "origin": "https://shop.example",
                "local_storage": { "theme": "dark", "jwt": "secret-jwt" },
                "session_storage": { "cart_step": "2" }
            }),
        );

    block_on(plugin1.on_browser(&browser1)).unwrap();
    block_on(plugin1.on_page_created(&page1)).unwrap();
    block_on(plugin1.after_navigate(
        &page1,
        &NavOutcome::new("https://shop.example/cart").status(200),
    ))
    .unwrap();
    block_on(plugin1.before_close(&browser1)).unwrap();

    let saved_file = dir.path().join("shop-user.json");
    assert!(saved_file.is_file());

    // Run 2: fresh instance restores cookies, storage hydration init script, and open tabs.
    let plugin2 = BrowserSession::new(cfg).unwrap();
    let mut launch2 = LaunchSettings::default();
    block_on(plugin2.before_launch(&mut launch2)).unwrap();

    let browser2 = RecordingBrowser::new();
    block_on(plugin2.on_browser(&browser2)).unwrap();
    let calls = browser2.calls();
    assert!(
        calls
            .iter()
            .any(|c| matches!(c, Call::Send(m, _) if m == "Storage.setCookies")),
        "expected Storage.setCookies restore, got {calls:?}"
    );

    let page2 = RecordingPage::new();
    block_on(plugin2.on_page_created(&page2)).unwrap();
    let page_calls = page2.calls();
    assert!(
        page_calls.iter().any(|c| matches!(
            c,
            Call::InitScript(s) if s.contains("localStorage.setItem") && s.contains("theme")
        )),
        "expected storage hydration init script, got {page_calls:?}"
    );
    assert!(
        page_calls
            .iter()
            .any(|c| matches!(c, Call::Send(m, _) if m == "Emulation.setLocaleOverride"))
    );
    assert!(
        page_calls
            .iter()
            .any(|c| matches!(c, Call::Send(m, _) if m == "Emulation.setTimezoneOverride"))
    );
    assert!(
        page_calls
            .iter()
            .any(|c| matches!(c, Call::Send(m, _) if m == "Emulation.setGeolocationOverride"))
    );
    assert!(
        page_calls
            .iter()
            .any(|c| matches!(c, Call::Send(m, _) if m == "Network.setUserAgentOverride"))
    );
}

#[test]
fn expired_container_ttl_does_not_restore_stale_state() {
    let dir = tempfile::tempdir().unwrap();
    let expired_json = json!({
        "version": 2,
        "saved_at_ms": 1_000,
        "expires_at_ms": 2_000,
        "cookies": [{
            "name": "old",
            "value": "stale",
            "domain": "example.com",
            "path": "/",
            "httpOnly": false,
            "secure": false
        }],
        "tabs": ["https://example.com/old"]
    });
    std::fs::write(
        dir.path().join("ephemeral.json"),
        serde_json::to_vec(&expired_json).unwrap(),
    )
    .unwrap();

    let cfg = SessionConfig::builder()
        .session("ephemeral")
        .session_dir(dir.path())
        .ttl_secs(60)
        .build()
        .unwrap();
    let plugin = BrowserSession::new(cfg).unwrap();
    let browser = RecordingBrowser::new();
    block_on(plugin.on_browser(&browser)).unwrap();
    assert!(
        !browser
            .calls()
            .iter()
            .any(|c| matches!(c, Call::Send(m, _) if m == "Storage.setCookies")),
        "expired container must not restore stale cookies"
    );
}

#[test]
fn legacy_v1_cookie_file_loads_cleanly() {
    let dir = tempfile::tempdir().unwrap();
    let legacy = json!({
        "version": 1,
        "saved_at_ms": 1_700_000_000_000u64,
        "cookies": [{
            "name": "legacy_auth",
            "value": "tok",
            "domain": "legacy.example",
            "path": "/",
            "httpOnly": true,
            "secure": true
        }]
    });
    std::fs::write(
        dir.path().join("legacy.json"),
        serde_json::to_vec(&legacy).unwrap(),
    )
    .unwrap();

    let cfg = SessionConfig::builder()
        .session("legacy")
        .session_dir(dir.path())
        .build()
        .unwrap();
    let plugin = BrowserSession::new(cfg).unwrap();
    let browser = RecordingBrowser::new();
    block_on(plugin.on_browser(&browser)).unwrap();
    assert!(
        browser
            .calls()
            .iter()
            .any(|c| matches!(c, Call::Send(m, _) if m == "Storage.setCookies"))
    );
}

#[test]
fn proxy_rotation_rotates_and_redacts_credentials() {
    let cfg = SessionConfig::builder()
        .proxies([
            "http://alice:hunter2@p1.example:8080",
            "http://bob:secret9@p2.example:8080",
        ])
        .rotation(RotationMode::RoundRobin)
        .build()
        .unwrap();

    let debug_text = format!("{cfg:?}");
    assert!(
        !debug_text.contains("hunter2"),
        "password leaked in Debug: {debug_text}"
    );
    assert!(
        !debug_text.contains("secret9"),
        "password leaked in Debug: {debug_text}"
    );
    assert!(debug_text.contains("***@p1.example:8080"));

    let plugin = BrowserSession::new(cfg).unwrap();
    let mut launch = LaunchSettings::default();
    block_on(plugin.before_launch(&mut launch)).unwrap();
    assert_eq!(
        launch.proxy.as_deref(),
        Some("http://alice:hunter2@p1.example:8080")
    );

    let mut ctx1 = ContextSettings::new();
    block_on(plugin.before_context(&mut ctx1)).unwrap();
    assert_eq!(
        ctx1.proxy.as_deref(),
        Some("http://bob:secret9@p2.example:8080")
    );

    let mut ctx2 = ContextSettings::new();
    block_on(plugin.before_context(&mut ctx2)).unwrap();
    assert_eq!(
        ctx2.proxy.as_deref(),
        Some("http://alice:hunter2@p1.example:8080")
    );
}

#[test]
fn configure_accepts_null_and_rejects_bad_options() {
    let default_plugin = BrowserSession::configure(&serde_json::Value::Null).unwrap();
    assert_eq!(default_plugin.name(), "browser");

    for bad in [
        json!({ "country": "GERMANY" }),
        json!({ "geolocation": [95.0, 0.0] }),
        json!({ "proxies": ["ftp://bad.example:21"] }),
        json!({ "ttl_secs": 0, "session": "a" }),
        json!({ "save_on_close": true }),
        json!({ "unknown_key": 1 }),
    ] {
        assert!(
            BrowserSession::configure(&bad).is_err(),
            "expected error for {bad}"
        );
    }
}

#[test]
fn checks_cleanly_against_cdp_host_info() {
    let plugin = Arc::new(BrowserSession::for_country("acct-us", "US").unwrap());
    let set = PluginSet::strict().with_shared(plugin).unwrap();
    set.check_with(&cdp_ctx(), &HostInfo::cdp()).unwrap();
}
