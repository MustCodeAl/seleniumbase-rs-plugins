//! Where tor runs in a set that also has the real `browser` plugin, and which
//! launches the set refuses it for.

use seleniumbase_rs_plugin::{
    BrowserFamily, Configurable, Engine, HostInfo, LaunchContext, PluginError, PluginSet,
};
use seleniumbase_rs_plugin_browser::BrowserSession;
use seleniumbase_rs_plugin_tor::Tor;
use serde_json::Value;

fn browser() -> BrowserSession {
    BrowserSession::configure(&Value::Null).expect("the default options of the browser plugin")
}

fn tor() -> Tor {
    Tor::configure(&Value::Null).expect("the default options of the tor plugin")
}

fn launch(engine: Engine, family: BrowserFamily, connecting: bool) -> LaunchContext {
    LaunchContext {
        engine,
        family,
        headless: true,
        connecting,
    }
}

#[test]
fn the_privacy_plugin_runs_after_the_extension_plugin_in_either_insertion_order() {
    let browser_first = PluginSet::strict()
        .with(browser())
        .unwrap()
        .with(tor())
        .unwrap();
    let tor_first = PluginSet::strict()
        .with(tor())
        .unwrap()
        .with(browser())
        .unwrap();
    // Category::Privacy runs in the Enforce phase, after Category::Extension
    // (Normal), so tor has the last word on the proxy the extension loader
    // may have seen.
    assert_eq!(browser_first.names(), ["browser", "tor"]);
    assert_eq!(tor_first.names(), ["browser", "tor"]);
}

#[test]
fn the_set_accepts_tor_on_a_launched_chromium_with_the_cdp_engine() {
    let plugins = PluginSet::strict().with(tor()).unwrap();
    plugins
        .check(&launch(Engine::Cdp, BrowserFamily::Chromium, false))
        .expect("tor runs here");
}

#[test]
fn the_set_refuses_tor_for_a_browser_the_program_attaches_to() {
    let plugins = PluginSet::strict().with(tor()).unwrap();
    let error = plugins
        .check(&launch(Engine::Cdp, BrowserFamily::Chromium, true))
        .unwrap_err();
    assert!(
        matches!(&error, PluginError::Requirement { plugin, reason }
            if plugin == "tor" && reason.contains("only works with a browser the program starts")),
        "{error:?}"
    );
}

#[test]
fn the_set_refuses_tor_for_another_browser_family() {
    let plugins = PluginSet::strict().with(tor()).unwrap();
    let error = plugins
        .check(&launch(Engine::Cdp, BrowserFamily::Firefox, false))
        .unwrap_err();
    assert!(
        matches!(&error, PluginError::Requirement { plugin, reason }
            if plugin == "tor" && reason.contains("Chromium")),
        "{error:?}"
    );
}

#[test]
fn the_set_refuses_tor_on_webdriver_and_names_the_missing_capability() {
    let plugins = PluginSet::strict().with(tor()).unwrap();
    let error = plugins
        .check_with(
            &launch(Engine::WebDriver, BrowserFamily::Chromium, false),
            &HostInfo::webdriver(BrowserFamily::Chromium),
        )
        .unwrap_err();
    assert!(
        matches!(&error, PluginError::Unsupported { plugin, capability, .. }
            if plugin == "tor" && capability == "contexts"),
        "{error:?}"
    );
}
