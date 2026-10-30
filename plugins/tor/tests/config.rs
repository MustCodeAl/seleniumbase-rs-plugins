//! The options of the tor plugin: defaults, parsing, validation.

use std::net::SocketAddr;

use seleniumbase_rs_plugin::PluginError;
use seleniumbase_rs_plugin::config::options;
use seleniumbase_rs_plugin_tor::{ControlAuth, Isolation, TorConfig};
use serde_json::json;

fn parse(value: serde_json::Value) -> Result<TorConfig, PluginError> {
    options::<TorConfig>("tor", &value)
}

fn addr(text: &str) -> SocketAddr {
    text.parse().expect("a socket address")
}

fn refusal(config: &TorConfig) -> String {
    match config.validate() {
        Err(PluginError::Config(message)) => message,
        other => panic!("expected a configuration error, got {other:?}"),
    }
}

#[test]
fn the_defaults_are_the_documented_ones() {
    let config = TorConfig::default();
    assert_eq!(config.socks, addr("127.0.0.1:9050"));
    assert_eq!(config.control, None);
    assert_eq!(config.control_auth, None);
    assert_eq!(config.isolation, Isolation::PerContext);
    assert!(config.require_bootstrapped);
    config.validate().expect("the defaults are valid");
    assert_eq!(
        parse(serde_json::Value::Null).expect("null means defaults"),
        config
    );
}

#[test]
fn every_option_is_read() {
    let config = parse(json!({
        "socks": "127.0.0.1:9150",
        "control": "127.0.0.1:9151",
        "control_auth": { "cookie_path": "/run/tor/control.authcookie" },
        "isolation": "browser",
        "require_bootstrapped": false,
    }))
    .expect("valid options");
    assert_eq!(config.socks, addr("127.0.0.1:9150"));
    assert_eq!(config.control, Some(addr("127.0.0.1:9151")));
    assert_eq!(
        config.control_auth,
        Some(ControlAuth::cookie("/run/tor/control.authcookie"))
    );
    assert_eq!(config.isolation, Isolation::Browser);
    assert!(!config.require_bootstrapped);
    config.validate().expect("valid");

    let by_password = parse(json!({
        "control": "[::1]:9051",
        "control_auth": { "password_env": "TOR_CONTROL_PASSWORD" },
    }))
    .expect("valid options");
    assert_eq!(
        by_password.control_auth,
        Some(ControlAuth::password_env("TOR_CONTROL_PASSWORD"))
    );
    by_password.validate().expect("valid");
}

#[test]
fn isolation_is_per_context_or_browser_and_nothing_else() {
    for (text, want) in [
        ("per-context", Isolation::PerContext),
        ("browser", Isolation::Browser),
    ] {
        assert_eq!(
            parse(json!({ "isolation": text }))
                .expect("a valid value")
                .isolation,
            want
        );
    }
    for text in ["per_context", "Browser", "context", "none", ""] {
        let error = parse(json!({ "isolation": text })).expect_err("an invalid value");
        let message = error.to_string();
        assert!(
            message.starts_with("plugin configuration: tor: "),
            "{message}"
        );
        assert!(
            message.contains("per-context") && message.contains("browser"),
            "the message names the valid values: {message}"
        );
    }
}

#[test]
fn a_misspelt_or_unknown_option_is_an_error() {
    let error = parse(json!({ "sock": "127.0.0.1:9050" })).expect_err("unknown option");
    assert_eq!(
        error.to_string(),
        "plugin configuration: tor: unknown option `sock`"
    );
    // A password is never an option value.
    let error = parse(json!({
        "control": "127.0.0.1:9051",
        "control_auth": { "password": "hunter2" },
    }))
    .expect_err("a password is not an option");
    let message = error.to_string();
    assert!(message.contains("unknown option `password`"), "{message}");
    assert!(!message.contains("hunter2"), "{message}");
}

#[test]
fn a_socks_address_that_is_not_loopback_is_refused() {
    for text in [
        "0.0.0.0:9050",
        "192.168.1.5:9050",
        "10.0.0.1:9050",
        "8.8.8.8:9050",
        "[2001:db8::1]:9050",
        "[::]:9050",
    ] {
        let message = refusal(&TorConfig::new().socks(addr(text)));
        assert!(message.starts_with("tor: "), "{message}");
        assert!(
            message.contains("`socks`") && message.contains("loopback"),
            "{message}"
        );
        assert!(
            message.contains(text),
            "the message names the address: {message}"
        );
    }
    for text in ["127.0.0.1:9050", "[::1]:9150", "127.0.0.2:9050"] {
        TorConfig::new()
            .socks(addr(text))
            .validate()
            .unwrap_or_else(|error| panic!("{text} is loopback: {error}"));
    }
    let message = refusal(&TorConfig::new().socks(addr("127.0.0.1:0")));
    assert!(message.contains("port"), "{message}");
}

#[test]
fn a_control_address_that_is_not_loopback_is_refused() {
    let config = TorConfig::new().control(addr("192.168.1.5:9051"), ControlAuth::cookie("/c"));
    let message = refusal(&config);
    assert!(
        message.contains("`control`") && message.contains("loopback"),
        "{message}"
    );
}

#[test]
fn control_needs_auth_and_auth_needs_control() {
    let mut config = TorConfig::new();
    config.control = Some(addr("127.0.0.1:9051"));
    let message = refusal(&config);
    assert!(
        message.contains("`control`") && message.contains("`control_auth`"),
        "{message}"
    );

    let mut config = TorConfig::new();
    config.control_auth = Some(ControlAuth::cookie("/run/tor/control.authcookie"));
    let message = refusal(&config);
    assert!(
        message.contains("`control_auth`") && message.contains("`control`"),
        "{message}"
    );
}

#[test]
fn control_auth_names_exactly_one_method() {
    let control = addr("127.0.0.1:9051");
    let with = |auth: ControlAuth| refusal(&TorConfig::new().control(control, auth));

    let both = parse(json!({
        "control": "127.0.0.1:9051",
        "control_auth": { "cookie_path": "/c", "password_env": "PW" },
    }))
    .expect("both fields parse");
    let message = refusal(&both);
    assert!(
        message.contains("cookie_path") && message.contains("password_env"),
        "{message}"
    );

    let message = with(ControlAuth::default());
    assert!(
        message.contains("cookie_path") && message.contains("password_env"),
        "{message}"
    );

    for bad in ["", "A=B", "A B", "A\0B"] {
        let message = with(ControlAuth::password_env(bad));
        assert!(message.contains("password_env"), "{bad:?}: {message}");
    }
    let message = with(ControlAuth::cookie(""));
    assert!(message.contains("cookie_path"), "{message}");

    TorConfig::new()
        .control(control, ControlAuth::password_env("TOR_CONTROL_PASSWORD"))
        .validate()
        .expect("a password variable is a valid method");
    TorConfig::new()
        .control(control, ControlAuth::cookie("/run/tor/control.authcookie"))
        .validate()
        .expect("a cookie file is a valid method");
}

#[test]
fn an_unknown_key_inside_control_auth_is_an_error() {
    let error = parse(json!({
        "control": "127.0.0.1:9051",
        "control_auth": { "cookie": "/c" },
    }))
    .expect_err("unknown key");
    assert!(
        error.to_string().contains("unknown option `cookie`"),
        "{error}"
    );
}
