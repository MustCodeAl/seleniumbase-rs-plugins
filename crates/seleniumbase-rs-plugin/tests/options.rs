//! `config::options`, the helper `Configurable::configure` uses.

use seleniumbase_rs_plugin::PluginError;
use seleniumbase_rs_plugin::config::options;
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Debug, Default, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
struct Opts {
    depth: u32,
    hosts: Vec<String>,
}

fn message(error: PluginError) -> String {
    match error {
        PluginError::Config(message) => message,
        other => panic!("not a configuration error: {other:?}"),
    }
}

#[test]
fn no_options_give_the_defaults() {
    assert_eq!(
        options::<Opts>("crawler", &Value::Null).unwrap(),
        Opts::default()
    );
    assert_eq!(
        options::<Opts>("crawler", &json!({})).unwrap(),
        Opts::default()
    );
}

#[test]
fn given_options_are_read_and_the_rest_keep_their_defaults() {
    let opts: Opts = options("crawler", &json!({"depth": 2})).unwrap();
    assert_eq!(
        opts,
        Opts {
            depth: 2,
            hosts: Vec::new()
        }
    );
    let opts: Opts = options("crawler", &json!({"hosts": ["a.test"]})).unwrap();
    assert_eq!(opts.hosts, ["a.test"]);
}

#[test]
fn an_unknown_option_is_named_with_the_plugin() {
    let error = options::<Opts>("crawler", &json!({"depth": 1, "dept": 2})).unwrap_err();
    assert_eq!(message(error), "crawler: unknown option `dept`");
}

#[test]
fn a_wrong_type_or_shape_names_the_plugin_and_says_what_was_wrong() {
    let error = options::<Opts>("crawler", &json!({"depth": "deep"})).unwrap_err();
    let text = message(error);
    assert!(text.starts_with("crawler: invalid type: string"), "{text}");
    let error = options::<Opts>("crawler", &json!("depth=2")).unwrap_err();
    assert!(message(error).starts_with("crawler: "));
}
