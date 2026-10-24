//! The plugin: options, registration, the task's input check, and one live
//! test that needs a real mailbox.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use seleniumbase_rs_plugin::{
    Capability, Clock, Configurable, Descriptor, NetScope, NoPrompt, PluginError, PluginSet,
    PluginSpec, Registry, TaskContext, Timer,
};
use seleniumbase_rs_plugin_imap::{Imap, ImapConfig, Query};
use seleniumbase_rs_plugin_testing::{ManualTimer, RecordingBrowser, VecSink, block_on};
use serde_json::{Value, json};

/// A change to a set of options, for the table of bad ones.
type Change = fn(&mut ImapConfig);

/// A variable that is not set anywhere.
const UNSET: &str = "SBRS_IMAP_TEST_UNSET_8F3A21";

fn config() -> ImapConfig {
    ImapConfig {
        host: "imap.example.com".into(),
        user: "me@example.com".into(),
        password_env: "MAIL_APP_PASSWORD".into(),
        ..ImapConfig::default()
    }
}

fn with_password(config: ImapConfig) -> Imap {
    Imap::new_with(config, &|_| Some("s3cret-app-password".into())).unwrap()
}

fn error_of(result: Result<Imap, PluginError>) -> String {
    match result {
        Err(PluginError::Config(message)) => message,
        other => panic!("expected a configuration error, got {other:?}"),
    }
}

// ---- options ------------------------------------------------------------------

#[test]
fn the_defaults_are_the_documented_ones() {
    let defaults = ImapConfig::default();
    assert_eq!(defaults.port, 993);
    assert_eq!(defaults.mailbox, "INBOX");
    assert_eq!(defaults.poll_secs, 5);
    assert_eq!(defaults.timeout_secs, 120);
    let plugin = with_password(config());
    assert_eq!(*plugin.config(), config());
}

#[test]
fn host_user_and_password_env_are_required() {
    assert!(error_of(Imap::configure(&Value::Null)).contains("`host`"));
    let mut c = config();
    c.user.clear();
    assert!(error_of(Imap::new_with(c, &|_| Some("x".into()))).contains("`user`"));
    let mut c = config();
    c.password_env.clear();
    assert!(error_of(Imap::new_with(c, &|_| Some("x".into()))).contains("`password_env`"));
}

#[test]
fn a_misspelt_option_names_the_plugin_and_the_option() {
    assert_eq!(
        error_of(Imap::configure(&json!({ "hots": "imap.example.com" }))),
        "imap: unknown option `hots`"
    );
    // The password is not an option, however it is spelt.
    assert_eq!(
        error_of(Imap::configure(&json!({ "password": "hunter2" }))),
        "imap: unknown option `password`"
    );
}

#[test]
fn a_missing_password_variable_is_named_in_the_error() {
    let message = error_of(Imap::configure(&json!({
        "host": "imap.example.com",
        "user": "me@example.com",
        "password_env": UNSET,
    })));
    assert!(message.starts_with("imap: "), "{message}");
    assert!(message.contains(UNSET), "{message}");
    assert!(message.contains("password_env"), "{message}");

    let mut c = config();
    c.password_env = "EMPTY_ONE".into();
    let message = error_of(Imap::new_with(c, &|_| Some(String::new())));
    assert!(message.contains("EMPTY_ONE"), "{message}");
}

#[test]
fn password_env_must_be_a_name_not_a_password() {
    for value in ["my secret pass", "pa$$word", "1ABC", "a=b"] {
        let mut c = config();
        c.password_env = value.into();
        let message = error_of(Imap::new_with(c, &|_| Some("x".into())));
        assert!(
            message.contains("NAME of an environment variable"),
            "{message}"
        );
        assert!(!message.contains(value), "{message}");
    }
}

#[test]
fn other_options_are_checked() {
    let cases: [(Change, &str); 7] = [
        (|c| c.host = "imap.example.com/x".into(), "`host`"),
        (|c| c.host = "bad host".into(), "`host`"),
        (|c| c.port = 0, "`port`"),
        (|c| c.mailbox = String::new(), "`mailbox`"),
        (|c| c.poll_secs = 0, "`poll_secs`"),
        (|c| c.timeout_secs = 0, "`timeout_secs`"),
        (|c| c.timeout_secs = 100_000, "`timeout_secs`"),
    ];
    for (change, needle) in cases {
        let mut c = config();
        change(&mut c);
        let message = error_of(Imap::new_with(c, &|_| Some("x".into())));
        assert!(message.starts_with("imap: "), "{message}");
        assert!(message.contains(needle), "{message}");
    }
}

#[test]
fn the_password_is_not_kept_in_the_plugin() {
    let plugin = with_password(config());
    let shown = format!("{plugin:?} {:?}", plugin.config());
    assert!(!shown.contains("s3cret-app-password"), "{shown}");
}

// ---- declaration and registration ---------------------------------------------

#[test]
fn it_declares_a_task_and_host_network_and_nothing_more() {
    let meta = Imap::describe();
    assert!(meta.capabilities.covers(&Capability::Task));
    assert!(
        meta.capabilities
            .covers(&Capability::HostNet(NetScope::Any))
    );
    for refused in [
        Capability::NetSensitive,
        Capability::CookiesRead,
        Capability::PageEvaluate,
        Capability::HostProcess,
    ] {
        assert!(!meta.capabilities.covers(&refused), "{refused}");
    }
}

#[test]
fn it_registers_and_its_options_are_checked_when_the_set_is_built() {
    let registry = Registry::new().with(Descriptor::of::<Imap>());
    assert_eq!(registry.names(), ["imap"]);
    let spec = PluginSpec::new("imap").options(json!({
        "host": "imap.example.com",
        "user": "me@example.com",
        "password_env": UNSET,
    }));
    let error = registry.plugin_set(&[spec]).unwrap_err().to_string();
    assert!(error.contains(UNSET), "{error}");
}

#[test]
fn the_set_offers_the_task() {
    let set = PluginSet::strict().with(with_password(config())).unwrap();
    assert_eq!(set.names(), ["imap"]);
    assert_eq!(set.task_names(), ["imap"]);
    assert!(set.task("imap").is_ok());
}

#[test]
fn a_bad_task_input_fails_before_any_connection() {
    let set = PluginSet::strict().with(with_password(config())).unwrap();
    let browser = RecordingBrowser::default();
    let sink = VecSink::new();
    let clock = Clock::new(Arc::new(ManualTimer::new()));
    let input = json!({ "since_secs": 0 });
    let cx = TaskContext::new(&browser, &input, &sink, &set, &clock, &NoPrompt);
    let error = block_on(set.task("imap").unwrap().run(&cx))
        .unwrap_err()
        .to_string();
    assert!(error.contains("since_secs"), "{error}");
    assert!(sink.lines().is_empty());
}

// ---- live ---------------------------------------------------------------------

struct TokioTimer;

impl Timer for TokioTimer {
    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(tokio::time::sleep(duration))
    }
}

/// Reads the newest unread email of the last day from a real mailbox. Run it
/// with `SB_TEST_IMAP_HOST`, `SB_TEST_IMAP_USER` and `SB_TEST_IMAP_PASSWORD_ENV`
/// (the NAME of the variable that holds the password) set:
/// `cargo test -p seleniumbase-rs-plugin-imap --test plugin -- --ignored`.
#[tokio::test(flavor = "current_thread")]
#[ignore = "needs a real mailbox: SB_TEST_IMAP_HOST, SB_TEST_IMAP_USER, SB_TEST_IMAP_PASSWORD_ENV"]
async fn live_a_real_mailbox_gives_its_newest_unread_email() {
    let var = |name: &str| std::env::var(name).unwrap_or_else(|_| panic!("{name} is not set"));
    let imap = Imap::new(ImapConfig {
        host: var("SB_TEST_IMAP_HOST"),
        user: var("SB_TEST_IMAP_USER"),
        password_env: var("SB_TEST_IMAP_PASSWORD_ENV"),
        poll_secs: 2,
        timeout_secs: 30,
        ..ImapConfig::default()
    })
    .expect("the options and the password variable");
    let query = Query {
        since_secs: 86_400,
        ..Query::default()
    };
    let found = imap
        .wait_for_email(&query, &Clock::new(Arc::new(TokioTimer)))
        .await
        .expect("an unread email with a code or a link from the last day");
    assert!(found.code.is_some() || found.link.is_some());
}
