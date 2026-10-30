//! The plugin: options, registration, the task's input check, and one live
//! test that needs a real mailbox.

use std::cell::Cell;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use seleniumbase_rs_plugin::{
    BrowserFamily, Capability, Category, Clock, Configurable, Descriptor, Engine, HostInfo,
    LaunchContext, NetScope, NoPrompt, PluginError, PluginSet, PluginSpec, Registry, TaskContext,
    Timer,
};
use seleniumbase_rs_plugin_imap::{Imap, ImapConfig, Query};
use seleniumbase_rs_plugin_testing::{ManualTimer, RecordingBrowser, VecSink, block_on};
use serde_json::{Value, json};

/// A change to a set of options, for the table of bad ones.
type Change = fn(&mut ImapConfig);

/// A variable that is not set anywhere. Its name starts with `SB_`, so the
/// check that refuses it is the unset one, not the prefix rule.
const UNSET: &str = "SB_IMAP_TEST_UNSET_8F3A21";

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
    assert_eq!(
        error_of(Imap::configure(&Value::Null)),
        "imap: `host` is required"
    );
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
    c.password_env = "IMAP_EMPTY_ONE".into();
    let message = error_of(Imap::new_with(c, &|_| Some(String::new())));
    assert!(message.contains("IMAP_EMPTY_ONE"), "{message}");
}

#[test]
fn a_missing_variable_whose_name_looks_like_a_password_is_not_repeated() {
    // `SB_hunter2` has an accepted prefix, but its lowercase letters make it
    // look like a pasted password rather than a variable name, so the error
    // does not repeat it.
    let mut c = config();
    c.password_env = "SB_hunter2".into();
    let message = error_of(Imap::new_with(c, &|_| None));
    assert_eq!(
        message,
        "imap: the environment variable named by `password_env` is not set or is empty; it must hold the password or app password"
    );
    assert!(!message.contains("hunter2"), "{message}");
}

#[test]
fn password_env_must_be_a_name_not_a_password() {
    for value in [
        "my secret pass",
        "pa$$word",
        "1ABC",
        "a=b",
        "SB_a=b",
        "IMAP_my pass",
    ] {
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

/// Names that `password_env` must refuse: the plugin sends the password they
/// hold to `host`, so a name outside `IMAP_`, `MAIL_` and `SB_` (a token that
/// another tool keeps in the environment, a different case, a longer word that
/// merely contains a prefix) must never get as far as the server.
///
/// The flag says whether the message may repeat the name: only a name that
/// looks like an environment variable (capitals, digits and `_`) is repeated,
/// so a password that someone pasted into the option is not printed back.
const REFUSED_NAMES: &[(&str, bool)] = &[
    ("GITHUB_TOKEN", true),
    ("AWS_SECRET_ACCESS_KEY", true),
    ("PATH", true),
    ("XIMAP_PASSWORD", true),
    ("SBRS_PASSWORD", true),
    ("SB", true),
    ("IMAP", true),
    ("password", false),
    ("imap_password", false),
    ("Mail_App_Password", false),
    ("sb_password", false),
    ("hunter2", false),
    ("Tr0ub4dor3", false),
];

#[test]
fn password_env_outside_the_prefixes_is_refused_without_reading_the_variable() {
    const RULE: &str =
        "imap: `password_env` must name a variable starting with IMAP_, MAIL_ or SB_";
    for (name, echoed) in REFUSED_NAMES {
        let read = Cell::new(false);
        let mut c = config();
        c.password_env = (*name).into();
        let message = error_of(Imap::new_with(c, &|_| {
            read.set(true);
            Some("s3cret-app-password".into())
        }));
        if *echoed {
            assert_eq!(message, format!("{RULE} (got `{name}`)"));
        } else {
            // Not a variable name: it may be a password, so it is not repeated.
            assert_eq!(message, RULE);
            assert!(!message.contains(&format!("`{name}`")), "{message}");
        }
        assert!(!read.get(), "{name}: the variable was read");
        assert!(!message.contains("s3cret-app-password"), "{message}");
    }
}

#[test]
fn a_refused_name_fails_the_options_even_when_the_variable_is_set() {
    // `PATH` is set in every process that runs these tests; a settings file
    // that names it (or any other variable) must not get it sent to `host`.
    let value = std::env::var("PATH").expect("PATH is set");
    let message = error_of(Imap::configure(&json!({
        "host": "attacker.example",
        "user": "me@example.com",
        "password_env": "PATH",
    })));
    assert!(message.starts_with("imap: "), "{message}");
    assert!(
        message.contains("starting with IMAP_, MAIL_ or SB_"),
        "{message}"
    );
    assert!(message.contains("`PATH`"), "{message}");
    assert!(!message.contains(&value), "{message}");
}

#[test]
fn each_accepted_prefix_is_accepted() {
    for name in [
        "IMAP_PASSWORD",
        "MAIL_APP_PASSWORD",
        "SB_TEST_PASSWORD",
        "IMAP_X1",
        "MAIL_x",
        "SB_9",
    ] {
        let mut c = config();
        c.password_env = name.into();
        let plugin = Imap::new_with(c, &|asked| (asked == name).then(|| "x".into()))
            .unwrap_or_else(|error| panic!("{name} was refused: {error}"));
        assert_eq!(plugin.config().password_env, name);
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
fn it_is_a_declared_testing_plugin_with_a_version_and_a_summary() {
    assert_eq!(Imap::NAME, "imap");
    let meta = Imap::describe();
    assert!(meta.is_declared());
    assert_eq!(meta.category, Some(Category::Testing));
    assert_eq!(meta.version, env!("CARGO_PKG_VERSION"));
    assert!(meta.summary.contains("IMAP"), "{}", meta.summary);
}

#[test]
fn it_keeps_no_state_because_each_wait_opens_its_own_connection() {
    let meta = Imap::describe();
    for refused in [
        Capability::State { persist: false },
        Capability::State { persist: true },
    ] {
        assert!(!meta.capabilities.covers(&refused), "{refused}");
    }
}

#[test]
fn tls_and_the_certificate_are_not_options() {
    // The connection is always TLS from the first byte and the certificate
    // and host name are always checked, so there is nothing to turn off.
    for option in ["tls", "ca_file", "starttls", "insecure", "verify"] {
        let error = error_of(Imap::configure(&json!({ option: "none" })));
        assert_eq!(error, format!("imap: unknown option `{option}`"));
    }
}

fn context(engine: Engine, family: BrowserFamily) -> LaunchContext {
    LaunchContext {
        engine,
        family,
        headless: true,
        connecting: false,
    }
}

#[test]
fn the_set_passes_the_check_on_the_cdp_engine() {
    let set = PluginSet::strict().with(with_password(config())).unwrap();
    let launch = context(Engine::Cdp, BrowserFamily::Chromium);
    set.check(&launch).unwrap();
    set.check_with(&launch, &HostInfo::cdp()).unwrap();
}

#[test]
fn a_webdriver_host_refuses_the_task_like_every_other_task_plugin() {
    // `HostInfo::supports` offers no tasks on WebDriver yet, so the set is
    // refused there for `task`, before any browser starts. Nothing else of
    // the plugin is a problem: it asks for no browser capability.
    let set = PluginSet::strict().with(with_password(config())).unwrap();
    for family in [BrowserFamily::Chromium, BrowserFamily::Firefox] {
        let launch = context(Engine::WebDriver, family);
        let error = set
            .check_with(&launch, &HostInfo::webdriver(family))
            .unwrap_err();
        assert!(
            matches!(&error, PluginError::Unsupported { capability, .. } if capability == "task"),
            "{family:?}: {error:?}"
        );
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
/// (the NAME of the variable that holds the password; it must start with
/// `IMAP_`, `MAIL_` or `SB_`) set:
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
