use std::sync::{Arc, Mutex};

use seleniumbase_rs_plugin::{
    BrowserFamily, Engine, LaunchContext, LaunchSettings, Package, PageHandle, Plugin, PluginError,
    PluginSet, Requirements, Result, async_trait,
};
use seleniumbase_rs_plugin_testing::{Call, RecordingPage, block_on};

/// A plugin whose behaviour each test sets up.
#[derive(Default)]
struct Probe {
    name: &'static str,
    needs: &'static [&'static str],
    requirements: Requirements,
    packages: Vec<Package>,
    fail: bool,
    log: Option<Arc<Mutex<Vec<String>>>>,
}

impl Probe {
    fn named(name: &'static str) -> Self {
        Self {
            name,
            ..Self::default()
        }
    }

    fn note(&self, hook: &str) {
        if let Some(log) = &self.log {
            log.lock().unwrap().push(format!("{}:{hook}", self.name));
        }
    }

    fn outcome(&self) -> Result<()> {
        if self.fail {
            Err(PluginError::other("boom"))
        } else {
            Ok(())
        }
    }
}

#[async_trait]
impl Plugin for Probe {
    fn name(&self) -> &str {
        self.name
    }
    fn dependencies(&self) -> &[&str] {
        self.needs
    }
    fn requirements(&self) -> Requirements {
        self.requirements
    }
    fn packages(&self) -> Vec<Package> {
        self.packages.clone()
    }
    async fn before_launch(&self, launch: &mut LaunchSettings) -> Result<()> {
        self.note("before_launch");
        launch.args.push(format!("--{}", self.name));
        self.outcome()
    }
    async fn on_page_created(&self, page: &dyn PageHandle) -> Result<()> {
        self.note("on_page_created");
        page.evaluate(self.name).await?;
        self.outcome()
    }
    async fn on_close(&self) -> Result<()> {
        self.note("on_close");
        self.outcome()
    }
}

fn context() -> LaunchContext {
    LaunchContext {
        engine: Engine::Cdp,
        family: BrowserFamily::Chromium,
        headless: true,
        connecting: false,
    }
}

#[test]
fn a_second_plugin_with_the_same_name_is_refused() {
    let error = PluginSet::new()
        .with(Probe::named("a"))
        .unwrap()
        .with(Probe::named("a"))
        .unwrap_err();
    assert!(matches!(error, PluginError::DuplicateName(name) if name == "a"));
}

#[test]
fn plugins_run_in_order_with_run_last_ones_at_the_end() {
    let set = PluginSet::new()
        .with(Probe {
            requirements: Requirements::RUN_LAST,
            ..Probe::named("last")
        })
        .unwrap()
        .with(Probe::named("first"))
        .unwrap()
        .with(Probe::named("second"))
        .unwrap();
    assert_eq!(set.names(), ["first", "second", "last"]);

    let mut launch = LaunchSettings::default();
    block_on(set.before_launch(&mut launch)).unwrap();
    assert_eq!(launch.args, ["--first", "--second", "--last"]);
}

#[test]
fn a_missing_dependency_is_named() {
    let set = PluginSet::new()
        .with(Probe {
            needs: &["stealth"],
            ..Probe::named("captcha")
        })
        .unwrap();
    let error = set.check(&context()).unwrap_err().to_string();
    assert!(
        error.contains("captcha") && error.contains("stealth"),
        "{error}"
    );
}

#[test]
fn requirements_refuse_a_browser_that_does_not_fit() {
    let headful = PluginSet::new()
        .with(Probe {
            requirements: Requirements::HEADFUL,
            ..Probe::named("watch")
        })
        .unwrap();
    assert!(matches!(
        headful.check(&context()),
        Err(PluginError::Requirement { .. })
    ));
    assert!(
        headful
            .check(&LaunchContext {
                headless: false,
                ..context()
            })
            .is_ok()
    );

    let chromium = PluginSet::new()
        .with(Probe {
            requirements: Requirements::CHROMIUM_ONLY | Requirements::LAUNCH_ONLY,
            ..Probe::named("cdp")
        })
        .unwrap();
    let firefox = LaunchContext {
        family: BrowserFamily::Firefox,
        ..context()
    };
    assert!(chromium.check(&firefox).is_err());
    assert!(
        chromium
            .check(&LaunchContext {
                connecting: true,
                ..context()
            })
            .is_err()
    );
    assert!(chromium.check(&context()).is_ok());
}

#[test]
fn a_package_that_does_not_say_where_it_loads_is_refused() {
    let set = PluginSet::new()
        .with(Probe {
            packages: vec![Package::script("window.x = 1")],
            ..Probe::named("loose")
        })
        .unwrap();
    let error = set.check(&context()).unwrap_err().to_string();
    assert!(error.contains("only_on"), "{error}");
}

#[test]
fn a_failing_hook_stops_the_launch_before_later_plugins_run() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let set = PluginSet::new()
        .with(Probe {
            fail: true,
            log: Some(log.clone()),
            ..Probe::named("proxy")
        })
        .unwrap()
        .with(Probe {
            log: Some(log.clone()),
            ..Probe::named("later")
        })
        .unwrap();
    let error = block_on(set.before_launch(&mut LaunchSettings::default())).unwrap_err();
    assert!(
        matches!(&error, PluginError::Hook { plugin, hook: "before_launch", .. } if plugin == "proxy"),
        "{error}"
    );
    assert_eq!(*log.lock().unwrap(), ["proxy:before_launch"]);
}

#[test]
fn every_plugin_closes_even_when_one_fails() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let set = PluginSet::new()
        .with(Probe {
            fail: true,
            log: Some(log.clone()),
            ..Probe::named("a")
        })
        .unwrap()
        .with(Probe {
            log: Some(log.clone()),
            ..Probe::named("b")
        })
        .unwrap();
    let failures = block_on(set.on_close());
    assert_eq!(failures.len(), 1);
    assert_eq!(*log.lock().unwrap(), ["a:on_close", "b:on_close"]);
}

#[test]
fn packages_are_added_before_the_plugins_own_page_hook() {
    let page = RecordingPage::new();
    let set = PluginSet::new()
        .with(Probe {
            packages: vec![Package::style("body { zoom: 0.9 }").everywhere()],
            ..Probe::named("zoom")
        })
        .unwrap();
    block_on(set.on_page_created(&page)).unwrap();
    let calls = page.calls();
    assert!(matches!(&calls[0], Call::InitScript(script) if script.contains("zoom: 0.9")));
    assert_eq!(calls[1], Call::Evaluate("zoom".into()));
}

#[test]
fn a_package_script_checks_the_host_and_quotes_its_values() {
    let script = Package::script_url("https://cdn.example/x.js?a=\"b\"")
        .integrity("sha384-abc")
        .only_on(["example.com"])
        .init_script()
        .unwrap();
    assert!(script.contains(r#"["example.com"]"#), "{script}");
    assert!(
        script.contains(r#""https://cdn.example/x.js?a=\"b\"""#),
        "{script}"
    );
    assert!(
        script.contains(r#"el.integrity = "sha384-abc""#),
        "{script}"
    );
    assert!(
        Package::script_url("https://cdn.example/x.js")
            .init_script()
            .is_none()
    );
}
