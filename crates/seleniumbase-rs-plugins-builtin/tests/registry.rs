//! The registry for the features that are on. Run with no features, with each
//! one, and with all of them (`cargo test -p seleniumbase-rs-plugins-builtin
//! --all-features`).

use seleniumbase_rs_plugins_builtin::registry;

#[cfg(not(any(
    feature = "shield",
    feature = "block-resources",
    feature = "crx",
    feature = "fetcher",
    feature = "extractor",
    feature = "batcher",
    feature = "imap",
    feature = "browser",
    feature = "tor",
    feature = "crawler"
)))]
#[test]
fn with_no_feature_the_registry_is_empty() {
    assert!(registry().names().is_empty());
    let Err(error) = registry().build(&seleniumbase_rs_plugins_builtin::PluginSpec::new("shield"))
    else {
        panic!("an unknown name must fail");
    };
    assert!(
        error.to_string().contains("no plugin named `shield`"),
        "{error}"
    );
}

#[cfg(feature = "shield")]
mod shield {
    use super::registry;
    use seleniumbase_rs_plugins_builtin::PluginSpec;
    use serde_json::json;

    #[test]
    fn it_is_listed_and_builds_by_name() {
        let registry = registry();
        assert!(registry.names().contains(&"shield"));
        let descriptor = registry.get("shield").unwrap();
        assert!(descriptor.metadata().is_declared());
        let plugin = registry
            .build(&PluginSpec::new("shield").options(json!({ "level": "strict" })))
            .unwrap();
        assert_eq!(plugin.name(), "shield");
    }

    #[test]
    fn a_wrong_option_fails_closed() {
        let Err(error) =
            registry().build(&PluginSpec::new("shield").options(json!({ "levle": "strict" })))
        else {
            panic!("a typo must fail");
        };
        assert!(error.to_string().contains("levle"), "{error}");
    }
}

#[cfg(feature = "block-resources")]
#[test]
fn block_resources_is_listed_and_builds_by_name() {
    use seleniumbase_rs_plugins_builtin::PluginSpec;
    let registry = registry();
    assert!(registry.names().contains(&"block-resources"));
    let plugin = registry.build(&PluginSpec::new("block-resources")).unwrap();
    assert_eq!(plugin.name(), "block-resources");
}

#[cfg(feature = "crx")]
#[test]
fn crx_is_listed_and_builds_from_its_files() {
    use seleniumbase_rs_plugins_builtin::PluginSpec;
    let registry = registry();
    assert!(registry.names().contains(&"crx"));
    let plugin = registry
        .build(&PluginSpec::new("crx").options(serde_json::json!({ "files": [] })))
        .unwrap();
    assert_eq!(plugin.name(), "crx");
}

#[cfg(feature = "fetcher")]
mod fetcher {
    use super::registry;
    use seleniumbase_rs_plugins_builtin::PluginSpec;
    use serde_json::json;

    #[test]
    fn it_is_listed_and_builds_from_default_options() {
        let registry = registry();
        assert!(registry.names().contains(&"fetcher"));
        assert!(registry.get("fetcher").unwrap().metadata().is_declared());
        let plugin = registry.build(&PluginSpec::new("fetcher")).unwrap();
        assert_eq!(plugin.name(), "fetcher");
        let set = registry.plugin_set(&[PluginSpec::new("fetcher")]).unwrap();
        assert_eq!(set.names(), ["fetcher"]);
    }

    #[test]
    fn a_wrong_option_fails_closed() {
        let Err(error) =
            registry().build(&PluginSpec::new("fetcher").options(json!({ "captur": [] })))
        else {
            panic!("a typo must fail");
        };
        assert!(error.to_string().contains("captur"), "{error}");
    }

    #[cfg(not(any(
        feature = "shield",
        feature = "block-resources",
        feature = "crx",
        feature = "extractor",
        feature = "batcher",
        feature = "imap",
        feature = "browser",
        feature = "tor",
        feature = "crawler"
    )))]
    #[test]
    fn it_adds_exactly_its_own_name() {
        assert_eq!(registry().names(), ["fetcher"]);
    }
}

#[cfg(feature = "extractor")]
mod extractor {
    use super::registry;
    use seleniumbase_rs_plugins_builtin::PluginSpec;
    use serde_json::json;

    #[test]
    fn it_is_listed_and_builds_from_default_options() {
        let registry = registry();
        assert!(registry.names().contains(&"extractor"));
        assert!(registry.get("extractor").unwrap().metadata().is_declared());
        let plugin = registry.build(&PluginSpec::new("extractor")).unwrap();
        assert_eq!(plugin.name(), "extractor");
        let set = registry
            .plugin_set(&[PluginSpec::new("extractor")])
            .unwrap();
        assert_eq!(set.names(), ["extractor"]);
    }

    #[test]
    fn a_wrong_option_fails_closed() {
        let Err(error) =
            registry().build(&PluginSpec::new("extractor").options(json!({ "min_repeat": 3 })))
        else {
            panic!("a typo must fail");
        };
        assert!(error.to_string().contains("min_repeat"), "{error}");
    }

    #[cfg(not(any(
        feature = "shield",
        feature = "block-resources",
        feature = "crx",
        feature = "fetcher",
        feature = "batcher",
        feature = "imap",
        feature = "browser",
        feature = "tor",
        feature = "crawler"
    )))]
    #[test]
    fn it_adds_exactly_its_own_name() {
        assert_eq!(registry().names(), ["extractor"]);
    }
}

#[cfg(feature = "batcher")]
mod batcher {
    use super::registry;
    use seleniumbase_rs_plugins_builtin::PluginSpec;
    use serde_json::json;

    #[test]
    fn it_is_listed_and_builds_from_default_options() {
        let registry = registry();
        assert!(registry.names().contains(&"batcher"));
        assert!(registry.get("batcher").unwrap().metadata().is_declared());
        let plugin = registry.build(&PluginSpec::new("batcher")).unwrap();
        assert_eq!(plugin.name(), "batcher");
        let set = registry.plugin_set(&[PluginSpec::new("batcher")]).unwrap();
        assert_eq!(set.names(), ["batcher"]);
    }

    #[test]
    fn a_wrong_option_fails_closed() {
        let Err(error) =
            registry().build(&PluginSpec::new("batcher").options(json!({ "concurency": 2 })))
        else {
            panic!("a typo must fail");
        };
        assert!(error.to_string().contains("concurency"), "{error}");
    }

    #[cfg(not(any(
        feature = "shield",
        feature = "block-resources",
        feature = "crx",
        feature = "fetcher",
        feature = "extractor",
        feature = "imap",
        feature = "browser",
        feature = "tor",
        feature = "crawler"
    )))]
    #[test]
    fn it_adds_exactly_its_own_name() {
        assert_eq!(registry().names(), ["batcher"]);
    }
}

#[cfg(feature = "crawler")]
mod crawler {
    use super::registry;
    use seleniumbase_rs_plugins_builtin::PluginSpec;
    use serde_json::json;

    #[test]
    fn it_is_listed_and_builds_from_default_options() {
        let registry = registry();
        assert!(registry.names().contains(&"crawler"));
        assert!(registry.get("crawler").unwrap().metadata().is_declared());
        let plugin = registry.build(&PluginSpec::new("crawler")).unwrap();
        assert_eq!(plugin.name(), "crawler");
        let set = registry.plugin_set(&[PluginSpec::new("crawler")]).unwrap();
        assert_eq!(set.names(), ["crawler"]);
    }

    #[test]
    fn a_wrong_option_fails_closed() {
        let Err(error) =
            registry().build(&PluginSpec::new("crawler").options(json!({ "max_dept": 2 })))
        else {
            panic!("a typo must fail");
        };
        assert!(error.to_string().contains("max_dept"), "{error}");
    }

    #[cfg(not(any(
        feature = "shield",
        feature = "block-resources",
        feature = "crx",
        feature = "fetcher",
        feature = "extractor",
        feature = "imap",
        feature = "browser",
        feature = "tor",
        feature = "batcher"
    )))]
    #[test]
    fn it_adds_exactly_its_own_name() {
        assert_eq!(registry().names(), ["crawler"]);
    }
}

#[cfg(feature = "browser")]
mod browser {
    use super::registry;
    use seleniumbase_rs_plugins_builtin::PluginSpec;
    use serde_json::json;

    #[test]
    fn it_is_listed_and_builds_from_default_options() {
        let registry = registry();
        assert!(registry.names().contains(&"browser"));
        assert!(registry.get("browser").unwrap().metadata().is_declared());
        let plugin = registry.build(&PluginSpec::new("browser")).unwrap();
        assert_eq!(plugin.name(), "browser");
        let set = registry.plugin_set(&[PluginSpec::new("browser")]).unwrap();
        assert_eq!(set.names(), ["browser"]);
    }

    #[test]
    fn it_builds_from_its_two_options_and_the_set_passes_the_check() {
        use seleniumbase_rs_plugin::{BrowserFamily, Engine, LaunchContext};

        let spec = PluginSpec::new("browser").options(json!({
            "extension_zip": "one.crx, two.zip",
            "extension_dir": ["folder"],
        }));
        let registry = registry();
        let plugin = registry.build(&spec).unwrap();
        assert_eq!(plugin.name(), "browser");
        // The paths are looked at at launch, not here; the set only needs the
        // grants the options ask for (read the paths, write a temp folder).
        let set = registry.plugin_set(&[spec]).unwrap();
        set.check(&LaunchContext {
            engine: Engine::Cdp,
            family: BrowserFamily::Chromium,
            headless: true,
            connecting: false,
        })
        .unwrap();
    }

    #[test]
    fn a_wrong_option_fails_closed() {
        let Err(error) =
            registry().build(&PluginSpec::new("browser").options(json!({ "extension_zp": [] })))
        else {
            panic!("a typo must fail");
        };
        assert!(error.to_string().contains("extension_zp"), "{error}");
    }

    #[test]
    fn the_options_that_are_not_built_yet_are_refused() {
        // `wait_for_workers` and `session` wait for plugin API hooks, so the
        // plugin refuses them instead of taking them and doing nothing.
        for option in ["wait_for_workers", "session"] {
            let Err(error) =
                registry().build(&PluginSpec::new("browser").options(json!({ option: true })))
            else {
                panic!("`{option}` must be refused");
            };
            assert!(error.to_string().contains(option), "{error}");
        }
    }

    #[cfg(not(any(
        feature = "shield",
        feature = "block-resources",
        feature = "crx",
        feature = "fetcher",
        feature = "extractor",
        feature = "batcher",
        feature = "imap",
        feature = "tor",
        feature = "crawler"
    )))]
    #[test]
    fn it_adds_exactly_its_own_name() {
        assert_eq!(registry().names(), ["browser"]);
    }
}

/// The password variable the `imap` tests name, and a way to have it set.
///
/// `imap` only accepts a `password_env` that starts with `IMAP_`, `MAIL_` or
/// `SB_`, and it needs the variable set when it is built. No process that runs
/// these tests has such a variable, and a test cannot set one itself: the tests
/// of a binary share one process and `std::env::set_var` is `unsafe` in edition
/// 2024. So a test that needs the variable runs again in a child process of
/// this same test binary that has it ([`imap_variable::with_password_set`]).
/// Its value is never used: nothing here connects to a mail server.
#[cfg(feature = "imap")]
mod imap_variable {
    use std::process::Command;

    /// The variable the tests name as `password_env`.
    pub const NAME: &str = "SB_BUILTIN_IMAP_TEST_PASSWORD";

    /// Runs `body` with [`NAME`] set. `test` is the full libtest name of the
    /// calling test (such as `imap::it_builds_from_options`): when the variable
    /// is not set, that one test is run again in a child process that has it,
    /// and the child's success is asserted.
    pub fn with_password_set(test: &str, body: impl FnOnce()) {
        if std::env::var_os(NAME).is_some() {
            body();
            return;
        }
        let exe = std::env::current_exe().expect("the path of this test binary");
        let output = Command::new(exe)
            .args([test, "--exact", "--nocapture", "--test-threads=1"])
            .env(NAME, "not-a-real-password")
            .output()
            .expect("the test binary starts again");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        // `--exact` with a name that matches nothing also exits 0, so the
        // test that ran must be counted.
        assert!(
            output.status.success() && stdout.contains("test result: ok. 1 passed;"),
            "{test} failed in the child process ({}):\n{stdout}\n{stderr}",
            output.status
        );
    }
}

#[cfg(feature = "imap")]
mod imap {
    use super::imap_variable::with_password_set;
    use super::registry;
    use seleniumbase_rs_plugin::{BrowserFamily, Engine, HostInfo, LaunchContext};
    use seleniumbase_rs_plugins_builtin::PluginSpec;
    use serde_json::json;

    /// The variable the plugin finds a "password" in when it is built. Only a
    /// test run through `with_password_set` has it; its value is never used:
    /// nothing here connects to a mail server.
    const SET_VARIABLE: &str = super::imap_variable::NAME;

    /// A variable that is not set anywhere (its `SB_` prefix keeps the prefix rule out of the way).
    const UNSET_VARIABLE: &str = "SB_BUILTIN_IMAP_TEST_UNSET_5C1E";

    fn spec() -> PluginSpec {
        PluginSpec::new("imap").options(json!({
            "host": "imap.example.com",
            "user": "me@example.com",
            "password_env": SET_VARIABLE,
        }))
    }

    #[test]
    fn it_is_listed_and_declared() {
        let registry = registry();
        assert!(registry.names().contains(&"imap"));
        assert!(registry.get("imap").unwrap().metadata().is_declared());
    }

    #[test]
    fn it_builds_from_host_user_and_password_env_and_offers_its_task() {
        with_password_set(
            "imap::it_builds_from_host_user_and_password_env_and_offers_its_task",
            || {
                let registry = registry();
                let plugin = registry.build(&spec()).unwrap();
                assert_eq!(plugin.name(), "imap");
                assert!(plugin.task().is_some());
                let set = registry.plugin_set(&[spec()]).unwrap();
                assert_eq!(set.names(), ["imap"]);
                assert_eq!(set.task_names(), ["imap"]);
            },
        );
    }

    #[test]
    fn the_set_passes_the_check_on_the_cdp_engine() {
        with_password_set("imap::the_set_passes_the_check_on_the_cdp_engine", || {
            // A WebDriver host offers no tasks, so it refuses this plugin for
            // `task`, as it does every task plugin (the plugin's own tests assert
            // that); the CDP engine is the one that runs it as a plugin.
            let set = registry().plugin_set(&[spec()]).unwrap();
            for connecting in [false, true] {
                let launch = LaunchContext {
                    engine: Engine::Cdp,
                    family: BrowserFamily::Chromium,
                    headless: true,
                    connecting,
                };
                set.check(&launch).unwrap();
                set.check_with(&launch, &HostInfo::cdp()).unwrap();
            }
        });
    }

    #[test]
    fn a_wrong_option_fails_closed() {
        let Err(error) = registry()
            .build(&PluginSpec::new("imap").options(json!({ "hots": "imap.example.com" })))
        else {
            panic!("a typo must fail");
        };
        assert!(error.to_string().contains("hots"), "{error}");
    }

    #[test]
    fn the_password_is_not_an_option() {
        let Err(error) =
            registry().build(&PluginSpec::new("imap").options(json!({ "password": "hunter2" })))
        else {
            panic!("a password option must be refused");
        };
        let message = error.to_string();
        assert!(message.contains("password"), "{message}");
        assert!(!message.contains("hunter2"), "{message}");
    }

    #[test]
    fn a_missing_host_and_an_unset_password_variable_fail_the_build() {
        let Err(error) = registry().build(&PluginSpec::new("imap")) else {
            panic!("no host must fail");
        };
        assert!(error.to_string().contains("`host` is required"), "{error}");

        let Err(error) = registry().build(&PluginSpec::new("imap").options(json!({
            "host": "imap.example.com",
            "user": "me@example.com",
            "password_env": UNSET_VARIABLE,
        }))) else {
            panic!("an unset password variable must fail");
        };
        assert!(error.to_string().contains(UNSET_VARIABLE), "{error}");
        assert!(error.to_string().contains("not set or is empty"), "{error}");
    }

    #[test]
    fn a_password_variable_outside_the_prefixes_is_refused_even_when_it_is_set() {
        // A settings file that names `GITHUB_TOKEN` (or any variable that is
        // not `IMAP_`, `MAIL_` or `SB_`) would have the plugin send that
        // variable's value to `host`, so the build fails and the message names
        // the rule and the variable, never its value. `PATH` is set in every
        // process that runs these tests.
        let value = std::env::var("PATH").expect("PATH is set");
        for name in ["PATH", "GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY", "password"] {
            let Err(error) = registry().build(&PluginSpec::new("imap").options(json!({
                "host": "attacker.example",
                "user": "me@example.com",
                "password_env": name,
            }))) else {
                panic!("{name} must be refused");
            };
            let message = error.to_string();
            assert!(
                message.contains("must name a variable starting with IMAP_, MAIL_ or SB_"),
                "{message}"
            );
            assert!(message.contains(&format!("`{name}`")), "{message}");
            assert!(!message.contains(&value), "{message}");
        }
    }

    #[cfg(not(any(
        feature = "shield",
        feature = "block-resources",
        feature = "crx",
        feature = "fetcher",
        feature = "extractor",
        feature = "batcher",
        feature = "browser",
        feature = "tor",
        feature = "crawler"
    )))]
    #[test]
    fn it_adds_exactly_its_own_name() {
        assert_eq!(registry().names(), ["imap"]);
    }
}

#[cfg(feature = "tor")]
mod tor {
    use super::registry;
    use seleniumbase_rs_plugin::{BrowserFamily, Engine, HostInfo, LaunchContext, PluginError};
    use seleniumbase_rs_plugins_builtin::PluginSpec;
    use serde_json::json;

    fn context(connecting: bool) -> LaunchContext {
        LaunchContext {
            engine: Engine::Cdp,
            family: BrowserFamily::Chromium,
            headless: true,
            connecting,
        }
    }

    #[test]
    fn it_is_listed_and_declared() {
        let registry = registry();
        assert!(registry.names().contains(&"tor"));
        assert!(registry.get("tor").unwrap().metadata().is_declared());
    }

    #[test]
    fn it_builds_from_default_options_and_from_browser_isolation() {
        let registry = registry();
        let plugin = registry.build(&PluginSpec::new("tor")).unwrap();
        assert_eq!(plugin.name(), "tor");
        let set = registry.plugin_set(&[PluginSpec::new("tor")]).unwrap();
        assert_eq!(set.names(), ["tor"]);

        let spec = PluginSpec::new("tor").options(json!({ "isolation": "browser" }));
        let plugin = registry.build(&spec).unwrap();
        assert_eq!(plugin.name(), "tor");
        let set = registry.plugin_set(&[spec]).unwrap();
        assert_eq!(set.names(), ["tor"]);
    }

    #[test]
    fn the_re_export_is_the_plugin_crate_and_its_default_is_the_local_socks_port() {
        use seleniumbase_rs_plugin::Configurable;
        use seleniumbase_rs_plugins_builtin::tor::{Isolation, Tor};

        let default = Tor::configure(&serde_json::Value::Null).unwrap();
        assert_eq!(default.config().socks, "127.0.0.1:9050".parse().unwrap());
        assert_eq!(default.config().isolation, Isolation::PerContext);

        let browser = Tor::configure(&json!({ "isolation": "browser" })).unwrap();
        assert_eq!(browser.config().isolation, Isolation::Browser);
    }

    #[test]
    fn the_set_passes_the_check_without_a_tor_daemon() {
        // `check` reads declarations only; the SOCKS probe runs in
        // `before_launch`, so no listener is needed here.
        let set = registry().plugin_set(&[PluginSpec::new("tor")]).unwrap();
        set.check(&context(false)).unwrap();
        set.check_with(&context(false), &HostInfo::cdp()).unwrap();
    }

    #[test]
    fn the_set_refuses_a_browser_the_program_attaches_to() {
        let set = registry().plugin_set(&[PluginSpec::new("tor")]).unwrap();
        let error = set.check(&context(true)).unwrap_err();
        assert!(
            matches!(&error, PluginError::Requirement { plugin, .. } if plugin == "tor"),
            "{error:?}"
        );
    }

    #[test]
    fn a_control_port_with_a_cookie_file_builds_and_passes_the_check() {
        // The cookie file is the one file the plugin reads: it comes out as a
        // declared `host.fs.read`, which the strict set grants. The file is
        // not opened here.
        let spec = PluginSpec::new("tor").options(json!({
            "control": "127.0.0.1:9051",
            "control_auth": { "cookie_path": "/var/run/tor/control.authcookie" },
        }));
        let set = registry().plugin_set(&[spec]).unwrap();
        set.check(&context(false)).unwrap();
        set.check_with(&context(false), &HostInfo::cdp()).unwrap();
    }

    #[test]
    fn a_socks_address_that_is_not_loopback_is_refused() {
        for address in ["192.168.1.10:9050", "10.0.0.1:9050", "0.0.0.0:9050"] {
            let Err(error) =
                registry().build(&PluginSpec::new("tor").options(json!({ "socks": address })))
            else {
                panic!("`{address}` must be refused");
            };
            assert!(matches!(error, PluginError::Config(_)), "{error:?}");
            let message = error.to_string();
            assert!(
                message.contains("socks") && message.contains("loopback"),
                "{message}"
            );
        }
        // A loopback address on another port is the usual Tor Browser setup.
        registry()
            .build(&PluginSpec::new("tor").options(json!({ "socks": "127.0.0.1:9150" })))
            .unwrap();
    }

    #[test]
    fn a_wrong_option_fails_closed() {
        let Err(error) =
            registry().build(&PluginSpec::new("tor").options(json!({ "sock": "127.0.0.1:9050" })))
        else {
            panic!("a typo must fail");
        };
        assert!(error.to_string().contains("sock"), "{error}");

        let Err(error) =
            registry().build(&PluginSpec::new("tor").options(json!({ "isolation": "tab" })))
        else {
            panic!("an unknown isolation must fail");
        };
        assert!(error.to_string().contains("per-context"), "{error}");
    }

    #[test]
    fn the_control_password_is_not_an_option() {
        let Err(error) = registry().build(&PluginSpec::new("tor").options(json!({
            "control": "127.0.0.1:9051",
            "control_auth": { "password": "hunter2" },
        }))) else {
            panic!("a password option must be refused");
        };
        let message = error.to_string();
        assert!(message.contains("password"), "{message}");
        assert!(!message.contains("hunter2"), "{message}");
    }

    #[cfg(not(any(
        feature = "shield",
        feature = "block-resources",
        feature = "crx",
        feature = "fetcher",
        feature = "extractor",
        feature = "batcher",
        feature = "imap",
        feature = "browser",
        feature = "crawler"
    )))]
    #[test]
    fn it_adds_exactly_its_own_name() {
        assert_eq!(registry().names(), ["tor"]);
    }
}

/// `tor` is a privacy plugin (the Enforce phase) and `browser` an extension
/// plugin (the Normal phase), so a set runs `browser` first whichever one was
/// added first, and the two pass the check together.
#[cfg(all(feature = "browser", feature = "tor"))]
#[test]
fn a_set_with_browser_and_tor_runs_browser_first() {
    use seleniumbase_rs_plugin::{BrowserFamily, Engine, LaunchContext};
    use seleniumbase_rs_plugins_builtin::PluginSpec;

    let launch = LaunchContext {
        engine: Engine::Cdp,
        family: BrowserFamily::Chromium,
        headless: true,
        connecting: false,
    };
    for specs in [
        [PluginSpec::new("browser"), PluginSpec::new("tor")],
        [PluginSpec::new("tor"), PluginSpec::new("browser")],
    ] {
        let set = registry().plugin_set(&specs).unwrap();
        assert_eq!(set.names(), ["browser", "tor"]);
        set.check(&launch).unwrap();
    }
}

#[cfg(all(
    feature = "shield",
    feature = "block-resources",
    feature = "crx",
    feature = "fetcher",
    feature = "extractor",
    feature = "batcher",
    feature = "imap",
    feature = "browser",
    feature = "tor",
    feature = "crawler"
))]
#[test]
fn all_ten_are_listed_in_order() {
    let registry = registry();
    assert_eq!(
        registry.names(),
        [
            "shield",
            "block-resources",
            "crx",
            "fetcher",
            "extractor",
            "batcher",
            "crawler",
            "browser",
            "imap",
            "tor"
        ]
    );
    for name in registry.names() {
        assert!(
            registry.get(name).unwrap().metadata().is_declared(),
            "{name}"
        );
    }
}

/// `crx` and `browser` load extensions and cannot share a set, so the whole
/// set of built-ins is checked as two sets of nine, one without each of them,
/// and the pair as a conflict.
#[cfg(all(
    feature = "shield",
    feature = "block-resources",
    feature = "crx",
    feature = "fetcher",
    feature = "extractor",
    feature = "batcher",
    feature = "crawler",
    feature = "imap",
    feature = "tor",
    feature = "browser"
))]
mod all_built_ins {
    use super::imap_variable::{NAME as IMAP_VARIABLE, with_password_set};
    use super::registry;
    use seleniumbase_rs_plugin::{
        BrowserFamily, Engine, HostInfo, LaunchContext, PluginError, PluginSet,
    };
    use seleniumbase_rs_plugins_builtin::PluginSpec;
    use serde_json::json;

    fn context() -> LaunchContext {
        LaunchContext {
            engine: Engine::Cdp,
            family: BrowserFamily::Chromium,
            headless: true,
            connecting: false,
        }
    }

    /// The specs of every built-in plugin except the two that load extensions.
    fn common() -> Vec<PluginSpec> {
        vec![
            PluginSpec::new("shield"),
            PluginSpec::new("block-resources"),
            PluginSpec::new("fetcher"),
            PluginSpec::new("extractor"),
            PluginSpec::new("batcher"),
            PluginSpec::new("crawler"),
            imap(),
            PluginSpec::new("tor"),
        ]
    }

    fn crx() -> PluginSpec {
        PluginSpec::new("crx").options(json!({ "files": [] }))
    }

    /// `imap` reads its password from the variable `password_env` names when it
    /// is built. Only a test run through `with_password_set` has the variable and its
    /// value is never used: nothing here connects to a mail server.
    fn imap() -> PluginSpec {
        PluginSpec::new("imap").options(json!({
            "host": "imap.example.com",
            "user": "me@example.com",
            "password_env": IMAP_VARIABLE,
        }))
    }

    fn set_of(specs: &[PluginSpec]) -> PluginSet {
        registry().plugin_set(specs).unwrap()
    }

    #[test]
    fn every_plugin_but_browser_forms_one_strict_set() {
        with_password_set(
            "all_built_ins::every_plugin_but_browser_forms_one_strict_set",
            || {
                let mut specs = common();
                specs.push(crx());
                let set = set_of(&specs);
                set.check(&context()).unwrap();
                let mut names = set.names();
                names.sort_unstable();
                assert_eq!(
                    names,
                    [
                        "batcher",
                        "block-resources",
                        "crawler",
                        "crx",
                        "extractor",
                        "fetcher",
                        "imap",
                        "shield",
                        "tor"
                    ]
                );
            },
        );
    }

    #[test]
    fn every_plugin_but_crx_forms_one_strict_set() {
        with_password_set(
            "all_built_ins::every_plugin_but_crx_forms_one_strict_set",
            || {
                let mut specs = common();
                specs.push(PluginSpec::new("browser"));
                let set = set_of(&specs);
                set.check(&context()).unwrap();
                set.check_with(&context(), &HostInfo::cdp()).unwrap();
                let mut names = set.names();
                names.sort_unstable();
                assert_eq!(
                    names,
                    [
                        "batcher",
                        "block-resources",
                        "browser",
                        "crawler",
                        "extractor",
                        "fetcher",
                        "imap",
                        "shield",
                        "tor"
                    ]
                );
            },
        );
    }

    #[test]
    fn crx_and_browser_conflict_in_a_checked_set() {
        // The registry only refuses a duplicate name; the conflict the
        // `browser` plugin declares with `crx` comes out when the set is
        // checked, whichever one was added first.
        for specs in [
            [crx(), PluginSpec::new("browser")],
            [PluginSpec::new("browser"), crx()],
        ] {
            let set = set_of(&specs);
            assert_eq!(set.names().len(), 2);
            let checked = set.check(&context());
            assert!(
                matches!(checked, Err(PluginError::Conflict { .. })),
                "{checked:?}"
            );
            let with_host = set.check_with(&context(), &HostInfo::cdp());
            assert!(
                matches!(with_host, Err(PluginError::Conflict { .. })),
                "{with_host:?}"
            );
        }
    }
}
