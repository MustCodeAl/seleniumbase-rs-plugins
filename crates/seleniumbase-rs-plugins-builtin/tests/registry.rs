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
    feature = "browser",
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
        feature = "browser",
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
        feature = "browser",
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
        feature = "browser",
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
        feature = "browser",
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
        feature = "crawler"
    )))]
    #[test]
    fn it_adds_exactly_its_own_name() {
        assert_eq!(registry().names(), ["browser"]);
    }
}

#[cfg(all(
    feature = "shield",
    feature = "block-resources",
    feature = "crx",
    feature = "fetcher",
    feature = "extractor",
    feature = "batcher",
    feature = "browser",
    feature = "crawler"
))]
#[test]
fn all_eight_are_listed_in_order() {
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
            "browser"
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
/// set of built-ins is checked as two sets of seven, one without each of them,
/// and the pair as a conflict.
#[cfg(all(
    feature = "shield",
    feature = "block-resources",
    feature = "crx",
    feature = "fetcher",
    feature = "extractor",
    feature = "batcher",
    feature = "crawler",
    feature = "browser"
))]
mod all_built_ins {
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
        ]
    }

    fn crx() -> PluginSpec {
        PluginSpec::new("crx").options(json!({ "files": [] }))
    }

    fn set_of(specs: &[PluginSpec]) -> PluginSet {
        registry().plugin_set(specs).unwrap()
    }

    #[test]
    fn every_plugin_but_browser_forms_one_strict_set() {
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
                "shield"
            ]
        );
    }

    #[test]
    fn every_plugin_but_crx_forms_one_strict_set() {
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
                "shield"
            ]
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
