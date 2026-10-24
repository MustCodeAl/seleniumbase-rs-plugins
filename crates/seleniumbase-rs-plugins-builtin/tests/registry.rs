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
        feature = "batcher"
    )))]
    #[test]
    fn it_adds_exactly_its_own_name() {
        assert_eq!(registry().names(), ["crawler"]);
    }
}

#[cfg(all(
    feature = "shield",
    feature = "block-resources",
    feature = "crx",
    feature = "fetcher",
    feature = "extractor",
    feature = "batcher",
    feature = "crawler"
))]
#[test]
fn all_seven_are_listed_in_order_and_form_one_strict_set() {
    use seleniumbase_rs_plugin::{BrowserFamily, Engine, LaunchContext};
    use seleniumbase_rs_plugins_builtin::PluginSpec;
    use serde_json::json;

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
            "crawler"
        ]
    );
    for name in registry.names() {
        assert!(
            registry.get(name).unwrap().metadata().is_declared(),
            "{name}"
        );
    }
    let set = registry
        .plugin_set(&[
            PluginSpec::new("shield"),
            PluginSpec::new("block-resources"),
            PluginSpec::new("crx").options(json!({ "files": [] })),
            PluginSpec::new("fetcher"),
            PluginSpec::new("extractor"),
            PluginSpec::new("batcher"),
            PluginSpec::new("crawler"),
        ])
        .unwrap();
    set.check(&LaunchContext {
        engine: Engine::Cdp,
        family: BrowserFamily::Chromium,
        headless: true,
        connecting: false,
    })
    .unwrap();
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
