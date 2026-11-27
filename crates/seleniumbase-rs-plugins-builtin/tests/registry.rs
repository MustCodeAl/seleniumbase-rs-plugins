//! The registry for the enabled built-in plugins (`shield`, `crx`, `fetcher`,
//! `extractor`, `batcher`, `crawler`, `browser`).

use seleniumbase_rs_plugins_builtin::registry;

#[cfg(not(any(
    feature = "shield",
    feature = "crx",
    feature = "fetcher",
    feature = "extractor",
    feature = "batcher",
    feature = "crawler",
    feature = "browser"
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
    fn it_is_listed_and_builds_with_and_without_tor() {
        let registry = registry();
        assert!(registry.names().contains(&"shield"));
        let descriptor = registry.get("shield").unwrap();
        assert!(descriptor.metadata().is_declared());

        let strict = registry
            .build(&PluginSpec::new("shield").options(json!({ "level": "strict" })))
            .unwrap();
        assert_eq!(strict.name(), "shield");

        let with_tor = registry
            .build(&PluginSpec::new("shield").options(json!({ "tor": true })))
            .unwrap();
        assert_eq!(with_tor.name(), "shield");

        let custom_tor = registry
            .build(&PluginSpec::new("shield").options(json!({
                "tor": { "socks": "127.0.0.1:9150", "isolation": "browser" }
            })))
            .unwrap();
        assert_eq!(custom_tor.name(), "shield");
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

#[cfg(feature = "crx")]
#[test]
fn crx_is_listed_and_builds_with_legacy_and_unified_options() {
    use seleniumbase_rs_plugins_builtin::PluginSpec;
    let registry = registry();
    assert!(registry.names().contains(&"crx"));
    assert_eq!(
        registry
            .build(&PluginSpec::new("crx").options(serde_json::json!({ "files": [] })))
            .unwrap()
            .name(),
        "crx"
    );
    assert_eq!(
        registry
            .build(&PluginSpec::new("crx").options(serde_json::json!({
                "extension_zip": [],
                "extension_dir": []
            })))
            .unwrap()
            .name(),
        "crx"
    );
}

#[cfg(all(
    feature = "shield",
    feature = "crx",
    feature = "fetcher",
    feature = "extractor",
    feature = "batcher",
    feature = "crawler",
    feature = "browser"
))]
mod all_built_ins {
    use super::registry;
    use seleniumbase_rs_plugin::{BrowserFamily, Engine, HostInfo, LaunchContext};
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

    #[test]
    fn all_seven_builtins_including_crx_and_browser_compose_without_conflict() {
        let specs = vec![
            PluginSpec::new("shield"),
            PluginSpec::new("crx").options(json!({ "extension_zip": [], "extension_dir": [] })),
            PluginSpec::new("fetcher"),
            PluginSpec::new("extractor"),
            PluginSpec::new("batcher"),
            PluginSpec::new("crawler"),
            PluginSpec::new("browser").options(json!({ "country": "US" })),
        ];
        let set = registry().plugin_set(&specs).unwrap();
        set.check(&context()).unwrap();
        set.check_with(&context(), &HostInfo::cdp()).unwrap();
        let mut names = set.names();
        names.sort_unstable();
        assert_eq!(
            names,
            [
                "batcher",
                "browser",
                "crawler",
                "crx",
                "extractor",
                "fetcher",
                "shield"
            ]
        );
    }

    #[test]
    fn community_and_merged_plugins_are_not_in_builtin_registry() {
        let names = registry().names();
        for absent in ["block-resources", "imap", "tor", "wasm"] {
            assert!(
                !names.contains(&absent),
                "`{absent}` should not be in built-in registry: {names:?}"
            );
        }
    }
}
