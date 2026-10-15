//! The README is the ABI's documentation: keep what it says true.

use seleniumbase_rs_plugin::{Package, Plugin};
use seleniumbase_rs_plugin_wasm::{ABI_VERSION, FORBIDDEN_FLAGS, Limits, WasmPlugin};

const README: &str = include_str!("../README.md");
const HELLO: &str = include_str!("../examples/hello.wat");

#[test]
fn the_readme_shows_the_example_module_as_it_is() {
    assert!(
        README.contains(HELLO.trim_end()),
        "examples/hello.wat and the README have drifted apart"
    );
}

#[test]
fn the_example_module_is_a_working_plugin() {
    let wasm = wat::parse_str(HELLO).unwrap();
    let plugin = WasmPlugin::from_bytes(&wasm).unwrap();
    assert_eq!(plugin.name(), "hello");
    assert_eq!(
        plugin.packages(),
        [Package::script("console.log('hello from wasm')").only_on(["example.com"])]
    );
    assert!(plugin.launch_args().is_empty());
    assert!(plugin.blocked_urls().is_empty());
}

#[test]
fn the_readme_names_every_refused_switch() {
    for flag in FORBIDDEN_FLAGS {
        assert!(
            README.contains(&format!("`{flag}`")),
            "the README does not list `{flag}`"
        );
    }
}

#[test]
fn the_readme_states_the_abi_version_and_the_default_limits() {
    assert_eq!(ABI_VERSION, 1);
    let limits = Limits::default();
    assert_eq!(limits.max_module_bytes, 4 * 1024 * 1024);
    assert_eq!(limits.max_memory_bytes, 16 * 1024 * 1024);
    assert_eq!(limits.fuel_per_call, 20_000_000);
    assert_eq!(limits.max_value_bytes, 1024 * 1024);
    for text in ["4 MiB", "16 MiB", "20,000,000", "1 MiB"] {
        assert!(README.contains(text), "the README does not say `{text}`");
    }
}
