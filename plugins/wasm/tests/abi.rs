//! The plugin host against WebAssembly modules written in WAT: the happy
//! paths, and every way a module can be wrong, hostile or runaway.

mod common;

use common::Module;
use seleniumbase_rs_plugin::{
    BrowserFamily, Engine, LaunchContext, LaunchSettings, Package, Plugin, PluginError, PluginSet,
    Requirements,
};
use seleniumbase_rs_plugin_testing::{Call, RecordingBrowser, RecordingPage, block_on};
use seleniumbase_rs_plugin_wasm::{Limits, WasmError, WasmPlugin};
use serde_json::json;

fn load(module: &Module) -> Result<WasmPlugin, WasmError> {
    WasmPlugin::from_bytes(&module.build())
}

fn refused(module: &Module) -> WasmError {
    load(module).expect_err("the host must refuse this module")
}

fn small_fuel() -> Limits {
    Limits::default().with_fuel_per_call(1_000_000)
}

fn chromium() -> LaunchContext {
    LaunchContext {
        engine: Engine::Cdp,
        family: BrowserFamily::Chromium,
        headless: true,
        connecting: false,
    }
}

fn firefox() -> LaunchContext {
    LaunchContext {
        engine: Engine::WebDriver,
        family: BrowserFamily::Firefox,
        headless: true,
        connecting: false,
    }
}

// ---- a module that works -------------------------------------------------

#[test]
fn a_module_with_every_export_becomes_a_working_plugin() {
    let module = Module::named("demo")
        .json("sbrs_launch_args", r#"["--lang=de","--mute-audio"]"#)
        .json(
            "sbrs_scripts",
            r#"[{"code":"window.demo = 1","hosts":["example.com","example.org"]},{"code":"window.all = 1","hosts":"everywhere"}]"#,
        )
        .json("sbrs_blocked_urls", r#"["*.png","*://ads.example.com/*"]"#);
    let plugin = load(&module).unwrap();

    assert_eq!(plugin.name(), "demo");
    assert_eq!(plugin.requirements(), Requirements::CHROMIUM_ONLY);
    let demo = Package::script("window.demo = 1").only_on(["example.com", "example.org"]);
    let all = Package::script("window.all = 1").everywhere();
    assert_eq!(plugin.packages(), [demo.clone(), all.clone()]);
    assert_eq!(plugin.launch_args(), ["--lang=de", "--mute-audio"]);
    assert_eq!(plugin.blocked_urls(), ["*.png", "*://ads.example.com/*"]);

    let set = PluginSet::new().with(plugin).unwrap();
    set.check(&chromium()).unwrap();

    let mut settings = LaunchSettings::default();
    settings.args.push("--existing".into());
    block_on(set.before_launch(&mut settings)).unwrap();
    assert_eq!(settings.args, ["--existing", "--lang=de", "--mute-audio"]);

    let page = RecordingPage::new();
    block_on(set.on_page_created(&page)).unwrap();
    assert_eq!(
        page.calls(),
        [
            Call::InitScript(demo.init_script().unwrap()),
            Call::InitScript(all.init_script().unwrap()),
            Call::Send("Network.enable".into(), json!({})),
            Call::Send(
                "Network.setBlockedURLs".into(),
                json!({ "urls": ["*.png", "*://ads.example.com/*"] })
            ),
        ]
    );

    let browser = RecordingBrowser::new();
    block_on(set.on_browser(&browser)).unwrap();
    assert_eq!(browser.calls(), Vec::<Call>::new());
}

#[test]
fn a_module_that_blocks_urls_needs_a_chromium_browser() {
    let module = Module::named("blocker").json("sbrs_blocked_urls", r#"["*.png"]"#);
    let set = PluginSet::new().with(load(&module).unwrap()).unwrap();
    set.check(&chromium()).unwrap();
    let error = set.check(&firefox()).unwrap_err();
    assert!(
        matches!(&error, PluginError::Requirement { plugin, .. } if plugin == "blocker"),
        "{error}"
    );
}

#[test]
fn a_module_with_only_a_name_is_a_plugin_that_does_nothing() {
    let plugin = load(&Module::named("quiet")).unwrap();
    assert_eq!(plugin.name(), "quiet");
    assert_eq!(plugin.requirements(), Requirements::empty());
    assert_eq!(plugin.packages(), Vec::<Package>::new());
    assert!(plugin.launch_args().is_empty());
    assert!(plugin.blocked_urls().is_empty());

    let set = PluginSet::new().with(plugin).unwrap();
    set.check(&firefox()).unwrap();
    let mut settings = LaunchSettings::default();
    block_on(set.before_launch(&mut settings)).unwrap();
    assert_eq!(settings, LaunchSettings::default());
    let page = RecordingPage::new();
    block_on(set.on_page_created(&page)).unwrap();
    assert_eq!(page.calls(), Vec::<Call>::new());
}

#[test]
fn empty_lists_are_the_same_as_missing_exports() {
    let module = Module::named("empty")
        .json("sbrs_launch_args", "[]")
        .json("sbrs_scripts", "[]")
        .json("sbrs_blocked_urls", "[]");
    let plugin = load(&module).unwrap();
    assert_eq!(plugin.requirements(), Requirements::empty());
    assert!(plugin.packages().is_empty());
}

#[test]
fn a_string_that_ends_at_the_last_byte_of_the_memory_is_read() {
    let module = Module::bare()
        .version(1)
        .bytes_at(65_532, b"\"ab\"")
        .packed("sbrs_name", 65_532, 4);
    assert_eq!(load(&module).unwrap().name(), "ab");
}

#[test]
fn json_whitespace_around_the_value_is_fine() {
    let module = Module::bare()
        .version(1)
        .json("sbrs_name", " \n\"spaced\"\t ");
    assert_eq!(load(&module).unwrap().name(), "spaced");
}

#[test]
fn exports_that_do_not_start_with_sbrs_are_ignored() {
    let module = Module::named("tidy").fields(r#"(func (export "helper"))"#);
    assert_eq!(load(&module).unwrap().name(), "tidy");
}

#[test]
fn a_plugin_from_a_module_joins_a_set_like_any_other() {
    let first = load(&Module::named("twin")).unwrap();
    let second = load(&Module::named("twin")).unwrap();
    let error = PluginSet::new()
        .with(first)
        .unwrap()
        .with(second)
        .unwrap_err();
    assert!(matches!(error, PluginError::DuplicateName(name) if name == "twin"));
}

#[test]
fn a_failing_command_names_the_plugin_and_the_hook() {
    let module = Module::named("blocker").json("sbrs_blocked_urls", r#"["*.png"]"#);
    let set = PluginSet::new().with(load(&module).unwrap()).unwrap();
    let page = RecordingPage::new().failing("Network.setBlockedURLs");
    let error = block_on(set.on_page_created(&page))
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("blocker") && error.contains("on_page_created"),
        "{error}"
    );
}

// ---- the ABI version and the shape of the exports -------------------------

#[test]
fn another_abi_version_is_refused() {
    for found in [0, 2, -1, i32::MAX] {
        let module = Module::bare()
            .version(found)
            .json("sbrs_name", "\"future\"");
        let error = refused(&module);
        assert!(
            matches!(error, WasmError::UnsupportedAbi { found: seen } if seen == found),
            "{error}"
        );
    }
}

#[test]
fn the_version_is_checked_before_anything_else_is_looked_at() {
    // No memory and no name: a version 2 module is still told its version is wrong.
    let module =
        Module::without_memory(r#"(func (export "sbrs_abi_version") (result i32) (i32.const 2))"#);
    assert!(matches!(
        refused(&module),
        WasmError::UnsupportedAbi { found: 2 }
    ));
}

#[test]
fn a_missing_required_export_is_named() {
    let no_version = Module::bare().json("sbrs_name", "\"x\"");
    assert!(matches!(
        refused(&no_version),
        WasmError::MissingExport("sbrs_abi_version")
    ));

    let no_name = Module::bare().version(1);
    assert!(matches!(
        refused(&no_name),
        WasmError::MissingExport("sbrs_name")
    ));

    let no_memory = Module::without_memory(
        r#"(func (export "sbrs_abi_version") (result i32) (i32.const 1))
           (func (export "sbrs_name") (result i64) (i64.const 0))"#,
    );
    assert!(matches!(
        refused(&no_memory),
        WasmError::MissingExport("memory")
    ));
}

#[test]
fn an_export_of_the_wrong_type_is_refused() {
    let returns_i32 = Module::bare()
        .version(1)
        .fields(r#"(func (export "sbrs_name") (result i32) (i32.const 0))"#);
    assert!(matches!(
        refused(&returns_i32),
        WasmError::BadExport {
            export: "sbrs_name",
            ..
        }
    ));

    let takes_a_parameter = Module::bare()
        .version(1)
        .fields(r#"(func (export "sbrs_name") (param i32) (result i64) (i64.const 0))"#);
    assert!(matches!(
        refused(&takes_a_parameter),
        WasmError::BadExport {
            export: "sbrs_name",
            ..
        }
    ));

    let version_is_a_global =
        Module::bare().fields(r#"(global (export "sbrs_abi_version") i32 (i32.const 1))"#);
    assert!(matches!(
        refused(&version_is_a_global),
        WasmError::BadExport {
            export: "sbrs_abi_version",
            ..
        }
    ));

    let optional_has_the_wrong_type =
        Module::named("x").fields(r#"(func (export "sbrs_scripts") (result i32) (i32.const 0))"#);
    assert!(matches!(
        refused(&optional_has_the_wrong_type),
        WasmError::BadExport {
            export: "sbrs_scripts",
            ..
        }
    ));
}

#[test]
fn a_memory_export_that_is_not_a_memory_is_refused() {
    let module = Module::without_memory(
        r#"(func (export "memory"))
           (func (export "sbrs_abi_version") (result i32) (i32.const 1))
           (func (export "sbrs_name") (result i64) (i64.const 0))"#,
    );
    assert!(matches!(
        refused(&module),
        WasmError::MissingExport("memory")
    ));
}

#[test]
fn an_unknown_sbrs_export_is_an_error_not_silence() {
    let module = Module::named("typo").json("sbrs_script", "[]");
    let error = refused(&module);
    assert!(
        matches!(&error, WasmError::UnknownExport(name) if name == "sbrs_script"),
        "{error}"
    );
}

// ---- what is not a module, and modules that ask for too much ---------------

#[test]
fn bytes_that_are_not_a_module_are_refused() {
    for bytes in [&b""[..], b"hello", b"\0asm", b"\0asm\x01\0\0\0\xff\xff\xff"] {
        let error = WasmPlugin::from_bytes(bytes).unwrap_err();
        assert!(matches!(error, WasmError::InvalidModule(_)), "{error}");
    }
}

#[test]
fn the_text_format_is_not_accepted() {
    // The host takes binary modules only: no WAT parser runs on untrusted input.
    let error = WasmPlugin::from_bytes(b"(module)").unwrap_err();
    assert!(matches!(error, WasmError::InvalidModule(_)), "{error}");
}

#[test]
fn a_module_larger_than_the_limit_is_refused() {
    let wasm = Module::named("big").build();
    let limits = Limits::default().with_max_module_bytes(wasm.len() - 1);
    let error = WasmPlugin::from_bytes_with(&wasm, &limits).unwrap_err();
    assert!(matches!(error, WasmError::ModuleTooLarge { .. }), "{error}");
    // One byte more is fine.
    let limits = Limits::default().with_max_module_bytes(wasm.len());
    assert!(WasmPlugin::from_bytes_with(&wasm, &limits).is_ok());
}

#[test]
fn a_module_with_imports_is_refused() {
    // An import must come before the module's own functions in WAT, so these
    // modules are written out whole.
    let module = Module::without_memory(
        r#"(import "env" "now" (func $now (result i64)))
           (memory (export "memory") 1)
           (func (export "sbrs_abi_version") (result i32) (i32.const 1))
           (func (export "sbrs_name") (result i64) (call $now))"#,
    );
    let error = refused(&module);
    assert!(
        matches!(&error, WasmError::HasImports { module, name } if module == "env" && name == "now"),
        "{error}"
    );

    let wasi = Module::without_memory(
        r#"(import "wasi_snapshot_preview1" "fd_write"
             (func (param i32 i32 i32 i32) (result i32)))
           (memory (export "memory") 1)
           (func (export "sbrs_abi_version") (result i32) (i32.const 1))
           (func (export "sbrs_name") (result i64) (i64.const 0))"#,
    );
    assert!(matches!(refused(&wasi), WasmError::HasImports { .. }));
}

#[test]
fn a_module_that_starts_with_too_much_memory_is_refused() {
    // 1000 pages are 65 MB; the limit is 16 MiB.
    let module = Module::without_memory(
        r#"(memory (export "memory") 1000)
           (func (export "sbrs_abi_version") (result i32) (i32.const 1))
           (func (export "sbrs_name") (result i64) (i64.const 0))"#,
    );
    let error = refused(&module);
    assert!(matches!(error, WasmError::MemoryTooLarge { .. }), "{error}");

    // The same module is fine when the limit allows it.
    let limits = Limits::default().with_max_memory_bytes(1000 * 65_536);
    let error = WasmPlugin::from_bytes_with(&module.build(), &limits).unwrap_err();
    assert!(
        !matches!(error, WasmError::MemoryTooLarge { .. }),
        "the limit was raised, but: {error}"
    );
}

#[test]
fn a_memory_of_the_biggest_allowed_size_is_fine() {
    let module = Module::without_memory(
        r#"(memory (export "memory") 256)
           (data (i32.const 0) "\22\6f\6b\22")
           (func (export "sbrs_abi_version") (result i32) (i32.const 1))
           (func (export "sbrs_name") (result i64) (i64.const 4))"#,
    );
    // 256 pages are exactly 16 MiB.
    assert_eq!(load(&module).unwrap().name(), "ok");
}

#[test]
fn a_private_memory_that_starts_too_big_is_never_allocated() {
    // Not exported, so the size check on exports cannot see it: the store's
    // limiter refuses the allocation (60,000 pages would be almost 4 GB).
    let module = Module::without_memory(
        r#"(memory 60000)
           (func (export "sbrs_abi_version") (result i32) (i32.const 1))
           (func (export "sbrs_name") (result i64) (i64.const 0))"#,
    );
    let error = refused(&module);
    assert!(matches!(error, WasmError::Instantiate(_)), "{error}");
}

#[test]
fn growing_the_memory_past_the_limit_fails_and_does_not_trap() {
    // memory.grow returns -1 when the host says no; the module then names itself.
    let denied = Module::bare().version(1).bytes_at(16, b"\"ok\"").fields(
        r#"(func (export "sbrs_name") (result i64)
             (if (result i64) (i32.eq (memory.grow (i32.const 1000)) (i32.const -1))
               (then (i64.const 0x0000_0010_0000_0004))
               (else (i64.const -1))))"#,
    );
    assert_eq!(load(&denied).unwrap().name(), "ok");

    // Growing within the limit works: it returns the old size, one page.
    let allowed = Module::bare().version(1).bytes_at(16, b"\"ok\"").fields(
        r#"(func (export "sbrs_name") (result i64)
             (if (result i64) (i32.eq (memory.grow (i32.const 1)) (i32.const 1))
               (then (i64.const 0x0000_0010_0000_0004))
               (else (i64.const -1))))"#,
    );
    assert_eq!(load(&allowed).unwrap().name(), "ok");
}

#[test]
fn a_module_with_two_memories_is_refused() {
    let module = Module::without_memory(
        r#"(memory 1)
           (memory (export "memory") 1)
           (func (export "sbrs_abi_version") (result i32) (i32.const 1))
           (func (export "sbrs_name") (result i64) (i64.const 0))"#,
    );
    assert!(matches!(refused(&module), WasmError::InvalidModule(_)));
}

#[test]
fn a_64_bit_memory_is_refused() {
    // Pointers in the ABI are 32 bits: a memory64 module cannot speak it.
    let module = Module::without_memory(
        r#"(memory (export "memory") i64 1)
           (func (export "sbrs_abi_version") (result i32) (i32.const 1))
           (func (export "sbrs_name") (result i64) (i64.const 0))"#,
    );
    assert!(matches!(refused(&module), WasmError::InvalidModule(_)));
}

#[test]
fn a_memory_with_a_custom_page_size_is_refused() {
    // A one-byte page would make every size check in the host wrong.
    let module = Module::without_memory(
        r#"(memory (export "memory") 100 (pagesize 1))
           (func (export "sbrs_abi_version") (result i32) (i32.const 1))
           (func (export "sbrs_name") (result i64) (i64.const 0))"#,
    );
    assert!(matches!(refused(&module), WasmError::InvalidModule(_)));
}

#[test]
fn a_table_that_starts_too_big_is_refused_and_one_cannot_grow_past_the_limit() {
    let huge_table = Module::without_memory(
        r#"(memory (export "memory") 1)
           (table 4000000 funcref)
           (func (export "sbrs_abi_version") (result i32) (i32.const 1))
           (func (export "sbrs_name") (result i64) (i64.const 0))"#,
    );
    assert!(matches!(
        refused(&huge_table),
        WasmError::Instantiate(_) | WasmError::InvalidModule(_)
    ));

    // table.grow past the limit answers -1, as the WebAssembly specification says.
    let growing = Module::bare().version(1).bytes_at(16, b"\"ok\"").fields(
        r#"(table $t 1 funcref)
           (func (export "sbrs_name") (result i64)
             (if (result i64)
               (i32.eq (table.grow $t (ref.null func) (i32.const 4000000)) (i32.const -1))
               (then (i64.const 0x0000_0010_0000_0004))
               (else (i64.const -1))))"#,
    );
    assert_eq!(load(&growing).unwrap().name(), "ok");
}

// ---- runaway and crashing modules ------------------------------------------

const FOREVER: &str = "(loop $again (br $again))";

#[test]
fn a_function_that_never_returns_runs_out_of_fuel() {
    let module = Module::bare().version(1).fields(&format!(
        r#"(func (export "sbrs_name") (result i64) {FOREVER} (i64.const 0))"#
    ));
    let error = WasmPlugin::from_bytes_with(&module.build(), &small_fuel()).unwrap_err();
    assert!(
        matches!(
            error,
            WasmError::OutOfFuel {
                export: "sbrs_name",
                ..
            }
        ),
        "{error}"
    );
}

#[test]
fn the_default_fuel_also_stops_a_runaway_function() {
    let module = Module::bare().version(1).fields(&format!(
        r#"(func (export "sbrs_name") (result i64) {FOREVER} (i64.const 0))"#
    ));
    let error = WasmPlugin::from_bytes(&module.build()).unwrap_err();
    assert!(matches!(error, WasmError::OutOfFuel { .. }), "{error}");
}

#[test]
fn every_export_runs_out_of_fuel_on_its_own() {
    for export in [
        "sbrs_abi_version",
        "sbrs_launch_args",
        "sbrs_scripts",
        "sbrs_blocked_urls",
    ] {
        let result = if export == "sbrs_abi_version" {
            "i32"
        } else {
            "i64"
        };
        let spinner =
            format!(r#"(func (export "{export}") (result {result}) {FOREVER} ({result}.const 0))"#);
        let mut module = Module::bare();
        if export != "sbrs_abi_version" {
            module = module.version(1).json("sbrs_name", "\"x\"");
        }
        let module = module.fields(&spinner);
        let error = WasmPlugin::from_bytes_with(&module.build(), &small_fuel()).unwrap_err();
        assert!(
            matches!(&error, WasmError::OutOfFuel { export: seen, .. } if *seen == export),
            "{export}: {error}"
        );
    }
}

#[test]
fn a_start_function_that_never_returns_runs_out_of_fuel() {
    let module = Module::named("x").fields(&format!("(func $spin {FOREVER})\n(start $spin)"));
    let error = WasmPlugin::from_bytes_with(&module.build(), &small_fuel()).unwrap_err();
    assert!(
        matches!(&error, WasmError::OutOfFuel { export, .. } if export.contains("start")),
        "{error}"
    );
}

/// A function that counts down 5,000 times, then returns `constant`.
fn spender(export: &str, result: &str, constant: &str) -> String {
    format!(
        r#"(func (export "{export}") (result {result})
             (local $n i32)
             (local.set $n (i32.const 5000))
             (loop $again
               (local.set $n (i32.sub (local.get $n) (i32.const 1)))
               (br_if $again (local.get $n)))
             ({constant}))"#
    )
}

fn loads_with_fuel(module: &Module, fuel: u64) -> bool {
    let limits = Limits::default().with_fuel_per_call(fuel);
    WasmPlugin::from_bytes_with(&module.build(), &limits).is_ok()
}

#[test]
fn each_call_gets_its_own_fuel() {
    let name = spender("sbrs_name", "i64", "i64.const 0x0000_0010_0000_0006");
    let one_spender = Module::bare()
        .version(1)
        .bytes_at(16, b"\"busy\"")
        .fields(&name);
    let two_spenders = Module::bare()
        .bytes_at(16, b"\"busy\"")
        .fields(&spender("sbrs_abi_version", "i32", "i32.const 1"))
        .fields(&name);

    // The least fuel that one spending call needs, by bisection.
    let (mut low, mut high) = (1_u64, 50_000_000_u64);
    while low < high {
        let middle = low + (high - low) / 2;
        if loads_with_fuel(&one_spender, middle) {
            high = middle;
        } else {
            low = middle + 1;
        }
    }
    let enough_for_one = low;
    assert!(
        enough_for_one > 5_000,
        "the loop costs fuel: {enough_for_one}"
    );
    assert!(!loads_with_fuel(&one_spender, enough_for_one - 1));
    // Two calls that each fit the budget load, though together they spend twice
    // the budget: the fuel is refilled for every call.
    assert!(loads_with_fuel(&two_spenders, enough_for_one));
}

#[test]
fn a_trap_is_an_error_naming_the_export() {
    let module = Module::bare()
        .version(1)
        .fields(r#"(func (export "sbrs_name") (result i64) unreachable)"#);
    let error = refused(&module);
    assert!(
        matches!(
            error,
            WasmError::Trapped {
                export: "sbrs_name",
                ..
            }
        ),
        "{error}"
    );
}

#[test]
fn endless_recursion_is_a_trap_and_not_a_crash() {
    let module = Module::bare()
        .version(1)
        .fields(r#"(func $deeper (export "sbrs_name") (result i64) (call $deeper))"#);
    let error = WasmPlugin::from_bytes_with(&module.build(), &small_fuel()).unwrap_err();
    assert!(
        matches!(&error, WasmError::Trapped { export: "sbrs_name", message } if message.contains("stack")),
        "{error}"
    );
}

#[test]
fn an_out_of_bounds_access_inside_the_module_is_a_trap() {
    let module = Module::bare().version(1).fields(
        r#"(func (export "sbrs_name") (result i64)
             (i64.extend_i32_u (i32.load (i32.const 70000))))"#,
    );
    assert!(matches!(
        refused(&module),
        WasmError::Trapped {
            export: "sbrs_name",
            ..
        }
    ));
}

// ---- pointers and lengths that lie -------------------------------------------

#[test]
fn a_range_outside_the_memory_is_refused() {
    let page = 65_536;
    for (pointer, length) in [
        (page, 4),           // starts after the end
        (page - 2, 4),       // starts inside, ends after
        (page + 1, 0),       // an empty range past the end is still outside
        (u32::MAX, 1),       // the last address of a 4 GiB space
        (u32::MAX - 15, 32), // pointer + length wraps around in 32 bits
        (u32::MAX - 15, 16), // pointer + length is exactly 2^32
    ] {
        let module = Module::bare()
            .version(1)
            .packed("sbrs_name", pointer, length);
        let error = refused(&module);
        assert!(
            matches!(
                error,
                WasmError::OutOfBounds {
                    export: "sbrs_name",
                    ..
                }
            ),
            "pointer {pointer}, length {length}: {error}"
        );
    }
}

#[test]
fn a_length_over_the_limit_is_refused_before_the_memory_is_read() {
    let module = Module::bare().version(1).packed("sbrs_name", 0, u32::MAX);
    let error = refused(&module);
    assert!(
        matches!(
            error,
            WasmError::TooLong {
                export: "sbrs_name",
                ..
            }
        ),
        "{error}"
    );

    let long = format!("\"{}\"", "a".repeat(40));
    let module = Module::bare().version(1).json("sbrs_name", &long);
    let limits = Limits::default().with_max_value_bytes(16);
    let error = WasmPlugin::from_bytes_with(&module.build(), &limits).unwrap_err();
    assert!(matches!(error, WasmError::TooLong { .. }), "{error}");
}

#[test]
fn an_empty_range_is_not_json() {
    let module = Module::bare().version(1).packed("sbrs_name", 0, 0);
    assert!(matches!(
        refused(&module),
        WasmError::Json {
            export: "sbrs_name",
            ..
        }
    ));
}

// ---- JSON that is wrong ----------------------------------------------------

fn name_module(json: &str) -> Module {
    Module::bare().version(1).json("sbrs_name", json)
}

fn with_optional(export: &str, json: &str) -> Module {
    Module::named("x").json(export, json)
}

fn assert_bad_value(error: &WasmError, export: &str, case: &str) {
    assert!(
        matches!(error, WasmError::Json { .. } | WasmError::Value { .. }),
        "{case}: {error:?}"
    );
    assert!(
        error.to_string().contains(export),
        "{case}: the message names `{export}`: {error}"
    );
}

#[test]
fn a_name_that_is_not_json_is_refused() {
    for json in [
        "not json",
        "{",
        "\"unclosed",
        "\"x\" \"y\"",
        "\"x\" trailing",
        "null",
    ] {
        let error = refused(&name_module(json));
        assert_bad_value(&error, "sbrs_name", json);
    }
}

#[test]
fn a_name_that_is_not_a_string_is_refused() {
    for json in ["42", "true", "[]", "{}", r#"["demo"]"#] {
        let error = refused(&name_module(json));
        assert_bad_value(&error, "sbrs_name", json);
    }
}

#[test]
fn a_name_that_is_not_a_plugin_name_is_refused() {
    let too_long = format!("\"{}\"", "a".repeat(65));
    let cases = [
        "\"\"",
        "\"Upper\"",
        "\"has space\"",
        "\"-leading\"",
        "\"_leading\"",
        "\"dot.ted\"",
        "\"slash/y\"",
        "\"caf\\u00e9\"",
        "\"nul\\u0000\"",
        "\"new\\nline\"",
        too_long.as_str(),
    ];
    for json in cases {
        let error = refused(&name_module(json));
        assert!(
            matches!(error, WasmError::Value { .. }),
            "{json}: {error:?}"
        );
    }
    // The longest allowed name, and the allowed characters.
    let longest = format!("\"{}\"", "a".repeat(64));
    assert_eq!(load(&name_module(&longest)).unwrap().name().len(), 64);
    assert_eq!(load(&name_module("\"0-a_b-9\"")).unwrap().name(), "0-a_b-9");
}

#[test]
fn bytes_that_are_not_utf8_are_refused() {
    let module = Module::bare()
        .version(1)
        .bytes("sbrs_name", &[b'"', 0xff, 0xfe, b'"']);
    let error = refused(&module);
    assert!(matches!(error, WasmError::Json { .. }), "{error:?}");
    assert!(error.to_string().contains("UTF-8"), "{error}");
}

#[test]
fn launch_args_that_are_not_a_list_of_switches_are_refused() {
    let long = format!("[\"--{}\"]", "x".repeat(4096));
    let many = format!("[{}]", vec!["\"--lang=de\""; 257].join(","));
    let cases = [
        "{}",
        "\"--lang=de\"",
        "[1]",
        "[null]",
        r#"["lang=de"]"#,
        r#"["https://example.com"]"#,
        r#"[""]"#,
        r#"["-"]"#,
        r#"["--"]"#,
        r#"["---lang"]"#,
        r#"["--=value"]"#,
        r#"["--lang=\u0000"]"#,
        r#"["--lang=a\nb"]"#,
        long.as_str(),
        many.as_str(),
    ];
    for json in cases {
        let error = refused(&with_optional("sbrs_launch_args", json));
        assert_bad_value(&error, "sbrs_launch_args", &json[..json.len().min(40)]);
    }
    // The largest allowed list and switch.
    let longest = format!("[\"--{}\"]", "x".repeat(4096 - 2));
    assert!(load(&with_optional("sbrs_launch_args", &longest)).is_ok());
    let most = format!("[{}]", vec!["\"--lang=de\""; 256].join(","));
    assert_eq!(
        load(&with_optional("sbrs_launch_args", &most))
            .unwrap()
            .launch_args()
            .len(),
        256
    );
}

#[test]
fn switches_that_run_programs_or_switch_protections_off_are_refused() {
    for flag in [
        "--renderer-cmd-prefix=sh -c evil",
        "--utility-cmd-prefix=sh",
        "--gpu-launcher=/tmp/x",
        "--browser-subprocess-path=/tmp/x",
        "--no-sandbox",
        "-no-sandbox",
        "--NO-SANDBOX",
        "--disable-web-security",
        "--remote-debugging-port=9222",
        "--remote-allow-origins=*",
        "--load-extension=/tmp/ext",
        "--proxy-server=http://evil:8080",
        "--user-data-dir=/Users/someone/Library/Application Support/Google/Chrome",
    ] {
        let json = serde_json::to_string(&[flag]).unwrap();
        let error = refused(&with_optional("sbrs_launch_args", &json));
        assert!(
            matches!(
                &error,
                WasmError::Value {
                    export: "sbrs_launch_args",
                    ..
                }
            ),
            "{flag}: {error:?}"
        );
        assert!(
            error.to_string().contains("not allowed"),
            "{flag}: the message says why: {error}"
        );
    }
    // Ordinary switches pass, including ones that only look similar.
    let plugin = load(&with_optional(
        "sbrs_launch_args",
        r#"["--lang=de","--mute-audio","--window-size=800,600","--disable-gpu","--no-first-run"]"#,
    ))
    .unwrap();
    assert_eq!(plugin.launch_args().len(), 5);
}

#[test]
fn scripts_that_are_wrong_are_refused() {
    let many = format!(
        "[{}]",
        vec![r#"{"code":"x","hosts":"everywhere"}"#; 65].join(",")
    );
    let many_hosts = format!(
        r#"[{{"code":"x","hosts":[{}]}}]"#,
        vec!["\"example.com\""; 65].join(",")
    );
    let cases = [
        "{}",
        "\"code\"",
        r#"[{"code":"x"}]"#,
        r#"[{"hosts":"everywhere"}]"#,
        r#"[{"code":"x","hosts":"nowhere"}]"#,
        r#"[{"code":"x","hosts":"Everywhere"}]"#,
        r#"[{"code":"x","hosts":[]}]"#,
        r#"[{"code":"x","hosts":null}]"#,
        r#"[{"code":"x","hosts":[1]}]"#,
        r#"[{"code":"x","hosts":["http://example.com"]}]"#,
        r#"[{"code":"x","hosts":["example.com/path"]}]"#,
        r#"[{"code":"x","hosts":["example.com:8080"]}]"#,
        r#"[{"code":"x","hosts":["Example.com"]}]"#,
        r#"[{"code":"x","hosts":["*.example.com"]}]"#,
        r#"[{"code":"x","hosts":[""]}]"#,
        r#"[{"code":"x","hosts":["a..b"]}]"#,
        r#"[{"code":"x","hosts":[".example.com"]}]"#,
        r#"[{"code":"x","hosts":["example.com."]}]"#,
        r#"[{"code":"x","hosts":["-a.com"]}]"#,
        r#"[{"code":"x","hosts":["a b.com"]}]"#,
        r#"[{"code":"x","hosts":["example.com"],"extra":1}]"#,
        r#"[{"code":"","hosts":"everywhere"}]"#,
        r#"[{"code":1,"hosts":"everywhere"}]"#,
        r#"[1]"#,
        many.as_str(),
        many_hosts.as_str(),
    ];
    for json in cases {
        let error = refused(&with_optional("sbrs_scripts", json));
        assert_bad_value(&error, "sbrs_scripts", &json[..json.len().min(50)]);
    }
}

#[test]
fn scripts_that_are_right_are_accepted() {
    let plugin = load(&with_optional(
        "sbrs_scripts",
        r#"[
            {"code":"a()","hosts":["example.com"]},
            {"code":"b()","hosts":["a-b.example.co.uk","xn--bcher-kva.example","127.0.0.1"]},
            {"code":"c()","hosts":"everywhere"}
        ]"#,
    ))
    .unwrap();
    assert_eq!(
        plugin.packages(),
        [
            Package::script("a()").only_on(["example.com"]),
            Package::script("b()").only_on([
                "a-b.example.co.uk",
                "xn--bcher-kva.example",
                "127.0.0.1"
            ]),
            Package::script("c()").everywhere(),
        ]
    );
    // JavaScript is passed through byte for byte: quotes, newlines and unicode.
    let code = "console.log(\"hi\\n\", '\u{1F600}')\n// end";
    let json = serde_json::to_string(&[json!({"code": code, "hosts": "everywhere"})]).unwrap();
    let plugin = load(&with_optional("sbrs_scripts", &json)).unwrap();
    assert_eq!(plugin.packages(), [Package::script(code).everywhere()]);
}

#[test]
fn blocked_urls_that_are_wrong_are_refused() {
    let too_long = format!("[\"{}\"]", "a".repeat(2049));
    let many = format!("[{}]", vec!["\"*.png\""; 1025].join(","));
    let cases = [
        "{}",
        "\"*.png\"",
        "[1]",
        "[null]",
        r#"[""]"#,
        r#"["a\u0000b"]"#,
        r#"["a\nb"]"#,
        too_long.as_str(),
        many.as_str(),
    ];
    for json in cases {
        let error = refused(&with_optional("sbrs_blocked_urls", json));
        assert_bad_value(&error, "sbrs_blocked_urls", &json[..json.len().min(40)]);
    }
    let longest = format!("[\"{}\"]", "a".repeat(2048));
    assert!(load(&with_optional("sbrs_blocked_urls", &longest)).is_ok());
}

// ---- files and error conversion ----------------------------------------------

#[test]
fn a_module_is_loaded_from_a_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("demo.wasm");
    std::fs::write(&path, Module::named("from-file").build()).unwrap();
    assert_eq!(WasmPlugin::from_file(&path).unwrap().name(), "from-file");
}

#[test]
fn a_missing_file_is_a_read_error_that_names_the_path() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nothing.wasm");
    let error = WasmPlugin::from_file(&path).unwrap_err();
    assert!(matches!(error, WasmError::Read { .. }), "{error}");
    assert!(error.to_string().contains("nothing.wasm"), "{error}");
}

#[test]
fn a_directory_is_a_read_error() {
    let dir = tempfile::tempdir().unwrap();
    let error = WasmPlugin::from_file(dir.path()).unwrap_err();
    assert!(matches!(error, WasmError::Read { .. }), "{error}");
}

#[test]
fn a_file_over_the_limit_is_refused_without_being_read_whole() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("big.wasm");
    std::fs::write(&path, vec![0u8; 1024 * 1024]).unwrap();
    let limits = Limits::default().with_max_module_bytes(1024);
    let error = WasmPlugin::from_file_with(&path, &limits).unwrap_err();
    assert!(matches!(error, WasmError::ModuleTooLarge { .. }), "{error}");
}

#[test]
fn a_host_error_converts_into_a_plugin_error_with_its_message() {
    let error = refused(&Module::bare().version(2).json("sbrs_name", "\"x\""));
    let message = error.to_string();
    let converted: PluginError = error.into();
    assert_eq!(converted.to_string(), message);
    assert!(message.contains('2'), "{message}");
}

#[test]
fn the_error_messages_say_what_is_wrong() {
    let cases: [(WasmError, &str); 3] = [
        (refused(&Module::bare().version(1)), "sbrs_name"),
        (refused(&name_module("42")), "sbrs_name"),
        (
            refused(&Module::bare().version(1).packed("sbrs_name", 70_000, 4)),
            "memory",
        ),
    ];
    for (error, needle) in cases {
        assert!(error.to_string().contains(needle), "{error}");
    }
}

// ---- the plugin is data once it is loaded -------------------------------------

#[test]
fn a_loaded_plugin_can_be_shared_between_sets_and_threads() {
    use std::sync::Arc;
    let plugin: Arc<dyn Plugin> = Arc::new(load(&Module::named("shared")).unwrap());
    let first = PluginSet::new().with_shared(Arc::clone(&plugin)).unwrap();
    let second = PluginSet::new().with_shared(plugin).unwrap();
    let handle = std::thread::spawn(move || second.names().len());
    assert_eq!(first.names(), ["shared"]);
    assert_eq!(handle.join().unwrap(), 1);
}
