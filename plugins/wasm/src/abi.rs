//! The ABI: export names, the packed return value, and the validation of what
//! a module returns. Nothing here knows about the interpreter.
//!
//! Every value that comes from a module is untrusted. [`describe`] parses the
//! JSON a module returned, checks each field against a fixed bound and turns it
//! into plain data; a value it cannot vouch for is an error, never a panic and
//! never silently dropped.

use seleniumbase_rs_plugin::Package;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::WasmError;

/// The ABI version this host speaks: what `sbrs_abi_version` must return.
pub const ABI_VERSION: i32 = 1;

/// Browser switches (names, without the leading dashes) that a module may not
/// ask for: the ones that run a program, switch the browser's sandbox or other
/// protections off, open a control channel, load code from disk, or send the
/// traffic elsewhere. The list is a floor, not an audit of every switch; see the
/// README.
pub const FORBIDDEN_FLAGS: &[&str] = &[
    // Run a program of the module's choosing.
    "renderer-cmd-prefix",
    "utility-cmd-prefix",
    "zygote-cmd-prefix",
    "gpu-launcher",
    "ppapi-plugin-launcher",
    "browser-subprocess-path",
    "nacl-gdb",
    // Switch the browser's sandbox or protections off.
    "no-sandbox",
    "disable-setuid-sandbox",
    "disable-gpu-sandbox",
    "no-zygote",
    "disable-web-security",
    "ignore-certificate-errors",
    // Send the traffic elsewhere; `LaunchSettings::proxy` is the way to set a proxy.
    "proxy-server",
    "proxy-pac-url",
    // Open a control channel to the browser.
    "remote-debugging-port",
    "remote-debugging-address",
    "remote-debugging-pipe",
    "remote-allow-origins",
    // Load code or a profile from disk.
    "load-extension",
    "disable-extensions-except",
    "user-data-dir",
];

pub(crate) const EXPORT_MEMORY: &str = "memory";
pub(crate) const EXPORT_VERSION: &str = "sbrs_abi_version";
pub(crate) const EXPORT_NAME: &str = "sbrs_name";
pub(crate) const EXPORT_LAUNCH_ARGS: &str = "sbrs_launch_args";
pub(crate) const EXPORT_SCRIPTS: &str = "sbrs_scripts";
pub(crate) const EXPORT_BLOCKED_URLS: &str = "sbrs_blocked_urls";

/// Export names that start with this are reserved for the ABI.
pub(crate) const RESERVED_PREFIX: &str = "sbrs_";

/// Every function export the ABI defines.
pub(crate) const KNOWN_FUNCTIONS: [&str; 5] = [
    EXPORT_VERSION,
    EXPORT_NAME,
    EXPORT_LAUNCH_ARGS,
    EXPORT_SCRIPTS,
    EXPORT_BLOCKED_URLS,
];

const MAX_NAME_BYTES: usize = 64;
const MAX_LAUNCH_ARGS: usize = 256;
const MAX_LAUNCH_ARG_BYTES: usize = 4096;
const MAX_SCRIPTS: usize = 64;
const MAX_HOSTS: usize = 64;
const MAX_HOST_BYTES: usize = 253;
const MAX_HOST_LABEL_BYTES: usize = 63;
const MAX_BLOCKED_URLS: usize = 1024;
const MAX_URL_PATTERN_BYTES: usize = 2048;

/// The raw bytes a module returned, before any parsing.
#[derive(Debug)]
pub(crate) struct Raw {
    pub name: Vec<u8>,
    pub launch_args: Option<Vec<u8>>,
    pub scripts: Option<Vec<u8>>,
    pub blocked_urls: Option<Vec<u8>>,
}

/// What a module describes, checked.
#[derive(Debug)]
pub(crate) struct Description {
    pub name: String,
    pub launch_args: Vec<String>,
    pub packages: Vec<Package>,
    pub blocked_urls: Vec<String>,
}

/// Splits the `i64` a function returns into the pointer (high half) and the
/// length (low half), both as the unsigned 32-bit numbers they are.
pub(crate) fn unpack(packed: i64) -> (u32, u32) {
    let [p0, p1, p2, p3, l0, l1, l2, l3] = packed.to_be_bytes();
    (
        u32::from_be_bytes([p0, p1, p2, p3]),
        u32::from_be_bytes([l0, l1, l2, l3]),
    )
}

/// Parses and checks everything a module returned.
pub(crate) fn describe(raw: &Raw) -> Result<Description, WasmError> {
    Ok(Description {
        name: name(&raw.name)?,
        launch_args: match &raw.launch_args {
            Some(bytes) => launch_args(bytes)?,
            None => Vec::new(),
        },
        packages: match &raw.scripts {
            Some(bytes) => scripts(bytes)?,
            None => Vec::new(),
        },
        blocked_urls: match &raw.blocked_urls {
            Some(bytes) => blocked_urls(bytes)?,
            None => Vec::new(),
        },
    })
}

fn parse<T: DeserializeOwned>(export: &'static str, bytes: &[u8]) -> Result<T, WasmError> {
    let text = std::str::from_utf8(bytes).map_err(|error| WasmError::Json {
        export,
        message: format!("not valid UTF-8: {error}"),
    })?;
    serde_json::from_str(text).map_err(|error| WasmError::Json {
        export,
        message: error.to_string(),
    })
}

fn refuse(export: &'static str, reason: impl Into<String>) -> WasmError {
    WasmError::Value {
        export,
        reason: reason.into(),
    }
}

/// `text` as a short, escaped quotation for an error message: a module's value
/// is untrusted, so it is neither echoed whole nor with raw control characters.
fn shown(text: &str) -> String {
    const MAX_CHARS: usize = 40;
    let head: String = text.chars().take(MAX_CHARS).collect();
    let more = if text.chars().count() > MAX_CHARS {
        "..."
    } else {
        ""
    };
    format!("{head:?}{more}")
}

fn has_control_character(text: &str) -> bool {
    text.chars().any(char::is_control)
}

// ---- sbrs_name ------------------------------------------------------------

fn name(bytes: &[u8]) -> Result<String, WasmError> {
    let name: String = parse(EXPORT_NAME, bytes)?;
    let allowed = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit();
    let valid = !name.is_empty()
        && name.len() <= MAX_NAME_BYTES
        && name.starts_with(allowed)
        && name.chars().all(|c| allowed(c) || c == '-' || c == '_');
    if valid {
        Ok(name)
    } else {
        Err(refuse(
            EXPORT_NAME,
            format!(
                "the name {} must be 1 to {MAX_NAME_BYTES} characters from a-z, 0-9, `-` and `_`, \
                 starting with a letter or a digit",
                shown(&name)
            ),
        ))
    }
}

// ---- sbrs_launch_args -----------------------------------------------------

fn launch_args(bytes: &[u8]) -> Result<Vec<String>, WasmError> {
    let args: Vec<String> = parse(EXPORT_LAUNCH_ARGS, bytes)?;
    if args.len() > MAX_LAUNCH_ARGS {
        return Err(refuse(
            EXPORT_LAUNCH_ARGS,
            format!(
                "{} switches are more than the limit of {MAX_LAUNCH_ARGS}",
                args.len()
            ),
        ));
    }
    for arg in &args {
        check_switch(arg)?;
    }
    Ok(args)
}

fn check_switch(arg: &str) -> Result<(), WasmError> {
    let export = EXPORT_LAUNCH_ARGS;
    if arg.len() > MAX_LAUNCH_ARG_BYTES {
        return Err(refuse(
            export,
            format!(
                "a switch of {} bytes is more than the limit of {MAX_LAUNCH_ARG_BYTES}",
                arg.len()
            ),
        ));
    }
    if has_control_character(arg) {
        return Err(refuse(
            export,
            format!("the switch {} holds a control character", shown(arg)),
        ));
    }
    let Some(rest) = arg.strip_prefix("--").or_else(|| arg.strip_prefix('-')) else {
        return Err(refuse(
            export,
            format!(
                "{} is not a switch: it must start with `-` (the browser would take it for a URL)",
                shown(arg)
            ),
        ));
    };
    let flag = rest.split('=').next().unwrap_or_default();
    let name_char = |c: char| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.');
    if !flag.starts_with(|c: char| c.is_ascii_alphanumeric()) || !flag.chars().all(name_char) {
        return Err(refuse(
            export,
            format!(
                "{} is not a switch: its name must start with a letter or a digit and hold only \
                 letters, digits, `-`, `_` and `.`",
                shown(arg)
            ),
        ));
    }
    if FORBIDDEN_FLAGS
        .iter()
        .any(|forbidden| flag.eq_ignore_ascii_case(forbidden))
    {
        return Err(refuse(
            export,
            format!(
                "the switch `--{flag}` is not allowed: it can run programs or switch off the \
                 browser's protections"
            ),
        ));
    }
    Ok(())
}

// ---- sbrs_scripts ---------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScriptWire {
    code: String,
    hosts: Value,
}

fn scripts(bytes: &[u8]) -> Result<Vec<Package>, WasmError> {
    let scripts: Vec<ScriptWire> = parse(EXPORT_SCRIPTS, bytes)?;
    if scripts.len() > MAX_SCRIPTS {
        return Err(refuse(
            EXPORT_SCRIPTS,
            format!(
                "{} scripts are more than the limit of {MAX_SCRIPTS}",
                scripts.len()
            ),
        ));
    }
    scripts
        .into_iter()
        .enumerate()
        .map(|(index, script)| {
            if script.code.is_empty() {
                return Err(refuse(
                    EXPORT_SCRIPTS,
                    format!("script {index} has no code"),
                ));
            }
            let package = Package::script(script.code);
            Ok(match hosts(index, &script.hosts)? {
                Some(hosts) => package.only_on(hosts),
                None => package.everywhere(),
            })
        })
        .collect()
}

/// The hosts of a script: `None` for `"everywhere"`.
fn hosts(index: usize, value: &Value) -> Result<Option<Vec<String>>, WasmError> {
    let wrong = |what: String| {
        refuse(
            EXPORT_SCRIPTS,
            format!(
                "`hosts` of script {index} {what}; it must be \"everywhere\" or a list of 1 to \
                 {MAX_HOSTS} lower-case host names"
            ),
        )
    };
    match value {
        Value::String(text) if text == "everywhere" => Ok(None),
        Value::String(text) => Err(wrong(format!("is the string {}", shown(text)))),
        Value::Array(items) if items.is_empty() => Err(wrong("is an empty list".to_owned())),
        Value::Array(items) if items.len() > MAX_HOSTS => {
            Err(wrong(format!("has {} entries", items.len())))
        }
        Value::Array(items) => items
            .iter()
            .map(|item| match item {
                Value::String(host) if is_host(host) => Ok(host.clone()),
                Value::String(host) => Err(wrong(format!("has the entry {}", shown(host)))),
                _ => Err(wrong("has an entry that is not a string".to_owned())),
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Some),
        _ => Err(wrong("is neither a string nor a list".to_owned())),
    }
}

/// A lower-case DNS name (or an IPv4 address): labels of `a-z`, `0-9` and `-`
/// that neither start nor end with `-`, separated by single dots.
fn is_host(host: &str) -> bool {
    let label = |label: &str| {
        !label.is_empty()
            && label.len() <= MAX_HOST_LABEL_BYTES
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    };
    !host.is_empty() && host.len() <= MAX_HOST_BYTES && host.split('.').all(label)
}

// ---- sbrs_blocked_urls ----------------------------------------------------

fn blocked_urls(bytes: &[u8]) -> Result<Vec<String>, WasmError> {
    let patterns: Vec<String> = parse(EXPORT_BLOCKED_URLS, bytes)?;
    if patterns.len() > MAX_BLOCKED_URLS {
        return Err(refuse(
            EXPORT_BLOCKED_URLS,
            format!(
                "{} patterns are more than the limit of {MAX_BLOCKED_URLS}",
                patterns.len()
            ),
        ));
    }
    for pattern in &patterns {
        if pattern.is_empty()
            || pattern.len() > MAX_URL_PATTERN_BYTES
            || has_control_character(pattern)
        {
            return Err(refuse(
                EXPORT_BLOCKED_URLS,
                format!(
                    "the pattern {} must be 1 to {MAX_URL_PATTERN_BYTES} bytes without control \
                     characters",
                    shown(pattern)
                ),
            ));
        }
    }
    Ok(patterns)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_packed_value_splits_into_pointer_and_length() {
        assert_eq!(unpack(0), (0, 0));
        assert_eq!(unpack(0x0000_0010_0000_0007), (16, 7));
        assert_eq!(unpack(-1), (u32::MAX, u32::MAX));
        assert_eq!(unpack(i64::MIN), (0x8000_0000, 0));
        assert_eq!(unpack(i64::MAX), (0x7FFF_FFFF, u32::MAX));
    }

    #[test]
    fn hosts_are_lower_case_dns_names() {
        for good in [
            "example.com",
            "a",
            "a-b.c-d.example",
            "127.0.0.1",
            "xn--bcher-kva.de",
        ] {
            assert!(is_host(good), "{good}");
        }
        let long_label = "a".repeat(64);
        let long_host = vec!["a"; 127].join(".") + "a";
        for bad in [
            "",
            ".",
            "a..b",
            ".a",
            "a.",
            "-a",
            "a-",
            "A.com",
            "a_b.com",
            "a b",
            "a/b",
            "a:80",
            "*.a",
            "caf\u{e9}.com",
            long_label.as_str(),
            long_host.as_str(),
        ] {
            assert!(!is_host(bad), "{bad:?}");
        }
        // The longest host: 253 bytes in labels of at most 63.
        let longest = [
            &"a".repeat(63),
            &"b".repeat(63),
            &"c".repeat(63),
            &"d".repeat(61),
        ]
        .map(String::as_str)
        .join(".");
        assert_eq!(longest.len(), 253);
        assert!(is_host(&longest));
        assert!(!is_host(&format!("{longest}e")));
    }

    #[test]
    fn a_switch_needs_a_dash_and_a_plain_name() {
        for good in [
            "--lang=de",
            "-headless",
            "--a",
            "--force-dark-mode",
            "--js-flags=--x=y",
        ] {
            assert!(check_switch(good).is_ok(), "{good}");
        }
        for bad in [
            "",
            "-",
            "--",
            "---x",
            "--=x",
            "lang",
            "/lang",
            "--a b",
            "--l\u{e4}ng",
            "--x\n",
        ] {
            assert!(check_switch(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn forbidden_switches_match_in_any_spelling() {
        for spelling in [
            "--no-sandbox",
            "-no-sandbox",
            "--No-Sandbox",
            "--no-sandbox=1",
        ] {
            let error = check_switch(spelling).unwrap_err().to_string();
            assert!(error.contains("not allowed"), "{spelling}: {error}");
        }
        for flag in FORBIDDEN_FLAGS {
            assert!(check_switch(&format!("--{flag}")).is_err(), "{flag}");
            assert!(
                flag.chars().all(|c| c.is_ascii_lowercase() || c == '-'),
                "{flag}"
            );
        }
        // Similar but different switches pass.
        assert!(check_switch("--no-sandbox-for-fun").is_ok());
        assert!(check_switch("--disable-gpu").is_ok());
    }

    #[test]
    fn untrusted_text_is_quoted_and_cut_in_messages() {
        assert_eq!(shown("ab"), "\"ab\"");
        assert_eq!(shown("a\nb\u{0}"), "\"a\\nb\\0\"");
        let long = "x".repeat(100);
        let text = shown(&long);
        assert!(text.ends_with("\"..."), "{text}");
        assert!(text.len() < 50, "{text}");
    }
}
