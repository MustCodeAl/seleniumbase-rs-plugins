//! The one list of browser switches that no plugin may add.

/// Switch names (no dashes, lower case) refused for every plugin. A native
/// plugin that truly needs one declares `raw:switches` and is trusted by name.
pub const REFUSED_SWITCHES: &[&str] = &[
    "renderer-cmd-prefix",
    "utility-cmd-prefix",
    "zygote-cmd-prefix",
    "gpu-launcher",
    "ppapi-plugin-launcher",
    "plugin-launcher",
    "browser-subprocess-path",
    "nacl-gdb",
    "nacl-gdb-script",
    "no-sandbox",
    "disable-setuid-sandbox",
    "disable-gpu-sandbox",
    "no-zygote",
    "disable-web-security",
    "ignore-certificate-errors",
    "ignore-certificate-errors-spki-list",
    "proxy-server",
    "proxy-pac-url",
    "host-resolver-rules",
    "host-rules",
    "remote-debugging-port",
    "remote-debugging-address",
    "remote-debugging-pipe",
    "remote-allow-origins",
    "load-extension",
    "load-component-extension",
    "disable-extensions-except",
    "user-data-dir",
    "js-flags",
    "disable-site-isolation-trials",
    "allow-file-access-from-files",
    "unsafely-treat-insecure-origin-as-secure",
    "allow-running-insecure-content",
    "log-net-log",
    "net-log-capture-mode",
    "enable-logging",
    "log-file",
    "disk-cache-dir",
    "crash-dumps-dir",
    "single-process",
];

/// Feature names that may not be disabled or enabled through
/// `--disable-features` or `--enable-features`.
pub const REFUSED_FEATURES: &[&str] = &["isolateorigins", "site-per-process"];

/// The switch name of `arg`: dashes and any `=value` removed, lower case.
/// `None` when `arg` is not a switch.
#[must_use]
pub fn switch_name(arg: &str) -> Option<String> {
    let trimmed = arg.trim();
    let stripped = trimmed
        .strip_prefix("--")
        .or_else(|| trimmed.strip_prefix('-'))?;
    let name = stripped.split('=').next().unwrap_or("").trim();
    if name.is_empty() {
        return None;
    }
    Some(name.to_ascii_lowercase())
}

/// Why `arg` is refused, or `None` when it is allowed.
#[must_use]
pub fn refusal(arg: &str) -> Option<String> {
    let name = switch_name(arg)?;
    if REFUSED_SWITCHES.contains(&name.as_str()) {
        return Some(format!("the switch `--{name}` is refused for every plugin"));
    }
    if name == "disable-features" || name == "enable-features" {
        let value = arg.split_once('=').map_or("", |(_, v)| v);
        for feature in value.split(',') {
            if feature_refused(feature.trim().trim_start_matches('-')) {
                return Some(format!(
                    "the feature `{}` may not be changed by a plugin",
                    feature.trim()
                ));
            }
        }
    }
    None
}

/// Whether `feature` (as in `--disable-features=`) is refused.
#[must_use]
pub fn feature_refused(feature: &str) -> bool {
    let feature = feature
        .trim()
        .split(':')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    REFUSED_FEATURES.contains(&feature.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refused_in_every_spelling() {
        for arg in [
            "--host-resolver-rules=MAP * 1.2.3.4",
            "-host-resolver-rules=x",
            "--Host-Resolver-Rules",
            "--ignore-certificate-errors-spki-list=abc",
            " --NO-SANDBOX ",
            "--disable-features=Foo,IsolateOrigins",
            "--enable-features=site-per-process:x/y",
        ] {
            assert!(refusal(arg).is_some(), "{arg}");
        }
    }

    #[test]
    fn benign_switches_pass() {
        for arg in [
            "--lang=de",
            "--window-size=800,600",
            "--disable-features=Translate",
            "plain",
        ] {
            assert!(refusal(arg).is_none(), "{arg}");
        }
    }
}
