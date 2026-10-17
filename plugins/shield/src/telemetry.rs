//! What shield switches off in the browser itself.
//!
//! Every entry was checked against the Chromium source on 2026-10-17 (the
//! `main` branch at chromium.googlesource.com/chromium/src). Chrome renames and
//! removes switches, features and endpoints between releases: re-check this
//! file against each new Chrome stable, and drop an entry that is gone instead
//! of keeping it "just in case". Entries that could not be found in the source
//! were left out on purpose:
//!
//! - `--disable-breakpad`: no longer declared in `crash_switches.h`,
//!   `chrome_switches.h` or `content_switches.h` (Chrome uses Crashpad).
//! - the features `OptimizationGuideModelDownloading` and
//!   `AutofillServerCommunication`: not declared in
//!   `optimization_guide_features.cc` or `autofill_features.h`.
//!
//! None of the switches is on [`REFUSED_SWITCHES`], and none of the features on
//! [`REFUSED_FEATURES`] (a test checks both).
//!
//! [`REFUSED_SWITCHES`]: seleniumbase_rs_plugin::switch_policy::REFUSED_SWITCHES
//! [`REFUSED_FEATURES`]: seleniumbase_rs_plugin::switch_policy::REFUSED_FEATURES

/// Browser switches that stop the browser's background network use.
///
/// Source: `chrome/common/chrome_switches.h` for all but one;
/// `components/sync/base/command_line_switches.h` for `disable-sync`.
pub const SWITCHES: &[&str] = &[
    // "Disable several subsystems which run network requests in the background."
    "--disable-background-networking",
    // Declared as `kDisableComponentUpdate`; stops component update checks.
    "--disable-component-update",
    // "Disables Domain Reliability Monitoring."
    "--disable-domain-reliability",
    // "Disables syncing browser data to a Google Account."
    "--disable-sync",
    // "Don't send hyperlink auditing pings"
    "--no-pings",
    // "Disables installation of default apps on first run."
    "--disable-default-apps",
];

/// Features turned off with `--disable-features`.
///
/// Sources, in `BASE_FEATURE` declarations (the feature name is the
/// identifier without the leading `k`):
/// `kOptimizationHints` in `components/optimization_guide/core/optimization_guide_features.cc`,
/// `kMediaRouter` in `chrome/browser/media/router/media_router_feature.cc`.
pub const FEATURES: &[&str] = &["OptimizationHints", "MediaRouter"];

/// Hosts the browser process itself reports to or fetches from. At the
/// [`Strict`](crate::Level::Strict) level the browser can no longer resolve
/// them. Pages never reach this list: a request a page makes goes through the
/// page's own blocking, not through the browser's resolver rules.
///
/// Sources (the URL constant, in the Chromium tree):
///
/// - `update.googleapis.com`: `kUpdaterJSONDefaultUrl`,
///   `components/component_updater/component_updater_url_constants.cc`
/// - `clientservices.googleapis.com`: `kDefaultServerUrl` (the variations
///   seed), `components/variations/variations_url_constants.cc`
/// - `optimizationguide-pa.googleapis.com`:
///   `kOptimizationGuideServiceGetModelsDefaultURL`,
///   `components/optimization_guide/core/optimization_guide_features.cc`
/// - `content-autofill.googleapis.com`: `kDefaultAutofillServerURL`,
///   `components/autofill/core/browser/crowdsourcing/autofill_crowdsourcing_manager.cc`
/// - `clients4.google.com`: `kSyncServerUrl`, `components/sync/base/sync_util.h`
/// - `clients2.google.com`: `kTimeServiceURL`,
///   `components/network_time/network_time_tracker.cc`
///
/// Safe Browsing's hosts are not here: shield leaves Safe Browsing on unless
/// `safe_browsing` is `false`.
pub const BROWSER_HOSTS: &[&str] = &[
    "update.googleapis.com",
    "clientservices.googleapis.com",
    "optimizationguide-pa.googleapis.com",
    "content-autofill.googleapis.com",
    "clients4.google.com",
    "clients2.google.com",
];

/// The `--host-resolver-rules` entry that makes `host` fail to resolve.
///
/// `^NOTFOUND` is the target `net/dns/mapped_host_resolver.h` documents: "then
/// all matched hostnames will fail to be resolved with
/// ERR_NAME_NOT_RESOLVED". (Many web pages spell it `~NOTFOUND`; the source on
/// `main` says `^`, so this plugin uses `^`.)
pub(crate) fn resolver_rule(host: &str) -> String {
    format!("MAP {host} ^NOTFOUND")
}
