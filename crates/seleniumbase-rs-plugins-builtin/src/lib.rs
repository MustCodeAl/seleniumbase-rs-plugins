//! The built-in seleniumbase-rs plugins, one cargo feature each, and a
//! [`registry`] of the ones that are on.
//!
//! | Feature | Plugin | Crate |
//! |---|---|---|
//! | `shield` | `shield`, privacy hardening with optional local Tor SOCKS5 routing and per-context circuit isolation | `seleniumbase-rs-plugin-shield` |
//! | `crx` | `crx`, loads browser extensions from `.crx`, `.zip`, and unpacked Manifest V3 folders with service-worker waits | `seleniumbase-rs-plugin-crx` |
//! | `browser` | `browser`, containerized persistent browser sessions (cookies, storage, open tabs, identity, TTL, geo targeting, IP rotation, SPA flows) | `seleniumbase-rs-plugin-browser` |
//! | `fetcher` | `fetcher`, request rules, response records and a fetch task | `seleniumbase-rs-plugin-fetcher` |
//! | `extractor` | `extractor`, finds and extracts structured data from pages | `seleniumbase-rs-plugin-extractor` |
//! | `batcher` | `batcher`, runs a list of jobs in tabs, in chunks, with retries and resume | `seleniumbase-rs-plugin-batcher` |
//! | `crawler` | `crawler`, crawls a site you own or may test and reports broken pages | `seleniumbase-rs-plugin-crawler` |
//!
//! Community plugins (`block-resources`, `imap`, `antibot-detector`,
//! `behavior-dataset`, `cloud-logging`, `langchain`, `ocr`, `owasp`) live as
//! standalone crates in the same repository. The sandboxed WebAssembly plugin
//! host is an opt-in feature (`wasm`) of `seleniumbase-rs-plugin`.
//!
//! ```
//! let registry = seleniumbase_rs_plugins_builtin::registry();
//! for name in registry.names() {
//!     println!("{name}");
//! }
//! ```

pub use seleniumbase_rs_plugin::{Descriptor, PluginSpec, Registry};

#[cfg(feature = "batcher")]
pub use seleniumbase_rs_plugin_batcher as batcher;
#[cfg(feature = "browser")]
pub use seleniumbase_rs_plugin_browser as browser;
#[cfg(feature = "crawler")]
pub use seleniumbase_rs_plugin_crawler as crawler;
#[cfg(feature = "crx")]
pub use seleniumbase_rs_plugin_crx as crx;
#[cfg(feature = "extractor")]
pub use seleniumbase_rs_plugin_extractor as extractor;
#[cfg(feature = "fetcher")]
pub use seleniumbase_rs_plugin_fetcher as fetcher;
#[cfg(feature = "shield")]
pub use seleniumbase_rs_plugin_shield as shield;

/// A registry of every built-in plugin whose feature is on, in the order
/// `shield`, `crx`, `fetcher`, `extractor`, `batcher`, `crawler`, `browser`.
/// Empty when no feature is on.
#[must_use]
pub fn registry() -> Registry {
    #[allow(unused_mut)]
    let mut registry = Registry::new();
    #[cfg(feature = "shield")]
    {
        registry = registry.with(Descriptor::of::<shield::Shield>());
    }
    #[cfg(feature = "crx")]
    {
        registry = registry.with(Descriptor::of::<crx::CrxExtensions>());
    }
    #[cfg(feature = "fetcher")]
    {
        registry = registry.with(Descriptor::of::<fetcher::Fetcher>());
    }
    #[cfg(feature = "extractor")]
    {
        registry = registry.with(Descriptor::of::<extractor::Extractor>());
    }
    #[cfg(feature = "batcher")]
    {
        registry = registry.with(Descriptor::of::<batcher::Batcher>());
    }
    #[cfg(feature = "crawler")]
    {
        registry = registry.with(Descriptor::of::<crawler::Crawler>());
    }
    #[cfg(feature = "browser")]
    {
        registry = registry.with(Descriptor::of::<browser::BrowserSession>());
    }
    registry
}
