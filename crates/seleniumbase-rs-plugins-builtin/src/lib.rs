//! The built-in seleniumbase-rs plugins, one cargo feature each, and a
//! [`registry`] of the ones that are on.
//!
//! | Feature | Plugin | Crate |
//! |---|---|---|
//! | `shield` | `shield`, privacy hardening | `seleniumbase-rs-plugin-shield` |
//! | `block-resources` | `block-resources`, no images, fonts or media | `seleniumbase-rs-plugin-block-resources` |
//! | `crx` | `crx`, loads packed extensions | `seleniumbase-rs-plugin-crx` |
//! | `fetcher` | `fetcher`, request rules, response records and a fetch task | `seleniumbase-rs-plugin-fetcher` |
//! | `extractor` | `extractor`, finds and extracts structured data from pages | `seleniumbase-rs-plugin-extractor` |
//! | `batcher` | `batcher`, runs a list of jobs in tabs, in chunks, with retries and resume | `seleniumbase-rs-plugin-batcher` |
//! | `crawler` | `crawler`, crawls a site you own or may test and reports broken pages | `seleniumbase-rs-plugin-crawler` |
//! | `browser` | `browser`, loads extensions from `.zip` and `.crx` files and unpacked folders; cannot share a set with `crx` | `seleniumbase-rs-plugin-browser` |
//! | `imap` | `imap`, waits for an email in an IMAP mailbox and extracts its one-time code or link (the task `wait_for_email`); the password comes from the environment variable `password_env` names | `seleniumbase-rs-plugin-imap` |
//!
//! No feature is on by default, so a build compiles only the plugins it asks
//! for. Every plugin is also a crate of its own that depends on the plugin API
//! only; this crate adds nothing to them but the feature switches and the
//! registry.
//!
//! The `wasm` plugin host is not part of this crate: it cannot be built from a
//! name and options yet, because it needs the path of a module.
//!
//! ```
//! let registry = seleniumbase_rs_plugins_builtin::registry();
//! // With `--features shield`, this lists "shield".
//! for name in registry.names() {
//!     println!("{name}");
//! }
//! ```

pub use seleniumbase_rs_plugin::{Descriptor, PluginSpec, Registry};

#[cfg(feature = "batcher")]
pub use seleniumbase_rs_plugin_batcher as batcher;
#[cfg(feature = "block-resources")]
pub use seleniumbase_rs_plugin_block_resources as block_resources;
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
#[cfg(feature = "imap")]
pub use seleniumbase_rs_plugin_imap as imap;
#[cfg(feature = "shield")]
pub use seleniumbase_rs_plugin_shield as shield;

/// A registry of every built-in plugin whose feature is on, in the order
/// `shield`, `block-resources`, `crx`, `fetcher`, `extractor`, `batcher`,
/// `crawler`, `browser`, `imap`. Empty when no feature is on.
#[must_use]
pub fn registry() -> Registry {
    #[allow(unused_mut)]
    let mut registry = Registry::new();
    #[cfg(feature = "shield")]
    {
        registry = registry.with(Descriptor::of::<shield::Shield>());
    }
    #[cfg(feature = "block-resources")]
    {
        registry = registry.with(Descriptor::of::<block_resources::BlockResources>());
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
    #[cfg(feature = "imap")]
    {
        registry = registry.with(Descriptor::of::<imap::Imap>());
    }
    registry
}
