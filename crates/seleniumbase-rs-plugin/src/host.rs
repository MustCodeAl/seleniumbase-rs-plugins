//! What the host that runs the plugins supports.

use crate::BrowserFamily;
use crate::capability::Capability;

/// The kind of host a plugin set runs in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum HostKind {
    /// The pure CDP engine: everything.
    Cdp,
    /// WebDriver with a Chromium browser.
    WebDriverChromium,
    /// WebDriver with Firefox or Safari.
    WebDriverOther,
    /// A Tauri webview.
    Embedded,
}

/// Passed to [`PluginSet::check_with`](crate::PluginSet::check_with) so the set
/// can refuse a plugin whose capabilities the host cannot provide.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostInfo {
    kind: HostKind,
}

impl HostInfo {
    /// The CDP engine.
    #[must_use]
    pub const fn cdp() -> Self {
        Self {
            kind: HostKind::Cdp,
        }
    }

    /// The WebDriver engine with a browser of `family`.
    #[must_use]
    pub fn webdriver(family: BrowserFamily) -> Self {
        Self {
            kind: if family == BrowserFamily::Chromium {
                HostKind::WebDriverChromium
            } else {
                HostKind::WebDriverOther
            },
        }
    }

    /// A Tauri webview.
    #[must_use]
    pub const fn embedded() -> Self {
        Self {
            kind: HostKind::Embedded,
        }
    }

    /// The kind of host.
    #[must_use]
    pub const fn kind(&self) -> HostKind {
        self.kind
    }

    /// A short name for messages.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self.kind {
            HostKind::Cdp => "the CDP engine",
            HostKind::WebDriverChromium => "WebDriver with Chromium",
            HostKind::WebDriverOther => "WebDriver with Firefox or Safari",
            HostKind::Embedded => "an embedded webview",
        }
    }

    /// Whether the host can provide `capability`. WebDriver hosts offer no
    /// browser contexts, request interception, tasks or test hooks yet, so a
    /// plugin that needs one is refused there with a message naming it.
    #[must_use]
    pub fn supports(&self, capability: &Capability) -> bool {
        use Capability as C;
        match self.kind {
            HostKind::Cdp => true,
            HostKind::WebDriverChromium => !matches!(
                capability,
                C::Contexts
                    | C::NetObserve
                    | C::NetSensitive
                    | C::NetBodies
                    | C::NetIntercept
                    | C::NetFulfill
                    | C::Task
                    | C::TestHooks
            ),
            HostKind::WebDriverOther => !matches!(
                capability,
                C::Contexts
                    | C::NetObserve
                    | C::NetSensitive
                    | C::NetBodies
                    | C::NetIntercept
                    | C::NetFulfill
                    | C::Task
                    | C::TestHooks
                    | C::Cdp(_)
                    | C::Raw(_)
            ),
            HostKind::Embedded => matches!(
                capability,
                C::PageScript(_) | C::PageEvaluate | C::TestHooks | C::Clock | C::Random
            ),
        }
    }
}
