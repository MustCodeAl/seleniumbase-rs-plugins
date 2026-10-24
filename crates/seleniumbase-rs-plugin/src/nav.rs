//! Navigation hooks: a plugin may cancel or redirect a navigation the program
//! starts, and learns how it ended.
//!
//! [`Plugin::before_navigate`](crate::Plugin::before_navigate) covers only
//! navigation the program asks for (`Page::goto`, the MCP `navigate` tool).
//! Navigation the page starts itself, such as a link click or a script, shows
//! up in [`Plugin::on_request`](crate::Plugin::on_request) with
//! [`RequestView::navigation`](crate::RequestView::navigation) set.

use crate::{Capability, PageHandle, PluginError, PluginSet, Result};

/// The most redirects plugins may apply to one navigation.
pub const MAX_REDIRECTS: usize = 5;

/// Who started a navigation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum NavOrigin {
    /// The program, through the library or the command line.
    Program,
    /// An MCP client.
    Mcp,
}

/// A navigation about to start.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Navigation {
    /// The address to open.
    pub url: String,
    /// Who asked for it.
    pub origin: NavOrigin,
}

impl Navigation {
    /// A navigation to `url` asked for by `origin`.
    #[must_use]
    pub fn new(url: impl Into<String>, origin: NavOrigin) -> Self {
        Self {
            url: url.into(),
            origin,
        }
    }

    /// A navigation to `url` asked for by the program.
    #[must_use]
    pub fn program(url: impl Into<String>) -> Self {
        Self::new(url, NavOrigin::Program)
    }
}

/// What a plugin decides about a navigation.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum NavDecision {
    /// Go on.
    Continue,
    /// Open this address instead. Only `http`, `https`, `about:blank` and
    /// `data:` addresses are accepted, and the plugin needs
    /// [`Capability::PageNavigate`].
    Redirect(String),
    /// Do not navigate; the message says why and reaches the caller.
    Cancel(String),
}

/// How a navigation ended.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct NavOutcome {
    /// The address that was opened.
    pub url: String,
    /// The HTTP status of the document, when the host knows it.
    pub status: Option<u16>,
    /// Why the navigation failed, such as `net::ERR_NAME_NOT_RESOLVED`.
    pub error: Option<String>,
}

impl NavOutcome {
    /// A navigation to `url` that ended without an error and with no status.
    #[must_use]
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            status: None,
            error: None,
        }
    }

    /// Sets the HTTP status.
    #[must_use]
    pub fn status(mut self, status: u16) -> Self {
        self.status = Some(status);
        self
    }

    /// Marks the navigation as failed.
    #[must_use]
    pub fn failed(mut self, error: impl Into<String>) -> Self {
        self.error = Some(error.into());
        self
    }

    /// Whether the page loaded: no error, and a status below 400 when known.
    #[must_use]
    pub fn ok(&self) -> bool {
        self.error.is_none() && self.status.is_none_or(|status| status < 400)
    }
}

/// Whether a plugin may send a navigation to `url`.
fn redirect_allowed(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    lower.starts_with("http://")
        || lower.starts_with("https://")
        || lower == "about:blank"
        || lower.starts_with("data:")
}

impl PluginSet {
    /// Asks every plugin, in order, whether a navigation may go on, and
    /// returns the navigation to carry out.
    ///
    /// - The first [`NavDecision::Cancel`] wins: no command is sent and the
    ///   caller gets [`PluginError::NavigationCancelled`].
    /// - A [`NavDecision::Redirect`] is applied at once, so each later plugin
    ///   sees the new address. It is refused unless the plugin holds
    ///   [`Capability::PageNavigate`] and the address starts with `http://`,
    ///   `https://` or `data:`, or is `about:blank`; at most [`MAX_REDIRECTS`]
    ///   are applied.
    ///
    /// # Errors
    ///
    /// [`PluginError::NavigationCancelled`], or a [`PluginError::Hook`] from a
    /// failing hook or a refused redirect. The navigation does not start.
    pub async fn before_navigate(
        &self,
        page: &dyn PageHandle,
        navigation: &Navigation,
    ) -> Result<Navigation> {
        let mut current = navigation.clone();
        let mut redirects = 0;
        for entry in self.ordered() {
            let decision = self
                .run_hook(
                    entry,
                    "before_navigate",
                    entry.plugin.before_navigate(page, &current),
                )
                .await?;
            let name = entry.plugin.name();
            match decision {
                NavDecision::Continue => {}
                NavDecision::Cancel(reason) => {
                    return Err(PluginError::NavigationCancelled {
                        plugin: name.to_owned(),
                        url: current.url,
                        reason,
                    });
                }
                NavDecision::Redirect(url) => {
                    let refusal = if !entry.grants.covers(&Capability::PageNavigate) {
                        Some("it redirected a navigation without `page.navigate`".to_owned())
                    } else if !redirect_allowed(&url) {
                        Some(format!(
                            "redirect to `{url}` refused: only http, https, about:blank and data: addresses are allowed"
                        ))
                    } else if redirects == MAX_REDIRECTS {
                        Some(format!(
                            "redirect to `{url}` refused: a navigation is redirected at most {MAX_REDIRECTS} times"
                        ))
                    } else {
                        None
                    };
                    if let Some(message) = refusal {
                        return Err(PluginError::Hook {
                            plugin: name.to_owned(),
                            hook: "before_navigate",
                            message,
                        });
                    }
                    if url != current.url {
                        redirects += 1;
                        current.url = url;
                    }
                }
            }
        }
        Ok(current)
    }

    /// Tells every plugin how a navigation ended. Every plugin runs even when
    /// one fails; the failures are returned for the caller to log.
    pub async fn after_navigate(
        &self,
        page: &dyn PageHandle,
        outcome: &NavOutcome,
    ) -> Vec<PluginError> {
        let mut failures = Vec::new();
        for entry in self.ordered() {
            if let Err(error) = self
                .run_hook(
                    entry,
                    "after_navigate",
                    entry.plugin.after_navigate(page, outcome),
                )
                .await
            {
                failures.push(error);
            }
        }
        failures
    }
}
