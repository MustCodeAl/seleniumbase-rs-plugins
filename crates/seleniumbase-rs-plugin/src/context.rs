//! Identifiers and browser contexts: separate sessions inside one browser.
//!
//! A context has its own cookies and storage and can have its own proxy, so a
//! plugin such as an anonymiser gives each batch of work a fresh one.
//! [`Plugin::before_context`](crate::Plugin::before_context) may change the
//! [`ContextSettings`] before the context is made,
//! [`Plugin::on_context_created`](crate::Plugin::on_context_created) sees it
//! once it exists and [`Plugin::on_context_closed`](crate::Plugin::on_context_closed)
//! when it is gone. All three reach only plugins that hold
//! [`Capability::Contexts`].

use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;

use crate::{Capability, Entry, PageHandle, PluginError, PluginSet, Result, Seals, async_trait};

macro_rules! id_type {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(Arc<str>);

        impl $name {
            /// An identifier with this text.
            #[must_use]
            pub fn new(id: impl AsRef<str>) -> Self {
                Self(Arc::from(id.as_ref()))
            }

            /// The identifier of a thing the host cannot name.
            #[must_use]
            pub fn unknown() -> Self {
                Self::new("unknown")
            }

            /// The text.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

id_type!(
    /// Names a browser, for logs and for telling two browsers of a pool apart.
    BrowserId
);
id_type!(
    /// Names a tab.
    PageId
);
id_type!(
    /// Names a browser context.
    ContextId
);

/// What a new browser context is made with. Plugins change it in
/// [`Plugin::before_context`](crate::Plugin::before_context).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ContextSettings {
    /// The proxy server for this context, such as `socks5://127.0.0.1:1080`.
    pub proxy: Option<String>,
    /// Hosts the proxy is not used for.
    pub bypass: Vec<String>,
}

impl ContextSettings {
    /// Settings with no proxy.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the proxy.
    #[must_use]
    pub fn proxy(mut self, proxy: impl Into<String>) -> Self {
        self.proxy = Some(proxy.into());
        self
    }

    /// Sets the hosts the proxy is not used for.
    #[must_use]
    pub fn bypass<I, S>(mut self, hosts: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.bypass = hosts.into_iter().map(Into::into).collect();
        self
    }
}

/// An extension the browser loaded, as the host reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct LoadedExtension {
    /// The extension's id.
    pub id: String,
    /// The folder it was loaded from.
    pub path: PathBuf,
}

impl LoadedExtension {
    /// An extension with this id, loaded from `path`.
    #[must_use]
    pub fn new(id: impl Into<String>, path: impl Into<PathBuf>) -> Self {
        Self {
            id: id.into(),
            path: path.into(),
        }
    }
}

/// A browser context, as a plugin sees it. Always borrowed: a plugin cannot
/// keep one.
#[async_trait]
pub trait ContextHandle: Send + Sync {
    /// The context's id.
    fn id(&self) -> &ContextId;

    /// Opens a tab in this context, at `url` if given.
    ///
    /// # Errors
    ///
    /// The host's error, or [`PluginError::NotSupported`].
    async fn new_page<'a>(&'a self, url: Option<&str>) -> Result<Box<dyn PageHandle + 'a>>;

    /// Closes the context and its tabs.
    ///
    /// # Errors
    ///
    /// The host's error.
    async fn dispose(&self) -> Result<()>;
}

impl PluginSet {
    /// Lets every plugin that holds [`Capability::Contexts`] change the settings
    /// of a context about to be made, in order. After each plugin the change is
    /// checked: a new proxy or bypass list needs [`Capability::LaunchProxy`],
    /// the bypass list only grows, and a proxy another plugin sealed with
    /// [`Seals::CONTEXT_PROXY`] keeps its value.
    ///
    /// # Errors
    ///
    /// The first hook error, as [`PluginError::Hook`], or the first rule
    /// broken, as [`PluginError::Capability`] or [`PluginError::Sealed`]. No
    /// context is made then.
    pub async fn before_context(&self, settings: &mut ContextSettings) -> Result<()> {
        let mut sealed: Option<(String, Option<String>)> = None;
        for entry in self.holding(&Capability::Contexts) {
            let before = settings.clone();
            self.run_hook(
                entry,
                "before_context",
                entry.plugin.before_context(settings),
            )
            .await?;
            verify_context(entry, &before, settings, &mut sealed)?;
        }
        Ok(())
    }

    /// Tells every plugin that holds [`Capability::Contexts`] that a context
    /// exists, before the program uses it.
    ///
    /// # Errors
    ///
    /// The first hook error, as [`PluginError::Hook`]; the caller disposes the
    /// half-made context.
    pub async fn on_context_created(&self, context: &dyn ContextHandle) -> Result<()> {
        for entry in self.holding(&Capability::Contexts) {
            self.run_hook(
                entry,
                "on_context_created",
                entry.plugin.on_context_created(context),
            )
            .await?;
        }
        Ok(())
    }

    /// Tells every plugin that holds [`Capability::Contexts`] that a context is
    /// gone. Every plugin runs even when one fails; the failures are returned
    /// for the caller to log.
    pub async fn on_context_closed(&self, id: &ContextId) -> Vec<PluginError> {
        let mut failures = Vec::new();
        for entry in self.holding(&Capability::Contexts) {
            if let Err(error) = self
                .run_hook(
                    entry,
                    "on_context_closed",
                    entry.plugin.on_context_closed(id),
                )
                .await
            {
                failures.push(error);
            }
        }
        failures
    }
}

/// Checks what one plugin's `before_context` changed.
fn verify_context(
    entry: &Entry,
    before: &ContextSettings,
    after: &ContextSettings,
    sealed: &mut Option<(String, Option<String>)>,
) -> Result<()> {
    let name = entry.plugin.name();
    let denied = |what: &str, reason: &str| crate::denied(name, what, reason);
    if !before.bypass.iter().all(|host| after.bypass.contains(host)) {
        return Err(denied(
            "context.bypass",
            "list settings only grow; it removed an entry",
        ));
    }
    let changed = before.proxy != after.proxy || before.bypass != after.bypass;
    if changed && !entry.grants.covers(&Capability::LaunchProxy) {
        return Err(denied(
            &Capability::LaunchProxy.to_string(),
            "it changed a context's proxy settings without the capability",
        ));
    }
    if before.proxy != after.proxy {
        if let Some((owner, held)) = sealed.as_ref() {
            if *held != after.proxy {
                return Err(PluginError::Sealed {
                    field: "context.proxy",
                    a: owner.clone(),
                    b: name.to_owned(),
                });
            }
        } else if entry.plugin.metadata().seals.contains(Seals::CONTEXT_PROXY) {
            *sealed = Some((name.to_owned(), after.proxy.clone()));
        }
    }
    Ok(())
}
