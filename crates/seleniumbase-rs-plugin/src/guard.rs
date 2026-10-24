//! Guarded handles: what a plugin gets instead of the host's own handles.
//!
//! [`PluginSet`] wraps every handle it passes to a hook in a [`Guarded`] made
//! for that plugin, so the rules hold for any engine and can be tested with
//! fakes. The guard checks three things:
//!
//! - **Capabilities.** Each protocol command goes through
//!   [`cdp_policy::required`]: `Network.getCookies` needs `cookies.read`,
//!   `Runtime.evaluate` needs `page.evaluate`, an unknown method needs
//!   `raw:cdp`, and so on. A plugin that holds `raw:cdp` may send any command
//!   that is not owned by the host. The typed methods follow the same table:
//!   `navigate` needs `page.navigate`, `new_context` needs `contexts`.
//! - **The host's own commands.** `Fetch.*` (the host owns interception),
//!   `Target.setAutoAttach` and `Browser.close`, `Browser.crash` and
//!   `Browser.crashGpuProcess` are refused for every plugin, whatever it holds.
//!   A raw `Network.setBlockedURLs` is not sent as it is, because it would
//!   replace the list other plugins and the host set: it becomes
//!   [`PageHandle::block_urls`], and goes out as it is only when the host's
//!   tab does not offer that.
//! - **Re-entrancy.** `navigate` inside `before_navigate`, and `new_page` or
//!   `new_context` inside a page or context hook, fail with
//!   [`PluginError::Reentrant`]: they would run the hook they are in again.
//!
//! A refusal is an `Err` the plugin sees at the call; the browser never
//! receives the command.

use std::fmt;
use std::ops::Deref;

use serde_json::{Value, json};

use crate::{
    BrowserFamily, BrowserHandle, Capability, ContextHandle, ContextId, ContextSettings, Engine,
    Entry, LoadedExtension, PageHandle, PageId, PluginError, PluginSet, RawKind, Result, Seals,
    async_trait,
};

/// What a protocol command needs, and which commands the host keeps for itself.
pub mod cdp_policy {
    use serde_json::Value;

    use crate::{Capability, HostScope, PathScope, RawKind};

    /// The Chrome DevTools Protocol domains a plugin may use through
    /// `cdp:<Domain>`. A method of any other domain is unknown and needs
    /// `raw:cdp`.
    const DOMAINS: &[&str] = &[
        "Accessibility",
        "Animation",
        "Audits",
        "Autofill",
        "BackgroundService",
        "BluetoothEmulation",
        "Browser",
        "CSS",
        "CacheStorage",
        "Cast",
        "Console",
        "DOM",
        "DOMDebugger",
        "DOMSnapshot",
        "DOMStorage",
        "Debugger",
        "DeviceAccess",
        "DeviceOrientation",
        "Emulation",
        "EventBreakpoints",
        "Extensions",
        "FedCm",
        "Fetch",
        "FileSystem",
        "HeadlessExperimental",
        "HeapProfiler",
        "IO",
        "IndexedDB",
        "Input",
        "Inspector",
        "LayerTree",
        "Log",
        "Media",
        "Memory",
        "Network",
        "Overlay",
        "PWA",
        "Page",
        "Performance",
        "PerformanceTimeline",
        "Preload",
        "Profiler",
        "Runtime",
        "Schema",
        "Security",
        "ServiceWorker",
        "Storage",
        "SystemInfo",
        "Target",
        "Tethering",
        "Tracing",
        "WebAudio",
        "WebAuthn",
    ];

    /// The capabilities the command `method` with `params` needs, all of them.
    ///
    /// A few commands have their own rule:
    ///
    /// | Method | Needs |
    /// |---|---|
    /// | `Network.getAllCookies`, `Network.getCookies`, `Storage.getCookies` | `cookies.read` |
    /// | `Network.setCookie`, `Network.setCookies`, `Network.deleteCookies`, `Storage.setCookies` | `cookies.write` |
    /// | `Network.clearBrowserCookies`, `Network.clearBrowserCache`, `Storage.clearCookies`, `Storage.clearDataForOrigin`, `Storage.clearDataForStorageKey` | `storage.clear` |
    /// | `Network.getResponseBody` (and the interception variants) | `net.bodies` |
    /// | `Runtime.evaluate`, `Runtime.callFunctionOn`, `Runtime.compileScript`, `Runtime.runScript` | `page.evaluate` |
    /// | `Page.addScriptToEvaluateOnNewDocument`, `Page.addScriptToEvaluateOnLoad` | `page.script:*` |
    /// | `Page.navigate` | `page.navigate` |
    /// | `Target.createBrowserContext` | `contexts`, and `launch.proxy` when it carries `proxyServer` |
    /// | `Target.disposeBrowserContext` | `contexts` |
    /// | `Browser.setDownloadBehavior` | `host.fs.write:run-output` |
    ///
    /// Every other method of a known domain needs `cdp:<Domain>`; a method of
    /// an unknown domain, or without a domain, needs `raw:cdp`. The commands
    /// of [`host_owned`] are not covered here: no capability allows them.
    ///
    /// ```
    /// use seleniumbase_rs_plugin::{cdp_policy, Capability};
    /// use serde_json::json;
    ///
    /// assert_eq!(
    ///     cdp_policy::required("Network.getCookies", &json!({})),
    ///     [Capability::CookiesRead]
    /// );
    /// assert_eq!(
    ///     cdp_policy::required("DOM.getDocument", &json!({})),
    ///     [Capability::Cdp("DOM".into())]
    /// );
    /// ```
    #[must_use]
    pub fn required(method: &str, params: &Value) -> Vec<Capability> {
        use Capability as C;
        match method {
            "Network.getAllCookies" | "Network.getCookies" | "Storage.getCookies" => {
                vec![C::CookiesRead]
            }
            "Network.setCookie"
            | "Network.setCookies"
            | "Network.deleteCookies"
            | "Storage.setCookies" => vec![C::CookiesWrite],
            "Network.clearBrowserCookies"
            | "Network.clearBrowserCache"
            | "Storage.clearCookies"
            | "Storage.clearDataForOrigin"
            | "Storage.clearDataForStorageKey" => vec![C::StorageClear],
            "Network.getResponseBody"
            | "Network.getResponseBodyForInterception"
            | "Network.takeResponseBodyForInterceptionAsStream" => vec![C::NetBodies],
            "Runtime.evaluate"
            | "Runtime.callFunctionOn"
            | "Runtime.compileScript"
            | "Runtime.runScript" => vec![C::PageEvaluate],
            "Page.addScriptToEvaluateOnNewDocument" | "Page.addScriptToEvaluateOnLoad" => {
                vec![C::PageScript(HostScope::Everywhere)]
            }
            "Page.navigate" => vec![C::PageNavigate],
            "Target.createBrowserContext" => {
                let mut needs = vec![C::Contexts];
                if carries_proxy(params) {
                    needs.push(C::LaunchProxy);
                }
                needs
            }
            "Target.disposeBrowserContext" => vec![C::Contexts],
            "Browser.setDownloadBehavior" => vec![C::HostFsWrite(PathScope::RunOutput)],
            _ => match method.split_once('.') {
                Some((domain, name)) if !name.is_empty() => {
                    DOMAINS.iter().find(|known| **known == domain).map_or_else(
                        || vec![C::Raw(RawKind::Cdp)],
                        |known| vec![C::Cdp((*known).into())],
                    )
                }
                _ => vec![C::Raw(RawKind::Cdp)],
            },
        }
    }

    /// Why the host refuses `method` for every plugin, whatever it holds, or
    /// `None` when a plugin may send it.
    ///
    /// The host owns `Fetch.*` (one router serves every plugin),
    /// `Target.setAutoAttach` (it decides which targets are attached) and the
    /// commands that close or crash the browser.
    ///
    /// ```
    /// use seleniumbase_rs_plugin::cdp_policy;
    ///
    /// assert!(cdp_policy::host_owned("Fetch.enable").is_some());
    /// assert!(cdp_policy::host_owned("Browser.close").is_some());
    /// assert!(cdp_policy::host_owned("Network.enable").is_none());
    /// ```
    #[must_use]
    pub fn host_owned(method: &str) -> Option<&'static str> {
        let (domain, name) = method.split_once('.')?;
        let is = |domain_name: &str, command: &str| {
            domain.eq_ignore_ascii_case(domain_name) && name.eq_ignore_ascii_case(command)
        };
        if domain.eq_ignore_ascii_case("Fetch") {
            Some("the host owns request interception; declare `network()` and use `on_request`")
        } else if is("Target", "setAutoAttach") {
            Some("the host decides which targets are attached")
        } else if is("Browser", "close")
            || is("Browser", "crash")
            || is("Browser", "crashGpuProcess")
        {
            Some("a plugin may not close or crash the browser")
        } else {
            None
        }
    }

    /// Whether `params` of `Target.createBrowserContext` name a proxy.
    pub(super) fn carries_proxy(params: &Value) -> bool {
        params
            .get("proxyServer")
            .and_then(Value::as_str)
            .is_some_and(|proxy| !proxy.is_empty())
    }
}

/// Where in the hooks a handle was handed out, for the re-entrancy rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Scope {
    /// A hook in which navigating and opening things is allowed.
    Free,
    /// `before_navigate`: a navigation here would run it again.
    BeforeNavigate,
    /// A page or context hook (named): opening a tab or context here would
    /// run the hooks of the tab or context again.
    Hook(&'static str),
}

impl Scope {
    fn hook(self) -> &'static str {
        match self {
            Self::Free => "a hook",
            Self::BeforeNavigate => "before_navigate",
            Self::Hook(name) => name,
        }
    }
}

/// What a guarded `send` does with a command.
enum Vet {
    /// Send it as it is.
    Forward,
    /// Block these URL patterns through `block_urls` instead.
    BlockUrls(Vec<String>),
}

/// A handle's owner and the rules that apply to it.
#[derive(Clone, Copy)]
struct Rules<'a> {
    set: &'a PluginSet,
    entry: &'a Entry,
    scope: Scope,
}

impl<'a> Rules<'a> {
    fn plugin(&self) -> &'a str {
        self.entry.plugin.name()
    }

    /// The rules for a handle this plugin made through another one: opening
    /// things from it is not the hook's business any more.
    fn free(self) -> Self {
        Self {
            scope: Scope::Free,
            ..self
        }
    }

    fn denied(&self, what: impl fmt::Display, reason: &str) -> PluginError {
        crate::denied(self.plugin(), what, reason)
    }

    /// Whether the plugin may use `method`: the host does not keep it, and the
    /// plugin holds what [`cdp_policy::required`] says (or `raw:cdp`).
    fn check_command(&self, method: &str, params: &Value) -> Result<()> {
        if let Some(reason) = cdp_policy::host_owned(method) {
            return Err(self.denied(method, reason));
        }
        let grants = &self.entry.grants;
        if grants.covers(&Capability::Raw(RawKind::Cdp)) {
            return Ok(());
        }
        for needed in cdp_policy::required(method, params) {
            if !grants.covers(&needed) {
                return Err(self.denied(&needed, &format!("`{method}` needs it")));
            }
        }
        Ok(())
    }

    fn refuse_navigate(&self, operation: &'static str) -> Result<()> {
        if self.scope == Scope::BeforeNavigate {
            return Err(self.reentrant(operation));
        }
        Ok(())
    }

    fn refuse_spawn(&self, operation: &'static str) -> Result<()> {
        if self.scope == Scope::Free {
            Ok(())
        } else {
            Err(self.reentrant(operation))
        }
    }

    fn reentrant(&self, operation: &'static str) -> PluginError {
        PluginError::Reentrant {
            plugin: self.plugin().to_owned(),
            operation,
            hook: self.scope.hook(),
        }
    }

    /// A raw context proxy while another plugin has sealed the proxy of new
    /// contexts: the hooks that enforce the seal would not run for it.
    fn check_context_proxy_seal(&self) -> Result<()> {
        let me = self.plugin();
        let owner = self.set.entries.iter().find(|other| {
            other.plugin.name() != me
                && other.plugin.metadata().seals.contains(Seals::CONTEXT_PROXY)
        });
        match owner {
            Some(owner) => Err(PluginError::Sealed {
                field: "context.proxy",
                a: owner.plugin.name().to_owned(),
                b: me.to_owned(),
            }),
            None => Ok(()),
        }
    }

    /// Decides what a raw command becomes.
    fn vet_send(&self, method: &str, params: &Value) -> Result<Vet> {
        self.check_command(method, params)?;
        if method == "Target.createBrowserContext" && cdp_policy::carries_proxy(params) {
            self.check_context_proxy_seal()?;
        }
        if method == "Page.navigate" {
            self.refuse_navigate("Page.navigate")?;
        }
        if method == "Network.setBlockedURLs" {
            return Ok(Vet::BlockUrls(self.blocked_urls(params)?));
        }
        Ok(Vet::Forward)
    }

    fn blocked_urls(&self, params: &Value) -> Result<Vec<String>> {
        let urls = params
            .get("urls")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                PluginError::other(format!(
                    "plugin `{}`: `Network.setBlockedURLs` needs a `urls` array of strings",
                    self.plugin()
                ))
            })?;
        urls.iter()
            .map(|url| {
                url.as_str().map(str::to_owned).ok_or_else(|| {
                    PluginError::other(format!(
                        "plugin `{}`: `Network.setBlockedURLs` needs a `urls` array of strings",
                        self.plugin()
                    ))
                })
            })
            .collect()
    }

    /// Blocking URLs is interception: the plugin needs `net.intercept` or the
    /// `Network` domain.
    fn check_block_urls(&self) -> Result<()> {
        let grants = &self.entry.grants;
        if grants.covers(&Capability::NetIntercept)
            || grants.covers(&Capability::Cdp("Network".into()))
        {
            Ok(())
        } else {
            Err(self.denied(
                Capability::NetIntercept,
                "`block_urls` needs it, or `cdp:Network`",
            ))
        }
    }
}

/// A handle or a borrowed one.
enum Held<'a, H: ?Sized> {
    Borrowed(&'a H),
    Owned(Box<H>),
}

impl<H: ?Sized> Deref for Held<'_, H> {
    type Target = H;

    fn deref(&self) -> &H {
        match self {
            Self::Borrowed(handle) => handle,
            Self::Owned(handle) => handle,
        }
    }
}

/// A handle as one plugin sees it: the host's [`BrowserHandle`],
/// [`PageHandle`] or [`ContextHandle`] behind three rules: a command needs the capabilities [`cdp_policy::required`] names, the commands of [`cdp_policy::host_owned`] are refused, and a handle may not start the hook it is in again ([`PluginError::Reentrant`]).
///
///
/// [`PluginSet`] makes one for each plugin and each hook; a plugin never holds
/// the host's own handle. The handles it opens through a guarded handle are
/// guarded too. A host that calls a plugin outside the hooks, such as a task,
/// makes the guarded handle with [`PluginSet::guarded_browser`],
/// [`PluginSet::guarded_page`] or [`PluginSet::guarded_context`].
pub struct Guarded<'a, H: ?Sized + 'a> {
    inner: Held<'a, H>,
    rules: Rules<'a>,
}

impl<H: ?Sized> fmt::Debug for Guarded<'_, H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Guarded")
            .field("plugin", &self.rules.plugin())
            .field("scope", &self.rules.scope)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl<H: PageHandle + ?Sized> PageHandle for Guarded<'_, H> {
    fn engine(&self) -> Engine {
        self.inner.engine()
    }

    async fn send(&self, method: &str, params: Value) -> Result<Value> {
        match self.rules.vet_send(method, &params)? {
            Vet::Forward => self.inner.send(method, params).await,
            Vet::BlockUrls(patterns) => match self.inner.block_urls(&patterns).await {
                // A tab that keeps no list per plugin: send the command, as
                // before the guard.
                Err(PluginError::NotSupported(_)) => self.inner.send(method, params).await,
                other => other.map(|()| json!({})),
            },
        }
    }

    async fn add_init_script(&self, source: &str) -> Result<()> {
        self.rules
            .check_command("Page.addScriptToEvaluateOnNewDocument", &Value::Null)?;
        self.inner.add_init_script(source).await
    }

    async fn evaluate(&self, expression: &str) -> Result<Value> {
        self.rules.check_command("Runtime.evaluate", &Value::Null)?;
        self.inner.evaluate(expression).await
    }

    fn id(&self) -> PageId {
        self.inner.id()
    }

    fn context(&self) -> Option<ContextId> {
        self.inner.context()
    }

    async fn url(&self) -> Result<String> {
        self.inner.url().await
    }

    async fn navigate(&self, url: &str) -> Result<()> {
        self.rules.check_command("Page.navigate", &Value::Null)?;
        self.rules.refuse_navigate("navigate")?;
        self.inner.navigate(url).await
    }

    async fn block_urls(&self, patterns: &[String]) -> Result<()> {
        self.rules.check_block_urls()?;
        self.inner.block_urls(patterns).await
    }

    async fn close(&self) -> Result<()> {
        self.inner.close().await
    }
}

#[async_trait]
impl<H: BrowserHandle + ?Sized> BrowserHandle for Guarded<'_, H> {
    fn engine(&self) -> Engine {
        self.inner.engine()
    }

    fn family(&self) -> BrowserFamily {
        self.inner.family()
    }

    fn id(&self) -> crate::BrowserId {
        self.inner.id()
    }

    fn extensions(&self) -> Vec<LoadedExtension> {
        self.inner.extensions()
    }

    async fn new_context<'b>(
        &'b self,
        settings: ContextSettings,
    ) -> Result<Box<dyn ContextHandle + 'b>> {
        self.rules.refuse_spawn("new_context")?;
        self.rules.check_command(
            "Target.createBrowserContext",
            &json!({ "proxyServer": settings.proxy }),
        )?;
        let context = self.inner.new_context(settings).await?;
        Ok(Box::new(Guarded {
            inner: Held::Owned(context),
            rules: self.rules.free(),
        }))
    }

    async fn new_page<'b>(&'b self, url: Option<&str>) -> Result<Box<dyn PageHandle + 'b>> {
        self.rules.refuse_spawn("new_page")?;
        if url.is_some() {
            self.rules.check_command("Page.navigate", &Value::Null)?;
        }
        let page = self.inner.new_page(url).await?;
        Ok(Box::new(Guarded {
            inner: Held::Owned(page),
            rules: self.rules.free(),
        }))
    }

    async fn send(&self, method: &str, params: Value) -> Result<Value> {
        match self.rules.vet_send(method, &params)? {
            Vet::Forward => self.inner.send(method, params).await,
            Vet::BlockUrls(_) => Err(self.rules.denied(
                method,
                "a browser-level command cannot block URLs; use a tab's `block_urls`",
            )),
        }
    }
}

#[async_trait]
impl<H: ContextHandle + ?Sized> ContextHandle for Guarded<'_, H> {
    fn id(&self) -> &ContextId {
        self.inner.id()
    }

    async fn new_page<'b>(&'b self, url: Option<&str>) -> Result<Box<dyn PageHandle + 'b>> {
        self.rules.refuse_spawn("new_page")?;
        if url.is_some() {
            self.rules.check_command("Page.navigate", &Value::Null)?;
        }
        let page = self.inner.new_page(url).await?;
        Ok(Box::new(Guarded {
            inner: Held::Owned(page),
            rules: self.rules.free(),
        }))
    }

    async fn dispose(&self) -> Result<()> {
        self.inner.dispose().await
    }
}

impl PluginSet {
    /// `page` as the entry's plugin sees it in a hook.
    pub(crate) fn guard_page<'a>(
        &'a self,
        entry: &'a Entry,
        scope: Scope,
        page: &'a dyn PageHandle,
    ) -> Guarded<'a, dyn PageHandle + 'a> {
        Guarded {
            inner: Held::Borrowed(page),
            rules: Rules {
                set: self,
                entry,
                scope,
            },
        }
    }

    /// `browser` as the entry's plugin sees it in a hook.
    pub(crate) fn guard_browser<'a>(
        &'a self,
        entry: &'a Entry,
        scope: Scope,
        browser: &'a dyn BrowserHandle,
    ) -> Guarded<'a, dyn BrowserHandle + 'a> {
        Guarded {
            inner: Held::Borrowed(browser),
            rules: Rules {
                set: self,
                entry,
                scope,
            },
        }
    }

    /// `context` as the entry's plugin sees it in a hook.
    pub(crate) fn guard_context<'a>(
        &'a self,
        entry: &'a Entry,
        scope: Scope,
        context: &'a dyn ContextHandle,
    ) -> Guarded<'a, dyn ContextHandle + 'a> {
        Guarded {
            inner: Held::Borrowed(context),
            rules: Rules {
                set: self,
                entry,
                scope,
            },
        }
    }

    /// `browser` as the plugin called `plugin` sees it, for work outside the
    /// hooks, such as the browser in a [`TaskContext`](crate::TaskContext).
    /// Navigating and opening things are allowed, as far as the plugin's
    /// capabilities go.
    ///
    /// # Errors
    ///
    /// [`PluginError::Config`] if no plugin has that name.
    pub fn guarded_browser<'a>(
        &'a self,
        plugin: &str,
        browser: &'a dyn BrowserHandle,
    ) -> Result<Guarded<'a, dyn BrowserHandle + 'a>> {
        Ok(self.guard_browser(self.named(plugin)?, Scope::Free, browser))
    }

    /// `page` as the plugin called `plugin` sees it, for work outside the
    /// hooks, such as the tab a [`JobRunner`](crate::JobRunner) gets.
    ///
    /// # Errors
    ///
    /// [`PluginError::Config`] if no plugin has that name.
    pub fn guarded_page<'a>(
        &'a self,
        plugin: &str,
        page: &'a dyn PageHandle,
    ) -> Result<Guarded<'a, dyn PageHandle + 'a>> {
        Ok(self.guard_page(self.named(plugin)?, Scope::Free, page))
    }

    /// `context` as the plugin called `plugin` sees it, for work outside the
    /// hooks.
    ///
    /// # Errors
    ///
    /// [`PluginError::Config`] if no plugin has that name.
    pub fn guarded_context<'a>(
        &'a self,
        plugin: &str,
        context: &'a dyn ContextHandle,
    ) -> Result<Guarded<'a, dyn ContextHandle + 'a>> {
        Ok(self.guard_context(self.named(plugin)?, Scope::Free, context))
    }
}
