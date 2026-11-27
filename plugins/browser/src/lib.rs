//! Containerized persistent browser sessions for `seleniumbase-rs`.
//!
//! Keep cookies, `localStorage`, `sessionStorage`, authentication state, open
//! tabs, and regional identity alive across calls and runs without reconnecting
//! or repeating logins. Pair with built-in geolocation targeting, proxy/IP
//! auto-rotation across isolated contexts, session TTL expiry, interactive
//! manual sign-in capture, and dynamic SPA flow/extraction tasks.
//!
//! Browser extension loading (`.crx`, `.zip`, unpacked Manifest V3 folders) is
//! handled exclusively by `seleniumbase-rs-plugin-crx` (`--plugin crx`). Both
//! plugins compose cleanly in the same [`PluginSet`](seleniumbase_rs_plugin::PluginSet).
//!
//! ```
//! use seleniumbase_rs_plugin::PluginSet;
//! use seleniumbase_rs_plugin_browser::BrowserSession;
//!
//! // One-line containerized persistent session
//! let plugin = BrowserSession::container("checkout-account")?;
//! let plugins = PluginSet::strict().with(plugin)?;
//! assert_eq!(plugins.names(), ["browser"]);
//! # Ok::<(), seleniumbase_rs_plugin::PluginError>(())
//! ```

mod config;
mod flow;
pub mod geo;
mod interactive;
mod session;

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use seleniumbase_rs_plugin::config::options;
use seleniumbase_rs_plugin::{
    BrowserHandle, Capability, Category, Configurable, ContextSettings, Engine, HostScope,
    LaunchSettings, Metadata, NavOutcome, PageHandle, PathScope, Plugin, PluginError, Requirements,
    Result, Task, TaskContext, async_trait,
};
use serde_json::{Value, json};

pub use config::{RotationMode, SessionConfig, SessionConfigBuilder};
pub use geo::GeoProfile;
pub use session::{ContainerIdentity, OriginStorage, SaveSummary};

const NAME: &str = "browser";

/// Live state tracked for one running browser instance.
#[derive(Debug, Default)]
struct LiveState {
    /// Cached storage hydration init script from the loaded container.
    storage_init_script: Option<String>,
    /// Per-origin `localStorage` and `sessionStorage` captured during this run.
    storage: BTreeMap<String, OriginStorage>,
    /// Open `http://`/`https://` tab URLs observed during this run.
    tabs: Vec<String>,
    /// Resolved container identity (loaded + config overrides).
    identity: ContainerIdentity,
}

/// Containerized persistent browser sessions plugin. See the [crate docs](crate).
#[derive(Debug)]
pub struct BrowserSession {
    config: SessionConfig,
    store: Option<session::Store>,
    proxy_cursor: Arc<AtomicUsize>,
    live: Mutex<LiveState>,
}

impl BrowserSession {
    /// One-line constructor for a named persistent container (`save_on_close = true`,
    /// `restore_tabs = true`).
    ///
    /// # Errors
    ///
    /// [`PluginError::Config`] when `name` is invalid or persistence is unavailable.
    pub fn container(name: impl Into<String>) -> Result<Self> {
        let config = SessionConfig::builder()
            .session(name)
            .save_on_close(true)
            .restore_tabs(true)
            .build()?;
        Self::new(config)
    }

    /// One-line constructor for a geo-targeted persistent container.
    ///
    /// # Errors
    ///
    /// [`PluginError::Config`] when `name` or `country` is invalid.
    pub fn for_country(name: impl Into<String>, country: impl Into<String>) -> Result<Self> {
        let config = SessionConfig::builder()
            .session(name)
            .country(country)
            .save_on_close(true)
            .restore_tabs(true)
            .build()?;
        Self::new(config)
    }

    /// Builds the plugin from a validated [`SessionConfig`].
    ///
    /// # Errors
    ///
    /// [`PluginError::Config`] when any option in `config` is invalid.
    pub fn new(mut config: SessionConfig) -> Result<Self> {
        config.normalize_and_check()?;
        let store = session::Store::from_config(&config)?;
        Ok(Self::checked(config, store, Arc::new(AtomicUsize::new(0))))
    }

    fn checked(
        config: SessionConfig,
        store: Option<session::Store>,
        proxy_cursor: Arc<AtomicUsize>,
    ) -> Self {
        Self {
            config,
            store,
            proxy_cursor,
            live: Mutex::new(LiveState::default()),
        }
    }

    /// Returns the configuration this plugin was built with.
    #[must_use]
    pub fn config(&self) -> &SessionConfig {
        &self.config
    }

    fn live(&self) -> MutexGuard<'_, LiveState> {
        self.live.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn build_identity(&self, loaded: Option<&ContainerIdentity>) -> ContainerIdentity {
        let base = loaded.cloned().unwrap_or_default();
        ContainerIdentity {
            country: self.config.country.clone().or(base.country),
            locale: self
                .config
                .effective_locale()
                .map(str::to_owned)
                .or(base.locale),
            timezone: self
                .config
                .effective_timezone()
                .map(str::to_owned)
                .or(base.timezone),
            geolocation: self
                .config
                .effective_geolocation()
                .map(|(lat, lon)| [lat, lon])
                .or(base.geolocation),
            user_agent: self.config.user_agent.clone().or(base.user_agent),
            proxy_index: base.proxy_index,
        }
    }

    fn next_proxy(&self, for_context: bool) -> Option<(usize, String)> {
        if self.config.proxies.is_empty() {
            return None;
        }
        let len = self.config.proxies.len();
        let idx = match self.config.rotation {
            RotationMode::Sticky => {
                if for_context {
                    return None;
                }
                self.live().identity.proxy_index.unwrap_or(0) % len
            }
            RotationMode::RoundRobin => self.proxy_cursor.fetch_add(1, Ordering::Relaxed) % len,
            RotationMode::PerContext => {
                if for_context {
                    self.proxy_cursor.fetch_add(1, Ordering::Relaxed) % len
                } else {
                    0
                }
            }
        };
        Some((idx, self.config.proxies[idx].clone()))
    }

    async fn save_container(&self, browser: &dyn BrowserHandle) -> Result<SaveSummary> {
        let Some(ref store) = self.store else {
            return Err(PluginError::other(
                "browser: saving a container requires `session`",
            ));
        };
        let cookies = session::capture_cookies(browser).await?;
        let now_ms = session::unix_millis();
        let expires_at_ms = self
            .config
            .ttl_secs
            .map(|ttl| now_ms.saturating_add(ttl.saturating_mul(1_000)));
        let (storage, tabs, identity) = {
            let live = self.live();
            (
                live.storage.clone(),
                live.tabs.clone(),
                live.identity.clone(),
            )
        };
        let summary = SaveSummary {
            session: store.name().to_owned(),
            cookies: cookies.len(),
            storage_origins: storage.len(),
            tabs: tabs.len(),
        };
        let snapshot = session::ContainerSnapshot {
            saved_at_ms: now_ms,
            expires_at_ms,
            cookies,
            storage,
            tabs,
            identity,
        };
        store.write(&snapshot)?;
        Ok(summary)
    }

    fn record_tab(&self, url: &str) {
        if !session::is_http_url(url) {
            return;
        }
        let mut live = self.live();
        if !live.tabs.iter().any(|existing| existing == url) && live.tabs.len() < 32 {
            live.tabs.push(url.to_owned());
        }
    }

    fn record_storage(&self, origin: String, storage: OriginStorage) {
        if storage.local_storage.is_empty() && storage.session_storage.is_empty() {
            return;
        }
        let mut live = self.live();
        live.storage.insert(origin, storage);
    }
}

fn declared() -> Metadata {
    Metadata::new(Category::Environment)
        .version(env!("CARGO_PKG_VERSION"))
        .summary(
            "Containerized persistent browser sessions: cookies, Web Storage, open tabs, \
             identity, TTL expiry, geolocation targeting, IP rotation, and dynamic SPA flows",
        )
        .optional(Capability::LaunchArgs)
        .optional(Capability::LaunchProxy)
        .optional(Capability::Contexts)
        .optional(Capability::CookiesRead)
        .optional(Capability::CookiesWrite)
        .optional(Capability::PageScript(HostScope::Everywhere))
        .optional(Capability::PageEvaluate)
        .optional(Capability::PageNavigate)
        .optional(Capability::Cdp("Emulation".into()))
        .optional(Capability::Cdp("Network".into()))
        .optional(Capability::Clock)
        .optional(Capability::Task)
}

impl Configurable for BrowserSession {
    const NAME: &'static str = NAME;

    fn describe() -> Metadata {
        declared()
    }

    fn configure(value: &Value) -> Result<Self> {
        let config = if value.is_null() {
            SessionConfig::new()
        } else {
            options::<SessionConfig>(NAME, value)?
        };
        Self::new(config)
    }
}

#[async_trait]
impl Task for BrowserSession {
    async fn run(&self, cx: &TaskContext<'_>) -> Result<Value> {
        let browser = cx.plugins.guarded_browser(NAME, cx.browser)?;
        if self.config.interactive {
            let Some(ref store) = self.store else {
                return Err(PluginError::other(
                    "browser: `interactive` requires `session`",
                ));
            };
            let url = interactive::start_url(cx.input)?;
            store.check_writable()?;
            let page = browser.new_page(url).await?;
            cx.prompt
                .wait(self.config.pause_message_or_default(), &*page)
                .await
                .map_err(|error| {
                    PluginError::other(format!(
                        "browser: `interactive` needs a person at the keyboard: {error}"
                    ))
                })?;
            if let Ok(current) = page.url().await {
                self.record_tab(&current);
            }
            if let Ok(Some((origin, st))) = flow::snapshot_page_storage(&*page).await {
                self.record_storage(origin, st);
            }
            let summary = self.save_container(&browser).await?;
            let out = serde_json::to_value(&summary)
                .map_err(|e| PluginError::other(format!("browser: {e}")))?;
            cx.sink.record(&out)?;
            return Ok(out);
        }

        let (extracted, visited_urls, captured_storage, save_flag) =
            flow::execute(&browser, cx.input).await?;
        for url in visited_urls {
            self.record_tab(&url);
        }
        for (origin, st) in captured_storage {
            self.record_storage(origin, st);
        }
        let saved = if (save_flag || self.config.save_on_close) && self.store.is_some() {
            Some(self.save_container(&browser).await?)
        } else {
            None
        };
        let out = json!({
            "session": self.config.session,
            "extracted": extracted,
            "saved": saved,
        });
        cx.sink.record(&out)?;
        Ok(out)
    }
}

#[async_trait]
impl Plugin for BrowserSession {
    fn name(&self) -> &str {
        NAME
    }

    fn requirements(&self) -> Requirements {
        let mut needs = Requirements::CHROMIUM_ONLY;
        if self.config.interactive {
            needs = needs | Requirements::HEADFUL;
        }
        needs
    }

    fn metadata(&self) -> Metadata {
        let mut meta = Metadata::new(Category::Environment)
            .version(env!("CARGO_PKG_VERSION"))
            .summary(
                "Containerized persistent browser sessions: cookies, Web Storage, open tabs, \
                 identity, TTL expiry, geolocation targeting, IP rotation, and dynamic SPA flows",
            )
            .capability(Capability::Task)
            .capability(Capability::PageNavigate)
            .capability(Capability::PageEvaluate)
            .capability(Capability::PageScript(HostScope::Everywhere))
            .capability(Capability::Clock);

        if self.config.effective_locale().is_some()
            || self.config.effective_timezone().is_some()
            || self.config.effective_geolocation().is_some()
        {
            meta = meta
                .capability(Capability::LaunchArgs)
                .capability(Capability::Cdp("Emulation".into()));
        }
        if self.config.user_agent.is_some() {
            meta = meta.capability(Capability::Cdp("Network".into()));
        }
        if !self.config.proxies.is_empty() {
            meta = meta
                .capability(Capability::LaunchProxy)
                .capability(Capability::Contexts);
        }
        if let Some(ref store) = self.store {
            meta = meta
                .capability(Capability::CookiesWrite)
                .capability(Capability::HostFsRead(PathScope::Declared(vec![
                    store.file().to_path_buf(),
                ])));
            if self.config.saves() {
                meta =
                    meta.capability(Capability::CookiesRead)
                        .capability(Capability::HostFsWrite(PathScope::Declared(vec![
                            store.dir().to_path_buf(),
                        ])));
            }
        }
        meta
    }

    fn task(&self) -> Option<&dyn Task> {
        Some(self as &dyn Task)
    }

    fn per_launch(&self) -> Option<Arc<dyn Plugin>> {
        Some(Arc::new(Self::checked(
            self.config.clone(),
            self.store.clone(),
            Arc::clone(&self.proxy_cursor),
        )))
    }

    async fn before_launch(&self, launch: &mut LaunchSettings) -> Result<()> {
        let loaded = match &self.store {
            Some(store) => store.load(self.config.ttl_secs)?,
            None => None,
        };
        let mut identity = self.build_identity(loaded.as_ref().map(|s| &s.identity));

        if let Some(ref locale) = identity.locale {
            let arg = format!("--lang={locale}");
            if !launch.args.contains(&arg) {
                launch.args.push(arg);
            }
        }

        if launch.proxy.is_none()
            && let Some((idx, proxy_url)) = self.next_proxy(false)
        {
            launch.proxy = Some(proxy_url);
            identity.proxy_index = Some(idx);
        }

        let mut live = self.live();
        live.identity = identity;
        if let Some(snapshot) = loaded {
            live.storage_init_script = snapshot.storage_init_script();
            live.storage = snapshot.storage;
            live.tabs = snapshot.tabs;
        }
        Ok(())
    }

    async fn before_context(&self, settings: &mut ContextSettings) -> Result<()> {
        if settings.proxy.is_none()
            && let Some((_, proxy_url)) = self.next_proxy(true)
        {
            settings.proxy = Some(proxy_url);
        }
        Ok(())
    }

    async fn on_browser(&self, browser: &dyn BrowserHandle) -> Result<()> {
        if self.config.save_on_close && browser.engine() != Engine::Cdp {
            return Err(PluginError::other(
                "browser: `save_on_close` requires the pure CDP engine (`before_close` hook)",
            ));
        }
        let Some(ref store) = self.store else {
            return Ok(());
        };
        if let Some(snapshot) = store.load(self.config.ttl_secs)? {
            let _ = session::restore_cookies(browser, &snapshot.cookies).await?;
            let tabs_to_open = if self.config.restore_tabs {
                snapshot.tabs.clone()
            } else {
                Vec::new()
            };
            {
                let mut live = self.live();
                live.storage_init_script = snapshot.storage_init_script();
                live.storage = snapshot.storage;
                live.tabs = snapshot.tabs;
                live.identity = self.build_identity(Some(&snapshot.identity));
            }
            for url in tabs_to_open {
                let _ = browser.new_page(Some(&url)).await;
            }
        }
        Ok(())
    }

    async fn on_page_created(&self, page: &dyn PageHandle) -> Result<()> {
        let (script, identity) = {
            let live = self.live();
            (live.storage_init_script.clone(), live.identity.clone())
        };
        if let Some(src) = script {
            page.add_init_script(&src).await?;
        }
        if page.engine() == Engine::Cdp {
            if let Some(ref locale) = identity.locale {
                let _ = page
                    .send("Emulation.setLocaleOverride", json!({ "locale": locale }))
                    .await;
            }
            if let Some(ref tz) = identity.timezone {
                let _ = page
                    .send("Emulation.setTimezoneOverride", json!({ "timezoneId": tz }))
                    .await;
            }
            if let Some([lat, lon]) = identity.geolocation {
                let _ = page
                    .send(
                        "Emulation.setGeolocationOverride",
                        json!({ "latitude": lat, "longitude": lon, "accuracy": 100.0 }),
                    )
                    .await;
            }
            if let Some(ref ua) = identity.user_agent {
                let _ = page
                    .send("Network.setUserAgentOverride", json!({ "userAgent": ua }))
                    .await;
            }
        }
        Ok(())
    }

    async fn after_navigate(&self, page: &dyn PageHandle, outcome: &NavOutcome) -> Result<()> {
        self.record_tab(&outcome.url);
        if let Ok(Some((origin, st))) = flow::snapshot_page_storage(page).await {
            self.record_storage(origin, st);
        }
        Ok(())
    }

    async fn before_close(&self, browser: &dyn BrowserHandle) -> Result<()> {
        if self.config.save_on_close && self.store.is_some() {
            let _ = self.save_container(browser).await?;
        }
        Ok(())
    }
}
