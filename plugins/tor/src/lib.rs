//! Sends the browser's traffic through a local Tor daemon, so that sites do not
//! see the address of the person running the automation, and lets that person
//! test their own onion services.
//!
//! It protects the person who runs the automation. It is not a way around bans
//! or rate limits, and it has no call that asks Tor for a new identity.
//!
//! ```
//! use seleniumbase_rs_plugin::PluginSet;
//! use seleniumbase_rs_plugin_tor::{Isolation, Tor, TorConfig};
//!
//! let tor = Tor::new(TorConfig::new().isolation(Isolation::PerContext))?;
//! let plugins = PluginSet::strict().with(tor)?;
//! assert_eq!(plugins.names(), ["tor"]);
//! # Ok::<(), seleniumbase_rs_plugin::PluginError>(())
//! ```
//!
//! # What it needs
//!
//! A Tor daemon on this machine, with its SocksPort (`127.0.0.1:9050` unless
//! `socks` says otherwise). The plugin never installs, starts or stops Tor,
//! and it talks to loopback addresses only: a `socks` or `control` address that
//! is not loopback is a configuration error. It works with a browser that the
//! program starts, on the pure CDP engine, with a Chromium browser.
//!
//! # What it does
//!
//! In [`before_launch`](Plugin::before_launch), in this order:
//!
//! 1. It refuses the launch if a proxy is already set (`LaunchSettings::proxy`,
//!    or a `--proxy-*` or `--no-proxy-server` argument): remove it, or chain it
//!    in `torrc`. Nothing has changed yet.
//! 2. It checks Tor ([`health::check`]): something must answer as a SOCKS5
//!    proxy at `socks`, and with a `control` port and `require_bootstrapped`,
//!    Tor must report that it finished bootstrapping. A failure stops the
//!    launch before the browser starts, with a message that names the address.
//! 3. It starts a [`Forwarder`] on a free loopback port and sets the proxy to
//!    `socks5://127.0.0.1:<port>`. It adds the host-resolver rule
//!    `MAP * ^NOTFOUND , EXCLUDE 127.0.0.1 , EXCLUDE localhost`, turns QUIC
//!    off, sets the WebRTC policy `disable_non_proxied_udp` and the preference
//!    `net.network_prediction_options = 2`. It seals the proxy, the proxy of
//!    new contexts and the WebRTC policy, so no plugin that runs later can
//!    change them.
//!
//! The browser's names are sent to Tor as names (SOCKS5 address type 3), so
//! Tor resolves them, and so it reaches `.onion` services. The host-resolver
//! rule stops any lookup the browser starts by itself from using this
//! machine's resolver.
//!
//! # Isolation
//!
//! Chrome speaks SOCKS5 without authentication, and ignores a proxy URL with a
//! user name (it then goes direct: the plugin never builds one), so it cannot
//! ask Tor for circuits of its own. The forwarder does it: it passes every
//! connection to Tor with a random isolation parameter of its own, and Tor's
//! `IsolateSOCKSAuth` (on by default for a SocksPort) puts streams with
//! different parameters on different circuits.
//!
//! With `isolation = "per-context"` (the default) every browser context made
//! while the plugin runs gets a forwarder of its own, through
//! `Plugin::before_context` and `ContextSettings::proxy`, and the forwarder
//! stops when the context closes. The browser's default context and its other
//! tabs share the browser's forwarder. With `isolation = "browser"` the whole
//! browser shares one. At most [`Tor::MAX_CONTEXT_FORWARDERS`] contexts may be
//! alive at once.
//!
//! The forwarder serves CONNECT only (BIND and UDP ASSOCIATE get reply 7),
//! gives a connection ten seconds to finish its handshake, serves at most 256
//! connections at once, reads at most a few hundred bytes of handshake, and
//! never connects to the target itself: if Tor cannot be reached or refuses,
//! the browser gets a failure and nothing else happens.
//!
//! # Control port
//!
//! Optional, and used for one thing: to read `status/bootstrap-phase` before
//! the browser starts. `control_auth` is `{ cookie_path = "..." }`
//! (`SAFECOOKIE`: the control port proves that it knows the cookie before the
//! plugin proves the same, and the raw cookie is never sent) or
//! `{ password_env = "NAME" }` (`HASHEDPASSWORD`, the password is read from
//! that environment variable when it is needed). A password is never an option
//! value. The cookie file is the only file the plugin reads, and a plugin
//! configured with one declares `host.fs.read` for exactly that path.
//!
//! # Not done
//!
//! There is no new-identity call (`SIGNAL NEWNYM`): it invites evading rate
//! limits, and the control port is read-only here. `COOKIE` and `NULL` control
//! authentication are not supported. The plugin does not check the daemon's
//! `SocksPort` flags: per-context isolation relies on `IsolateSOCKSAuth`, which
//! is on unless the daemon turns it off with `NoIsolateSOCKSAuth`.
//!
//! The behaviour of Chrome that the design rests on was checked with Chrome
//! 156 against a fake SOCKS5 listener; see the README of this crate.
#![warn(missing_docs)]

mod config;
mod control;
pub mod forwarder;
pub mod health;
mod socks;

pub use config::{ControlAuth, Isolation, TorConfig};
pub use forwarder::{Forwarder, IsolationToken, Limits};

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use seleniumbase_rs_plugin::config::options;
use seleniumbase_rs_plugin::{
    Capability, Category, Configurable, ContextHandle, ContextId, ContextSettings, LaunchSettings,
    Metadata, NetScope, PathScope, Plugin, PluginError, Requirements, Result, Seals, WebRtcPolicy,
    async_trait,
};
use serde_json::json;
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};

/// The host-resolver rule that makes every name fail to resolve on this
/// machine, except the loopback names the browser needs for itself. Names go to
/// Tor through the SOCKS proxy, which resolves them remotely; this rule keeps
/// any lookup the browser starts by itself from reaching the local resolver.
const NO_LOCAL_DNS: &str = "MAP * ^NOTFOUND , EXCLUDE 127.0.0.1 , EXCLUDE localhost";

/// How long `before_context` waits for the context made before it to report in
/// (`on_context_created`) before it takes that context's forwarder back. Less
/// than the ten seconds a hook is given by default.
const ADMIT_WAIT: Duration = Duration::from_secs(5);

/// The tor plugin. See the [crate documentation](crate).
#[derive(Debug)]
pub struct Tor {
    config: TorConfig,
    /// Held from `before_context` to `on_context_created`, so that contexts
    /// are made one at a time and each forwarder reaches its own context.
    gate: Arc<AsyncMutex<()>>,
    /// The forwarders. The lock is never held across an `.await`.
    state: Mutex<State>,
}

/// The forwarders of one browser.
#[derive(Debug, Default)]
struct State {
    /// The forwarder the browser's `--proxy-server` points at.
    browser: Option<Forwarder>,
    /// The forwarder of each browser context.
    contexts: HashMap<ContextId, Forwarder>,
    /// The forwarder of the context that is being made, with the gate that
    /// keeps the next context from starting before this one is bound.
    in_flight: Option<InFlight>,
}

/// A context's forwarder before the context has an id.
#[derive(Debug)]
struct InFlight {
    forwarder: Forwarder,
    /// Dropped when the context reports in, which admits the next one.
    _gate: OwnedMutexGuard<()>,
}

impl Tor {
    /// The most browser contexts that may be alive at once with
    /// `isolation = "per-context"`: each has a forwarder with a listening
    /// socket, so the number is bounded.
    pub const MAX_CONTEXT_FORWARDERS: usize = 128;

    /// A plugin with these options.
    ///
    /// # Errors
    ///
    /// [`PluginError::Config`] when [`TorConfig::validate`] refuses them.
    pub fn new(config: TorConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self::checked(config))
    }

    fn checked(config: TorConfig) -> Self {
        Self {
            config,
            gate: Arc::default(),
            state: Mutex::default(),
        }
    }

    /// The options.
    #[must_use]
    pub fn config(&self) -> &TorConfig {
        &self.config
    }

    /// How many forwarders are alive: the browser's, one for each browser
    /// context, and the one of a context that is being made.
    #[must_use]
    pub fn live_forwarders(&self) -> usize {
        let state = self.state();
        usize::from(state.browser.is_some())
            + state.contexts.len()
            + usize::from(state.in_flight.is_some())
    }

    /// A forwarder to Tor's SocksPort with an isolation token of its own.
    async fn start_forwarder(&self) -> Result<Forwarder> {
        let token = IsolationToken::random()
            .map_err(|error| PluginError::other(format!("tor: {error}")))?;
        Forwarder::start(self.config.socks, token, Limits::default())
            .await
            .map_err(|error| {
                PluginError::other(format!(
                    "tor: cannot start the local SOCKS forwarder on a loopback port: {error}"
                ))
            })
    }

    /// Takes the gate that keeps contexts from being made at the same time.
    ///
    /// A context that never reported in (the browser failed to make it) would
    /// hold the gate for ever, so after [`ADMIT_WAIT`] what it left behind is
    /// dropped, which frees the gate.
    async fn admit(&self) -> OwnedMutexGuard<()> {
        if let Ok(gate) =
            tokio::time::timeout(ADMIT_WAIT, Arc::clone(&self.gate).lock_owned()).await
        {
            return gate;
        }
        let stale = self.state().in_flight.take();
        drop(stale);
        Arc::clone(&self.gate).lock_owned().await
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Whether a launch argument sets the browser's proxy. A second proxy would
/// leave it unclear which one the browser uses, so tor refuses the launch.
fn sets_a_proxy(arg: &str) -> bool {
    arg.starts_with("--proxy-") || arg.starts_with("--no-proxy-server")
}

impl Configurable for Tor {
    const NAME: &'static str = "tor";

    fn describe() -> Metadata {
        use Capability::{Contexts, HostFsRead, HostNet, LaunchNetwork, LaunchPrefs, LaunchProxy};
        Metadata::new(Category::Privacy)
            .version(env!("CARGO_PKG_VERSION"))
            .summary(
                "Routes the browser through a local Tor daemon, with circuits of their own for \
                 each browser context; names are resolved by Tor, never on this machine",
            )
            .capabilities([
                LaunchProxy,
                LaunchNetwork,
                LaunchPrefs,
                Contexts,
                HostNet(NetScope::Loopback),
            ])
            // Read only when a control port is configured with a cookie file;
            // `metadata()` of a configured plugin names that file.
            .optional(HostFsRead(PathScope::Declared(Vec::new())))
            .seal(Seals::PROXY | Seals::CONTEXT_PROXY | Seals::WEBRTC)
    }

    fn configure(value: &serde_json::Value) -> Result<Self> {
        Self::new(options::<TorConfig>(Self::NAME, value)?)
    }
}

#[async_trait]
impl Plugin for Tor {
    fn name(&self) -> &str {
        Self::NAME
    }

    fn requirements(&self) -> Requirements {
        Requirements::CHROMIUM_ONLY | Requirements::LAUNCH_ONLY
    }

    fn metadata(&self) -> Metadata {
        let mut metadata = Self::describe();
        if self.config.require_bootstrapped
            && self.config.control.is_some()
            && let Some(path) = self
                .config
                .control_auth
                .as_ref()
                .and_then(|auth| auth.cookie_path.clone())
        {
            metadata
                .capabilities
                .insert(Capability::HostFsRead(PathScope::Declared(vec![path])));
        }
        metadata
    }

    /// Refuses a launch that already has a proxy, checks that Tor is there,
    /// starts the browser's forwarder and points the browser at it.
    ///
    /// Everything that can fail is checked before the launch settings change,
    /// so a refusal leaves them as they were and no browser starts.
    async fn before_launch(&self, launch: &mut LaunchSettings) -> Result<()> {
        if launch.proxy.is_some() {
            return Err(PluginError::other(
                "tor: a proxy is already set; remove it (Python parity: --proxy), or chain it in \
                 torrc",
            ));
        }
        if let Some(arg) = launch.args.iter().find(|arg| sets_a_proxy(arg)) {
            return Err(PluginError::other(format!(
                "tor: the launch arguments set a proxy (`{arg}`); remove it, or chain it in torrc"
            )));
        }
        health::check(&self.config).await?;
        let forwarder = self.start_forwarder().await?;

        launch.proxy = Some(forwarder.proxy_url());
        if !launch
            .host_resolver_rules
            .iter()
            .any(|rule| rule == NO_LOCAL_DNS)
        {
            launch.host_resolver_rules.push(NO_LOCAL_DNS.to_owned());
        }
        launch.disable_quic = true;
        launch.webrtc_policy = Some(WebRtcPolicy::DisableNonProxiedUdp);
        // 2 is NetworkPredictionOptions::kDisabled: no preconnect or prefetch
        // that would start a connection the user did not ask for.
        launch
            .prefs
            .insert("net.network_prediction_options".to_owned(), json!(2));

        let replaced = self.state().browser.replace(forwarder);
        drop(replaced);
        Ok(())
    }

    /// With `isolation = "per-context"`, starts a forwarder for the context
    /// about to be made and gives the context its address as its proxy.
    ///
    /// Contexts are made one at a time: this waits until the context made
    /// before it has reported in, so that each forwarder reaches its own
    /// context. If that context never does (the browser failed to make it),
    /// the wait ends after a few seconds and its forwarder is dropped.
    async fn before_context(&self, settings: &mut ContextSettings) -> Result<()> {
        if self.config.isolation != Isolation::PerContext {
            return Ok(());
        }
        if settings.proxy.is_some() {
            return Err(PluginError::other(
                "tor: a context may not set its own proxy; the plugin gives each context a \
                 forwarder of its own (isolation = \"browser\" leaves contexts on the browser's)",
            ));
        }
        let gate = self.admit().await;
        if self.state().contexts.len() >= Self::MAX_CONTEXT_FORWARDERS {
            return Err(PluginError::other(format!(
                "tor: too many live browser contexts ({}); close some before making more",
                Self::MAX_CONTEXT_FORWARDERS
            )));
        }
        let forwarder = self.start_forwarder().await?;
        settings.proxy = Some(forwarder.proxy_url());
        self.state().in_flight = Some(InFlight {
            forwarder,
            _gate: gate,
        });
        Ok(())
    }

    /// Binds the forwarder that `before_context` started to the context that
    /// now exists, and lets the next context start.
    async fn on_context_created(&self, context: &dyn ContextHandle) -> Result<()> {
        let mut state = self.state();
        if let Some(InFlight { forwarder, _gate }) = state.in_flight.take() {
            state.contexts.insert(context.id().clone(), forwarder);
        }
        Ok(())
    }

    /// Stops the forwarder of the context that is gone.
    async fn on_context_closed(&self, id: &ContextId) -> Result<()> {
        let forwarder = self.state().contexts.remove(id);
        drop(forwarder);
        Ok(())
    }

    /// Stops every forwarder: the listeners close and so do the tunnels.
    async fn on_close(&self) -> Result<()> {
        let state = std::mem::take(&mut *self.state());
        drop(state);
        Ok(())
    }

    fn per_launch(&self) -> Option<Arc<dyn Plugin>> {
        Some(Arc::new(Self::checked(self.config.clone())))
    }
}

/// Runs a future to completion on a small runtime, for the unit tests.
#[cfg(test)]
pub(crate) fn run<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime")
        .block_on(future)
}
