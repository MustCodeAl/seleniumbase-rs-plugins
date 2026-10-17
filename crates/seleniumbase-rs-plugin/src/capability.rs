//! Capabilities: what a plugin may do, as a scoped enum with stable strings.

use std::borrow::Cow;
use std::collections::BTreeSet;
use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;

/// Which sites a page script may run on.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum HostScope {
    /// Only these hosts and their subdomains.
    Hosts(Vec<String>),
    /// Every site.
    Everywhere,
}

/// Which network peers a plugin may talk to from the host.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum NetScope {
    /// Loopback addresses only.
    Loopback,
    /// Any address.
    Any,
}

/// Which files a plugin may use.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PathScope {
    /// A temporary folder owned by the plugin.
    Temp,
    /// The run's output folder.
    RunOutput,
    /// These paths.
    Declared(Vec<PathBuf>),
}

/// The kind of raw access a plugin has.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RawKind {
    /// Any Chrome DevTools Protocol command.
    Cdp,
    /// Any browser switch that is not refused for everyone.
    Switches,
}

/// How dangerous a capability is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Risk {
    /// Harmless to the user's data and network.
    Low,
    /// Changes browser behaviour in the plugin's own area.
    Medium,
    /// Can read or redirect user data or the network.
    High,
    /// Never granted without being named, and never to WASM.
    Critical,
}

/// Whether the host stops a plugin that goes beyond a capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Enforcement {
    /// The API surface or a sandbox stops it.
    Enforced,
    /// The plugin promises; a native Rust plugin can still use `std`.
    DeclaredOnly,
}

/// One thing a plugin may do.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Capability {
    /// Add browser switches (the refused list applies).
    LaunchArgs,
    /// Set browser preferences.
    LaunchPrefs,
    /// Change headless mode.
    LaunchHeadless,
    /// Change network settings: host rules, WebRTC policy, QUIC.
    LaunchNetwork,
    /// Set the proxy.
    LaunchProxy,
    /// Load extensions.
    LaunchExtensions,
    /// Use the profile folder.
    LaunchProfile,
    /// Add scripts to pages.
    PageScript(HostScope),
    /// Evaluate JavaScript in pages.
    PageEvaluate,
    /// Navigate pages.
    PageNavigate,
    /// Use one CDP domain.
    Cdp(Cow<'static, str>),
    /// Observe requests and responses.
    NetObserve,
    /// See cookies and authorization headers.
    NetSensitive,
    /// Read response bodies.
    NetBodies,
    /// Intercept and change requests.
    NetIntercept,
    /// Answer requests without the network.
    NetFulfill,
    /// Read cookies.
    CookiesRead,
    /// Write cookies.
    CookiesWrite,
    /// Clear storage.
    StorageClear,
    /// Create browser contexts.
    Contexts,
    /// Hook test start and end.
    TestHooks,
    /// Run as a task.
    Task,
    /// Write files to the run's output.
    ArtifactsWrite,
    /// Host network access.
    HostNet(NetScope),
    /// Host file reads.
    HostFsRead(PathScope),
    /// Host file writes.
    HostFsWrite(PathScope),
    /// Start host processes.
    HostProcess,
    /// Read the clock.
    Clock,
    /// Use randomness.
    Random,
    /// Keep state, optionally across runs.
    State {
        /// Whether the state outlives the run.
        persist: bool,
    },
    /// Raw access.
    Raw(RawKind),
}

impl Capability {
    /// How dangerous the capability is.
    #[must_use]
    pub fn risk(&self) -> Risk {
        use Capability as C;
        match self {
            C::LaunchArgs
            | C::NetObserve
            | C::TestHooks
            | C::Clock
            | C::Random
            | C::State { .. }
            | C::PageScript(HostScope::Hosts(_)) => Risk::Low,
            C::PageScript(HostScope::Everywhere)
            | C::CookiesRead
            | C::CookiesWrite
            | C::NetSensitive
            | C::NetBodies
            | C::NetFulfill
            | C::LaunchProxy
            | C::LaunchNetwork
            | C::LaunchExtensions
            | C::HostNet(_)
            | C::HostFsRead(_)
            | C::HostFsWrite(_) => Risk::High,
            C::Raw(_) | C::HostProcess => Risk::Critical,
            C::Cdp(domain) if matches!(domain.as_ref(), "Target" | "Browser") => Risk::Critical,
            _ => Risk::Medium,
        }
    }

    /// Whether a WASM module or manifest may be granted it.
    #[must_use]
    pub fn wasm_grantable(&self) -> bool {
        self.risk() != Risk::Critical
            && !matches!(
                self,
                Self::HostProcess
                    | Self::HostFsRead(_)
                    | Self::HostFsWrite(_)
                    | Self::HostNet(_)
                    | Self::LaunchExtensions
                    | Self::LaunchProfile
            )
    }

    /// Whether the host enforces it for a plugin of this kind. Host I/O is
    /// enforced only for WASM; for native Rust it is declared.
    #[must_use]
    pub fn enforcement(&self, wasm: bool) -> Enforcement {
        match self {
            Self::HostNet(_) | Self::HostFsRead(_) | Self::HostFsWrite(_) | Self::HostProcess
                if !wasm =>
            {
                Enforcement::DeclaredOnly
            }
            _ => Enforcement::Enforced,
        }
    }

    /// Whether holding `self` allows `wanted`.
    #[must_use]
    pub fn covers(&self, wanted: &Self) -> bool {
        use Capability as C;
        match (self, wanted) {
            (C::PageScript(HostScope::Everywhere), C::PageScript(_)) => true,
            (C::PageScript(HostScope::Hosts(have)), C::PageScript(HostScope::Hosts(want))) => {
                want.iter().all(|h| have.contains(h))
            }
            (C::HostNet(NetScope::Any), C::HostNet(_)) => true,
            (C::Raw(RawKind::Cdp), C::Cdp(_)) => true,
            (C::HostFsRead(a), C::HostFsRead(b)) | (C::HostFsWrite(a), C::HostFsWrite(b)) => {
                a == b
                    || matches!((a, b), (PathScope::Declared(have), PathScope::Declared(want))
                        if want.iter().all(|p| have.contains(p)))
            }
            _ => self == wanted,
        }
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Capability as C;
        match self {
            C::LaunchArgs => f.write_str("launch.args"),
            C::LaunchPrefs => f.write_str("launch.prefs"),
            C::LaunchHeadless => f.write_str("launch.headless"),
            C::LaunchNetwork => f.write_str("launch.network"),
            C::LaunchProxy => f.write_str("launch.proxy"),
            C::LaunchExtensions => f.write_str("launch.extensions"),
            C::LaunchProfile => f.write_str("launch.profile"),
            C::PageScript(HostScope::Everywhere) => f.write_str("page.script:*"),
            C::PageScript(HostScope::Hosts(h)) => write!(f, "page.script:{}", h.join(",")),
            C::PageEvaluate => f.write_str("page.evaluate"),
            C::PageNavigate => f.write_str("page.navigate"),
            C::Cdp(d) => write!(f, "cdp:{d}"),
            C::NetObserve => f.write_str("net.observe"),
            C::NetSensitive => f.write_str("net.sensitive"),
            C::NetBodies => f.write_str("net.bodies"),
            C::NetIntercept => f.write_str("net.intercept"),
            C::NetFulfill => f.write_str("net.fulfill"),
            C::CookiesRead => f.write_str("cookies.read"),
            C::CookiesWrite => f.write_str("cookies.write"),
            C::StorageClear => f.write_str("storage.clear"),
            C::Contexts => f.write_str("contexts"),
            C::TestHooks => f.write_str("test.hooks"),
            C::Task => f.write_str("task"),
            C::ArtifactsWrite => f.write_str("artifacts.write"),
            C::HostNet(NetScope::Loopback) => f.write_str("host.net:loopback"),
            C::HostNet(NetScope::Any) => f.write_str("host.net:any"),
            C::HostFsRead(s) => write!(f, "host.fs.read:{}", path_scope(s)),
            C::HostFsWrite(s) => write!(f, "host.fs.write:{}", path_scope(s)),
            C::HostProcess => f.write_str("host.process"),
            C::Clock => f.write_str("clock"),
            C::Random => f.write_str("random"),
            C::State { persist: false } => f.write_str("state"),
            C::State { persist: true } => f.write_str("state:persist"),
            C::Raw(RawKind::Cdp) => f.write_str("raw:cdp"),
            C::Raw(RawKind::Switches) => f.write_str("raw:switches"),
        }
    }
}

fn path_scope(scope: &PathScope) -> String {
    match scope {
        PathScope::Temp => "temp".to_owned(),
        PathScope::RunOutput => "run-output".to_owned(),
        PathScope::Declared(paths) => paths
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(","),
    }
}

/// A capability string that does not parse.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("unknown capability `{0}`")]
pub struct ParseCapabilityError(pub String);

impl FromStr for Capability {
    type Err = ParseCapabilityError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        use Capability as C;
        let list = |v: &str| -> Vec<String> {
            v.split(',')
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect()
        };
        let scope = |v: &str| match v {
            "temp" => PathScope::Temp,
            "run-output" => PathScope::RunOutput,
            other => PathScope::Declared(list(other).into_iter().map(PathBuf::from).collect()),
        };
        let (head, arg) = match text.split_once(':') {
            Some((h, a)) => (h, Some(a)),
            None => (text, None),
        };
        Ok(match (head, arg) {
            ("launch.args", None) => C::LaunchArgs,
            ("launch.prefs", None) => C::LaunchPrefs,
            ("launch.headless", None) => C::LaunchHeadless,
            ("launch.network", None) => C::LaunchNetwork,
            ("launch.proxy", None) => C::LaunchProxy,
            ("launch.extensions", None) => C::LaunchExtensions,
            ("launch.profile", None) => C::LaunchProfile,
            ("page.script", Some("*")) => C::PageScript(HostScope::Everywhere),
            ("page.script", Some(hosts)) if !hosts.is_empty() => {
                C::PageScript(HostScope::Hosts(list(hosts)))
            }
            ("page.evaluate", None) => C::PageEvaluate,
            ("page.navigate", None) => C::PageNavigate,
            ("cdp", Some(d)) if !d.is_empty() => C::Cdp(Cow::Owned(d.to_owned())),
            ("net.observe", None) => C::NetObserve,
            ("net.sensitive", None) => C::NetSensitive,
            ("net.bodies", None) => C::NetBodies,
            ("net.intercept", None) => C::NetIntercept,
            ("net.fulfill", None) => C::NetFulfill,
            ("cookies.read", None) => C::CookiesRead,
            ("cookies.write", None) => C::CookiesWrite,
            ("storage.clear", None) => C::StorageClear,
            ("contexts", None) => C::Contexts,
            ("test.hooks", None) => C::TestHooks,
            ("task", None) => C::Task,
            ("artifacts.write", None) => C::ArtifactsWrite,
            ("host.net", Some("loopback")) => C::HostNet(NetScope::Loopback),
            ("host.net", Some("any")) => C::HostNet(NetScope::Any),
            ("host.fs.read", Some(s)) if !s.is_empty() => C::HostFsRead(scope(s)),
            ("host.fs.write", Some(s)) if !s.is_empty() => C::HostFsWrite(scope(s)),
            ("host.process", None) => C::HostProcess,
            ("clock", None) => C::Clock,
            ("random", None) => C::Random,
            ("state", None) => C::State { persist: false },
            ("state", Some("persist")) => C::State { persist: true },
            ("raw", Some("cdp")) => C::Raw(RawKind::Cdp),
            ("raw", Some("switches")) => C::Raw(RawKind::Switches),
            _ => return Err(ParseCapabilityError(text.to_owned())),
        })
    }
}

/// A set of capabilities.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CapabilitySet(BTreeSet<Capability>);

impl CapabilitySet {
    /// The empty set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// What a plugin that declares nothing is treated as having: today's
    /// behaviour, `raw:cdp` included.
    #[must_use]
    pub fn legacy() -> Self {
        [
            Capability::LaunchArgs,
            Capability::LaunchPrefs,
            Capability::LaunchHeadless,
            Capability::LaunchProxy,
            Capability::LaunchExtensions,
            Capability::PageScript(HostScope::Everywhere),
            Capability::PageEvaluate,
            Capability::Raw(RawKind::Cdp),
        ]
        .into_iter()
        .collect()
    }

    /// Adds a capability.
    pub fn insert(&mut self, capability: Capability) {
        self.0.insert(capability);
    }

    /// Whether some member allows `wanted`.
    #[must_use]
    pub fn covers(&self, wanted: &Capability) -> bool {
        self.0.iter().any(|have| have.covers(wanted))
    }

    /// The members, in order.
    pub fn iter(&self) -> impl Iterator<Item = &Capability> {
        self.0.iter()
    }

    /// Whether the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The union of two sets.
    #[must_use]
    pub fn union(&self, other: &Self) -> Self {
        Self(self.0.union(&other.0).cloned().collect())
    }

    /// The members that are not [`Risk::Critical`].
    #[must_use]
    pub fn without_critical(&self) -> Self {
        Self(
            self.0
                .iter()
                .filter(|c| c.risk() != Risk::Critical)
                .cloned()
                .collect(),
        )
    }
}

impl FromIterator<Capability> for CapabilitySet {
    fn from_iter<I: IntoIterator<Item = Capability>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strings_round_trip() {
        for text in [
            "launch.args",
            "page.script:*",
            "page.script:example.com,example.org",
            "cdp:Network",
            "net.bodies",
            "host.net:loopback",
            "host.fs.write:temp",
            "state:persist",
            "raw:cdp",
            "raw:switches",
        ] {
            let parsed: Capability = text.parse().unwrap();
            assert_eq!(parsed.to_string(), text);
        }
        assert!("nonsense".parse::<Capability>().is_err());
        assert!("page.script:".parse::<Capability>().is_err());
    }

    #[test]
    fn risk_levels_follow_the_adr() {
        assert_eq!(Capability::LaunchArgs.risk(), Risk::Low);
        assert_eq!(Capability::LaunchPrefs.risk(), Risk::Medium);
        assert_eq!(Capability::LaunchProxy.risk(), Risk::High);
        assert_eq!(Capability::Raw(RawKind::Cdp).risk(), Risk::Critical);
        assert_eq!(Capability::Cdp("Target".into()).risk(), Risk::Critical);
        assert_eq!(Capability::Cdp("Network".into()).risk(), Risk::Medium);
        assert!(!Capability::HostProcess.wasm_grantable());
        assert!(Capability::NetObserve.wasm_grantable());
        assert_eq!(
            Capability::HostNet(NetScope::Any).enforcement(false),
            Enforcement::DeclaredOnly
        );
        assert_eq!(
            Capability::HostNet(NetScope::Any).enforcement(true),
            Enforcement::Enforced
        );
    }

    #[test]
    fn scopes_cover_narrower_scopes() {
        let wide: CapabilitySet = [Capability::PageScript(HostScope::Everywhere)]
            .into_iter()
            .collect();
        assert!(wide.covers(&"page.script:a.com".parse().unwrap()));
        let narrow: CapabilitySet = ["page.script:a.com".parse().unwrap()].into_iter().collect();
        assert!(!narrow.covers(&"page.script:*".parse().unwrap()));
        assert!(narrow.covers(&"page.script:a.com".parse().unwrap()));
        assert!(CapabilitySet::legacy().covers(&Capability::Cdp("Page".into())));
    }
}
