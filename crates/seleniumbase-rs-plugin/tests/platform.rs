//! Metadata, capabilities, ordering, seals, strict sets and the registry.

use std::sync::Arc;

use seleniumbase_rs_plugin::{
    BrowserFamily, Capability, CapabilitySet, Category, Configurable, Descriptor, Engine, HostInfo,
    LaunchContext, LaunchSettings, Metadata, Phase, Plugin, PluginError, PluginSet, PluginSpec,
    RawKind, Registry, Result, Seals, WebRtcPolicy, async_trait,
};
use seleniumbase_rs_plugin_testing::block_on;

type Edit = fn(&mut LaunchSettings);

struct P {
    name: &'static str,
    meta: Option<Metadata>,
    edit: Edit,
    fresh: bool,
}

fn p(name: &'static str, meta: Option<Metadata>, edit: Edit) -> P {
    P {
        name,
        meta,
        edit,
        fresh: false,
    }
}

#[async_trait]
impl Plugin for P {
    fn name(&self) -> &str {
        self.name
    }
    fn metadata(&self) -> Metadata {
        self.meta.clone().unwrap_or_else(Metadata::legacy)
    }
    fn per_launch(&self) -> Option<Arc<dyn Plugin>> {
        self.fresh.then(|| {
            Arc::new(P {
                name: self.name,
                meta: Some(Metadata::new(Category::Core).version("fresh")),
                edit: self.edit,
                fresh: false,
            }) as Arc<dyn Plugin>
        })
    }
    async fn before_launch(&self, l: &mut LaunchSettings) -> Result<()> {
        (self.edit)(l);
        Ok(())
    }
}

fn nop(_: &mut LaunchSettings) {}

fn context() -> LaunchContext {
    LaunchContext {
        engine: Engine::Cdp,
        family: BrowserFamily::Chromium,
        headless: true,
        connecting: false,
    }
}

fn launch(set: &PluginSet) -> Result<LaunchSettings> {
    let mut settings = LaunchSettings::default();
    block_on(set.before_launch(&mut settings)).map(|()| settings)
}

#[test]
fn categories_order_plugins_and_edges_refine_them() {
    let set = PluginSet::new()
        .with(p("watch", Some(Metadata::new(Category::Testing)), nop))
        .unwrap()
        .with(p("shield", Some(Metadata::new(Category::Privacy)), nop))
        .unwrap()
        .with(p("env", Some(Metadata::new(Category::Environment)), nop))
        .unwrap()
        .with(p(
            "core",
            Some(Metadata::new(Category::Core).before("env")),
            nop,
        ))
        .unwrap();
    set.check(&context()).unwrap();
    assert_eq!(set.names(), ["core", "env", "shield", "watch"]);
    let set = PluginSet::new()
        .with(p(
            "a",
            Some(Metadata::new(Category::Core).phase(Phase::Last)),
            nop,
        ))
        .unwrap()
        .with(p("b", Some(Metadata::new(Category::Core)), nop))
        .unwrap();
    assert_eq!(set.names(), ["b", "a"]);
}

#[test]
fn requires_conflicts_and_cycles_stop_the_check() {
    let needs = PluginSet::new()
        .with(p(
            "a",
            Some(Metadata::new(Category::Core).requires("b")),
            nop,
        ))
        .unwrap();
    assert!(matches!(
        needs.check(&context()),
        Err(PluginError::MissingDependency { .. })
    ));
    let conflict = PluginSet::new()
        .with(p(
            "a",
            Some(Metadata::new(Category::Core).conflicts_with("b")),
            nop,
        ))
        .unwrap()
        .with(p("b", Some(Metadata::new(Category::Core)), nop))
        .unwrap();
    assert!(matches!(
        conflict.check(&context()),
        Err(PluginError::Conflict { .. })
    ));
    let cycle = PluginSet::new()
        .with(p(
            "a",
            Some(Metadata::new(Category::Core).requires("b")),
            nop,
        ))
        .unwrap()
        .with(p(
            "b",
            Some(Metadata::new(Category::Core).requires("a")),
            nop,
        ))
        .unwrap();
    assert!(matches!(
        cycle.check(&context()),
        Err(PluginError::Cycle(_))
    ));
}

#[test]
fn critical_capabilities_need_to_be_named() {
    let meta = || Metadata::new(Category::Core).capability(Capability::Raw(RawKind::Cdp));
    let plain = PluginSet::new().with(p("raw", Some(meta()), nop)).unwrap();
    assert!(matches!(
        plain.check(&context()),
        Err(PluginError::Capability { .. })
    ));
    let trusted = PluginSet::new()
        .with_trusted(
            p("raw", Some(meta()), nop),
            &[Capability::Raw(RawKind::Cdp)],
        )
        .unwrap();
    trusted.check(&context()).unwrap();
    let granted = PluginSet::new()
        .with_grants(p("raw", Some(meta()), nop), CapabilitySet::legacy())
        .unwrap();
    granted.check(&context()).unwrap();
}

#[test]
fn the_host_must_support_required_capabilities() {
    let set = PluginSet::new()
        .with(p(
            "net",
            Some(Metadata::new(Category::Core).capability(Capability::NetIntercept)),
            nop,
        ))
        .unwrap();
    set.check_with(&context(), &HostInfo::cdp()).unwrap();
    assert!(matches!(
        set.check_with(&context(), &HostInfo::webdriver(BrowserFamily::Chromium)),
        Err(PluginError::Unsupported { .. })
    ));
    assert!(matches!(
        set.check_with(&context(), &HostInfo::embedded()),
        Err(PluginError::Unsupported { .. })
    ));
}

#[test]
fn strict_sets_refuse_legacy_plugins() {
    let strict = PluginSet::strict().with(p("old", None, nop)).unwrap();
    assert!(matches!(
        strict.check(&context()),
        Err(PluginError::Undeclared(_))
    ));
    PluginSet::new()
        .with(p("old", None, nop))
        .unwrap()
        .check(&context())
        .unwrap();
}

#[test]
fn launch_changes_need_their_capability() {
    let meta = Metadata::new(Category::Environment).capability(Capability::LaunchArgs);
    let ok = PluginSet::new()
        .with(p("ok", Some(meta.clone()), |l| {
            l.args.push("--lang=de".into())
        }))
        .unwrap();
    assert_eq!(launch(&ok).unwrap().args, ["--lang=de"]);
    let proxy = PluginSet::new()
        .with(p("proxy", Some(meta), |l| {
            l.proxy = Some("http://x".into())
        }))
        .unwrap();
    assert!(matches!(
        launch(&proxy),
        Err(PluginError::Capability { .. })
    ));
}

#[test]
fn refused_switches_are_refused_for_every_plugin_unless_trusted() {
    let legacy = PluginSet::new()
        .with(p("old", None, |l| {
            l.args.push("--host-resolver-rules=MAP * 1.2.3.4".into());
        }))
        .unwrap();
    assert!(matches!(
        launch(&legacy),
        Err(PluginError::Capability { .. })
    ));
    let meta = || Metadata::new(Category::Core).capability(Capability::LaunchArgs);
    let features = PluginSet::new()
        .with(p("f", Some(meta()), |l| {
            l.disable_features.push("IsolateOrigins".into());
        }))
        .unwrap();
    assert!(matches!(
        launch(&features),
        Err(PluginError::Capability { .. })
    ));
    let trusted = PluginSet::new()
        .with_trusted(
            p("t", Some(meta()), |l| {
                l.args.push("--js-flags=--foo".into())
            }),
            &[Capability::Raw(RawKind::Switches)],
        )
        .unwrap();
    assert_eq!(launch(&trusted).unwrap().args, ["--js-flags=--foo"]);
}

#[test]
fn list_settings_only_grow() {
    let meta = || Metadata::new(Category::Core).capability(Capability::LaunchArgs);
    let set = PluginSet::new()
        .with(p("add", Some(meta()), |l| l.args.push("--lang=de".into())))
        .unwrap()
        .with(p("wipe", Some(meta()), |l| l.args.clear()))
        .unwrap();
    assert!(matches!(launch(&set), Err(PluginError::Capability { .. })));
}

#[test]
fn a_sealed_field_keeps_its_value() {
    let net = |seals| {
        Metadata::new(Category::Privacy)
            .capability(Capability::LaunchNetwork)
            .seal(seals)
    };
    let sealer = |name| {
        p(name, Some(net(Seals::WEBRTC)), |l| {
            l.webrtc_policy = Some(WebRtcPolicy::DisableNonProxiedUdp);
        })
    };
    let other = p("other", Some(net(Seals::empty())), |l| {
        l.webrtc_policy = Some(WebRtcPolicy::Default);
    });
    let conflicting = PluginSet::new()
        .with(sealer("a"))
        .unwrap()
        .with(other)
        .unwrap();
    assert!(matches!(
        launch(&conflicting),
        Err(PluginError::Sealed {
            field: "webrtc_policy",
            ..
        })
    ));
    let same = PluginSet::new()
        .with(sealer("a"))
        .unwrap()
        .with(sealer("b"))
        .unwrap();
    assert_eq!(
        launch(&same).unwrap().webrtc_policy,
        Some(WebRtcPolicy::DisableNonProxiedUdp)
    );
}

#[test]
fn for_launch_swaps_in_fresh_instances_and_keeps_grants() {
    let mut shared = p("pooled", Some(Metadata::new(Category::Core)), nop);
    shared.fresh = true;
    let set = PluginSet::new().with(shared).unwrap();
    let fresh = set.for_launch();
    assert_eq!(fresh.names(), ["pooled"]);
    assert_eq!(fresh.audit(), set.audit());
}

#[test]
fn the_audit_lists_capabilities_with_risk_and_grant() {
    let set = PluginSet::new()
        .with(p(
            "a",
            Some(Metadata::new(Category::Environment).capability(Capability::LaunchProxy)),
            nop,
        ))
        .unwrap();
    let rows = set.audit();
    assert_eq!(rows.len(), 1);
    assert!(rows[0].granted);
    assert_eq!(rows[0].risk, seleniumbase_rs_plugin::Risk::High);
}

struct Hello {
    greeting: String,
}

#[async_trait]
impl Plugin for Hello {
    fn name(&self) -> &str {
        "hello"
    }
    fn metadata(&self) -> Metadata {
        Self::describe()
    }
}

impl Configurable for Hello {
    const NAME: &'static str = "hello";
    fn describe() -> Metadata {
        Metadata::new(Category::Testing).summary("says hello")
    }
    fn configure(options: &serde_json::Value) -> Result<Self> {
        let greeting = match options.get("greeting") {
            None => "hi".to_owned(),
            Some(v) => v
                .as_str()
                .ok_or_else(|| PluginError::Config("greeting must be a string".into()))?
                .to_owned(),
        };
        Ok(Self { greeting })
    }
}

#[test]
fn the_registry_builds_strict_sets_from_specs() {
    let registry = Registry::new().with(Descriptor::of::<Hello>());
    assert_eq!(registry.names(), ["hello"]);
    assert_eq!(
        registry.get("hello").unwrap().metadata().summary,
        "says hello"
    );
    let set = registry
        .plugin_set(&[PluginSpec::new("hello").options(serde_json::json!({"greeting": "yo"}))])
        .unwrap();
    set.check(&context()).unwrap();
    assert_eq!(set.names(), ["hello"]);
    assert!(matches!(
        registry.plugin_set(&[PluginSpec::new("nope")]),
        Err(PluginError::Config(_))
    ));
    assert!(matches!(
        registry
            .plugin_set(&[PluginSpec::new("hello").options(serde_json::json!({"greeting": 1}))]),
        Err(PluginError::Config(_))
    ));
    assert_eq!(
        Hello::configure(&serde_json::Value::Null).unwrap().greeting,
        "hi"
    );
}
