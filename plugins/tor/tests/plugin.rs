//! The plugin's hooks, driven through a `PluginSet` (so the set's capability
//! and seal checks apply) against a fake Tor SocksPort.

mod support;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use seleniumbase_rs_plugin::{
    BrowserHandle, Capability, Category, Configurable, ContextId, ContextSettings, LaunchSettings,
    Metadata, PathScope, Plugin, PluginError, PluginSet, Requirements, Result, Seals, WebRtcPolicy,
    async_trait,
};
use seleniumbase_rs_plugin_testing::RecordingBrowser;
use seleniumbase_rs_plugin_tor::{ControlAuth, Isolation, Tor, TorConfig};
use serde_json::json;
use support::{
    Answer, FakeSocksUpstream, dead_address, open, read_n, request_name, run, run_paused,
};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

const NO_LOCAL_DNS: &str = "MAP * ^NOTFOUND , EXCLUDE 127.0.0.1 , EXCLUDE localhost";

fn tor_at(socks: SocketAddr) -> Tor {
    Tor::new(TorConfig::new().socks(socks)).expect("valid options")
}

/// The plugin as the set shares it, while the test keeps its own handle to ask
/// how many forwarders are alive.
fn shared(tor: &Arc<Tor>) -> Arc<dyn Plugin> {
    Arc::clone(tor) as Arc<dyn Plugin>
}

fn proxy_address(url: &str) -> SocketAddr {
    url.strip_prefix("socks5://")
        .unwrap_or_else(|| panic!("not a socks5 URL: {url}"))
        .parse()
        .unwrap_or_else(|error| panic!("no address in {url}: {error}"))
}

async fn launched(plugins: &PluginSet) -> LaunchSettings {
    let mut launch = LaunchSettings::default();
    plugins
        .before_launch(&mut launch)
        .await
        .expect("the launch settings");
    launch
}

async fn is_listening(address: SocketAddr) -> bool {
    TcpStream::connect(address).await.is_ok()
}

async fn wait_until_closed(address: SocketAddr) {
    for _ in 0..300 {
        if !is_listening(address).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("{address} is still listening");
}

/// A CONNECT to a name through the forwarder at `proxy`.
async fn connect_through(proxy: SocketAddr, host: &str) {
    let mut client = open(proxy).await;
    client.write_all(&request_name(host, 80)).await.unwrap();
    assert_eq!(read_n(&mut client, 10).await[1], 0, "the tunnel to {host}");
}

/// What the host does to make a context: `before_context`, the browser makes
/// it (this takes `pause`), `on_context_created`.
async fn make_context(
    plugins: &PluginSet,
    browser: &RecordingBrowser,
    pause: Duration,
) -> Result<(ContextId, Option<String>)> {
    let mut settings = ContextSettings::new();
    plugins.before_context(&mut settings).await?;
    tokio::time::sleep(pause).await;
    let context = browser.new_context(settings.clone()).await?;
    plugins.on_context_created(&*context).await?;
    Ok((context.id().clone(), settings.proxy))
}

/// The passwords the fake Tor was sent, one for each CONNECT, in order.
fn passwords(upstream: &FakeSocksUpstream) -> Vec<Vec<u8>> {
    upstream
        .seen()
        .into_iter()
        .filter(|seen| !seen.request.is_empty())
        .map(|seen| seen.auth)
        .collect()
}

#[test]
fn the_plugin_declares_what_the_design_table_says() {
    let metadata = Tor::describe();
    assert_eq!(metadata.category, Some(Category::Privacy));
    assert_eq!(metadata.version, env!("CARGO_PKG_VERSION"));
    assert!(!metadata.summary.is_empty());
    let mut declared: Vec<String> = metadata
        .capabilities
        .iter()
        .map(ToString::to_string)
        .collect();
    declared.sort();
    assert_eq!(
        declared,
        [
            "contexts",
            "host.net:loopback",
            "launch.network",
            "launch.prefs",
            "launch.proxy"
        ]
    );
    assert!(
        metadata
            .optional
            .iter()
            .any(|capability| matches!(capability, Capability::HostFsRead(_))),
        "the cookie file is an optional capability"
    );
    for seal in [Seals::PROXY, Seals::CONTEXT_PROXY, Seals::WEBRTC] {
        assert!(metadata.seals.contains(seal));
    }
    assert!(!metadata.seals.contains(Seals::HEADLESS));

    let tor = Tor::new(TorConfig::new()).unwrap();
    assert_eq!(tor.name(), "tor");
    let requirements = tor.requirements();
    assert!(requirements.contains(Requirements::CHROMIUM_ONLY));
    assert!(requirements.contains(Requirements::LAUNCH_ONLY));
    assert!(!requirements.contains(Requirements::HEADFUL));
}

#[test]
fn a_cookie_file_makes_the_plugin_declare_that_one_file() {
    let path = std::path::PathBuf::from("/run/tor/control.authcookie");
    let config = TorConfig::new().control(
        "127.0.0.1:9051".parse().unwrap(),
        ControlAuth::cookie(&path),
    );
    let with_cookie = Tor::new(config.clone()).unwrap().metadata();
    assert!(
        with_cookie
            .capabilities
            .covers(&Capability::HostFsRead(PathScope::Declared(vec![
                path.clone()
            ])))
    );
    assert!(
        !with_cookie
            .capabilities
            .covers(&Capability::HostFsRead(PathScope::Declared(vec![
                "/etc/shadow".into()
            ]))),
        "only that file"
    );
    // Nothing is read without `require_bootstrapped`, so nothing is declared.
    let without = Tor::new(config.require_bootstrapped(false))
        .unwrap()
        .metadata();
    assert!(
        !without
            .capabilities
            .iter()
            .any(|capability| matches!(capability, Capability::HostFsRead(_)))
    );
    // A password needs no file.
    let by_password = Tor::new(TorConfig::new().control(
        "127.0.0.1:9051".parse().unwrap(),
        ControlAuth::password_env("TOR_CONTROL_PASSWORD"),
    ))
    .unwrap()
    .metadata();
    assert!(
        !by_password
            .capabilities
            .iter()
            .any(|capability| matches!(capability, Capability::HostFsRead(_)))
    );
}

#[test]
fn configure_reads_the_options_and_refuses_unknown_and_invalid_ones() {
    let tor = Tor::configure(&json!({ "socks": "127.0.0.1:9150", "isolation": "browser" }))
        .expect("valid options");
    assert_eq!(tor.config().socks, "127.0.0.1:9150".parse().unwrap());
    assert_eq!(tor.config().isolation, Isolation::Browser);
    assert_eq!(
        Tor::configure(&serde_json::Value::Null).unwrap().config(),
        &TorConfig::default()
    );
    let error = Tor::configure(&json!({ "sock": "127.0.0.1:9150" })).unwrap_err();
    assert_eq!(
        error.to_string(),
        "plugin configuration: tor: unknown option `sock`"
    );
    assert!(matches!(
        Tor::configure(&json!({ "socks": "8.8.8.8:9050" })),
        Err(PluginError::Config(_))
    ));
    assert!(Tor::new(TorConfig::new().socks("0.0.0.0:9050".parse().unwrap())).is_err());
}

#[test]
fn before_launch_points_the_browser_at_a_forwarder_and_shuts_local_dns_off() {
    run(async {
        let upstream = FakeSocksUpstream::start(Answer::Succeed).await;
        let plugins = PluginSet::strict().with(tor_at(upstream.addr())).unwrap();
        let launch = launched(&plugins).await;

        let proxy = launch.proxy.clone().expect("a proxy");
        assert!(proxy.starts_with("socks5://127.0.0.1:"), "{proxy}");
        assert!(
            !proxy.contains('@'),
            "Chrome ignores a proxy URL with credentials and goes direct: {proxy}"
        );
        assert_eq!(launch.host_resolver_rules, [NO_LOCAL_DNS]);
        assert!(launch.disable_quic);
        assert_eq!(
            launch.webrtc_policy,
            Some(WebRtcPolicy::DisableNonProxiedUdp)
        );
        assert_eq!(launch.prefs.len(), 1);
        assert_eq!(
            launch.prefs.get("net.network_prediction_options"),
            Some(&json!(2))
        );
        assert!(launch.args.is_empty());
        assert!(launch.extensions.is_empty());
        assert!(launch.enable_features.is_empty() && launch.disable_features.is_empty());

        // End to end: the name goes through the real forwarder to the fake Tor.
        connect_through(proxy_address(&proxy), "example.onion").await;
        let seen = upstream.seen();
        let probe = &seen[0];
        assert_eq!(probe.greeting, [5, 1, 0], "the health check only greets");
        let connect = seen
            .iter()
            .find(|seen| !seen.request.is_empty())
            .expect("a CONNECT reached the fake Tor");
        assert_eq!(
            connect.request,
            [&[5u8, 1, 0, 3, 13][..], b"example.onion", &[0, 80][..]].concat()
        );
    });
}

#[test]
fn a_resolver_rule_another_plugin_added_is_kept_and_ours_follows_it() {
    run(async {
        let upstream = FakeSocksUpstream::start(Answer::Succeed).await;
        let tor = tor_at(upstream.addr());
        let mut launch = LaunchSettings::default();
        launch
            .host_resolver_rules
            .push("MAP ads.example ^NOTFOUND".to_owned());
        tor.before_launch(&mut launch).await.unwrap();
        tor.before_launch(&mut launch)
            .await
            .expect_err("a proxy is set now");
        assert_eq!(
            launch.host_resolver_rules,
            ["MAP ads.example ^NOTFOUND", NO_LOCAL_DNS]
        );
    });
}

#[test]
fn a_proxy_that_is_already_set_is_refused_and_nothing_changes() {
    run(async {
        let upstream = FakeSocksUpstream::start(Answer::Succeed).await;
        let plugins = PluginSet::strict().with(tor_at(upstream.addr())).unwrap();
        let mut launch = LaunchSettings::default();
        launch.proxy = Some("http://127.0.0.1:8080".to_owned());
        let before = launch.clone();
        let error = plugins.before_launch(&mut launch).await.unwrap_err();
        assert!(
            error.to_string().contains(
                "tor: a proxy is already set; remove it (Python parity: --proxy), or chain it in \
                 torrc"
            ),
            "{error}"
        );
        assert_eq!(launch, before);
        assert!(upstream.seen().is_empty(), "refused before Tor was probed");
    });
}

#[test]
fn a_proxy_set_through_the_arguments_is_refused_too() {
    run(async {
        let upstream = FakeSocksUpstream::start(Answer::Succeed).await;
        let tor = tor_at(upstream.addr());
        for arg in [
            "--proxy-server=http://127.0.0.1:8080",
            "--proxy-pac-url=http://x/pac",
            "--no-proxy-server",
            "--proxy-auto-detect",
        ] {
            let mut launch = LaunchSettings::default();
            launch.args.push(arg.to_owned());
            let before = launch.clone();
            let error = tor.before_launch(&mut launch).await.unwrap_err();
            assert!(error.to_string().contains(arg), "{error}");
            assert_eq!(launch, before, "{arg}");
        }
        let mut harmless = LaunchSettings::default();
        harmless.args.push("--lang=de".to_owned());
        tor.before_launch(&mut harmless)
            .await
            .expect("other switches are fine");
    });
}

#[test]
fn without_a_tor_daemon_the_launch_fails_closed_and_changes_nothing() {
    run(async {
        let dead = dead_address();
        let plugins = PluginSet::strict().with(tor_at(dead)).unwrap();
        let mut launch = LaunchSettings::default();
        let error = plugins.before_launch(&mut launch).await.unwrap_err();
        let text = error.to_string();
        assert!(
            text.contains(&format!("tor: no SOCKS listener at {dead}")),
            "{text}"
        );
        assert!(text.contains("sbrs never installs or starts Tor"), "{text}");
        assert_eq!(launch, LaunchSettings::default());
    });
}

#[test]
fn each_pooled_browser_gets_a_forwarder_of_its_own() {
    run(async {
        let upstream = FakeSocksUpstream::start(Answer::Succeed).await;
        let template = PluginSet::strict().with(tor_at(upstream.addr())).unwrap();
        let first = template.for_launch();
        let second = template.for_launch();
        let proxy_first = launched(&first).await.proxy.expect("a proxy");
        let proxy_second = launched(&second).await.proxy.expect("a proxy");
        assert_ne!(proxy_first, proxy_second);
        connect_through(proxy_address(&proxy_first), "a.example").await;
        connect_through(proxy_address(&proxy_second), "a.example").await;
        let passwords = passwords(&upstream);
        assert_eq!(passwords.len(), 2);
        assert_ne!(passwords[0], passwords[1], "browsers never share circuits");

        // Closing one browser leaves the other's forwarder alone.
        assert!(first.on_close().await.is_empty());
        wait_until_closed(proxy_address(&proxy_first)).await;
        assert!(is_listening(proxy_address(&proxy_second)).await);
    });
}

#[test]
fn on_close_stops_every_forwarder() {
    run(async {
        let upstream = FakeSocksUpstream::start(Answer::Succeed).await;
        let tor = Arc::new(tor_at(upstream.addr()));
        let plugins = PluginSet::strict().with_shared(shared(&tor)).unwrap();
        let proxy = launched(&plugins).await.proxy.expect("a proxy");
        let browser = RecordingBrowser::new().with_contexts();
        let (_, context_proxy) = make_context(&plugins, &browser, Duration::ZERO)
            .await
            .unwrap();
        assert_eq!(tor.live_forwarders(), 2);

        assert!(plugins.on_close().await.is_empty());
        assert_eq!(tor.live_forwarders(), 0);
        wait_until_closed(proxy_address(&proxy)).await;
        wait_until_closed(proxy_address(&context_proxy.expect("a context proxy"))).await;
    });
}

#[test]
fn per_context_isolation_gives_every_context_forwarder_circuits_of_its_own() {
    run(async {
        let upstream = FakeSocksUpstream::start(Answer::Succeed).await;
        let tor = Arc::new(tor_at(upstream.addr()));
        let plugins = PluginSet::strict().with_shared(shared(&tor)).unwrap();
        let browser_proxy = launched(&plugins).await.proxy.expect("a proxy");
        let browser = RecordingBrowser::new().with_contexts();

        let (id_a, proxy_a) = make_context(&plugins, &browser, Duration::ZERO)
            .await
            .unwrap();
        let (_id_b, proxy_b) = make_context(&plugins, &browser, Duration::ZERO)
            .await
            .unwrap();
        let (proxy_a, proxy_b) = (proxy_a.expect("a proxy"), proxy_b.expect("a proxy"));
        assert_ne!(proxy_a, proxy_b);
        assert_ne!(proxy_a, browser_proxy);
        assert!(proxy_a.starts_with("socks5://127.0.0.1:") && !proxy_a.contains('@'));
        assert_eq!(tor.live_forwarders(), 3);
        let contexts = browser.contexts();
        assert_eq!(
            contexts[0].settings().proxy.as_deref(),
            Some(proxy_a.as_str())
        );
        assert_eq!(
            contexts[1].settings().proxy.as_deref(),
            Some(proxy_b.as_str())
        );

        for proxy in [&browser_proxy, &proxy_a, &proxy_b] {
            connect_through(proxy_address(proxy), "a.example").await;
        }
        let passwords = passwords(&upstream);
        assert_eq!(passwords.len(), 3);
        assert!(
            passwords[0] != passwords[1]
                && passwords[1] != passwords[2]
                && passwords[0] != passwords[2],
            "three forwarders, three isolation parameters"
        );

        // Closing context A drops A's forwarder and nobody else's.
        assert!(plugins.on_context_closed(&id_a).await.is_empty());
        wait_until_closed(proxy_address(&proxy_a)).await;
        assert!(is_listening(proxy_address(&proxy_b)).await);
        assert!(is_listening(proxy_address(&browser_proxy)).await);
        assert_eq!(tor.live_forwarders(), 2);
    });
}

#[test]
fn contexts_made_at_the_same_time_each_keep_their_own_forwarder() {
    run(async {
        let upstream = FakeSocksUpstream::start(Answer::Succeed).await;
        let tor = Arc::new(tor_at(upstream.addr()));
        let plugins = Arc::new(PluginSet::strict().with_shared(shared(&tor)).unwrap());
        let browser = Arc::new(RecordingBrowser::new().with_contexts());

        // A takes long to be made, B is quick: B must not overtake A and take
        // A's forwarder.
        let local = tokio::task::LocalSet::new();
        let (a, b) = local
            .run_until(async {
                let spawn = |pause: u64| {
                    let (plugins, browser) = (Arc::clone(&plugins), Arc::clone(&browser));
                    tokio::task::spawn_local(async move {
                        make_context(&plugins, &browser, Duration::from_millis(pause)).await
                    })
                };
                let a = spawn(80);
                let b = spawn(5);
                (a.await.unwrap().unwrap(), b.await.unwrap().unwrap())
            })
            .await;
        let (id_a, proxy_a) = (a.0, proxy_address(&a.1.expect("a proxy")));
        let (id_b, proxy_b) = (b.0, proxy_address(&b.1.expect("a proxy")));
        assert_ne!(proxy_a, proxy_b);
        assert_eq!(tor.live_forwarders(), 2);

        assert!(plugins.on_context_closed(&id_a).await.is_empty());
        wait_until_closed(proxy_a).await;
        assert!(
            is_listening(proxy_b).await,
            "B's forwarder survived A's close"
        );
        assert!(plugins.on_context_closed(&id_b).await.is_empty());
        wait_until_closed(proxy_b).await;
        assert_eq!(tor.live_forwarders(), 0);
    });
}

#[test]
fn a_context_that_never_reports_in_does_not_block_the_next_one() {
    run_paused(async {
        let tor = Arc::new(tor_at(dead_address()));
        let plugins = PluginSet::strict().with_shared(shared(&tor)).unwrap();

        // The browser failed to make this context, so `on_context_created`
        // never comes.
        let mut abandoned = ContextSettings::new();
        plugins.before_context(&mut abandoned).await.unwrap();

        let started = tokio::time::Instant::now();
        let mut next = ContextSettings::new();
        plugins.before_context(&mut next).await.unwrap();
        let waited = started.elapsed();
        assert!(
            waited >= Duration::from_secs(4) && waited <= Duration::from_secs(10),
            "{waited:?}: it waits for the first context, but less than a hook's time limit"
        );
        assert!(next.proxy.is_some());
        assert_ne!(abandoned.proxy, next.proxy);
        wait_until_closed(proxy_address(&abandoned.proxy.expect("a proxy"))).await;
        assert_eq!(tor.live_forwarders(), 1);
    });
}

#[test]
fn a_context_with_a_proxy_of_its_own_is_refused() {
    run(async {
        let tor = Arc::new(tor_at(dead_address()));
        let plugins = PluginSet::strict().with_shared(shared(&tor)).unwrap();
        let mut settings = ContextSettings::new().proxy("http://127.0.0.1:8080");
        let error = plugins.before_context(&mut settings).await.unwrap_err();
        assert!(
            error
                .to_string()
                .contains("a context may not set its own proxy"),
            "{error}"
        );
        assert_eq!(tor.live_forwarders(), 0);
    });
}

#[test]
fn with_browser_isolation_contexts_are_left_alone() {
    run(async {
        let upstream = FakeSocksUpstream::start(Answer::Succeed).await;
        let config = TorConfig::new()
            .socks(upstream.addr())
            .isolation(Isolation::Browser);
        let tor = Arc::new(Tor::new(config).unwrap());
        let plugins = PluginSet::strict().with_shared(shared(&tor)).unwrap();
        let _ = launched(&plugins).await;
        let browser = RecordingBrowser::new().with_contexts();
        let (_, proxy) = make_context(&plugins, &browser, Duration::ZERO)
            .await
            .unwrap();
        assert_eq!(proxy, None, "the context uses the browser's proxy");
        assert_eq!(tor.live_forwarders(), 1);
    });
}

#[test]
fn the_number_of_live_contexts_is_bounded() {
    run(async {
        let tor = Arc::new(tor_at(dead_address()));
        let plugins = PluginSet::strict().with_shared(shared(&tor)).unwrap();
        let browser = RecordingBrowser::new().with_contexts();
        let mut first = None;
        for _ in 0..Tor::MAX_CONTEXT_FORWARDERS {
            let (id, _) = make_context(&plugins, &browser, Duration::ZERO)
                .await
                .unwrap();
            first.get_or_insert(id);
        }
        let error = make_context(&plugins, &browser, Duration::ZERO)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("too many"), "{error}");
        assert_eq!(tor.live_forwarders(), Tor::MAX_CONTEXT_FORWARDERS);

        // A closed context makes room, and the refused one left nothing behind.
        plugins.on_context_closed(&first.unwrap()).await;
        make_context(&plugins, &browser, Duration::ZERO)
            .await
            .expect("room again");
    });
}

/// A plugin that runs after tor and tries to change what tor sealed.
struct Meddler(&'static str);

#[async_trait]
impl Plugin for Meddler {
    fn name(&self) -> &str {
        "meddler"
    }

    fn metadata(&self) -> Metadata {
        Metadata::new(Category::Testing).capabilities([
            Capability::LaunchProxy,
            Capability::LaunchNetwork,
            Capability::Contexts,
        ])
    }

    async fn before_launch(&self, launch: &mut LaunchSettings) -> Result<()> {
        match self.0 {
            "proxy" => launch.proxy = Some("http://evil.example:8080".to_owned()),
            _ => launch.webrtc_policy = Some(WebRtcPolicy::Default),
        }
        Ok(())
    }

    async fn before_context(&self, settings: &mut ContextSettings) -> Result<()> {
        settings.proxy = Some("http://evil.example:8080".to_owned());
        Ok(())
    }
}

#[test]
fn a_later_plugin_cannot_change_the_proxy_the_webrtc_policy_or_a_context_proxy() {
    run(async {
        let upstream = FakeSocksUpstream::start(Answer::Succeed).await;
        for (what, field) in [("proxy", "proxy"), ("webrtc", "webrtc_policy")] {
            let plugins = PluginSet::strict()
                .with(Meddler(what))
                .unwrap()
                .with(tor_at(upstream.addr()))
                .unwrap();
            assert_eq!(plugins.names(), ["tor", "meddler"], "tor runs first");
            let mut launch = LaunchSettings::default();
            let error = plugins.before_launch(&mut launch).await.unwrap_err();
            assert!(
                matches!(&error, PluginError::Sealed { field: f, a, b }
                    if *f == field && a == "tor" && b == "meddler"),
                "{what}: {error:?}"
            );
        }
        let plugins = PluginSet::strict()
            .with(Meddler("proxy"))
            .unwrap()
            .with(tor_at(upstream.addr()))
            .unwrap();
        let mut settings = ContextSettings::new();
        let error = plugins.before_context(&mut settings).await.unwrap_err();
        assert!(
            matches!(&error, PluginError::Sealed { field, a, .. } if *field == "context.proxy" && a == "tor"),
            "{error:?}"
        );
    });
}
