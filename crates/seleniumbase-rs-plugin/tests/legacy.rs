//! A plugin written against 0.1.0, before metadata, capabilities and the new
//! hooks, still compiles and runs, and the new dispatchers leave it alone.

use seleniumbase_rs_plugin::{
    BrowserFamily, Engine, LaunchContext, NavOutcome, Navigation, PageHandle, Plugin, PluginError,
    PluginSet, ProtocolEvent, RequestDecision, RequestView, Requirements, ResourceKind,
    ResponseView, Result, TestInfo, TestOutcome, TestVerdict, async_trait,
};
use seleniumbase_rs_plugin_testing::{Call, RecordingBrowser, RecordingPage, block_on};
use serde_json::json;

/// The `block-resources` plugin as shipped with 0.1.0: only the original
/// hooks, no `metadata`, no `Configurable`.
struct BlockResources {
    patterns: Vec<String>,
}

#[async_trait]
impl Plugin for BlockResources {
    fn name(&self) -> &str {
        "block-resources"
    }

    fn requirements(&self) -> Requirements {
        Requirements::CHROMIUM_ONLY
    }

    async fn on_page_created(&self, page: &dyn PageHandle) -> Result<()> {
        page.send("Network.enable", json!({})).await?;
        page.send("Network.setBlockedURLs", json!({ "urls": self.patterns }))
            .await?;
        Ok(())
    }
}

fn set() -> PluginSet {
    PluginSet::new()
        .with(BlockResources {
            patterns: vec!["*.png".to_owned()],
        })
        .unwrap()
}

#[test]
fn a_0_1_0_plugin_still_runs_its_hooks() {
    let page = RecordingPage::new();
    block_on(set().on_page_created(&page)).unwrap();
    // The guard turns the plugin's raw `Network.setBlockedURLs` into `block_urls`,
    // so that the host keeps one list for the tab instead of the last one sent.
    assert_eq!(
        page.calls(),
        [
            Call::Send("Network.enable".into(), json!({})),
            Call::BlockUrls(vec!["*.png".into()]),
        ]
    );
    set()
        .check(&LaunchContext {
            engine: Engine::Cdp,
            family: BrowserFamily::Chromium,
            headless: true,
            connecting: false,
        })
        .unwrap();
}

#[test]
fn the_new_hooks_do_nothing_for_it() {
    let set = set();
    let page = RecordingPage::new();
    let browser = RecordingBrowser::new();
    // Navigation: unchanged.
    let nav = Navigation::program("https://a.test/");
    assert_eq!(block_on(set.before_navigate(&page, &nav)).unwrap(), nav);
    assert!(block_on(set.after_navigate(&page, &NavOutcome::new("https://a.test/"))).is_empty());
    // Network: nothing declared, nothing blocked.
    assert!(set.interest().is_empty());
    assert!(set.protocol_events().is_empty());
    let request = RequestView::new("https://a.test/i.png", "GET", ResourceKind::Image);
    assert_eq!(
        block_on(set.on_request(&request)),
        RequestDecision::Continue
    );
    assert!(block_on(set.on_response(&ResponseView::new(&request, 200, "image/png"))).is_empty());
    assert!(set.extra_headers(&request).is_empty());
    assert!(
        block_on(set.on_protocol_event(&browser, &ProtocolEvent::new("Log.entryAdded", json!({}))))
            .is_empty()
    );
    // Tests and teardown.
    let test = TestInfo::new("t");
    assert!(block_on(set.on_test_start(&test)).is_empty());
    let (verdict, failures) = block_on(set.on_test_end(&test, &TestOutcome::Passed, Some(&page)));
    assert_eq!((verdict, failures.len()), (TestVerdict::Keep, 0));
    assert!(block_on(set.before_close(&browser)).is_empty());
    // Nothing reached the fakes.
    assert_eq!(page.calls(), []);
    assert_eq!(browser.calls(), []);
    // No tasks, no job runners.
    assert!(set.task_names().is_empty());
    assert!(matches!(
        set.task("block-resources").err().unwrap(),
        PluginError::Config(_)
    ));
    assert!(set.job_runner("block-resources").is_err());
}

#[test]
fn for_launch_and_duplicate_names_still_work() {
    let set = set();
    let fresh = set.for_launch();
    assert_eq!(fresh.names(), set.names());
    // Adding a plugin after the order was worked out puts it in the order.
    let grown = set
        .with(BlockResources {
            patterns: Vec::new(),
        })
        .err()
        .unwrap();
    assert!(matches!(grown, PluginError::DuplicateName(_)));
}
