//! The fakes behave like the handles they stand in for.

use seleniumbase_rs_plugin::Sink;
use seleniumbase_rs_plugin::{
    BrowserHandle, ContextSettings, Engine, LoadedExtension, PageHandle, PluginError, PluginSet,
    RequestDecision, RequestView, ResourceKind, ResponseView,
};
use seleniumbase_rs_plugin_testing::{
    Call, RecordingBrowser, RecordingPage, VecSink, block_on, drive_request, drive_response,
};
use serde_json::json;

#[test]
fn a_page_answers_evaluate_from_canned_replies_by_substring() {
    let page = RecordingPage::new()
        .evaluating("document.title", json!("Home"))
        .evaluating("count", json!(3));
    assert_eq!(
        block_on(page.evaluate("return document.title")).unwrap(),
        "Home"
    );
    assert_eq!(block_on(page.evaluate("items.count()")).unwrap(), 3);
    assert_eq!(block_on(page.evaluate("1 + 1")).unwrap(), json!(null));
    assert_eq!(page.calls().len(), 3);
}

#[test]
fn a_page_remembers_where_it_was_sent() {
    let page = RecordingPage::new().at("https://start.test/");
    assert_eq!(block_on(page.url()).unwrap(), "https://start.test/");
    block_on(page.navigate("https://next.test/")).unwrap();
    assert_eq!(block_on(page.url()).unwrap(), "https://next.test/");
    block_on(page.block_urls(&["*.png".to_owned()])).unwrap();
    block_on(page.close()).unwrap();
    assert_eq!(
        page.calls(),
        [
            Call::Url,
            Call::Navigate("https://next.test/".into()),
            Call::Url,
            Call::BlockUrls(vec!["*.png".into()]),
            Call::Close
        ]
    );
    assert_eq!(page.engine(), Engine::Cdp);
}

#[test]
fn a_failing_command_fails_the_new_handle_methods_too() {
    let page = RecordingPage::new().failing("navigate");
    assert!(block_on(page.navigate("https://x.test/")).is_err());
    let page = RecordingPage::new().failing("close");
    assert!(block_on(page.close()).is_err());
}

#[test]
fn a_clone_of_a_page_writes_to_the_same_record() {
    let page = RecordingPage::new();
    let clone = page.clone();
    block_on(clone.add_init_script("1")).unwrap();
    assert_eq!(page.calls(), [Call::InitScript("1".into())]);
}

#[test]
fn contexts_and_pages_are_counted_while_open() {
    let browser = RecordingBrowser::new().with_contexts();
    let first =
        block_on(browser.new_context(ContextSettings::new().proxy("socks5://x:1"))).unwrap();
    let second = block_on(browser.new_context(ContextSettings::new())).unwrap();
    assert_eq!(
        (browser.live_contexts(), browser.max_live_contexts()),
        (2, 2)
    );
    let page = block_on(first.new_page(Some("https://a.test/"))).unwrap();
    assert_eq!(page.context(), Some(first.id().clone()));
    let other = block_on(second.new_page(None)).unwrap();
    assert_eq!((browser.live_pages(), browser.max_live_pages()), (2, 2));
    block_on(page.close()).unwrap();
    block_on(page.close()).unwrap(); // closing twice counts once
    assert_eq!(browser.live_pages(), 1);
    // Disposing a context closes the tabs left in it.
    block_on(second.dispose()).unwrap();
    assert_eq!((browser.live_contexts(), browser.live_pages()), (1, 0));
    block_on(other.close()).unwrap(); // already counted out by `dispose`
    assert_eq!(browser.live_pages(), 0);
    block_on(first.dispose()).unwrap();
    assert_eq!(browser.live_contexts(), 0);
    assert_eq!(
        (
            browser.contexts_made(),
            browser.pages_made(),
            browser.max_live_contexts()
        ),
        (2, 2, 2)
    );
    let contexts = browser.contexts();
    assert_eq!(
        contexts[0].settings().proxy.as_deref(),
        Some("socks5://x:1")
    );
    assert!(contexts[0].disposed() && contexts[1].disposed());
    assert_eq!(contexts[0].pages().len(), 1);
    assert_eq!(
        contexts[0].calls(),
        [Call::NewPage(Some("https://a.test/".into())), Call::Dispose]
    );
    assert_eq!(
        browser.calls()[0],
        Call::NewContext(ContextSettings::new().proxy("socks5://x:1"))
    );
}

#[test]
fn pages_opened_straight_on_the_browser_are_counted_and_listed() {
    let browser = RecordingBrowser::new().with_contexts();
    let page = block_on(browser.new_page(None)).unwrap();
    assert_eq!(browser.live_pages(), 1);
    block_on(page.close()).unwrap();
    assert_eq!(browser.live_pages(), 0);
    assert_eq!(browser.pages().len(), 1);
    assert_eq!(browser.pages()[0].calls(), [Call::Close]);
}

#[test]
fn without_with_contexts_the_browser_offers_none_and_failures_can_be_injected() {
    let plain = RecordingBrowser::new();
    assert!(matches!(
        block_on(plain.new_context(ContextSettings::new()))
            .err()
            .unwrap(),
        PluginError::NotSupported(_)
    ));
    let failing = RecordingBrowser::new()
        .with_contexts()
        .failing("new_context");
    assert!(block_on(failing.new_context(ContextSettings::new())).is_err());
    assert_eq!(failing.live_contexts(), 0);
    let ids =
        RecordingBrowser::new().with_extensions(vec![LoadedExtension::new("abc", "/tmp/ext")]);
    assert_eq!(ids.extensions()[0].id, "abc");
}

#[test]
fn the_drive_helpers_run_a_set_like_the_host_and_the_sink_keeps_lines() {
    let set = PluginSet::new();
    let request = RequestView::new("https://a.test/", "GET", ResourceKind::Document);
    assert_eq!(
        drive_request(&set, request.clone()),
        RequestDecision::Continue
    );
    assert!(drive_response(&set, ResponseView::new(&request, 200, "text/html")).is_empty());
    let sink = VecSink::new();
    sink.record(&json!({"n": 1})).unwrap();
    sink.record(&json!({"n": 2})).unwrap();
    assert_eq!(sink.lines(), [json!({"n": 1}), json!({"n": 2})]);
}
