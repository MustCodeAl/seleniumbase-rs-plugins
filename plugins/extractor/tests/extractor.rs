//! The extractor against the plugin API's fakes: the page script's answers are
//! canned, so this tests everything but the script itself (see
//! `extractor_chrome.rs` for that).

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use seleniumbase_rs_plugin::{
    BrowserFamily, BrowserHandle, Capability, CapabilitySet, Clock, Configurable, Engine,
    JobRunner, NoPrompt, PageHandle, PluginError, PluginSet, TaskContext, async_trait,
};
use seleniumbase_rs_plugin_extractor::{Extractor, ExtractorConfig, FieldType, Schema, Source};
use seleniumbase_rs_plugin_testing::{Call, ManualTimer, RecordingPage, VecSink, block_on};
use serde_json::{Value, json};

fn extractor() -> Extractor {
    Extractor::new(ExtractorConfig::default()).unwrap()
}

fn config_error(config: Value) -> String {
    match Extractor::configure(&config) {
        Err(PluginError::Config(message)) => message,
        other => panic!("expected a configuration error, got {other:?}"),
    }
}

// ---- canned answers of the page script --------------------------------------------

fn product_candidate() -> Value {
    json!({
        "source": "json-ld", "item": "Product", "skip": 0, "items": 1,
        "fields": [
            { "name": "name", "path": "name", "samples": ["Widget"], "present": 1, "total": 1 },
            { "name": "price", "path": "offers.price", "samples": ["19.99 USD"], "present": 1, "total": 1 },
            { "name": "sku", "path": "sku", "samples": ["W-1"], "present": 1, "total": 1 },
        ],
    })
}

fn cards_candidate() -> Value {
    json!({
        "source": "repeat", "item": ".card", "skip": 0, "items": 5,
        "fields": [
            { "name": "title", "selector": "h3", "samples": ["A", "B"], "present": 5, "total": 5 },
            { "name": "price", "selector": ".price", "samples": ["$5", "$6.50"], "present": 5, "total": 5 },
            { "name": "link_url", "selector": "a", "attr": "href",
              "samples": ["https://s.test/1", "https://s.test/2"], "present": 4, "total": 5 },
        ],
    })
}

fn discovered(candidates: &[Value]) -> Value {
    json!({ "candidates": candidates, "truncated": false, "nodes": 10 })
}

fn read(records: Value, page: Value) -> Value {
    json!({ "records": records, "errors": [], "page": page, "truncated": false, "nodes": 4 })
}

const DISCOVER: &str = "\"mode\":\"discover\"";
const EXTRACT: &str = "\"mode\":\"extract\"";

fn scripts(page: &RecordingPage) -> Vec<String> {
    page.calls()
        .into_iter()
        .filter_map(|call| match call {
            Call::Evaluate(script) => Some(script),
            _ => None,
        })
        .collect()
}

// ---- options and metadata ----------------------------------------------------------

#[test]
fn defaults_and_bounds() {
    let plugin = Extractor::configure(&Value::Null).unwrap();
    assert_eq!(*plugin.config(), ExtractorConfig::default());
    assert_eq!(plugin.config().min_repeats, 3);
    assert_eq!(plugin.config().max_nodes, 20_000);
    assert_eq!(plugin.config().max_fields, 64);
    assert_eq!(
        config_error(json!({ "auto_save": "out" })),
        "extractor: unknown option `auto_save`"
    );
    for (option, value) in [
        ("min_repeats", json!(1)),
        ("max_nodes", json!(50)),
        ("max_fields", json!(0)),
        ("max_records", json!(0)),
        ("max_text_chars", json!(20_000_000)),
        ("max_links", json!(200_000)),
    ] {
        let message = config_error(json!({ option: value }));
        assert!(message.contains(option), "{message}");
    }
}

#[test]
fn it_declares_what_it_needs_and_nothing_to_write_files() {
    let meta = Extractor::describe();
    assert_eq!(meta.category, Some(seleniumbase_rs_plugin::Category::Core));
    for needed in [
        Capability::PageEvaluate,
        Capability::PageNavigate,
        Capability::Task,
    ] {
        assert!(meta.capabilities.covers(&needed), "{needed}");
    }
    for never in [
        Capability::ArtifactsWrite,
        Capability::NetObserve,
        Capability::NetIntercept,
        Capability::CookiesRead,
    ] {
        assert!(!meta.capabilities.covers(&never), "{never}");
        assert!(!meta.optional.covers(&never), "{never}");
    }
    let set = PluginSet::strict().with(extractor()).unwrap();
    assert_eq!(set.task_names(), ["extractor"]);
    assert!(set.job_runner("extractor").is_ok());
}

// ---- discovery ---------------------------------------------------------------------

#[test]
fn discovery_types_each_candidate_from_its_samples() {
    let page = RecordingPage::new().evaluating(
        DISCOVER,
        discovered(&[product_candidate(), cards_candidate()]),
    );
    let schemas = block_on(extractor().discover(&page)).unwrap();
    assert_eq!(schemas.len(), 2);

    let product = &schemas[0];
    assert_eq!(product.source, Source::JsonLd);
    assert_eq!(product.item.as_deref(), Some("Product"));
    let kinds: Vec<_> = product
        .fields
        .iter()
        .map(|f| (f.name.as_str(), f.kind))
        .collect();
    assert_eq!(
        kinds,
        [
            ("name", FieldType::Text),
            ("price", FieldType::Money),
            ("sku", FieldType::Text)
        ]
    );
    assert!(
        product.fields.iter().all(|f| f.required),
        "every sample was present"
    );
    assert_eq!(product.fields[1].path.as_deref(), Some("offers.price"));

    let cards = &schemas[1];
    assert_eq!(cards.source, Source::Repeat);
    assert_eq!(cards.fields[1].kind, FieldType::Money);
    assert_eq!(cards.fields[2].kind, FieldType::Url);
    assert_eq!(cards.fields[2].attr.as_deref(), Some("href"));
    assert!(cards.fields[1].required);
    assert!(!cards.fields[2].required, "4 of 5 cards had it");

    let calls = scripts(&page);
    assert_eq!(calls.len(), 1);
    assert!(calls[0].contains("\"min_repeats\":3"), "{}", calls[0]);
    assert!(calls[0].contains("\"max_nodes\":20000"), "{}", calls[0]);
}

#[test]
fn a_candidate_the_page_made_up_badly_is_dropped_not_trusted() {
    let mut bad_name = cards_candidate();
    bad_name["fields"][0]["name"] = json!("ti\ntle");
    let mut bad_source = cards_candidate();
    bad_source["source"] = json!("eval");
    let mut no_count = cards_candidate();
    no_count["fields"][1]
        .as_object_mut()
        .unwrap()
        .remove("present");
    let mut table_without_item = cards_candidate();
    table_without_item["source"] = json!("table");
    table_without_item.as_object_mut().unwrap().remove("item");
    let page = RecordingPage::new().evaluating(
        DISCOVER,
        discovered(&[
            bad_name,
            bad_source,
            no_count,
            table_without_item,
            cards_candidate(),
        ]),
    );
    let schemas = block_on(extractor().discover(&page)).unwrap();
    assert_eq!(schemas.len(), 1);
    assert_eq!(schemas[0].source, Source::Repeat);
}

#[test]
fn an_odd_reply_to_discovery_is_an_error() {
    for reply in [json!("nonsense"), json!({ "nothing": 1 }), Value::Null] {
        let page = RecordingPage::new().evaluating(DISCOVER, reply);
        let error = block_on(extractor().discover(&page)).unwrap_err();
        assert!(error.to_string().contains("unexpected reply"), "{error}");
    }
}

// ---- extraction --------------------------------------------------------------------

fn cards_schema() -> Schema {
    let page = RecordingPage::new().evaluating(DISCOVER, discovered(&[cards_candidate()]));
    block_on(extractor().discover(&page)).unwrap().remove(0)
}

#[test]
fn extraction_types_the_records_and_reports_the_scripts_own_errors() {
    let schema = cards_schema();
    let mut reply = read(
        json!([
            { "title": "A", "price": "$5", "link_url": "https://s.test/1" },
            { "title": "B", "price": "free", "link_url": null },
        ]),
        Value::Null,
    );
    reply["errors"] = json!(["field title: invalid selector"]);
    let page = RecordingPage::new().evaluating(EXTRACT, reply);
    let found = block_on(extractor().extract(&page, &schema)).unwrap();
    assert_eq!(
        found.records[0]["price"],
        json!({ "amount": 5, "currency": "USD" })
    );
    assert_eq!(found.records[1]["price"], Value::Null);
    assert_eq!(found.records[1]["link_url"], Value::Null);
    let problems: Vec<_> = found
        .problems
        .iter()
        .map(|p| (p.record, p.field.as_str()))
        .collect();
    assert_eq!(problems, [(1, "price"), (0, "")]);
    assert!(found.problems[1].problem.contains("invalid selector"));
    // The schema travels inside one JSON literal.
    let script = &scripts(&page)[0];
    assert!(script.contains("\"item\":\".card\""), "{script}");
}

#[test]
fn a_schema_is_checked_before_the_page_is_touched() {
    let page = RecordingPage::new();
    let schema: Schema = serde_json::from_value(json!({
        "source": "selectors",
        "fields": [{ "name": "a", "selector": "p\nq" }],
    }))
    .unwrap();
    let error = block_on(extractor().extract(&page, &schema)).unwrap_err();
    assert!(matches!(error, PluginError::Config(_)), "{error}");
    assert!(page.calls().is_empty());
}

// ---- the job runner ----------------------------------------------------------------

fn run(page: &RecordingPage, job: Value) -> Result<Value, PluginError> {
    block_on(extractor().run_job(page, &job))
}

#[test]
fn a_job_with_a_url_opens_it_discovers_and_extracts() {
    let page = RecordingPage::new()
        .evaluating(
            DISCOVER,
            discovered(&[product_candidate(), cards_candidate()]),
        )
        .evaluating(
            EXTRACT,
            read(
                json!([{ "name": "Widget", "price": "19.99 USD", "sku": "W-1" }]),
                json!({ "url": "https://shop.test/p/1", "title": "Widget" }),
            ),
        );
    let out = run(&page, json!({ "url": "https://shop.test/p/1" })).unwrap();
    assert_eq!(out["url"], "https://shop.test/p/1");
    assert_eq!(out["title"], "Widget");
    assert_eq!(out["schema"]["source"], "json-ld");
    assert_eq!(out["schema"]["fields"][1]["type"], "money");
    assert_eq!(
        out["records"],
        json!([{ "name": "Widget", "price": { "amount": 19.99, "currency": "USD" }, "sku": "W-1" }])
    );
    assert_eq!(out["problems"], json!([]));
    assert!(out.get("truncated").is_none() && out.get("text").is_none());

    let calls = page.calls();
    assert_eq!(calls[0], Call::Navigate("https://shop.test/p/1".into()));
    assert!(matches!(&calls[1], Call::Evaluate(s) if s.contains(DISCOVER)));
    assert!(matches!(&calls[2], Call::Evaluate(s) if s.contains(EXTRACT)));
    assert_eq!(calls.len(), 3);
}

#[test]
fn source_prefers_one_kind_of_structure() {
    let page = RecordingPage::new()
        .evaluating(
            DISCOVER,
            discovered(&[product_candidate(), cards_candidate()]),
        )
        .evaluating(EXTRACT, read(json!([]), Value::Null));
    let out = run(&page, json!({ "source": "repeat" })).unwrap();
    assert_eq!(out["schema"]["source"], "repeat");
    let page = RecordingPage::new()
        .evaluating(DISCOVER, discovered(&[product_candidate()]))
        .evaluating(EXTRACT, read(json!([]), Value::Null));
    let out = run(&page, json!({ "source": "table" })).unwrap();
    assert_eq!(
        out["schema"]["source"], "json-ld",
        "falls back to the best there is"
    );
}

#[test]
fn a_page_with_no_structure_gives_no_records_and_says_so() {
    let page = RecordingPage::new()
        .evaluating(DISCOVER, discovered(&[]))
        .evaluating(
            EXTRACT,
            read(json!([]), json!({ "url": "u", "title": "t" })),
        );
    let out = run(&page, json!({})).unwrap();
    assert_eq!(out["records"], json!([]));
    assert!(out.get("schema").is_none());
    assert_eq!(
        out["problems"][0]["problem"],
        "no structure found on the page"
    );
}

#[test]
fn a_select_map_reads_exactly_those_selectors_without_discovering() {
    let page = RecordingPage::new().evaluating(
        EXTRACT,
        read(
            json!([{ "title": "T", "price": "$5.25", "link": "https://s.test/x" }]),
            json!({ "url": "https://s.test/", "title": "Shop" }),
        ),
    );
    let out = run(
        &page,
        json!({
            "select": {
                "title": "h1",
                "price": { "selector": ".price", "type": "money", "required": true },
                "link": { "selector": "a", "attr": "href", "type": "url" },
            },
        }),
    )
    .unwrap();
    assert_eq!(
        out["records"][0]["price"],
        json!({ "amount": 5.25, "currency": "USD" })
    );
    assert_eq!(out["schema"]["source"], "selectors");
    let calls = scripts(&page);
    assert_eq!(calls.len(), 1, "no discovery");
    assert!(!calls[0].contains(DISCOVER));
}

#[test]
fn selectors_travel_as_json_and_cannot_leave_their_string() {
    let page = RecordingPage::new().evaluating(EXTRACT, read(json!([{ "x": "y" }]), Value::Null));
    let selector = "a[title=\"</script>\"]'));alert(1);//";
    run(&page, json!({ "select": { "x": selector } })).unwrap();
    let script = &scripts(&page)[0];
    let literal = serde_json::to_string(selector).unwrap();
    assert!(script.contains(&literal), "{script}");
    assert!(!script.replace(&literal, "").contains("alert(1);//"));
}

#[test]
fn page_parts_alone_need_no_schema_and_come_back_as_asked() {
    let page = RecordingPage::new().evaluating(
        EXTRACT,
        read(
            json!([]),
            json!({
                "url": "https://s.test/", "title": "Shop",
                "links": [{ "href": "https://s.test/a", "text": "A" }],
                "tables": [{ "headers": ["a"], "rows": [["1"]] }],
                "meta": { "description": "d" },
                "text": "hello",
            }),
        ),
    );
    let out = run(
        &page,
        json!({ "links": true, "tables": true, "meta": true, "text": true }),
    )
    .unwrap();
    assert_eq!(out["links"][0]["href"], "https://s.test/a");
    assert_eq!(out["tables"][0]["rows"], json!([["1"]]));
    assert_eq!(out["meta"]["description"], "d");
    assert_eq!(out["text"], "hello");
    assert_eq!(out["records"], json!([]));
    let calls = scripts(&page);
    assert_eq!(
        calls.len(),
        1,
        "no discovery when only page parts are asked for"
    );
    assert!(calls[0].contains("\"links\":true") && calls[0].contains("\"text\":true"));
}

#[test]
fn a_given_schema_is_applied_as_it_is() {
    let schema = serde_json::to_value(cards_schema()).unwrap();
    let page = RecordingPage::new().evaluating(
        EXTRACT,
        read(
            json!([{ "title": "A", "price": "$5", "link_url": null }]),
            Value::Null,
        ),
    );
    let out = run(&page, json!({ "schema": schema })).unwrap();
    assert_eq!(out["schema"]["item"], ".card");
    assert_eq!(scripts(&page).len(), 1);
}

#[test]
fn a_bad_job_fails_before_the_page_is_touched() {
    let page = RecordingPage::new();
    for job in [
        json!({ "url": "file:///etc/passwd" }),
        json!({ "url": "javascript:alert(1)" }),
        json!({ "url": "https://user:pw@a.test/" }),
        json!({ "item": ".card" }),
        json!({ "select": { "a": "" } }),
        json!({ "select": { "a": { "selector": "p", "colour": 1 } } }),
        json!({ "unknown": true }),
        json!("https://a.test/"),
        json!({ "schema": { "source": "repeat", "fields": [] } }),
    ] {
        let error = run(&page, job.clone()).unwrap_err();
        assert!(matches!(error, PluginError::Config(_)), "{job}: {error}");
    }
    assert!(page.calls().is_empty(), "{:?}", page.calls());
}

#[test]
fn an_odd_reply_to_the_read_is_an_error_not_a_panic() {
    let page = RecordingPage::new().evaluating(EXTRACT, json!("nonsense"));
    let error = run(&page, json!({ "select": { "a": "p" } })).unwrap_err();
    assert!(error.to_string().contains("unexpected reply"), "{error}");
}

#[test]
fn a_truncated_page_says_so() {
    let mut reply = read(json!([]), Value::Null);
    reply["truncated"] = json!(true);
    let page = RecordingPage::new().evaluating(EXTRACT, reply);
    let out = run(&page, json!({ "select": { "a": "p" } })).unwrap();
    assert_eq!(out["truncated"], true);
}

// ---- the task ----------------------------------------------------------------------

/// A browser that hands out one prepared tab and counts how often it is asked.
struct OneTab {
    page: RecordingPage,
    opened: AtomicUsize,
}

impl OneTab {
    fn new(page: RecordingPage) -> Self {
        Self {
            page,
            opened: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl BrowserHandle for OneTab {
    fn engine(&self) -> Engine {
        Engine::Cdp
    }

    fn family(&self) -> BrowserFamily {
        BrowserFamily::Chromium
    }

    async fn new_page<'a>(
        &'a self,
        _url: Option<&str>,
    ) -> seleniumbase_rs_plugin::Result<Box<dyn PageHandle + 'a>> {
        self.opened.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(self.page.clone()))
    }

    async fn send(&self, _method: &str, _params: Value) -> seleniumbase_rs_plugin::Result<Value> {
        Ok(Value::Null)
    }
}

fn run_task(
    set: &PluginSet,
    browser: &OneTab,
    input: &Value,
) -> (Result<Value, PluginError>, Vec<Value>) {
    let sink = VecSink::new();
    let clock = Clock::new(Arc::new(ManualTimer::new()));
    let cx = TaskContext::new(browser, input, &sink, set, &clock, &NoPrompt);
    let summary = block_on(set.task("extractor").unwrap().run(&cx));
    (summary, sink.lines())
}

fn shop_page() -> RecordingPage {
    RecordingPage::new().evaluating(
        EXTRACT,
        read(
            json!([{ "title": "A" }, { "title": "B" }]),
            json!({ "url": "https://shop.test/", "title": "Shop" }),
        ),
    )
}

#[test]
fn the_task_reads_each_url_in_one_tab_and_records_a_line_per_page() {
    let set = PluginSet::strict().with(extractor()).unwrap();
    let browser = OneTab::new(shop_page());
    let input = json!({
        "urls": ["https://shop.test/1", "https://shop.test/2"],
        "extract": { "select": { "title": "h3" }, "item": ".card" },
    });
    let (summary, lines) = run_task(&set, &browser, &input);
    assert_eq!(
        summary.unwrap(),
        json!({ "total": 2, "ok": 2, "failed": 0, "records": 4 })
    );
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0]["index"], 0);
    assert_eq!(lines[1]["index"], 1);
    assert_eq!(
        lines[0]["records"],
        json!([{ "title": "A" }, { "title": "B" }])
    );
    assert_eq!(lines[0]["title"], "Shop");
    assert_eq!(
        browser.opened.load(Ordering::SeqCst),
        1,
        "one tab for the whole task"
    );
    let calls = browser.page.calls();
    let navigations: Vec<_> = calls
        .iter()
        .filter_map(|c| match c {
            Call::Navigate(url) => Some(url.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(navigations, ["https://shop.test/1", "https://shop.test/2"]);
    assert!(calls.contains(&Call::Close));
}

#[test]
fn a_page_that_fails_does_not_stop_the_others() {
    let set = PluginSet::strict().with(extractor()).unwrap();
    let browser = OneTab::new(shop_page());
    // The second job navigates, but its read gets no usable answer: a select
    // map asks for a schema the canned page accepts, so make it fail instead
    // with a bad `item` on that job only.
    let input = json!({ "jobs": [
        { "url": "https://shop.test/1", "select": { "title": "h3" } },
        { "url": "https://shop.test/2", "item": ".card" },
        { "url": "https://shop.test/3", "select": { "title": "h3" } },
    ]});
    let (summary, lines) = run_task(&set, &browser, &input);
    assert_eq!(
        summary.unwrap(),
        json!({ "total": 3, "ok": 2, "failed": 1, "records": 4 })
    );
    assert_eq!(lines[1]["index"], 1);
    assert_eq!(lines[1]["url"], "https://shop.test/2");
    assert!(
        lines[1]["error"]
            .as_str()
            .unwrap()
            .contains("`item` needs a `select` map")
    );
    assert!(lines[2]["records"].is_array());
}

#[test]
fn the_task_input_is_checked_before_a_tab_is_opened() {
    let set = PluginSet::strict().with(extractor()).unwrap();
    let many: Vec<String> = (0..10_001).map(|n| format!("https://a.test/{n}")).collect();
    for input in [
        json!({}),
        json!({ "urls": [] }),
        json!({ "urls": ["https://a.test/"], "jobs": [{ "url": "https://a.test/" }] }),
        json!({ "urls": ["https://a.test/"], "delay_ms": 3_600_000 }),
        json!({ "urls": ["https://a.test/"], "proxy": "x" }),
        json!({ "urls": ["https://a.test/", "file:///etc/passwd"] }),
        json!({ "jobs": [{ "url": "https://a.test/", "item": ".card" }, { "url": "https://u:p@a.test/" }] }),
        json!({ "urls": many }),
    ] {
        let browser = OneTab::new(RecordingPage::new());
        let (summary, lines) = run_task(&set, &browser, &input);
        assert!(
            matches!(summary, Err(PluginError::Config(_))),
            "{}: {summary:?}",
            input.to_string().chars().take(60).collect::<String>()
        );
        assert!(lines.is_empty());
        assert_eq!(browser.opened.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn the_task_stops_when_a_capability_is_missing_and_still_closes_its_tab() {
    let mut grants = CapabilitySet::new();
    grants.insert(Capability::Task);
    grants.insert(Capability::PageEvaluate);
    let set = PluginSet::strict()
        .with_grants(extractor(), grants)
        .unwrap();
    let browser = OneTab::new(shop_page());
    let input = json!({ "urls": ["https://shop.test/1", "https://shop.test/2"] });
    let (summary, lines) = run_task(&set, &browser, &input);
    let error = summary.unwrap_err();
    assert!(
        matches!(error, PluginError::Capability { .. })
            && error.to_string().contains("page.navigate"),
        "{error}"
    );
    assert!(lines.is_empty());
    assert!(browser.page.calls().contains(&Call::Close));
}
