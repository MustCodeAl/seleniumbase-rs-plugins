//! The page script in a real Chrome. Every test is `#[ignore]`d: they need
//! Chrome and start one headless process per call to the page.
//!
//! The plugin API has no browser of its own, so a small `PageHandle` here puts
//! a fixture into a file, appends the expression the extractor wants
//! evaluated, lets headless Chrome run it (`--dump-dom`) and reads the answer
//! back out of the dumped page. The extractor code under test is the real one.
//!
//! Run them alone:
//!
//! ```text
//! cargo test -p seleniumbase-rs-plugin-extractor --test extractor_chrome -- --ignored --test-threads=1
//! ```
//!
//! `SB_TEST_CHROME` names the browser binary; otherwise Google Chrome on macOS,
//! then `google-chrome` and `chromium` on the path.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use seleniumbase_rs_plugin::{Engine, JobRunner, PageHandle, PluginError, Result, async_trait};
use seleniumbase_rs_plugin_extractor::{Extractor, ExtractorConfig, FieldType, Schema, Source};
use seleniumbase_rs_plugin_testing::block_on;
use serde_json::{Value, json};

mod support;
use support::valid;

static RUNS: AtomicUsize = AtomicUsize::new(0);

fn chrome() -> PathBuf {
    if let Some(path) = std::env::var_os("SB_TEST_CHROME") {
        return PathBuf::from(path);
    }
    let mac = Path::new("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome");
    if mac.exists() {
        return mac.to_path_buf();
    }
    PathBuf::from(if which("google-chrome") {
        "google-chrome"
    } else {
        "chromium"
    })
}

fn which(name: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|paths| std::env::split_paths(&paths).any(|dir| dir.join(name).exists()))
}

fn unescape(text: &str) -> String {
    text.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&nbsp;", "\u{a0}")
        .replace("&amp;", "&")
}

/// Evaluates `expression` in a page whose body is `body`, in headless Chrome.
fn run_in_chrome(body: &str, expression: &str) -> std::result::Result<Value, String> {
    let dir = std::env::temp_dir().join(format!(
        "sbrs-extractor-{}-{}",
        std::process::id(),
        RUNS.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let page = dir.join("page.html");
    let html = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Fixture</title>\
         <meta name=\"description\" content=\"A fixture\"></head><body>{body}\
         <pre id=\"sbrs-out\"></pre><script>(function () {{\
           var out = document.getElementById('sbrs-out');\
           try {{ Promise.resolve({expression}).then(\
             function (v) {{ out.textContent = JSON.stringify(v); }},\
             function (e) {{ out.textContent = JSON.stringify({{ error: String(e) }}); }});\
           }} catch (e) {{ out.textContent = JSON.stringify({{ error: String(e) }}); }}\
         }})();</script></body></html>"
    );
    std::fs::write(&page, html).map_err(|e| e.to_string())?;
    let output = Command::new(chrome())
        .args([
            "--headless=new",
            "--disable-gpu",
            "--no-sandbox",
            "--no-first-run",
            "--disable-extensions",
            "--disable-background-networking",
        ])
        .arg(format!("--user-data-dir={}", dir.join("profile").display()))
        .arg("--dump-dom")
        .arg(format!("file://{}", page.display()))
        .output()
        .map_err(|e| format!("could not start Chrome: {e}"))?;
    let dumped = String::from_utf8_lossy(&output.stdout).into_owned();
    let _ = std::fs::remove_dir_all(&dir);
    let open = "<pre id=\"sbrs-out\">";
    let start = dumped.find(open).ok_or_else(|| {
        format!(
            "no answer in the dumped page: {}",
            &dumped[..dumped.len().min(300)]
        )
    })? + open.len();
    let end = dumped[start..]
        .find("</pre>")
        .ok_or("unterminated answer")?
        + start;
    let text = unescape(&dumped[start..end]);
    if text.is_empty() {
        return Err("the page script gave no answer".into());
    }
    let value: Value = serde_json::from_str(&text).map_err(|e| format!("{e}: {text}"))?;
    match value.get("error") {
        Some(error) if value.as_object().is_some_and(|o| o.len() == 1) => Err(error.to_string()),
        _ => Ok(value),
    }
}

/// A tab whose document is a fixture and whose `evaluate` runs in Chrome.
struct ChromePage {
    body: String,
    visited: Mutex<Vec<String>>,
}

impl ChromePage {
    fn new(body: &str) -> Self {
        Self {
            body: body.to_owned(),
            visited: Mutex::default(),
        }
    }
}

#[async_trait]
impl PageHandle for ChromePage {
    fn engine(&self) -> Engine {
        Engine::Cdp
    }

    async fn send(&self, _method: &str, _params: Value) -> Result<Value> {
        Ok(Value::Null)
    }

    async fn add_init_script(&self, _source: &str) -> Result<()> {
        Ok(())
    }

    async fn evaluate(&self, expression: &str) -> Result<Value> {
        run_in_chrome(&self.body, expression)
            .map_err(|why| PluginError::other(format!("chrome: {why}")))
    }

    async fn navigate(&self, url: &str) -> Result<()> {
        self.visited.lock().unwrap().push(url.to_owned());
        Ok(())
    }
}

const PRODUCT: &str = r#"
<h1>Widget Pro</h1>
<script type="application/ld+json">
{"@context":"https://schema.org","@type":"Product","name":"Widget Pro","sku":"W-1",
 "releaseDate":"2025-03-09",
 "offers":{"@type":"Offer","price":"19.99","priceCurrency":"USD"}}
</script>
<script type="application/ld+json">{ this is not json</script>
"#;

const TABLE: &str = r#"
<table id="prices">
  <thead><tr><th>Name</th><th>Price</th><th>Released</th></tr></thead>
  <tbody>
    <tr><td>Alpha</td><td>$5.00</td><td>2025-01-02</td></tr>
    <tr><td>Beta</td><td>$7.50</td><td>2025-02-03</td></tr>
    <tr><td>Gamma</td><td>$1,200.00</td><td>2025-03-04</td></tr>
  </tbody>
</table>
"#;

fn cards(count: usize) -> String {
    let mut html = String::from("<div class=\"grid\">");
    for n in 1..=count {
        html.push_str(&format!(
            "<div class=\"card\"><h3 class=\"title\">Card {n}</h3>\
             <span class=\"price\">${n}.00</span>\
             <a class=\"more\" href=\"https://shop.test/item/{n}\">Details</a></div>"
        ));
    }
    html.push_str("</div>");
    html
}

fn extractor() -> Extractor {
    Extractor::new(ExtractorConfig::default()).unwrap()
}

#[test]
#[ignore = "needs Chrome; run alone"]
fn json_ld_gives_a_schema_with_a_money_field_and_the_json_schema_validates_the_records() {
    let page = ChromePage::new(PRODUCT);
    let schemas = block_on(extractor().discover(&page)).unwrap();
    let product = &schemas[0];
    assert_eq!(product.source, Source::JsonLd);
    assert_eq!(product.item.as_deref(), Some("Product"));
    let kind = |name: &str| product.fields.iter().find(|f| f.name == name).unwrap().kind;
    assert_eq!(kind("price"), FieldType::Money, "{product:?}");
    assert_eq!(kind("name"), FieldType::Text);
    assert_eq!(kind("releasedate"), FieldType::Date);

    let found = block_on(extractor().extract(&page, product)).unwrap();
    assert!(found.problems.is_empty(), "{:?}", found.problems);
    assert_eq!(found.records.len(), 1);
    assert_eq!(
        found.records[0]["price"],
        json!({ "amount": 19.99, "currency": "USD" })
    );
    assert_eq!(found.records[0]["name"], "Widget Pro");
    let json_schema = product.json_schema();
    for record in &found.records {
        assert!(valid(&json_schema, record), "{record}");
    }
}

#[test]
#[ignore = "needs Chrome; run alone"]
fn a_table_gives_one_record_per_row_typed_by_column() {
    let page = ChromePage::new(TABLE);
    let schemas = block_on(extractor().discover(&page)).unwrap();
    let table = schemas
        .iter()
        .find(|s| s.source == Source::Table)
        .expect("a table schema");
    assert_eq!(table.skip, 1);
    let names: Vec<_> = table.fields.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(names, ["name", "price", "released"]);
    let kinds: Vec<_> = table.fields.iter().map(|f| f.kind).collect();
    assert_eq!(kinds, [FieldType::Text, FieldType::Money, FieldType::Date]);

    let found = block_on(extractor().extract(&page, table)).unwrap();
    assert!(found.problems.is_empty(), "{:?}", found.problems);
    assert_eq!(found.records.len(), 3);
    assert_eq!(
        found.records[2]["price"],
        json!({ "amount": 1200, "currency": "USD" })
    );
    assert_eq!(found.records[1]["released"], "2025-02-03");
}

#[test]
#[ignore = "needs Chrome; run alone"]
fn five_repeated_cards_give_five_records() {
    let page = ChromePage::new(&cards(5));
    let schemas = block_on(extractor().discover(&page)).unwrap();
    let repeat = schemas
        .iter()
        .find(|s| s.source == Source::Repeat)
        .expect("a repeat schema");
    assert_eq!(repeat.item.as_deref(), Some("div.card"));
    let by = |name: &str| repeat.fields.iter().find(|f| f.name == name);
    assert_eq!(by("title").unwrap().kind, FieldType::Text);
    assert_eq!(by("price").unwrap().kind, FieldType::Money);
    let link = by("more_url").expect("the link field");
    assert_eq!(link.kind, FieldType::Url);
    assert_eq!(link.attr.as_deref(), Some("href"));
    assert!(repeat.fields.iter().all(|f| f.required));

    let found = block_on(extractor().extract(&page, repeat)).unwrap();
    assert!(found.problems.is_empty(), "{:?}", found.problems);
    assert_eq!(found.records.len(), 5);
    assert_eq!(found.records[0]["title"], "Card 1");
    assert_eq!(
        found.records[4]["price"],
        json!({ "amount": 5, "currency": "USD" })
    );
    assert_eq!(found.records[2]["more_url"], "https://shop.test/item/3");
    for record in &found.records {
        assert!(valid(&repeat.json_schema(), record), "{record}");
    }
}

#[test]
#[ignore = "needs Chrome; run alone"]
fn two_cards_are_not_a_list_with_the_default_min_repeats() {
    let page = ChromePage::new(&cards(2));
    let schemas = block_on(extractor().discover(&page)).unwrap();
    assert!(
        schemas.iter().all(|s| s.source != Source::Repeat),
        "{schemas:?}"
    );
    let low = Extractor::new(ExtractorConfig {
        min_repeats: 2,
        ..ExtractorConfig::default()
    })
    .unwrap();
    let schemas = block_on(low.discover(&page)).unwrap();
    assert!(schemas.iter().any(|s| s.source == Source::Repeat));
}

#[test]
#[ignore = "needs Chrome; run alone"]
fn a_select_map_with_an_item_reads_the_named_fields() {
    let page = ChromePage::new(&cards(5));
    let out = block_on(extractor().run_job(
        &page,
        &json!({
            "url": "https://shop.test/",
            "item": ".card",
            "select": {
                "title": "h3",
                "price": { "selector": ".price", "type": "money", "required": true },
                "link": { "selector": "a", "attr": "href", "type": "url" },
                "missing": ".nothing-here",
            },
        }),
    ))
    .unwrap();
    assert_eq!(out["title"], "Fixture");
    assert_eq!(out["records"].as_array().unwrap().len(), 5);
    assert_eq!(out["records"][0]["missing"], Value::Null);
    assert_eq!(out["records"][3]["link"], "https://shop.test/item/4");
    assert_eq!(out["problems"], json!([]));
    assert_eq!(
        page.visited.lock().unwrap().as_slice(),
        ["https://shop.test/"]
    );
}

#[test]
#[ignore = "needs Chrome; run alone"]
fn the_page_parts_come_back_as_asked() {
    let page = ChromePage::new(&format!("{TABLE}{}", cards(3)));
    let out = block_on(extractor().run_job(
        &page,
        &json!({ "text": true, "links": true, "tables": true, "meta": true }),
    ))
    .unwrap();
    assert_eq!(out["title"], "Fixture");
    assert!(out["text"].as_str().unwrap().contains("Card 2"));
    let links: Vec<_> = out["links"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l["href"].as_str().unwrap())
        .collect();
    assert_eq!(
        links,
        [
            "https://shop.test/item/1",
            "https://shop.test/item/2",
            "https://shop.test/item/3"
        ]
    );
    assert_eq!(
        out["tables"][0]["headers"],
        json!(["Name", "Price", "Released"])
    );
    assert_eq!(
        out["tables"][0]["rows"][0],
        json!(["Alpha", "$5.00", "2025-01-02"])
    );
    assert_eq!(out["meta"]["description"], "A fixture");
    assert_eq!(out["meta"]["lang"], "en");
    assert_eq!(out["records"], json!([]));
}

#[test]
#[ignore = "needs Chrome; run alone"]
fn a_bad_selector_is_a_problem_and_the_other_fields_still_come() {
    let page = ChromePage::new(&cards(3));
    let out = block_on(extractor().run_job(
        &page,
        &json!({ "item": ".card", "select": { "title": "h3", "bad": "div[[[" } }),
    ))
    .unwrap();
    assert_eq!(out["records"].as_array().unwrap().len(), 3);
    assert_eq!(out["records"][0]["title"], "Card 1");
    assert_eq!(out["records"][0]["bad"], Value::Null);
    let problem = out["problems"][0]["problem"].as_str().unwrap();
    assert!(problem.starts_with("field bad:"), "{problem}");
}

#[test]
#[ignore = "needs Chrome; run alone"]
fn a_page_bigger_than_max_nodes_is_cut_and_says_so() {
    let page = ChromePage::new(&cards(400));
    let small = Extractor::new(ExtractorConfig {
        max_nodes: 100,
        ..ExtractorConfig::default()
    })
    .unwrap();
    let out = block_on(small.run_job(
        &page,
        &json!({ "item": ".card", "select": { "title": "h3", "price": ".price" } }),
    ))
    .unwrap();
    assert_eq!(out["truncated"], true);
    let records = out["records"].as_array().unwrap().len();
    assert!(records > 0 && records < 400, "{records}");
}

#[test]
#[ignore = "needs Chrome; run alone"]
fn page_text_is_data_and_never_run() {
    // Markup in the text of the page and in a JSON-LD string: if anything ran
    // it, the title would change.
    let hostile = r##"<div class="note">&lt;img src=x onerror="document.title='pwned'"&gt;</div>
        <script type="application/ld+json">{"@type":"Product","name":"<img src=x onerror=\"document.title='pwned'\">"}</script>"##;
    let page = ChromePage::new(hostile);
    let out = block_on(extractor().run_job(&page, &json!({ "text": true }))).unwrap();
    assert_eq!(out["title"], "Fixture");
    assert!(out["text"].as_str().unwrap().contains("onerror"));

    let note: Schema = serde_json::from_value(json!({
        "source": "selectors",
        "fields": [{ "name": "note", "selector": ".note" }],
    }))
    .unwrap();
    let found = block_on(extractor().extract(&page, &note)).unwrap();
    assert!(
        found.records[0]["note"]
            .as_str()
            .unwrap()
            .contains("onerror")
    );

    let out = block_on(extractor().run_job(&page, &json!({}))).unwrap();
    assert_eq!(out["title"], "Fixture");
    assert_eq!(out["schema"]["source"], "json-ld");
    assert!(
        out["records"][0]["name"]
            .as_str()
            .unwrap()
            .contains("onerror")
    );
}
