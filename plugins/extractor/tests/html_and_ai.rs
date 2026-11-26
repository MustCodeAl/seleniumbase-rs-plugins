//! Tests for offline HTML extraction helpers and the `ai` prompt/response module.

use seleniumbase_rs_plugin_extractor::error::ExtractError;
use seleniumbase_rs_plugin_extractor::html::{
    FormData, PageMetadata, TableData, extract_json_ld, extract_json_ld_raw, html_to_markdown,
};
use serde::Deserialize;

#[test]
fn html_markdown_and_metadata_extract_cleanly() {
    let doc = r#"<!doctype html>
    <html lang="en">
      <head>
        <title>Widget Store</title>
        <meta name="description" content="Best widgets online">
        <meta property="og:title" content="Widget Store OG">
        <link rel="canonical" href="https://shop.example/widgets">
      </head>
      <body>
        <nav>Skip me</nav>
        <main>
          <h1>Featured Widgets</h1>
          <p>Read the <a href="https://shop.example/guide">guide</a>.</p>
        </main>
      </body>
    </html>"#;

    let meta = PageMetadata::from_html(doc);
    assert_eq!(meta.title.as_deref(), Some("Widget Store"));
    assert_eq!(meta.description.as_deref(), Some("Best widgets online"));
    assert_eq!(meta.language.as_deref(), Some("en"));
    assert_eq!(
        meta.canonical_url.as_deref(),
        Some("https://shop.example/widgets")
    );

    let md = html_to_markdown(doc);
    assert!(md.contains("Featured Widgets"));
    assert!(md.contains("guide"));
    assert!(!md.contains("Skip me"));
}

#[test]
fn html_json_ld_table_and_form_extract_cleanly() {
    #[derive(Debug, Deserialize, PartialEq)]
    struct Product {
        name: String,
    }

    let doc = r#"<html><head>
      <script type="application/ld+json">{"@type":"Product","name":"Sprocket"}</script>
    </head><body>
      <table>
        <thead><tr><th>name</th><th>qty</th></tr></thead>
        <tbody><tr><td>Bolt</td><td>12</td></tr></tbody>
      </table>
    </body></html>"#;

    let raw = extract_json_ld_raw(doc);
    assert_eq!(raw.len(), 1);
    let typed: Vec<Product> = extract_json_ld(doc).expect("valid json-ld");
    assert_eq!(typed[0].name, "Sprocket");

    let table = TableData::from_html(doc).expect("table present");
    assert_eq!(table.headers(), vec!["name", "qty"]);
    assert_eq!(table.rows(), vec![vec!["Bolt", "12"]]);

    let form = FormData::from_serializable(&serde_json::json!({
        "email": "user@example.com",
        "plan": "pro"
    }))
    .expect("form data");
    assert_eq!(form.get("email"), Some("user@example.com"));

    assert!(matches!(
        TableData::from_html("<p>no table</p>"),
        Err(ExtractError::InvalidInput(_))
    ));
}

#[cfg(feature = "ai")]
mod ai_tests {
    use seleniumbase_rs_plugin_extractor::ai::{
        AiPromptBuilder, object_schema, parse_ai_records, parse_ai_response,
    };
    use seleniumbase_rs_plugin_extractor::error::ExtractError;
    use serde_json::json;

    #[test]
    fn prompt_builder_produces_structured_messages() {
        let schema = object_schema(&[("title", "string"), ("price", "number")]);
        let prompt = AiPromptBuilder::new()
            .json_schema(schema.clone())
            .content("# Widget\nPrice: $19.99")
            .instructions("Extract all listed products.")
            .expect_array(true)
            .build()
            .expect("valid prompt");

        assert!(prompt.system.contains("JSON array"));
        assert!(prompt.user.contains("Extract all listed products."));
        assert!(prompt.user.contains("# Widget"));
        assert_eq!(prompt.json_schema, schema);
    }

    #[test]
    fn prompt_builder_rejects_missing_content_or_schema() {
        let empty = AiPromptBuilder::new()
            .json_schema(object_schema(&[("a", "string")]))
            .content("   ")
            .build();
        assert!(matches!(empty, Err(ExtractError::InvalidInput(_))));

        let no_schema = AiPromptBuilder::new().content("hello").build();
        assert!(matches!(no_schema, Err(ExtractError::InvalidInput(_))));
    }

    #[test]
    fn response_parser_handles_fences_arrays_wrapped_records_and_objects() {
        let fenced = "```json\n[{\"title\":\"Widget\",\"price\":19.99}]\n```";
        let parsed = parse_ai_response(fenced).expect("fenced json");
        assert_eq!(parsed, json!([{"title": "Widget", "price": 19.99}]));

        let records = parse_ai_records(fenced).expect("array records");
        assert_eq!(records.len(), 1);

        let wrapped = r#"{"records": [{"title": "A"}, {"title": "B"}]}"#;
        let wrapped_records = parse_ai_records(wrapped).expect("wrapped records");
        assert_eq!(wrapped_records.len(), 2);

        let single = r#"{"title": "Solo"}"#;
        let single_records = parse_ai_records(single).expect("single object");
        assert_eq!(single_records.len(), 1);

        assert!(matches!(
            parse_ai_records("42"),
            Err(ExtractError::InvalidInput(_))
        ));
    }
}
