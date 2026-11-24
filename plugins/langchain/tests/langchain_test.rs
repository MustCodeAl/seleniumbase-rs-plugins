//! Comprehensive unit and integration tests for seleniumbase-rs-plugin-langchain.

use seleniumbase_rs::extract::PageMetadata;
use seleniumbase_rs_plugin::PluginSet;
use seleniumbase_rs_plugin_langchain::{
    Document, DocumentMetadata, LangChainPlugin, SeleniumBaseLoader, SeleniumBaseTool, ToolAction,
    ToolInput, ToolOutput,
};
use seleniumbase_rs_plugin_testing::{Call, RecordingPage};
use serde_json::json;

#[test]
fn test_document_creation_and_serde() {
    let meta = DocumentMetadata::new("https://example.com/test")
        .title("Test Title")
        .description("Test Description")
        .language("en")
        .author("Rust Dev")
        .canonical_url("https://example.com/test")
        .extra("category", "automation");

    let doc = Document::new("# Hello LangChain\n\nExtracted content.", meta);

    assert_eq!(doc.content(), "# Hello LangChain\n\nExtracted content.");
    assert_eq!(doc.metadata().url, "https://example.com/test");
    assert_eq!(
        doc.metadata().source.as_deref(),
        Some("https://example.com/test")
    );
    assert_eq!(doc.metadata().title.as_deref(), Some("Test Title"));
    assert_eq!(
        doc.metadata().description.as_deref(),
        Some("Test Description")
    );
    assert_eq!(doc.metadata().language.as_deref(), Some("en"));
    assert_eq!(doc.metadata().author.as_deref(), Some("Rust Dev"));
    assert_eq!(
        doc.metadata().canonical_url.as_deref(),
        Some("https://example.com/test")
    );
    assert_eq!(
        doc.metadata().extra.get("category"),
        Some(&serde_json::Value::String("automation".into()))
    );

    // Test JSON serialization matching LangChain document convention
    let serialized = serde_json::to_string(&doc).expect("serialization to succeed");
    let val: serde_json::Value = serde_json::from_str(&serialized).expect("valid JSON");

    assert_eq!(
        val["page_content"],
        "# Hello LangChain\n\nExtracted content."
    );
    assert_eq!(val["metadata"]["url"], "https://example.com/test");
    assert_eq!(val["metadata"]["source"], "https://example.com/test");
    assert_eq!(val["metadata"]["title"], "Test Title");
    assert_eq!(val["metadata"]["description"], "Test Description");
    assert_eq!(val["metadata"]["category"], "automation");

    // Test deserialization roundtrip
    let deserialized: Document = serde_json::from_str(&serialized).expect("deserialization");
    assert_eq!(deserialized, doc);
}

#[test]
fn test_document_metadata_from_page_metadata() {
    let html = r#"
        <!doctype html>
        <html lang="en">
        <head>
            <title>Page Title</title>
            <meta name="description" content="SEO description">
            <meta name="author" content="Author Name">
            <meta property="og:title" content="OG Title">
            <meta property="og:description" content="OG Description">
            <meta property="og:image" content="https://example.com/img.png">
            <meta property="og:type" content="article">
            <link rel="canonical" href="https://example.com/canonical">
            <link rel="icon" href="https://example.com/favicon.ico">
            <meta name="custom-tag" content="custom-value">
        </head>
        <body></body>
        </html>
    "#;

    let page_meta = PageMetadata::from_html(html);
    let meta = DocumentMetadata::from_page_metadata("https://example.com/article", &page_meta);

    assert_eq!(meta.url, "https://example.com/article");
    assert_eq!(meta.source.as_deref(), Some("https://example.com/article"));
    assert_eq!(meta.title.as_deref(), Some("Page Title"));
    assert_eq!(meta.description.as_deref(), Some("SEO description"));
    assert_eq!(meta.language.as_deref(), Some("en"));
    assert_eq!(meta.author.as_deref(), Some("Author Name"));
    assert_eq!(
        meta.canonical_url.as_deref(),
        Some("https://example.com/canonical")
    );
    assert_eq!(
        meta.extra.get("og_image"),
        Some(&serde_json::Value::String(
            "https://example.com/img.png".into()
        ))
    );
    assert_eq!(
        meta.extra.get("og_type"),
        Some(&serde_json::Value::String("article".into()))
    );
    assert_eq!(
        meta.extra.get("favicon"),
        Some(&serde_json::Value::String(
            "https://example.com/favicon.ico".into()
        ))
    );
    assert_eq!(
        meta.extra.get("custom-tag"),
        Some(&serde_json::Value::String("custom-value".into()))
    );
}

#[test]
fn test_loader_html_to_markdown() {
    let html = r#"
        <!doctype html>
        <html>
        <head>
            <title>Rust Docs</title>
            <meta name="description" content="Language docs">
        </head>
        <body>
            <nav><a href="/home">Home</a></nav>
            <main>
                <h1>SeleniumBase Rust</h1>
                <p>A fast port of <strong>SeleniumBase</strong> to Rust.</p>
                <ul>
                    <li>CDP Engine</li>
                    <li>WebDriver</li>
                </ul>
                <pre><code>let x = 42;</code></pre>
            </main>
            <footer>Copyright 2026</footer>
        </body>
        </html>
    "#;

    let loader = SeleniumBaseLoader::new();
    let doc = loader.load_html(html, "https://example.com/docs");

    assert!(doc.page_content.contains("# SeleniumBase Rust"));
    assert!(doc.page_content.contains("SeleniumBase"));
    assert!(doc.page_content.contains("CDP Engine"));
    assert!(doc.page_content.contains("let x = 42;"));
    // Verify noisy boilerplate tags like nav/footer are excluded
    assert!(!doc.page_content.contains("Copyright 2026"));

    assert_eq!(doc.metadata.url, "https://example.com/docs");
    assert_eq!(doc.metadata.title.as_deref(), Some("Rust Docs"));
    assert_eq!(doc.metadata.description.as_deref(), Some("Language docs"));
}

#[test]
fn test_loader_options() {
    let html = r#"
        <html>
        <head><title>Options Test</title></head>
        <body>
            <p>Visit <a href="https://example.com">Example</a> for info.</p>
            <img src="test.png" alt="Test Image">
        </body>
        </html>
    "#;

    // Test strip_links
    let loader_no_links = SeleniumBaseLoader::new().strip_links(true);
    let doc = loader_no_links.load_html(html, "https://example.com");
    assert!(doc.page_content.contains("Example"));
    assert!(!doc.page_content.contains("[Example](https://example.com)"));

    // Test max_characters
    let loader_capped = SeleniumBaseLoader::new().max_characters(Some(10));
    let doc_capped = loader_capped.load_html(html, "https://example.com");
    assert!(doc_capped.page_content.len() <= 10);

    // Test extract_metadata disabled
    let loader_no_meta = SeleniumBaseLoader::new().extract_metadata(false);
    let doc_no_meta = loader_no_meta.load_html(html, "https://example.com");
    assert_eq!(doc_no_meta.metadata.title, None);
    assert_eq!(doc_no_meta.metadata.url, "https://example.com");
}

#[tokio::test]
async fn test_loader_recording_page() {
    let html = r#"
        <html>
        <head><title>Dynamic Page</title></head>
        <body>
            <article>
                <h1>Dynamic Title</h1>
                <p>Loaded via PageHandle evaluate.</p>
            </article>
        </body>
        </html>
    "#;

    let page = RecordingPage::new()
        .at("https://example.com/dynamic")
        .evaluating("document.documentElement.outerHTML", json!(html));

    let loader = SeleniumBaseLoader::new();
    let doc = loader.load_page(&page).await.expect("page load to succeed");

    assert!(doc.page_content.contains("# Dynamic Title"));
    assert!(doc.page_content.contains("Loaded via PageHandle evaluate."));
    assert_eq!(doc.metadata.url, "https://example.com/dynamic");
    assert_eq!(doc.metadata.title.as_deref(), Some("Dynamic Page"));
}

#[tokio::test]
async fn test_loader_load_urls() {
    let html1 = "<html><head><title>P1</title></head><body><h1>Page 1</h1></body></html>";

    let page = RecordingPage::new()
        .at("https://example.com/p1")
        .evaluating("document.documentElement.outerHTML", json!(html1));

    let loader =
        SeleniumBaseLoader::from_urls(["https://example.com/p1", "https://example.com/p2"]);
    assert_eq!(
        loader.urls(),
        &["https://example.com/p1", "https://example.com/p2"]
    );

    let doc1 = loader
        .load_url(&page, "https://example.com/p1")
        .await
        .expect("load url 1");
    assert!(doc1.page_content.contains("# Page 1"));
    assert_eq!(doc1.metadata.title.as_deref(), Some("P1"));

    // Check calls recorded
    let calls = page.calls();
    assert!(calls.contains(&Call::Navigate("https://example.com/p1".into())));
}

#[test]
fn test_tool_schema_and_definition() {
    let tool = SeleniumBaseTool::new()
        .with_name("my_browser_tool")
        .with_description("Custom browser tool");

    assert_eq!(tool.name(), "my_browser_tool");
    assert_eq!(tool.description(), "Custom browser tool");

    let schema = tool.schema();
    assert_eq!(schema["type"], "object");
    let actions = schema["properties"]["action"]["enum"]
        .as_array()
        .expect("array");
    let action_strings: Vec<&str> = actions.iter().filter_map(|v| v.as_str()).collect();
    assert!(action_strings.contains(&"navigate"));
    assert!(action_strings.contains(&"click"));
    assert!(action_strings.contains(&"type_text"));
    assert!(action_strings.contains(&"extract_markdown"));

    assert_eq!(schema["required"], json!(["action"]));

    let def = tool.tool_definition();
    assert_eq!(def["type"], "function");
    assert_eq!(def["function"]["name"], "my_browser_tool");
    assert_eq!(def["function"]["description"], "Custom browser tool");
    assert_eq!(def["function"]["parameters"], schema);
}

#[test]
fn test_tool_input_parsing() {
    // Navigate
    let nav_input = ToolInput {
        action: "navigate".into(),
        url: Some("https://example.com".into()),
        selector: None,
        text: None,
    };
    assert_eq!(
        nav_input.into_action().expect("valid navigate"),
        ToolAction::Navigate {
            url: "https://example.com".into()
        }
    );

    // Click
    let click_input = ToolInput {
        action: "click".into(),
        url: None,
        selector: Some("#submit-btn".into()),
        text: None,
    };
    assert_eq!(
        click_input.into_action().expect("valid click"),
        ToolAction::Click {
            selector: "#submit-btn".into()
        }
    );

    // Type text
    let type_input = ToolInput {
        action: "type_text".into(),
        url: None,
        selector: Some("#input-field".into()),
        text: Some("my input".into()),
    };
    assert_eq!(
        type_input.into_action().expect("valid type_text"),
        ToolAction::TypeText {
            selector: "#input-field".into(),
            text: "my input".into()
        }
    );

    // Type synonym "fill"
    let fill_input = ToolInput {
        action: "fill".into(),
        url: None,
        selector: Some("#search".into()),
        text: Some("query".into()),
    };
    assert_eq!(
        fill_input.into_action().expect("valid fill synonym"),
        ToolAction::TypeText {
            selector: "#search".into(),
            text: "query".into()
        }
    );

    // Extract markdown
    let extract_input = ToolInput {
        action: "extract_markdown".into(),
        url: None,
        selector: Some("main.content".into()),
        text: None,
    };
    assert_eq!(
        extract_input.into_action().expect("valid extract_markdown"),
        ToolAction::ExtractMarkdown {
            selector: Some("main.content".into())
        }
    );

    // Missing required field: click without selector
    let invalid_click = ToolInput {
        action: "click".into(),
        url: None,
        selector: None,
        text: None,
    };
    assert!(invalid_click.into_action().is_err());

    // Missing required field: type_text without text
    let invalid_type = ToolInput {
        action: "type_text".into(),
        url: None,
        selector: Some("#input".into()),
        text: None,
    };
    assert!(invalid_type.into_action().is_err());

    // Unknown action
    let unknown_action = ToolInput {
        action: "teleport".into(),
        url: None,
        selector: None,
        text: None,
    };
    assert!(unknown_action.into_action().is_err());
}

#[tokio::test]
async fn test_tool_execute_navigate() {
    let page = RecordingPage::new();
    let tool = SeleniumBaseTool::new();

    let action = ToolAction::Navigate {
        url: "https://example.com/login".into(),
    };

    let output = tool.execute(action, &page).await.expect("execute navigate");
    assert!(output.success);
    assert_eq!(
        output.result.as_deref(),
        Some("Navigated to https://example.com/login")
    );

    let calls = page.calls();
    assert!(calls.contains(&Call::Navigate("https://example.com/login".into())));
}

#[tokio::test]
async fn test_tool_execute_click_success_and_failure() {
    let tool = SeleniumBaseTool::new();

    // Success case
    let page_ok =
        RecordingPage::new().evaluating("document.querySelector", json!({ "success": true }));
    let output_ok = tool
        .execute(
            ToolAction::Click {
                selector: "#submit".into(),
            },
            &page_ok,
        )
        .await
        .expect("click execution");

    assert!(output_ok.success);
    assert!(
        output_ok
            .result
            .unwrap()
            .contains("Successfully clicked element '#submit'")
    );

    // Failure case (element not found)
    let page_fail = RecordingPage::new().evaluating(
        "document.querySelector",
        json!({ "success": false, "error": "Element not found" }),
    );
    let output_fail = tool
        .execute(
            ToolAction::Click {
                selector: "#missing".into(),
            },
            &page_fail,
        )
        .await
        .expect("click execution");

    assert!(!output_fail.success);
    assert!(
        output_fail
            .error
            .unwrap()
            .contains("Failed to click '#missing': Element not found")
    );
}

#[tokio::test]
async fn test_tool_execute_type_text_success_and_failure() {
    let tool = SeleniumBaseTool::new();

    // Success case
    let page_ok =
        RecordingPage::new().evaluating("document.querySelector", json!({ "success": true }));
    let output_ok = tool
        .execute(
            ToolAction::TypeText {
                selector: "#username".into(),
                text: "admin".into(),
            },
            &page_ok,
        )
        .await
        .expect("type_text execution");

    assert!(output_ok.success);
    assert!(
        output_ok
            .result
            .unwrap()
            .contains("Successfully typed text into element '#username'")
    );

    // Failure case
    let page_fail = RecordingPage::new().evaluating(
        "document.querySelector",
        json!({ "success": false, "error": "Element not found" }),
    );
    let output_fail = tool
        .execute(
            ToolAction::TypeText {
                selector: "#missing-input".into(),
                text: "admin".into(),
            },
            &page_fail,
        )
        .await
        .expect("type_text execution");

    assert!(!output_fail.success);
    assert!(
        output_fail
            .error
            .unwrap()
            .contains("Failed to type into '#missing-input'")
    );
}

#[tokio::test]
async fn test_tool_execute_extract_markdown() {
    let tool = SeleniumBaseTool::new();

    let html = "<div><h2>Product Features</h2><ul><li>Fast</li><li>Reliable</li></ul></div>";
    let page = RecordingPage::new().evaluating(
        "document.documentElement.outerHTML",
        json!({ "success": true, "html": html }),
    );

    let output = tool
        .execute(ToolAction::ExtractMarkdown { selector: None }, &page)
        .await
        .expect("extract markdown");

    assert!(output.success);
    let md = output.result.expect("markdown result");
    assert!(md.contains("## Product Features"));
    assert!(md.contains("Fast"));
    assert!(md.contains("Reliable"));
}

#[tokio::test]
async fn test_tool_execute_json_and_raw() {
    let tool = SeleniumBaseTool::new();
    let page = RecordingPage::new();

    // Test execute_json
    let json_arg = json!({
        "action": "navigate",
        "url": "https://example.com/search"
    });
    let output = tool
        .execute_json(&json_arg, &page)
        .await
        .expect("execute_json");
    assert!(output.success);

    // Test execute_raw
    let raw_str = r#"{"action":"navigate","url":"https://example.com/results"}"#;
    let raw_out = tool.execute_raw(raw_str, &page).await.expect("execute_raw");
    let parsed: ToolOutput = serde_json::from_str(&raw_out).expect("parsed output");
    assert!(parsed.success);
    assert_eq!(
        parsed.result.as_deref(),
        Some("Navigated to https://example.com/results")
    );
}

#[test]
fn test_plugin_set_registration() {
    let plugin = LangChainPlugin::new();
    let set = PluginSet::new()
        .with(plugin)
        .expect("plugin registration to succeed");
    assert!(set.names().contains(&"langchain"));
}
