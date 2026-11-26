//! LangChain integration plugin for seleniumbase-rs.
//!
//! Provides two core components for LLM and agentic workflows:
//! 1. [`SeleniumBaseLoader`]: Loads web pages into LangChain-compatible [`Document`] structures.
//!    Extracts token-efficient, clean Markdown via [`seleniumbase_rs_plugin_extractor::html::html_to_markdown`]
//!    and structured metadata (`url`, `title`, `description`, `source`) via
//!    [`seleniumbase_rs_plugin_extractor::html::PageMetadata`].
//! 2. [`SeleniumBaseTool`]: Tool-calling interface for LangChain and OpenAI-compatible agents.
//!    Supports `navigate`, `click`, `type_text`, and `extract_markdown` actions with full JSON Schema.
//!
//! # Examples
//!
//! ## Loading Documents for RAG / Search
//!
//! ```
//! use seleniumbase_rs_plugin_langchain::{Document, SeleniumBaseLoader};
//!
//! let html = r#"
//!     <!doctype html>
//!     <html>
//!     <head>
//!         <title>LangChain Integration</title>
//!         <meta name="description" content="Connecting SeleniumBase to LangChain pipelines.">
//!     </head>
//!     <body>
//!         <main>
//!             <h1>Automation with Rust</h1>
//!             <p>High speed, memory safe web extraction.</p>
//!         </main>
//!     </body>
//!     </html>
//! "#;
//!
//! let loader = SeleniumBaseLoader::new();
//! let doc = loader.load_html(html, "https://example.com/docs");
//!
//! assert!(doc.page_content.contains("# Automation with Rust"));
//! assert_eq!(doc.metadata.url, "https://example.com/docs");
//! assert_eq!(doc.metadata.title.as_deref(), Some("LangChain Integration"));
//! ```
//!
//! ## Agent Tool Calling
//!
//! ```
//! use seleniumbase_rs_plugin_langchain::{SeleniumBaseTool, ToolAction, ToolInput};
//!
//! let tool = SeleniumBaseTool::new();
//! let schema = tool.schema();
//! assert_eq!(schema["type"], "object");
//!
//! // Deserializing an LLM tool call payload:
//! let json_call = serde_json::json!({
//!     "action": "navigate",
//!     "url": "https://example.com"
//! });
//! let action: ToolAction = serde_json::from_value(json_call).unwrap();
//! assert_eq!(action, ToolAction::Navigate { url: "https://example.com".into() });
//! ```

#![warn(missing_docs)]

pub mod document;
pub mod error;
pub mod loader;
pub mod tool;

pub use document::{Document, DocumentMetadata};
pub use error::{LangChainError, Result};
pub use loader::SeleniumBaseLoader;
pub use tool::{SeleniumBaseTool, ToolAction, ToolInput, ToolOutput};

#[cfg(feature = "plugin")]
use seleniumbase_rs_plugin::{Capability, Category, Metadata, Plugin, async_trait};

/// Plugin implementation of the LangChain integration for seleniumbase-rs.
#[cfg(feature = "plugin")]
#[derive(Debug, Clone, Default)]
pub struct LangChainPlugin {
    loader: SeleniumBaseLoader,
    tool: SeleniumBaseTool,
}

#[cfg(feature = "plugin")]
impl LangChainPlugin {
    /// Creates a new `LangChainPlugin`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns a reference to the configured [`SeleniumBaseLoader`].
    #[must_use]
    pub fn loader(&self) -> &SeleniumBaseLoader {
        &self.loader
    }

    /// Returns a reference to the configured [`SeleniumBaseTool`].
    #[must_use]
    pub fn tool(&self) -> &SeleniumBaseTool {
        &self.tool
    }
}

#[cfg(feature = "plugin")]
#[async_trait]
impl Plugin for LangChainPlugin {
    fn name(&self) -> &str {
        "langchain"
    }

    fn metadata(&self) -> Metadata {
        Metadata::new(Category::Core)
            .version(env!("CARGO_PKG_VERSION"))
            .summary("LangChain integration: document loader and agent tool-calling interface")
            .capabilities([Capability::PageEvaluate, Capability::PageNavigate])
    }
}
