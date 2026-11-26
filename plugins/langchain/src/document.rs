//! LangChain-compatible Document and DocumentMetadata structures.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// A LangChain-compatible document representing extracted web content.
///
/// Follows the LangChain schema with [`page_content`] holding the extracted
/// LLM-ready markdown, and [`metadata`] containing page metadata such as URL,
/// title, and description.
///
/// # Examples
///
/// ```
/// use seleniumbase_rs_plugin_langchain::{Document, DocumentMetadata};
///
/// let meta = DocumentMetadata::new("https://example.com")
///     .title("Example Domain")
///     .description("An example website for demonstration.");
///
/// let doc = Document::new("# Example Domain\n\nThis is demo content.", meta);
/// assert_eq!(doc.page_content, "# Example Domain\n\nThis is demo content.");
/// assert_eq!(doc.metadata.url, "https://example.com");
/// assert_eq!(doc.metadata.title.as_deref(), Some("Example Domain"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Document {
    /// The text content of the document, typically in clean Markdown format.
    pub page_content: String,
    /// Associated metadata for the document (URL, title, description, etc.).
    pub metadata: DocumentMetadata,
}

impl Document {
    /// Creates a new `Document` with the given markdown content and metadata.
    #[must_use]
    pub fn new(page_content: impl Into<String>, metadata: DocumentMetadata) -> Self {
        Self {
            page_content: page_content.into(),
            metadata,
        }
    }

    /// Returns a reference to the page content.
    #[must_use]
    pub fn content(&self) -> &str {
        &self.page_content
    }

    /// Returns a reference to the document metadata.
    #[must_use]
    pub fn metadata(&self) -> &DocumentMetadata {
        &self.metadata
    }
}

/// Metadata associated with a [`Document`].
///
/// Contains standard metadata keys recognized by LangChain loaders (`url`,
/// `source`, `title`, `description`) as well as optional SEO and OpenGraph attributes.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DocumentMetadata {
    /// The page address / URL.
    pub url: String,
    /// The page title (`<title>` or `og:title`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Meta description (`<meta name="description">` or `og:description`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// LangChain convention: the source identifier (defaults to URL).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// The page language code (`<html lang="...">`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    /// Author (`<meta name="author">`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    /// Canonical URL (`<link rel="canonical">`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub canonical_url: Option<String>,
    /// Additional custom or OpenGraph metadata attributes.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl DocumentMetadata {
    /// Creates a new `DocumentMetadata` with the specified URL.
    /// Sets both `url` and `source` to the given URL.
    #[must_use]
    pub fn new(url: impl Into<String>) -> Self {
        let url_str = url.into();
        Self {
            source: Some(url_str.clone()),
            url: url_str,
            title: None,
            description: None,
            language: None,
            author: None,
            canonical_url: None,
            extra: BTreeMap::new(),
        }
    }

    /// Constructs `DocumentMetadata` from extracted [`seleniumbase_rs_plugin_extractor::html::PageMetadata`].
    #[must_use]
    pub fn from_page_metadata(
        url: impl Into<String>,
        meta: &seleniumbase_rs_plugin_extractor::html::PageMetadata,
    ) -> Self {
        let url_str = url.into();
        let mut extra = BTreeMap::new();

        if let Some(og_title) = &meta.og_title {
            extra.insert("og_title".to_string(), Value::String(og_title.clone()));
        }
        if let Some(og_desc) = &meta.og_description {
            extra.insert("og_description".to_string(), Value::String(og_desc.clone()));
        }
        if let Some(og_image) = &meta.og_image {
            extra.insert("og_image".to_string(), Value::String(og_image.clone()));
        }
        if let Some(og_type) = &meta.og_type {
            extra.insert("og_type".to_string(), Value::String(og_type.clone()));
        }
        if let Some(favicon) = &meta.favicon {
            extra.insert("favicon".to_string(), Value::String(favicon.clone()));
        }
        for (k, v) in &meta.custom {
            extra.insert(k.clone(), Value::String(v.clone()));
        }

        Self {
            source: Some(url_str.clone()),
            url: url_str,
            title: meta.title.clone().or_else(|| meta.og_title.clone()),
            description: meta
                .description
                .clone()
                .or_else(|| meta.og_description.clone()),
            language: meta.language.clone(),
            author: meta.author.clone(),
            canonical_url: meta.canonical_url.clone(),
            extra,
        }
    }

    /// Sets the document title.
    #[must_use]
    pub fn title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }

    /// Sets the document description.
    #[must_use]
    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Sets the document source identifier.
    #[must_use]
    pub fn source(mut self, source: impl Into<String>) -> Self {
        self.source = Some(source.into());
        self
    }

    /// Sets the document language code.
    #[must_use]
    pub fn language(mut self, lang: impl Into<String>) -> Self {
        self.language = Some(lang.into());
        self
    }

    /// Sets the document author.
    #[must_use]
    pub fn author(mut self, author: impl Into<String>) -> Self {
        self.author = Some(author.into());
        self
    }

    /// Sets the canonical URL.
    #[must_use]
    pub fn canonical_url(mut self, url: impl Into<String>) -> Self {
        self.canonical_url = Some(url.into());
        self
    }

    /// Inserts an extra metadata field.
    #[must_use]
    pub fn extra(mut self, key: impl Into<String>, value: impl Into<Value>) -> Self {
        self.extra.insert(key.into(), value.into());
        self
    }
}
