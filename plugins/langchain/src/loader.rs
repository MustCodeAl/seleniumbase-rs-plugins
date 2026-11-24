//! LangChain document loader for web pages using seleniumbase-rs.

use crate::document::{Document, DocumentMetadata};
use crate::error::{LangChainError, Result};
use seleniumbase_rs::extract::{MarkdownOptions, PageMetadata, html_to_markdown_with};

#[cfg(feature = "plugin")]
use seleniumbase_rs_plugin::PageHandle;

/// A LangChain-compatible document loader that extracts clean Markdown
/// and rich page metadata from web pages.
///
/// Uses [`seleniumbase_rs::extract::html_to_markdown`] for token-efficient content
/// conversion and [`seleniumbase_rs::extract::PageMetadata`] for structured head tags.
///
/// # Examples
///
/// ```
/// use seleniumbase_rs_plugin_langchain::SeleniumBaseLoader;
///
/// let html = r#"
///     <!doctype html>
///     <html>
///     <head>
///         <title>Rust Web Scraping</title>
///         <meta name="description" content="High performance web extraction.">
///     </head>
///     <body>
///         <article>
///             <h1>Rust Automation</h1>
///             <p>Fast, reliable, and type-safe.</p>
///         </article>
///     </body>
///     </html>
/// "#;
///
/// let loader = SeleniumBaseLoader::new();
/// let doc = loader.load_html(html, "https://example.com/rust");
///
/// assert!(doc.page_content.contains("# Rust Automation"));
/// assert_eq!(doc.metadata.url, "https://example.com/rust");
/// assert_eq!(doc.metadata.title.as_deref(), Some("Rust Web Scraping"));
/// assert_eq!(
///     doc.metadata.description.as_deref(),
///     Some("High performance web extraction.")
/// );
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeleniumBaseLoader {
    /// URLs configured to load.
    urls: Vec<String>,
    /// Optional CSS selector to scope extraction to a specific sub-tree.
    selector: Option<String>,
    /// Whether to strip hyperlinks in markdown output.
    strip_links: bool,
    /// Whether to strip images in markdown output.
    strip_images: bool,
    /// Optional maximum character limit for extracted markdown.
    max_characters: Option<usize>,
    /// Whether to extract head metadata (title, description, OpenGraph).
    extract_metadata: bool,
}

impl Default for SeleniumBaseLoader {
    fn default() -> Self {
        Self {
            urls: Vec::new(),
            selector: None,
            strip_links: false,
            strip_images: false,
            max_characters: None,
            extract_metadata: true,
        }
    }
}

impl SeleniumBaseLoader {
    /// Creates a new `SeleniumBaseLoader` with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a `SeleniumBaseLoader` configured for a single URL.
    #[must_use]
    pub fn from_url(url: impl Into<String>) -> Self {
        Self {
            urls: vec![url.into()],
            ..Self::default()
        }
    }

    /// Creates a `SeleniumBaseLoader` configured for multiple URLs.
    #[must_use]
    pub fn from_urls(urls: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            urls: urls.into_iter().map(Into::into).collect(),
            ..Self::default()
        }
    }

    /// Returns the list of configured target URLs.
    #[must_use]
    pub fn urls(&self) -> &[String] {
        &self.urls
    }

    /// Scopes content extraction to the elements matching `selector`.
    #[must_use]
    pub fn selector(mut self, selector: impl Into<String>) -> Self {
        self.selector = Some(selector.into());
        self
    }

    /// Configures whether to strip hyperlinks in the extracted Markdown.
    #[must_use]
    pub fn strip_links(mut self, strip: bool) -> Self {
        self.strip_links = strip;
        self
    }

    /// Configures whether to strip images in the extracted Markdown.
    #[must_use]
    pub fn strip_images(mut self, strip: bool) -> Self {
        self.strip_images = strip;
        self
    }

    /// Sets a maximum character limit for the extracted Markdown content.
    #[must_use]
    pub fn max_characters(mut self, max: Option<usize>) -> Self {
        self.max_characters = max;
        self
    }

    /// Configures whether to extract page metadata (title, description, etc.).
    #[must_use]
    pub fn extract_metadata(mut self, extract: bool) -> Self {
        self.extract_metadata = extract;
        self
    }

    /// Loads a web document directly from an HTML string and URL (synchronous/offline).
    ///
    /// # Examples
    ///
    /// ```
    /// use seleniumbase_rs_plugin_langchain::SeleniumBaseLoader;
    ///
    /// let loader = SeleniumBaseLoader::new();
    /// let doc = loader.load_html("<h1>Hello</h1>", "https://example.com");
    /// assert!(doc.page_content.contains("# Hello"));
    /// assert_eq!(doc.metadata.url, "https://example.com");
    /// ```
    #[must_use]
    pub fn load_html(&self, html: &str, url: &str) -> Document {
        let markdown_options = MarkdownOptions::new()
            .strip_links(self.strip_links)
            .strip_images(self.strip_images)
            .max_characters(self.max_characters);

        let page_content = html_to_markdown_with(html, &markdown_options);

        let metadata = if self.extract_metadata {
            let meta = PageMetadata::from_html(html);
            DocumentMetadata::from_page_metadata(url, &meta)
        } else {
            DocumentMetadata::new(url)
        };

        Document::new(page_content, metadata)
    }

    /// Loads the currently opened page from a [`PageHandle`] into a [`Document`].
    ///
    /// # Errors
    ///
    /// Returns [`LangChainError`] if retrieving the URL or DOM HTML from the page fails.
    #[cfg(feature = "plugin")]
    pub async fn load_page(&self, page: &dyn PageHandle) -> Result<Document> {
        let url = page
            .url()
            .await
            .map_err(|e| LangChainError::Page(format!("failed to get page url: {e}")))?;

        let script = if let Some(sel) = &self.selector {
            let sel_escaped = serde_json::to_string(sel)?;
            format!(
                r#"(() => {{
                    const el = document.querySelector({sel_escaped});
                    return el ? el.outerHTML : document.documentElement.outerHTML;
                }})()"#
            )
        } else {
            "document.documentElement.outerHTML".to_string()
        };

        let html_val = page.evaluate(&script).await.map_err(|e| {
            LangChainError::Page(format!("failed to evaluate html extraction: {e}"))
        })?;

        let html = match html_val {
            serde_json::Value::String(s) => s,
            other => other.to_string(),
        };

        Ok(self.load_html(&html, &url))
    }

    /// Navigates the page to `url` and loads it into a [`Document`].
    ///
    /// # Errors
    ///
    /// Returns [`LangChainError`] if navigation or page extraction fails.
    #[cfg(feature = "plugin")]
    pub async fn load_url(&self, page: &dyn PageHandle, url: &str) -> Result<Document> {
        page.navigate(url)
            .await
            .map_err(|e| LangChainError::Page(format!("failed to navigate to {url}: {e}")))?;

        self.load_page(page).await
    }

    /// Loads all configured URLs or the current page if no URLs were specified.
    ///
    /// # Errors
    ///
    /// Returns [`LangChainError`] if navigation or extraction fails on any page.
    #[cfg(feature = "plugin")]
    pub async fn load(&self, page: &dyn PageHandle) -> Result<Vec<Document>> {
        if self.urls.is_empty() {
            let doc = self.load_page(page).await?;
            Ok(vec![doc])
        } else {
            let mut docs = Vec::with_capacity(self.urls.len());
            for url in &self.urls {
                let doc = self.load_url(page, url).await?;
                docs.push(doc);
            }
            Ok(docs)
        }
    }

    /// Loads the current page in a [`seleniumbase_rs::BaseCase`] session.
    ///
    /// # Errors
    ///
    /// Returns [`LangChainError`] if reading the current URL or page source fails.
    pub async fn load_base_case(&self, sb: &mut seleniumbase_rs::BaseCase) -> Result<Document> {
        let url = sb.current_url().await?;
        let html = sb.page_source().await?;
        Ok(self.load_html(&html, &url))
    }

    /// Navigates a [`seleniumbase_rs::BaseCase`] session to `url` and loads the document.
    ///
    /// # Errors
    ///
    /// Returns [`LangChainError`] if opening the URL or reading page source fails.
    pub async fn load_url_base_case(
        &self,
        sb: &mut seleniumbase_rs::BaseCase,
        url: &str,
    ) -> Result<Document> {
        sb.open(url).await?;
        self.load_base_case(sb).await
    }
}
