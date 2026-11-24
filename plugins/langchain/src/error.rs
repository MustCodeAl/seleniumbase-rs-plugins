//! Error types for the LangChain integration plugin.

use thiserror::Error;

/// Result type alias for LangChain operations.
pub type Result<T, E = LangChainError> = std::result::Result<T, E>;

/// Errors that can occur during LangChain document loading or tool execution.
#[derive(Debug, Error)]
pub enum LangChainError {
    /// An error occurred while interacting with a web page.
    #[error("page operation failed: {0}")]
    Page(String),

    /// A required element was not found in the DOM.
    #[error("element not found matching selector: {0}")]
    ElementNotFound(String),

    /// Invalid or malformed tool input was supplied.
    #[error("invalid tool input: {0}")]
    InvalidInput(String),

    /// An error occurred during HTML-to-markdown or metadata extraction.
    #[error("extraction failed: {0}")]
    Extraction(String),

    /// Serialization or deserialization of JSON payload failed.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// A plugin-level error occurred.
    #[cfg(feature = "plugin")]
    #[error("plugin error: {0}")]
    Plugin(#[from] seleniumbase_rs_plugin::PluginError),

    /// A SeleniumBase core error occurred.
    #[error("seleniumbase error: {0}")]
    SeleniumBase(#[from] seleniumbase_rs::error::SeleniumBaseError),
}
