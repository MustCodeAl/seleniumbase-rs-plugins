//! Error types for offline HTML and AI extraction helpers.

use thiserror::Error;

/// Errors produced by HTML parsing, form serialization, and AI response parsing.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ExtractError {
    /// Input HTML or prompt/response content was invalid or missing expected structure.
    #[error("invalid extraction input: {0}")]
    InvalidInput(String),
    /// JSON serialization or deserialization failed.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}
