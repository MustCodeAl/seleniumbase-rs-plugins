//! Error types for synthetic behavioral dataset generation and export.

use thiserror::Error;

/// Failures produced when configuring, generating, or exporting behavioral datasets.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DatasetError {
    /// Core humanizer behavior parameters failed validation.
    #[error("invalid behavior configuration: {0}")]
    InvalidBehavior(#[from] seleniumbase_rs::SeleniumBaseError),

    /// Dataset generator configuration or input override is invalid.
    #[error("invalid dataset configuration: {0}")]
    InvalidConfig(String),

    /// Parsing an enum or identifier from text failed.
    #[error("invalid value `{value}` for {kind}")]
    Parse {
        /// The type or field being parsed.
        kind: &'static str,
        /// The invalid input string.
        value: String,
    },

    /// JSON or JSONL serialization failed.
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Formatting CSV or text output failed.
    #[error("formatting error: {0}")]
    Format(#[from] std::fmt::Error),
}

/// Result alias for `seleniumbase-rs-plugin-behavior-dataset`.
pub type Result<T> = std::result::Result<T, DatasetError>;
