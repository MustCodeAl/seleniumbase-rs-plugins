//! Error types for the defensive OWASP and PTK security auditing plugin.

use std::path::PathBuf;

/// Result alias using [`OwaspError`] as the default error type.
pub type Result<T, E = OwaspError> = std::result::Result<T, E>;

/// Errors produced by configuration, PTK manifest/catalog loading, passive
/// parsing, or plugin host integration.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum OwaspError {
    /// Invalid configuration or option value.
    #[error("owasp configuration error: {0}")]
    Config(String),
    /// Filesystem read or metadata error.
    #[error("I/O error at `{}`: {source}", path.display())]
    Io {
        /// Path associated with the I/O failure.
        path: PathBuf,
        /// Underlying OS error.
        #[source]
        source: std::io::Error,
    },
    /// JSON parsing or serialization error.
    #[error("JSON error ({context}): {source}")]
    Json {
        /// Where the JSON failure occurred.
        context: String,
        /// Underlying `serde_json` error.
        #[source]
        source: serde_json::Error,
    },
    /// Invalid PTK or Chromium browser extension directory or archive.
    #[error("invalid PTK extension at `{}`: {reason}", path.display())]
    InvalidExtension {
        /// Extension directory or archive path.
        path: PathBuf,
        /// Why validation failed.
        reason: String,
    },
    /// Malformed JWT string encountered during passive decoding.
    #[error("invalid JWT format: {0}")]
    InvalidJwt(String),
    /// Malformed HTTP header or `Set-Cookie` syntax.
    #[error("invalid header syntax: {0}")]
    InvalidHeader(String),
    /// Page evaluation or snapshot extraction failure.
    #[error("page evaluation error: {0}")]
    Evaluation(String),
    /// Error propagated from the plugin host API.
    #[cfg(feature = "plugin")]
    #[error("plugin error: {0}")]
    Plugin(#[from] seleniumbase_rs_plugin::PluginError),
    /// Unclassified error.
    #[error("{0}")]
    Other(String),
}
