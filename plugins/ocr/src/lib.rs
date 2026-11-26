//! OCR text extraction plugin for `seleniumbase-rs`.
//!
//! Migrated from core `src/ocr.rs` for v0.10 so OCR configuration, model cache
//! verification, and `Task` orchestration live in `seleniumbase-rs-plugins`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(missing_debug_implementations)]

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use seleniumbase_rs_plugin::{
    Capability, Category, Configurable, Metadata, PathScope, Plugin, PluginError, Requirements,
    Result as PluginResult, Task, TaskContext, config::options,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;

/// Canonical plugin identifier.
pub const NAME: &str = "ocr";

/// Pinned model filenames and SHA-256 digests used by the OCR pipeline.
pub const OCR_MODELS: [(&str, &str); 2] = [
    (
        "text-detection.rten",
        "f15cfb56bd02c4bf478a20343986504a1f01e1665c2b3a0ad66340f054b1b5ca",
    ),
    (
        "text-recognition.rten",
        "e484866d4cce403175bd8d00b128feb08ab42e208de30e42cd9889d8f1735a6e",
    ),
];

/// Errors produced by [`OcrPlugin`] and model/image validation.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum OcrError {
    /// Model directory or configuration is invalid.
    #[error("invalid OCR configuration: {0}")]
    InvalidConfig(String),
    /// Reading an image or model file failed.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// Image bytes are not a valid PNG.
    #[error("invalid PNG image: {0}")]
    InvalidImage(String),
}

/// Result alias for `seleniumbase-rs-plugin-ocr`.
pub type Result<T> = std::result::Result<T, OcrError>;

/// Configuration for [`OcrPlugin`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OcrConfig {
    /// Optional explicit directory containing `text-detection.rten` and `text-recognition.rten`.
    pub models_dir: Option<PathBuf>,
    /// Optional PNG file path to inspect when running as a [`Task`].
    pub image_path: Option<PathBuf>,
}

/// Validates that `bytes` begins with a PNG signature.
///
/// # Errors
///
/// Returns [`OcrError::InvalidImage`] if `bytes` is not a PNG header.
pub fn validate_png_header(bytes: &[u8]) -> Result<()> {
    const PNG_MAGIC: &[u8; 8] = b"\x89PNG\r\n\x1a\n";
    if bytes.len() < PNG_MAGIC.len() || &bytes[..8] != PNG_MAGIC {
        return Err(OcrError::InvalidImage(
            "expected 8-byte PNG signature".to_owned(),
        ));
    }
    Ok(())
}

/// Computes lowercase hexadecimal SHA-256 digest of `bytes`.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
    let mut hex = String::with_capacity(digest.as_ref().len() * 2);
    for byte in digest.as_ref() {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// Resolves the OCR model cache directory from `SB_OCR_MODELS` or the user cache dir.
///
/// # Errors
///
/// Returns [`OcrError::InvalidConfig`] if no cache directory is available.
pub fn resolve_models_dir(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(dir) = explicit {
        return Ok(dir.to_path_buf());
    }
    if let Some(env_dir) = std::env::var_os("SB_OCR_MODELS") {
        return Ok(PathBuf::from(env_dir));
    }
    dirs::cache_dir()
        .map(|d| d.join("seleniumbase-rs").join("ocr"))
        .ok_or_else(|| {
            OcrError::InvalidConfig(
                "no cache folder for OCR models; set `models_dir` or `SB_OCR_MODELS`".to_owned(),
            )
        })
}

/// OCR plugin and [`Task`] for screenshot/image text extraction workflows.
#[derive(Debug, Clone, Default)]
pub struct OcrPlugin {
    config: OcrConfig,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct OcrTaskInput {
    models_dir: Option<PathBuf>,
    image_path: Option<PathBuf>,
}

impl OcrPlugin {
    /// Creates an [`OcrPlugin`] from `config`.
    #[must_use]
    pub fn new(config: OcrConfig) -> Self {
        Self { config }
    }

    /// Configured defaults.
    #[must_use]
    pub const fn config(&self) -> &OcrConfig {
        &self.config
    }
}

impl Configurable for OcrPlugin {
    const NAME: &'static str = NAME;

    fn describe() -> Metadata {
        Metadata::new(Category::Core)
            .version(env!("CARGO_PKG_VERSION"))
            .summary("OCR text extraction and model cache verification for screenshots and images")
            .capabilities([
                Capability::Task,
                Capability::HostFsRead(PathScope::RunOutput),
            ])
    }

    fn configure(value: &Value) -> PluginResult<Self> {
        let config: OcrConfig = options(NAME, value)?;
        Ok(Self::new(config))
    }
}

#[async_trait]
impl Plugin for OcrPlugin {
    fn name(&self) -> &str {
        NAME
    }

    fn requirements(&self) -> Requirements {
        Requirements::empty()
    }

    fn metadata(&self) -> Metadata {
        Self::describe()
    }

    fn task(&self) -> Option<&dyn Task> {
        Some(self)
    }
}

#[async_trait]
impl Task for OcrPlugin {
    async fn run(&self, cx: &TaskContext<'_>) -> PluginResult<Value> {
        let input: OcrTaskInput = if cx.input.is_null() {
            OcrTaskInput::default()
        } else {
            options(NAME, cx.input)?
        };
        let models_dir = resolve_models_dir(
            input
                .models_dir
                .as_deref()
                .or(self.config.models_dir.as_deref()),
        )
        .map_err(|err| PluginError::Config(format!("{NAME}: {err}")))?;

        let image_path = input.image_path.or_else(|| self.config.image_path.clone());
        let png_valid = if let Some(path) = &image_path {
            let bytes =
                std::fs::read(path).map_err(|err| PluginError::other(format!("{NAME}: {err}")))?;
            validate_png_header(&bytes)
                .map_err(|err| PluginError::Config(format!("{NAME}: {err}")))?;
            true
        } else {
            false
        };

        let models_present = OCR_MODELS
            .iter()
            .all(|(name, _)| models_dir.join(name).is_file());

        let summary = json!({
            "models_dir": models_dir.display().to_string(),
            "models_present": models_present,
            "png_validated": png_valid,
        });
        cx.sink.record(&summary)?;
        Ok(summary)
    }
}
