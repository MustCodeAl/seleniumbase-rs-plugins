//! Cloud artifact uploader plugin (Google Cloud Storage and Azure Blob Storage)
//! for `seleniumbase-rs`.
//!
//! Migrated from core `gcp_logging_plugin` and `azure_logging_plugin` so cloud
//! uploaders live as standalone `seleniumbase-rs-plugin` crates without adding
//! cloud SDK weight to `seleniumbase-rs`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(missing_debug_implementations)]

use std::fmt;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use reqwest::Client;
use seleniumbase_rs_plugin::{
    Capability, Category, Configurable, Metadata, NetScope, PathScope, Plugin, PluginError,
    Requirements, Result as PluginResult, Task, TaskContext, config::options,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;
use tokio::fs;
use url::Url;

/// Canonical plugin identifier.
pub const NAME: &str = "cloud-logging";

/// Errors produced by [`CloudLoggingPlugin`], [`GcsUploader`], and [`AzureBlobUploader`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CloudUploadError {
    /// A required environment variable was unset or blank.
    #[error("missing environment variable {0}")]
    MissingEnv(&'static str),
    /// A configured URL or target path was invalid.
    #[error("invalid cloud target: {0}")]
    InvalidTarget(String),
    /// Reading the local artifact file failed.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// The cloud endpoint rejected the upload.
    #[error("upload failed: status={status} body={body}")]
    Upload {
        /// HTTP status code (`0` when not received).
        status: u16,
        /// Response body or diagnostic message.
        body: String,
    },
    /// Sending the HTTP request failed.
    #[error("request failed: {0}")]
    Request(#[from] reqwest::Error),
}

/// Result alias for `seleniumbase-rs-plugin-cloud-logging`.
pub type Result<T> = std::result::Result<T, CloudUploadError>;

/// Cloud storage provider backend.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CloudProvider {
    /// Google Cloud Storage JSON upload API (`SB_GCS_BUCKET`, `GCS_ACCESS_TOKEN`).
    #[default]
    Gcs,
    /// Azure Blob Storage SAS PUT API (`AZURE_BLOB_URL`).
    Azure,
}

/// Configuration for [`CloudLoggingPlugin`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CloudLoggingConfig {
    /// Target cloud backend (`"gcs"` or `"azure"`).
    pub provider: CloudProvider,
    /// Optional local artifact path to upload on `on_close` or `Task::run`.
    pub artifact_path: Option<PathBuf>,
    /// Optional object key/name for GCS uploads (defaults to the file name).
    pub object_name: Option<String>,
}

/// Google Cloud Storage artifact uploader (`SB_GCS_BUCKET`, `GCS_ACCESS_TOKEN`).
#[non_exhaustive]
pub struct GcsUploader {
    bucket: String,
    token: String,
}

impl fmt::Debug for GcsUploader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GcsUploader")
            .field("bucket", &self.bucket)
            .finish_non_exhaustive()
    }
}

impl GcsUploader {
    /// Builds a [`GcsUploader`] from `SB_GCS_BUCKET` and `GCS_ACCESS_TOKEN`.
    ///
    /// # Errors
    ///
    /// Returns [`CloudUploadError::MissingEnv`] when either variable is unset or blank.
    pub fn from_env() -> Result<Self> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    /// Builds a [`GcsUploader`] using a custom environment lookup closure.
    ///
    /// # Errors
    ///
    /// Returns [`CloudUploadError::MissingEnv`] when either variable is unset or blank.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self> {
        let bucket = required_var(&lookup, "SB_GCS_BUCKET")?;
        let token = required_var(&lookup, "GCS_ACCESS_TOKEN")?;
        Ok(Self { bucket, token })
    }

    /// Configured GCS bucket name.
    #[must_use]
    pub fn bucket(&self) -> &str {
        &self.bucket
    }

    /// Uploads the local file at `path` as `object_name` to the configured GCS bucket.
    ///
    /// # Errors
    ///
    /// Returns [`CloudUploadError::Io`], [`CloudUploadError::Request`], or
    /// [`CloudUploadError::Upload`] on failure.
    pub async fn upload(&self, path: impl AsRef<Path>, object_name: &str) -> Result<()> {
        let bytes = fs::read(path.as_ref()).await?;
        let url = Url::parse_with_params(
            &format!(
                "https://storage.googleapis.com/upload/storage/v1/b/{}/o",
                self.bucket
            ),
            &[("uploadType", "media"), ("name", object_name)],
        )
        .map_err(|err| CloudUploadError::InvalidTarget(format!("invalid GCS URL: {err}")))?;

        let client = build_http_client()?;
        let response = client
            .post(url.as_str())
            .header("Authorization", format!("Bearer {}", self.token))
            .header("Content-Type", "application/octet-stream")
            .body(bytes)
            .send()
            .await?;

        let status = response.status();
        if status.is_success() {
            Ok(())
        } else {
            let body = response.text().await.unwrap_or_default();
            Err(CloudUploadError::Upload {
                status: status.as_u16(),
                body,
            })
        }
    }
}

/// Azure Blob Storage SAS artifact uploader (`AZURE_BLOB_URL`).
#[non_exhaustive]
pub struct AzureBlobUploader {
    sas_url: String,
    blob_name: String,
}

impl fmt::Debug for AzureBlobUploader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AzureBlobUploader")
            .field("blob_name", &self.blob_name)
            .finish_non_exhaustive()
    }
}

impl AzureBlobUploader {
    /// Builds an [`AzureBlobUploader`] from `AZURE_BLOB_URL`.
    ///
    /// # Errors
    ///
    /// Returns [`CloudUploadError::MissingEnv`] or [`CloudUploadError::InvalidTarget`].
    pub fn from_env() -> Result<Self> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    /// Builds an [`AzureBlobUploader`] using a custom environment lookup closure.
    ///
    /// # Errors
    ///
    /// Returns [`CloudUploadError::MissingEnv`] or [`CloudUploadError::InvalidTarget`].
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self> {
        let sas_url = required_var(&lookup, "AZURE_BLOB_URL")?;
        let parsed = Url::parse(&sas_url)
            .map_err(|err| CloudUploadError::InvalidTarget(format!("invalid blob URL: {err}")))?;
        let host = parsed
            .host_str()
            .filter(|h| !h.is_empty())
            .ok_or_else(|| CloudUploadError::InvalidTarget("blob URL has no host".to_owned()))?;
        let _account = host
            .split('.')
            .next()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| CloudUploadError::InvalidTarget("blob URL has no account".to_owned()))?;
        let mut segments = parsed.path().trim_start_matches('/').splitn(2, '/');
        let _container = segments.next().filter(|s| !s.is_empty()).ok_or_else(|| {
            CloudUploadError::InvalidTarget("blob URL has no container".to_owned())
        })?;
        let blob_name = segments
            .next()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| CloudUploadError::InvalidTarget("blob URL has no blob name".to_owned()))?
            .to_owned();
        if parsed.query().is_none_or(str::is_empty) {
            return Err(CloudUploadError::InvalidTarget(
                "blob URL must include a SAS query string".to_owned(),
            ));
        }

        Ok(Self { sas_url, blob_name })
    }

    /// Target blob path extracted from `AZURE_BLOB_URL`.
    #[must_use]
    pub fn blob_name(&self) -> &str {
        &self.blob_name
    }

    /// Uploads the local file at `path` to the configured Azure Blob SAS URL.
    ///
    /// # Errors
    ///
    /// Returns [`CloudUploadError::Io`], [`CloudUploadError::Request`], or
    /// [`CloudUploadError::Upload`] on failure.
    pub async fn upload(&self, path: impl AsRef<Path>) -> Result<()> {
        let bytes = fs::read(path.as_ref()).await?;
        let client = build_http_client()?;
        let response = client
            .put(&self.sas_url)
            .header("x-ms-blob-type", "BlockBlob")
            .header("Content-Type", "application/octet-stream")
            .body(bytes)
            .send()
            .await?;

        let status = response.status();
        if status.is_success() {
            Ok(())
        } else {
            let body = response.text().await.unwrap_or_default();
            Err(CloudUploadError::Upload {
                status: status.as_u16(),
                body,
            })
        }
    }
}

/// Plugin and [`Task`] uploading test artifacts to GCS or Azure Blob Storage.
#[derive(Debug, Clone, Default)]
pub struct CloudLoggingPlugin {
    config: CloudLoggingConfig,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct TaskInput {
    provider: Option<CloudProvider>,
    artifact_path: Option<PathBuf>,
    object_name: Option<String>,
}

impl CloudLoggingPlugin {
    /// Creates a [`CloudLoggingPlugin`] from `config`.
    #[must_use]
    pub fn new(config: CloudLoggingConfig) -> Self {
        Self { config }
    }

    /// Configured defaults.
    #[must_use]
    pub const fn config(&self) -> &CloudLoggingConfig {
        &self.config
    }
}

impl Configurable for CloudLoggingPlugin {
    const NAME: &'static str = NAME;

    fn describe() -> Metadata {
        Metadata::new(Category::Core)
            .version(env!("CARGO_PKG_VERSION"))
            .summary("Uploads test artifacts to Google Cloud Storage or Azure Blob Storage")
            .capabilities([
                Capability::Task,
                Capability::HostNet(NetScope::Any),
                Capability::HostFsRead(PathScope::RunOutput),
            ])
    }

    fn configure(value: &Value) -> PluginResult<Self> {
        let config: CloudLoggingConfig = options(NAME, value)?;
        Ok(Self::new(config))
    }
}

#[async_trait]
impl Plugin for CloudLoggingPlugin {
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

    async fn on_close(&self) -> PluginResult<()> {
        let Some(path) = &self.config.artifact_path else {
            return Ok(());
        };
        upload_artifact(
            self.config.provider,
            path,
            self.config.object_name.as_deref(),
        )
        .await
        .map_err(|err| PluginError::other(format!("{NAME}: {err}")))
    }
}

#[async_trait]
impl Task for CloudLoggingPlugin {
    async fn run(&self, cx: &TaskContext<'_>) -> PluginResult<Value> {
        let input: TaskInput = if cx.input.is_null() {
            TaskInput::default()
        } else {
            options(NAME, cx.input)?
        };
        let provider = input.provider.unwrap_or(self.config.provider);
        let path = input
            .artifact_path
            .as_ref()
            .or(self.config.artifact_path.as_ref())
            .ok_or_else(|| PluginError::Config(format!("{NAME}: `artifact_path` is required")))?;
        let object_name = input
            .object_name
            .as_deref()
            .or(self.config.object_name.as_deref());

        upload_artifact(provider, path, object_name)
            .await
            .map_err(|err| PluginError::other(format!("{NAME}: {err}")))?;

        let summary = json!({
            "provider": match provider {
                CloudProvider::Gcs => "gcs",
                CloudProvider::Azure => "azure",
            },
            "artifact_path": path.display().to_string(),
            "uploaded": true,
        });
        cx.sink.record(&summary)?;
        Ok(summary)
    }
}

async fn upload_artifact(
    provider: CloudProvider,
    path: &Path,
    object_name: Option<&str>,
) -> Result<()> {
    match provider {
        CloudProvider::Gcs => {
            let uploader = GcsUploader::from_env()?;
            let key = object_name
                .or_else(|| path.file_name().and_then(|n| n.to_str()))
                .unwrap_or("artifact.bin");
            uploader.upload(path, key).await
        }
        CloudProvider::Azure => {
            let uploader = AzureBlobUploader::from_env()?;
            uploader.upload(path).await
        }
    }
}

fn build_http_client() -> Result<Client> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    Ok(Client::builder()
        .connect_timeout(std::time::Duration::from_secs(30))
        .read_timeout(std::time::Duration::from_secs(120))
        .build()?)
}

fn required_var(lookup: &impl Fn(&str) -> Option<String>, name: &'static str) -> Result<String> {
    lookup(name)
        .filter(|value| !value.trim().is_empty())
        .ok_or(CloudUploadError::MissingEnv(name))
}

#[cfg(test)]
mod unit_tests {
    use super::*;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpListener;

    #[test]
    fn uploader_validation_debug_and_plugin_config_work() {
        let gcs = GcsUploader::from_lookup(|k| match k {
            "SB_GCS_BUCKET" => Some("my-bucket".to_owned()),
            "GCS_ACCESS_TOKEN" => Some("secret-tok".to_owned()),
            _ => None,
        })
        .expect("gcs uploader");
        assert_eq!(gcs.bucket(), "my-bucket");
        let dbg = format!("{gcs:?}");
        assert!(dbg.contains("my-bucket") && !dbg.contains("secret-tok"));

        assert!(matches!(
            GcsUploader::from_lookup(|_| Some("  ".to_owned())),
            Err(CloudUploadError::MissingEnv("SB_GCS_BUCKET"))
        ));

        for bad in [
            "not-a-url",
            "https://acct.blob.core.windows.net/",
            "https://acct.blob.core.windows.net/container-only",
            "https://acct.blob.core.windows.net/container/blob.bin",
        ] {
            assert!(
                matches!(
                    AzureBlobUploader::from_lookup(|_| Some(bad.to_owned())),
                    Err(CloudUploadError::InvalidTarget(_))
                ),
                "expected InvalidTarget for {bad}"
            );
        }

        let az = AzureBlobUploader::from_lookup(|_| {
            Some("https://acct.blob.core.windows.net/logs/run.zip?sv=2024".to_owned())
        })
        .expect("azure uploader");
        assert_eq!(az.blob_name(), "run.zip");
        let az_dbg = format!("{az:?}");
        assert!(az_dbg.contains("run.zip") && !az_dbg.contains("sv=2024"));

        let plugin = CloudLoggingPlugin::configure(&json!({
            "provider": "azure",
            "object_name": "out.bin"
        }))
        .expect("configure");
        assert_eq!(plugin.name(), NAME);
        assert_eq!(plugin.config().provider, CloudProvider::Azure);
        assert_eq!(plugin.requirements(), Requirements::empty());
        assert_eq!(plugin.metadata().category, Some(Category::Core));
        assert!(plugin.task().is_some());
    }

    #[tokio::test]
    async fn azure_upload_succeeds_and_reports_http_failure_against_loopback() {
        let dir = std::env::temp_dir();
        let file = dir.join(format!("sbrs-cloud-test-{}.bin", std::process::id()));
        std::fs::write(&file, b"artifact-bytes").expect("write temp file");

        async fn serve_once(status_line: &'static str, body: &'static str) -> String {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let addr = listener.local_addr().expect("addr");
            tokio::spawn(async move {
                if let Ok((mut sock, _)) = listener.accept().await {
                    let mut buf = [0u8; 1024];
                    let _ = sock.read(&mut buf).await;
                    let resp = format!(
                        "HTTP/1.1 {status_line}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                }
            });
            format!("http://{addr}/logs/test.bin?sig=abc")
        }

        let ok_url = serve_once("201 Created", "ok").await;
        let ok_uploader = AzureBlobUploader::from_lookup(|_| Some(ok_url.clone())).expect("ok");
        ok_uploader.upload(&file).await.expect("201 upload");

        let err_url = serve_once("403 Forbidden", "denied").await;
        let err_uploader = AzureBlobUploader::from_lookup(|_| Some(err_url.clone())).expect("err");
        let err = err_uploader.upload(&file).await.expect_err("403 must fail");
        assert!(matches!(err, CloudUploadError::Upload { status: 403, .. }));

        // on_close with no artifact_path is a no-op.
        let plugin = CloudLoggingPlugin::default();
        plugin.on_close().await.expect("noop on_close");

        let _ = std::fs::remove_file(&file);
    }
}
