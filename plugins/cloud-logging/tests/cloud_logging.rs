//! Unit tests for `seleniumbase-rs-plugin-cloud-logging`.

use seleniumbase_rs_plugin::{Capability, Category, Configurable, PluginSet};
use seleniumbase_rs_plugin_cloud_logging::{
    AzureBlobUploader, CloudLoggingPlugin, CloudUploadError, GcsUploader, NAME,
};
use serde_json::{Value, json};

#[test]
fn gcs_uploader_validates_env_and_redacts_token_in_debug() {
    let err = GcsUploader::from_lookup(|_| None).unwrap_err();
    assert!(matches!(err, CloudUploadError::MissingEnv("SB_GCS_BUCKET")));

    let uploader = GcsUploader::from_lookup(|name| match name {
        "SB_GCS_BUCKET" => Some("sbrs-artifacts".to_owned()),
        "GCS_ACCESS_TOKEN" => Some("secret-token-value".to_owned()),
        _ => None,
    })
    .unwrap();
    assert_eq!(uploader.bucket(), "sbrs-artifacts");
    let dbg = format!("{uploader:?}");
    assert!(dbg.contains("sbrs-artifacts"));
    assert!(!dbg.contains("secret-token-value"));
}

#[test]
fn azure_uploader_validates_sas_url_and_redacts_in_debug() {
    let err = AzureBlobUploader::from_lookup(|_| None).unwrap_err();
    assert!(matches!(
        err,
        CloudUploadError::MissingEnv("AZURE_BLOB_URL")
    ));

    let bad = AzureBlobUploader::from_lookup(|name| {
        (name == "AZURE_BLOB_URL").then(|| "https://acct.blob.core.windows.net/cont".to_owned())
    })
    .unwrap_err();
    assert!(matches!(bad, CloudUploadError::InvalidTarget(_)));

    let uploader = AzureBlobUploader::from_lookup(|name| {
        (name == "AZURE_BLOB_URL")
            .then(|| "https://acct.blob.core.windows.net/cont/logs/shot.png?sig=secret".to_owned())
    })
    .unwrap();
    assert_eq!(uploader.blob_name(), "logs/shot.png");
    let dbg = format!("{uploader:?}");
    assert!(dbg.contains("logs/shot.png"));
    assert!(!dbg.contains("sig=secret"));
}

#[test]
fn plugin_registers_metadata_and_rejects_unknown_options() {
    let meta = CloudLoggingPlugin::describe();
    assert_eq!(meta.category, Some(Category::Core));
    assert!(meta.capabilities.covers(&Capability::Task));

    let plugin = CloudLoggingPlugin::configure(&Value::Null).unwrap();
    let set = PluginSet::strict().with(plugin).unwrap();
    assert_eq!(set.names(), [NAME]);
    assert_eq!(set.task_names(), [NAME]);

    assert!(CloudLoggingPlugin::configure(&json!({ "unknown": 1 })).is_err());
}
