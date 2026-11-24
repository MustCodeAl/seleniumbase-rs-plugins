use async_trait::async_trait;
use seleniumbase_rs_plugin::{
    Capability, Category, Metadata, Plugin, PluginError, Result, Task, TaskContext,
};
use serde_json::{Value, json};

use crate::detector::AntibotDetector;
use crate::types::Page;

/// Plugin identifier name.
pub const NAME: &str = "antibot-detector";

#[async_trait]
impl Plugin for AntibotDetector {
    fn name(&self) -> &str {
        NAME
    }

    fn metadata(&self) -> Metadata {
        Metadata::new(Category::Core)
            .capabilities([Capability::PageEvaluate, Capability::Task])
            .summary("Detects antibot systems, CAPTCHAs, and fingerprinting (Cloudflare, DataDome, Akamai, Kasada, PerimeterX, Imperva, AWS WAF, FingerprintJS)")
    }

    fn task(&self) -> Option<&dyn Task> {
        Some(self)
    }
}

#[async_trait]
impl Task for AntibotDetector {
    async fn run(&self, cx: &TaskContext<'_>) -> Result<Value> {
        let page_box = cx.browser.new_page(None).await?;
        let page_handle = page_box.as_ref();
        let page = Page::from_handle(page_handle)
            .await
            .map_err(|e| PluginError::other(e.to_string()))?;

        let detections = self
            .detect(&page)
            .map_err(|e| PluginError::other(e.to_string()))?;

        let value =
            serde_json::to_value(&detections).map_err(|e| PluginError::other(e.to_string()))?;

        cx.sink.record(&value)?;

        Ok(json!({
            "detections": detections,
            "blocked": detections.iter().any(|d| d.is_blocked),
        }))
    }
}
