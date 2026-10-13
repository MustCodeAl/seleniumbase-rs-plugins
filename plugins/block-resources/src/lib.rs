//! A seleniumbase-rs plugin that stops pages from loading some resources.
//!
//! Blocking images, fonts or media makes pages load faster and use less data
//! in tests and scrapers that do not look at them. It uses the Chrome DevTools
//! Protocol (`Network.setBlockedURLs`), so it needs a Chromium-based browser.
//!
//! ```
//! use seleniumbase_rs_plugin::PluginSet;
//! use seleniumbase_rs_plugin_block_resources::BlockResources;
//!
//! let plugins = PluginSet::new().with(BlockResources::images_and_fonts())?;
//! assert_eq!(plugins.names(), ["block-resources"]);
//! # Ok::<(), seleniumbase_rs_plugin::PluginError>(())
//! ```

use seleniumbase_rs_plugin::{PageHandle, Plugin, Requirements, Result, async_trait};
use serde_json::json;

const IMAGES: &[&str] = &[
    "*.png", "*.jpg", "*.jpeg", "*.gif", "*.webp", "*.avif", "*.svg", "*.ico",
];
const FONTS: &[&str] = &["*.woff", "*.woff2", "*.ttf", "*.otf"];
const MEDIA: &[&str] = &["*.mp4", "*.webm", "*.mp3", "*.ogg", "*.wav", "*.m4a"];

/// Blocks requests whose URL matches any of its patterns (`*` matches anything).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockResources {
    patterns: Vec<String>,
}

impl BlockResources {
    /// Blocks images and web fonts.
    #[must_use]
    pub fn images_and_fonts() -> Self {
        Self::patterns(IMAGES.iter().chain(FONTS))
    }

    /// Blocks audio and video files.
    #[must_use]
    pub fn media() -> Self {
        Self::patterns(MEDIA)
    }

    /// Blocks URLs that match these patterns, such as `*://ads.example.com/*`.
    #[must_use]
    pub fn patterns<I, S>(patterns: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self {
            patterns: patterns
                .into_iter()
                .map(|p| p.as_ref().to_owned())
                .collect(),
        }
    }
}

#[async_trait]
impl Plugin for BlockResources {
    fn name(&self) -> &str {
        "block-resources"
    }

    fn requirements(&self) -> Requirements {
        Requirements::CHROMIUM_ONLY
    }

    async fn on_page_created(&self, page: &dyn PageHandle) -> Result<()> {
        page.send("Network.enable", json!({})).await?;
        page.send("Network.setBlockedURLs", json!({ "urls": self.patterns }))
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seleniumbase_rs_plugin::PluginSet;
    use seleniumbase_rs_plugin_testing::{Call, RecordingPage, block_on};

    #[test]
    fn a_new_tab_gets_the_network_domain_and_the_patterns() {
        let page = RecordingPage::new();
        let set = PluginSet::new()
            .with(BlockResources::patterns(["*.png"]))
            .unwrap();
        block_on(set.on_page_created(&page)).unwrap();
        assert_eq!(
            page.calls(),
            [
                Call::Send("Network.enable".into(), json!({})),
                Call::Send(
                    "Network.setBlockedURLs".into(),
                    json!({ "urls": ["*.png"] })
                ),
            ]
        );
    }

    #[test]
    fn a_failed_command_stops_the_tab_and_names_the_plugin() {
        let page = RecordingPage::new().failing("Network.setBlockedURLs");
        let set = PluginSet::new().with(BlockResources::media()).unwrap();
        let error = block_on(set.on_page_created(&page))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("block-resources") && error.contains("on_page_created"),
            "{error}"
        );
    }
}
