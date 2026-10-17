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

use seleniumbase_rs_plugin::{
    Capability, Category, Configurable, Metadata, PageHandle, Plugin, PluginError, Requirements,
    Result, async_trait,
};
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

    fn metadata(&self) -> Metadata {
        Self::describe()
    }

    async fn on_page_created(&self, page: &dyn PageHandle) -> Result<()> {
        page.send("Network.enable", json!({})).await?;
        page.send("Network.setBlockedURLs", json!({ "urls": self.patterns }))
            .await?;
        Ok(())
    }
}

impl Configurable for BlockResources {
    const NAME: &'static str = "block-resources";

    fn describe() -> Metadata {
        Metadata::new(Category::Core)
            .version(env!("CARGO_PKG_VERSION"))
            .summary("Stops pages from loading images, fonts, media or URLs you name")
            .capability(Capability::Cdp("Network".into()))
    }

    /// Options: `preset` (`"images-and-fonts"`, the default, or `"media"`) or
    /// `patterns`, an array of URL patterns.
    fn configure(options: &serde_json::Value) -> Result<Self> {
        if let Some(patterns) = options.get("patterns") {
            let list = patterns
                .as_array()
                .and_then(|items| items.iter().map(|v| v.as_str()).collect::<Option<Vec<_>>>())
                .ok_or_else(|| {
                    PluginError::Config("`patterns` must be an array of strings".into())
                })?;
            return Ok(Self::patterns(list));
        }
        match options.get("preset").and_then(serde_json::Value::as_str) {
            None | Some("images-and-fonts") => Ok(Self::images_and_fonts()),
            Some("media") => Ok(Self::media()),
            Some(other) => Err(PluginError::Config(format!("unknown preset `{other}`"))),
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_configures_from_options_and_declares_its_category() {
        use super::*;
        use seleniumbase_rs_plugin::{BrowserFamily, Engine, LaunchContext, PluginSet};
        let media = BlockResources::configure(&json!({"preset": "media"})).unwrap();
        assert_eq!(media, BlockResources::media());
        let custom = BlockResources::configure(&json!({"patterns": ["*://a/*"]})).unwrap();
        assert_eq!(custom, BlockResources::patterns(["*://a/*"]));
        assert!(BlockResources::configure(&json!({"preset": "x"})).is_err());
        let set = PluginSet::strict().with(custom).unwrap();
        set.check(&LaunchContext {
            engine: Engine::Cdp,
            family: BrowserFamily::Chromium,
            headless: true,
            connecting: false,
        })
        .unwrap();
    }

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
