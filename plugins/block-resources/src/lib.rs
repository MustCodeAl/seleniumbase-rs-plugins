//! A seleniumbase-rs plugin that stops pages from loading some resources.
//!
//! Blocking images, fonts, stylesheets or media makes pages load faster and use
//! less data in tests and scrapers that do not look at them. It uses declarative
//! network rules ([`Plugin::network`]) matching CDP [`ResourceKind`] (so modern
//! dynamic/CDN URLs without file extensions like `/_next/image?url=...` are
//! blocked directly) as well as Chrome DevTools Protocol (`Network.setBlockedURLs`)
//! URL patterns.
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
    Capability, Category, Configurable, Metadata, NetRule, NetworkInterest, PageHandle, Plugin,
    PluginError, RequestFilter, Requirements, ResourceKind, Result, async_trait,
};
use serde_json::json;

const IMAGES: &[&str] = &[
    "*.png", "*.jpg", "*.jpeg", "*.gif", "*.webp", "*.avif", "*.svg", "*.ico",
];
const FONTS: &[&str] = &["*.woff", "*.woff2", "*.ttf", "*.otf"];
const MEDIA: &[&str] = &["*.mp4", "*.webm", "*.mp3", "*.ogg", "*.wav", "*.m4a"];
const STYLESHEETS: &[&str] = &["*.css"];

/// Blocks requests by resource type (e.g. image, font, media) and URL pattern.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockResources {
    kinds: Vec<ResourceKind>,
    patterns: Vec<String>,
}

impl BlockResources {
    /// Builds a blocker with specific resource kinds and URL patterns.
    #[must_use]
    pub fn new<K, P, S>(kinds: K, patterns: P) -> Self
    where
        K: IntoIterator<Item = ResourceKind>,
        P: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self {
            kinds: kinds.into_iter().collect(),
            patterns: patterns
                .into_iter()
                .map(|p| p.as_ref().to_owned())
                .collect(),
        }
    }

    /// Blocks images and web fonts by resource type and extension.
    #[must_use]
    pub fn images_and_fonts() -> Self {
        Self::new(
            [ResourceKind::Image, ResourceKind::Font],
            IMAGES.iter().chain(FONTS).copied(),
        )
    }

    /// Blocks audio and video files by resource type and extension.
    #[must_use]
    pub fn media() -> Self {
        Self::new([ResourceKind::Media], MEDIA.iter().copied())
    }

    /// Blocks stylesheets by resource type and extension.
    #[must_use]
    pub fn stylesheets() -> Self {
        Self::new([ResourceKind::Stylesheet], STYLESHEETS.iter().copied())
    }

    /// Blocks images, web fonts, audio/video, and stylesheets.
    #[must_use]
    pub fn all() -> Self {
        Self::new(
            [
                ResourceKind::Image,
                ResourceKind::Font,
                ResourceKind::Media,
                ResourceKind::Stylesheet,
            ],
            IMAGES
                .iter()
                .chain(FONTS)
                .chain(MEDIA)
                .chain(STYLESHEETS)
                .copied(),
        )
    }

    /// Blocks specific resource kinds.
    #[must_use]
    pub fn kinds<I>(kinds: I) -> Self
    where
        I: IntoIterator<Item = ResourceKind>,
    {
        Self::new(kinds, std::iter::empty::<&str>())
    }

    /// Blocks URLs that match these patterns, such as `*://ads.example.com/*`.
    #[must_use]
    pub fn patterns<I, S>(patterns: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self::new(std::iter::empty(), patterns)
    }

    /// The resource kinds this blocker filters.
    #[must_use]
    pub fn blocked_kinds(&self) -> &[ResourceKind] {
        &self.kinds
    }

    /// The URL patterns this blocker filters.
    #[must_use]
    pub fn blocked_patterns(&self) -> &[String] {
        &self.patterns
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

    fn network(&self) -> NetworkInterest {
        let mut interest = NetworkInterest::none();
        if !self.kinds.is_empty() {
            interest = interest.rule(NetRule::block(
                RequestFilter::any().kinds(self.kinds.clone()),
            ));
        }
        for pattern in &self.patterns {
            interest = interest.rule(NetRule::block(RequestFilter::any().url(pattern.as_str())));
        }
        interest
    }

    async fn on_page_created(&self, page: &dyn PageHandle) -> Result<()> {
        if !self.patterns.is_empty() {
            page.send("Network.enable", json!({})).await?;
            page.send("Network.setBlockedURLs", json!({ "urls": self.patterns }))
                .await?;
        }
        Ok(())
    }
}

fn parse_kind(s: &str) -> Result<ResourceKind> {
    match s.trim().to_ascii_lowercase().as_str() {
        "image" | "images" => Ok(ResourceKind::Image),
        "font" | "fonts" => Ok(ResourceKind::Font),
        "media" | "audio" | "video" => Ok(ResourceKind::Media),
        "stylesheet" | "stylesheets" | "css" => Ok(ResourceKind::Stylesheet),
        "script" | "scripts" | "js" => Ok(ResourceKind::Script),
        "xhr" => Ok(ResourceKind::Xhr),
        "fetch" => Ok(ResourceKind::Fetch),
        "websocket" | "ws" => Ok(ResourceKind::WebSocket),
        "other" => Ok(ResourceKind::Other),
        other => Err(PluginError::Config(format!(
            "unknown resource kind `{other}` (expected image, font, media, stylesheet, script, etc.)"
        ))),
    }
}

impl Configurable for BlockResources {
    const NAME: &'static str = "block-resources";

    fn describe() -> Metadata {
        Metadata::new(Category::Core)
            .version(env!("CARGO_PKG_VERSION"))
            .summary("Stops pages from loading images, fonts, media, stylesheets or URLs you name")
            .capability(Capability::NetIntercept)
            .capability(Capability::Cdp("Network".into()))
    }

    /// Options:
    /// - `preset`: `"images-and-fonts"` (default), `"media"`, `"stylesheets"`, or `"all"`
    /// - `strip` or `kinds`: an array of resource kind strings (e.g. `["image", "font", "css"]`)
    /// - `patterns`: an array of URL wildcard patterns
    fn configure(options: &serde_json::Value) -> Result<Self> {
        let mut kinds = Vec::new();
        let mut patterns = Vec::new();

        if let Some(strip_val) = options.get("strip").or_else(|| options.get("kinds")) {
            let list = strip_val.as_array().ok_or_else(|| {
                PluginError::Config("`strip`/`kinds` must be an array of strings".into())
            })?;
            for item in list {
                let s = item.as_str().ok_or_else(|| {
                    PluginError::Config("each item in `strip`/`kinds` must be a string".into())
                })?;
                kinds.push(parse_kind(s)?);
            }
        }

        if let Some(pats) = options.get("patterns") {
            let list = pats
                .as_array()
                .and_then(|items| items.iter().map(|v| v.as_str()).collect::<Option<Vec<_>>>())
                .ok_or_else(|| {
                    PluginError::Config("`patterns` must be an array of strings".into())
                })?;
            patterns.extend(list.into_iter().map(str::to_owned));
        }

        if !kinds.is_empty() || !patterns.is_empty() {
            return Ok(Self::new(kinds, patterns));
        }

        match options.get("preset").and_then(serde_json::Value::as_str) {
            None | Some("images-and-fonts") => Ok(Self::images_and_fonts()),
            Some("media") => Ok(Self::media()),
            Some("stylesheets") => Ok(Self::stylesheets()),
            Some("all") => Ok(Self::all()),
            Some(other) => Err(PluginError::Config(format!("unknown preset `{other}`"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seleniumbase_rs_plugin::PluginSet;
    use seleniumbase_rs_plugin_testing::{Call, RecordingPage, block_on};

    #[test]
    fn it_configures_from_options_and_presets() {
        use seleniumbase_rs_plugin::{BrowserFamily, Engine, LaunchContext};

        let media = BlockResources::configure(&json!({"preset": "media"})).unwrap();
        assert_eq!(media, BlockResources::media());

        let all = BlockResources::configure(&json!({"preset": "all"})).unwrap();
        assert_eq!(all, BlockResources::all());

        let custom = BlockResources::configure(&json!({"patterns": ["*://a/*"]})).unwrap();
        assert_eq!(custom, BlockResources::patterns(["*://a/*"]));

        let stripped =
            BlockResources::configure(&json!({"strip": ["image", "font", "css"]})).unwrap();
        assert_eq!(
            stripped.blocked_kinds(),
            &[
                ResourceKind::Image,
                ResourceKind::Font,
                ResourceKind::Stylesheet
            ]
        );

        assert!(BlockResources::configure(&json!({"preset": "invalid"})).is_err());
        assert!(BlockResources::configure(&json!({"strip": ["not_a_kind"]})).is_err());

        let set = PluginSet::strict().with(custom).unwrap();
        set.check(&LaunchContext {
            engine: Engine::Cdp,
            family: BrowserFamily::Chromium,
            headless: true,
            connecting: false,
        })
        .unwrap();
    }

    #[test]
    fn it_declares_network_interest_rules_for_kinds_and_patterns() {
        use seleniumbase_rs_plugin::RequestView;

        let blocker = BlockResources::all();
        let interest = blocker.network();
        assert!(!interest.is_empty());

        let kinds_only = BlockResources::kinds([ResourceKind::Image, ResourceKind::Media]);
        assert_eq!(
            kinds_only.blocked_kinds(),
            &[ResourceKind::Image, ResourceKind::Media]
        );
        assert!(kinds_only.blocked_patterns().is_empty());

        // Verify dynamic query URLs without extensions are matched by ResourceKind
        let dynamic_image_request = RequestView::new(
            "https://cdn.example.com/api/dynamic-avatar?userId=8482",
            "GET",
            ResourceKind::Image,
        );
        let filter = RequestFilter::any().kinds([ResourceKind::Image]);
        assert!(filter.matches(&dynamic_image_request));
    }

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
                Call::BlockUrls(vec!["*.png".into()]),
            ]
        );
    }

    #[test]
    fn a_failed_command_stops_the_tab_and_names_the_plugin() {
        let page = RecordingPage::new().failing("block_urls");
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
