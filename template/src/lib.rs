//! A seleniumbase-rs plugin. Rename the crate to `seleniumbase-rs-plugin-<name>`.

use seleniumbase_rs_plugin::{
    async_trait, Capability, Category, Metadata, PageHandle, Plugin, Result,
};

/// Says hello in the console of every page.
pub struct Hello;

#[async_trait]
impl Plugin for Hello {
    fn name(&self) -> &str {
        "hello"
    }

    // Declare what the plugin is and needs. Without this it is a "legacy"
    // plugin, which a strict set (the command line, the MCP server) refuses.
    fn metadata(&self) -> Metadata {
        Metadata::new(Category::Testing)
            .version(env!("CARGO_PKG_VERSION"))
            .summary("Says hello in the console of every page")
            .capability(Capability::PageEvaluate)
    }

    async fn on_page_created(&self, page: &dyn PageHandle) -> Result<()> {
        page.add_init_script("console.log('hello from a plugin')").await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seleniumbase_rs_plugin::PluginSet;
    use seleniumbase_rs_plugin_testing::{block_on, Call, RecordingPage};

    #[test]
    fn a_strict_set_accepts_it() {
        use seleniumbase_rs_plugin::{BrowserFamily, Engine, LaunchContext};
        let set = PluginSet::strict().with(Hello).unwrap();
        let context = LaunchContext {
            engine: Engine::Cdp,
            family: BrowserFamily::Chromium,
            headless: true,
            connecting: false,
        };
        set.check(&context).unwrap();
    }

    #[test]
    fn every_page_says_hello() {
        let page = RecordingPage::new();
        block_on(PluginSet::new().with(Hello).unwrap().on_page_created(&page)).unwrap();
        assert_eq!(page.calls(), [Call::InitScript("console.log('hello from a plugin')".into())]);
    }
}
