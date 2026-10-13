//! A seleniumbase-rs plugin. Rename the crate to `seleniumbase-rs-plugin-<name>`.

use seleniumbase_rs_plugin::{async_trait, PageHandle, Plugin, Result};

/// Says hello in the console of every page.
pub struct Hello;

#[async_trait]
impl Plugin for Hello {
    fn name(&self) -> &str {
        "hello"
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
    fn every_page_says_hello() {
        let page = RecordingPage::new();
        block_on(PluginSet::new().with(Hello).unwrap().on_page_created(&page)).unwrap();
        assert_eq!(page.calls(), [Call::InitScript("console.log('hello from a plugin')".into())]);
    }
}
