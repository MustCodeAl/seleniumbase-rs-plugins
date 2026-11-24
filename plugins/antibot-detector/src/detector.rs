use std::collections::HashMap;

use crate::rules::{DetectionContext, evaluate_rules};
use crate::types::{BotProtectionResult, Cookie, DetectionError, Page, Result};

/// An anti-bot and security challenge detector for web pages and browser sessions.
///
/// Models the capabilities of Scrapfly's Antibot-Detector, providing signal analysis
/// across cookies, HTML DOM elements, scripts, iframes, challenge markers, and headers.
///
/// # Examples
///
/// ```
/// use antibot_detector::{AntibotDetector, BotProtectionKind, Cookie, Page};
///
/// let detector = AntibotDetector::new();
/// let html = r#"<html><head></head><body><div class="cf-turnstile"></div></body></html>"#;
/// let cookies = vec![Cookie::new("cf_clearance", "token123")];
///
/// let page = Page::new(html).with_cookies(cookies);
/// let detections = detector.detect(&page).unwrap();
///
/// assert_eq!(detections.len(), 1);
/// assert_eq!(detections[0].provider, BotProtectionKind::Cloudflare);
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AntibotDetector {
    _private: (),
}

impl AntibotDetector {
    /// Creates a new default `AntibotDetector`.
    #[must_use]
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// Detects anti-bot protections and security challenges on a [`Page`].
    ///
    /// # Errors
    ///
    /// Returns Ok with detected protections, or a [`DetectionError`] if inspection fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use antibot_detector::{AntibotDetector, BotProtectionKind, Cookie, Page};
    ///
    /// let detector = AntibotDetector::new();
    /// let page = Page::new("<html><body><h1>Welcome</h1></body></html>")
    ///     .with_cookies(vec![Cookie::new("datadome", "secret_value")]);
    ///
    /// let results = detector.detect(&page).unwrap();
    /// assert_eq!(results[0].provider, BotProtectionKind::DataDome);
    /// ```
    pub fn detect(&self, page: &Page) -> Result<Vec<BotProtectionResult>, DetectionError> {
        let ctx = DetectionContext::new(
            &page.html,
            &page.cookies,
            &page.headers,
            page.status_code,
            page.url.as_deref(),
        );
        Ok(evaluate_rules(&ctx))
    }

    /// Detects anti-bot protections directly from an HTML string and slice of [`Cookie`]s.
    ///
    /// # Examples
    ///
    /// ```
    /// use antibot_detector::{AntibotDetector, BotProtectionKind, Cookie};
    ///
    /// let detector = AntibotDetector::new();
    /// let cookies = [Cookie::new("_abck", "sample_val")];
    /// let results = detector.detect_html("<html></html>", &cookies);
    ///
    /// assert_eq!(results[0].provider, BotProtectionKind::Akamai);
    /// ```
    #[must_use]
    pub fn detect_html(&self, html: &str, cookies: &[Cookie]) -> Vec<BotProtectionResult> {
        let empty_headers = HashMap::new();
        let ctx = DetectionContext::new(html, cookies, &empty_headers, None, None);
        evaluate_rules(&ctx)
    }

    /// Detects anti-bot protections on a live browser tab handle.
    ///
    /// # Errors
    ///
    /// Returns an error if extracting DOM or cookies from the page handle fails.
    #[cfg(feature = "plugin")]
    pub async fn detect_handle(
        &self,
        handle: &dyn seleniumbase_rs_plugin::PageHandle,
    ) -> Result<Vec<BotProtectionResult>, DetectionError> {
        let page = Page::from_handle(handle).await?;
        self.detect(&page)
    }
}
