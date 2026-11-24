//! Antibot and security challenge detector for [seleniumbase-rs](https://github.com/MustCodeAl/seleniumbase-rs).
//!
//! Inspired by and matching the capabilities of Scrapfly's Antibot-Detector, this crate provides
//! real-time multi-signal analysis to detect anti-bot systems, challenge pages, CAPTCHAs, and browser
//! fingerprinting libraries.
//!
//! # Supported Protections
//!
//! - **Cloudflare**: Turnstile iframes and containers, challenge page markers (`cf-ray`, `cf-challenge-running`),
//!   `cf_clearance`, `__cf_bm`, and Waiting Room queues (`__cfwaitingroom`).
//! - **DataDome**: Session cookies (`datadome`), Client IDs (`cid`), captcha delivery iframes (`geo.captcha-delivery.com`),
//!   and DataDome / GeeTest client scripts.
//! - **Akamai Bot Manager**: Sensor validation cookies (`_abck`, `bm_sz`, `bm_sv`), sensor scripts (`/akam/13/`,
//!   `bazadebezolkohpepadr`), and telemetry beacons.
//! - **Kasada**: Hexadecimal signature path hashes (`149e9513-...`), Inline Protection System (`ips.js`),
//!   and KPSDK tokens (`kpsdkct`, `kpsdkcd`, `window.KPSDK`).
//! - **PerimeterX / HUMAN Security**: Verification cookies (`_px`, `_px2`, `_px3`), client sensor scripts (`client.js`),
//!   and `px-captcha` challenge containers.
//! - **Imperva / Incapsula**: Session tokens (`visid_incap_*`, `incap_ses_*`), resource loaders (`/_Incapsula_Resource`),
//!   and incident block pages.
//! - **AWS WAF**: Token cookies (`aws-waf-token`), challenge scripts (`token.awswaf.com`), and captcha containers.
//! - **FingerprintJS**: Client-side library detection (`@fingerprintjs/fingerprintjs`, `openfpcdn.io`, `api.fpjs.io`)
//!   and visitor tokens (`visitorId`).
//! - **CAPTCHAs**: Google reCAPTCHA (v2/v3/Enterprise) and hCaptcha.
//!
//! # Usage
//!
//! ```
//! use antibot_detector::{AntibotDetector, BotProtectionKind, Cookie, Page};
//!
//! let detector = AntibotDetector::new();
//!
//! // Inspecting from a Page model
//! let html = r#"
//!     <html>
//!         <head><script src="https://challenges.cloudflare.com/turnstile/v0/api.js"></script></head>
//!         <body>
//!             <div class="cf-turnstile" data-sitekey="0x4AAAAAA"></div>
//!         </body>
//!     </html>
//! "#;
//! let cookies = vec![Cookie::new("cf_clearance", "abc123token")];
//! let page = Page::new(html).with_cookies(cookies);
//!
//! let results = detector.detect(&page).unwrap();
//! assert_eq!(results[0].provider, BotProtectionKind::Cloudflare);
//!
//! // Inspecting directly from raw HTML and cookies
//! let raw_results = detector.detect_html(html, &page.cookies);
//! assert!(!raw_results.is_empty());
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod detector;
mod rules;
mod types;

#[cfg(feature = "plugin")]
mod plugin;

pub use detector::AntibotDetector;
pub use types::{
    BotProtectionKind, BotProtectionResult, Cookie, DetectionError, DetectionSignal, Page,
    ProtectionCategory, Result, SignalKind,
};

#[cfg(feature = "plugin")]
pub use plugin::NAME;
