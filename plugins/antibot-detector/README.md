# antibot-detector

An anti-bot, CAPTCHA, and fingerprinting detector for [seleniumbase-rs](https://github.com/MustCodeAl/seleniumbase-rs), matching the capabilities of [Scrapfly's Antibot-Detector](https://github.com/scrapfly/Antibot-Detector).

## Features

- **Cloudflare**: Detects Turnstile iframes, containers (`cf-turnstile`), challenge page markers (`cf-ray`, `cf-challenge-running`, "Just a moment..."), clearance tokens (`cf_clearance`, `__cf_bm`), and Waiting Room queues (`__cfwaitingroom`, `cf-waiting-room`).
- **DataDome**: Identifies `datadome` cookies, client identifiers (`cid`), captcha delivery iframes (`geo.captcha-delivery.com`), and DataDome/GeeTest client SDKs.
- **Akamai Bot Manager**: Recognizes `_abck`, `bm_sz`, `bm_sv`, sensor scripts (`/akam/13/`, `bazadebezolkohpepadr`), and telemetry beacons.
- **Kasada**: Matches signature hexadecimal path hashes (`149e9513-...`), Inline Protection System (`ips.js`), and KPSDK tokens (`kpsdkct`, `kpsdkcd`, `window.KPSDK`).
- **PerimeterX / HUMAN Security**: Detects `_px`, `_px2`, `_px3`, client script telemetry (`client.js`), and `px-captcha` challenge elements.
- **Imperva / Incapsula**: Detects session cookies (`visid_incap_*`, `incap_ses_*`), resource loaders (`/_Incapsula_Resource`), and incident block pages.
- **AWS WAF**: Identifies `aws-waf-token`, challenge integrations (`token.awswaf.com`, `challenge.awswaf.com`), and captcha widgets.
- **FingerprintJS**: Analyzes browser fingerprinting imports (`@fingerprintjs/fingerprintjs`, `openfpcdn.io`) and `visitorId` tokens.
- **CAPTCHAs**: Detects Google reCAPTCHA and hCaptcha challenges.

## Quick Start

```rust
use antibot_detector::{AntibotDetector, BotProtectionKind, Cookie, Page};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let detector = AntibotDetector::new();

    // From Page
    let page = Page::new(r#"<div id="px-captcha"></div>"#)
        .with_cookies([Cookie::new("_px3", "px_token_val")]);

    let results = detector.detect(&page)?;
    for r in &results {
        println!("Detected: {} (Confidence: {}%)", r.provider, r.confidence);
        if r.is_blocked {
            println!("  Page is actively blocked or presenting a challenge!");
        }
    }

    // Direct from HTML and cookies
    let html_results = detector.detect_html(r#"<iframe src="https://challenges.cloudflare.com/turnstile/v0/api.js"></iframe>"#, &[]);
    assert_eq!(html_results[0].provider, BotProtectionKind::Cloudflare);

    Ok(())
}
```

## License

MIT
