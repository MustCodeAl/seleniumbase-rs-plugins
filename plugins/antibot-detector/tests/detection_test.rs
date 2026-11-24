use std::collections::HashMap;

use antibot_detector::{
    AntibotDetector, BotProtectionKind, Cookie, Page, ProtectionCategory, SignalKind,
};

#[test]
fn clean_page_returns_no_detections() {
    let detector = AntibotDetector::new();
    let html =
        "<html><head><title>Test Page</title></head><body><h1>Hello World</h1></body></html>";
    let cookies = [Cookie::new("session_id", "clean_user_123")];

    let results = detector.detect_html(html, &cookies);
    assert!(results.is_empty(), "clean page should have 0 detections");

    let page = Page::new(html).with_cookies(cookies);
    let page_results = detector.detect(&page).expect("detection should succeed");
    assert!(page_results.is_empty());
}

// ---------------------------------------------------------------------------
// 1. Cloudflare
// ---------------------------------------------------------------------------

#[test]
fn detect_cloudflare_turnstile_iframe() {
    let detector = AntibotDetector::new();
    let html = r#"
        <html>
            <body>
                <iframe src="https://challenges.cloudflare.com/turnstile/v0/b/123/api.js"></iframe>
            </body>
        </html>
    "#;

    let results = detector.detect_html(html, &[]);
    assert_eq!(results.len(), 1);
    let cf = &results[0];
    assert_eq!(cf.provider, BotProtectionKind::Cloudflare);
    assert_eq!(cf.category, ProtectionCategory::Captcha);
    assert!(cf.is_blocked);
    assert!(cf.signals.iter().any(|s| s.kind == SignalKind::Iframe));
}

#[test]
fn detect_cloudflare_challenge_page_markers() {
    let detector = AntibotDetector::new();
    let html = r#"
        <!DOCTYPE html>
        <html>
            <head><title>Just a moment...</title></head>
            <body>
                <div id="cf-challenge-running">
                    <span id="cf-ray">8e123456789abcde</span>
                    <p>Checking your browser before accessing the site.</p>
                </div>
            </body>
        </html>
    "#;

    let results = detector.detect_html(html, &[]);
    assert_eq!(results.len(), 1);
    let cf = &results[0];
    assert_eq!(cf.provider, BotProtectionKind::Cloudflare);
    assert!(cf.is_blocked);
    assert!(cf.signals.iter().any(|s| s.name.contains("cf-ray")));
    assert!(cf.signals.iter().any(|s| s.name.contains("Just a moment")));
}

#[test]
fn detect_cloudflare_cookies() {
    let detector = AntibotDetector::new();
    let cookies = [
        Cookie::new("cf_clearance", "cleared_challenge_token_456"),
        Cookie::new("__cf_bm", "bot_management_token_789"),
    ];

    let results = detector.detect_html("<html><body>Normal HTML</body></html>", &cookies);
    assert_eq!(results.len(), 1);
    let cf = &results[0];
    assert_eq!(cf.provider, BotProtectionKind::Cloudflare);
    assert_eq!(cf.category, ProtectionCategory::BotManagement);
    assert!(!cf.is_blocked); // Cookies alone don't block
    assert_eq!(cf.signals.len(), 2);
    assert!(cf.signals.iter().any(|s| s.name == "cf_clearance"));
    assert!(cf.signals.iter().any(|s| s.name == "__cf_bm"));
}

#[test]
fn detect_cloudflare_waiting_room() {
    let detector = AntibotDetector::new();
    let html = r#"
        <div id="waiting-room-container" class="cf-waiting-room">
            <h2>Waiting Room</h2>
            <p>You are in line. Estimated wait time: 2 minutes.</p>
        </div>
    "#;
    let cookies = [Cookie::new("__cfwaitingroom", "queue_pos_42")];

    let page = Page::new(html).with_cookies(cookies);
    let results = detector.detect(&page).expect("detection should succeed");

    assert_eq!(results.len(), 1);
    let cf = &results[0];
    assert_eq!(cf.provider, BotProtectionKind::Cloudflare);
    assert_eq!(cf.category, ProtectionCategory::WaitingRoom);
    assert!(cf.is_blocked);
    assert!(cf.description.contains("Waiting Room"));
}

// ---------------------------------------------------------------------------
// 2. DataDome
// ---------------------------------------------------------------------------

#[test]
fn detect_datadome_cookie_and_cid() {
    let detector = AntibotDetector::new();
    let cookies = [
        Cookie::new("datadome", "AHrlqAAAAAMAc6z9xQ..."),
        Cookie::new("cid", "client_id_tracker"),
    ];

    let results = detector.detect_html("<html></html>", &cookies);
    assert_eq!(results.len(), 1);
    let dd = &results[0];
    assert_eq!(dd.provider, BotProtectionKind::DataDome);
    assert_eq!(dd.confidence, 100);
    assert!(!dd.is_blocked);
    assert!(dd.signals.iter().any(|s| s.name == "datadome_cookie"));
}

#[test]
fn detect_datadome_captcha_iframe() {
    let detector = AntibotDetector::new();
    let html = r#"
        <html>
            <body>
                <iframe src="https://geo.captcha-delivery.com/captcha/?initialCid=AHrlqAAAA...&hash=123" width="100%" height="100%"></iframe>
            </body>
        </html>
    "#;

    let results = detector.detect_html(html, &[]);
    assert_eq!(results.len(), 1);
    let dd = &results[0];
    assert_eq!(dd.provider, BotProtectionKind::DataDome);
    assert_eq!(dd.category, ProtectionCategory::Captcha);
    assert!(dd.is_blocked);
    assert!(dd.signals.iter().any(|s| s.kind == SignalKind::Iframe));
}

#[test]
fn detect_datadome_scripts_and_geetest() {
    let detector = AntibotDetector::new();
    let html = r#"
        <head>
            <script src="https://js.datadome.co/tags.js"></script>
            <script>
                window.dd = { cid: "12345" };
            </script>
        </head>
        <body>
            <div data-datadome-geetest="true"></div>
        </body>
    "#;

    let results = detector.detect_html(html, &[]);
    assert_eq!(results.len(), 1);
    let dd = &results[0];
    assert_eq!(dd.provider, BotProtectionKind::DataDome);
    assert!(dd.signals.iter().any(|s| s.name == "datadome_js_script"));
    assert!(
        dd.signals
            .iter()
            .any(|s| s.name == "datadome_geetest_script")
    );
}

// ---------------------------------------------------------------------------
// 3. Akamai Bot Manager
// ---------------------------------------------------------------------------

#[test]
fn detect_akamai_cookies() {
    let detector = AntibotDetector::new();
    let cookies = [
        Cookie::new("_abck", "A0B1C2D3~0~..."),
        Cookie::new("bm_sz", "xyz987..."),
        Cookie::new("bm_sv", "token_val"),
    ];

    let results = detector.detect_html("<html></html>", &cookies);
    assert_eq!(results.len(), 1);
    let ak = &results[0];
    assert_eq!(ak.provider, BotProtectionKind::Akamai);
    assert_eq!(ak.confidence, 100);
    assert!(ak.signals.iter().any(|s| s.name == "_abck"));
    assert!(ak.signals.iter().any(|s| s.name == "bm_sz"));
    assert!(ak.signals.iter().any(|s| s.name == "bm_sv"));
}

#[test]
fn detect_akamai_telemetry_beacon_and_access_denied() {
    let detector = AntibotDetector::new();
    let html = r#"
        <html>
            <head>
                <script type="text/javascript" src="/akam/13/bazadebezolkohpepadr"></script>
                <script>window._abck = "val";</script>
            </head>
            <body>
                <h1>Access Denied - Akamai</h1>
                <p>Reference&#32;&#35;18.85461ab8.1690000000.123456</p>
            </body>
        </html>
    "#;

    let page = Page::new(html).with_status_code(403);
    let results = detector.detect(&page).expect("detection should succeed");

    assert_eq!(results.len(), 1);
    let ak = &results[0];
    assert_eq!(ak.provider, BotProtectionKind::Akamai);
    assert!(ak.is_blocked);
    assert!(
        ak.signals
            .iter()
            .any(|s| s.name.contains("bazadebezolkohpepadr"))
    );
    assert!(
        ak.signals
            .iter()
            .any(|s| s.name.contains("Akamai Access Denied"))
    );
}

// ---------------------------------------------------------------------------
// 4. Kasada
// ---------------------------------------------------------------------------

#[test]
fn detect_kasada_149e9513_ips_and_kpsdk() {
    let detector = AntibotDetector::new();
    let html = r#"
        <html>
            <head>
                <script src="/149e9513-01fa-4fb0-8445-32e4fb954159/2d206f/ips.js"></script>
                <script>
                    window.KPSDK = { version: "3.0" };
                </script>
            </head>
            <body>
                <div data-kpsdk-cd="xyz" data-kpsdk-ct="abc"></div>
            </body>
        </html>
    "#;
    let cookies = [
        Cookie::new("kpsdkct", "client_token_val"),
        Cookie::new("kpsdkcd", "client_data_val"),
    ];

    let page = Page::new(html).with_cookies(cookies);
    let results = detector.detect(&page).expect("detection should succeed");

    assert_eq!(results.len(), 1);
    let ks = &results[0];
    assert_eq!(ks.provider, BotProtectionKind::Kasada);
    assert_eq!(ks.confidence, 100);
    assert!(ks.signals.iter().any(|s| s.name == "kasada_149e9513_path"));
    assert!(ks.signals.iter().any(|s| s.name == "kasada_ips_js"));
    assert!(ks.signals.iter().any(|s| s.name == "kpsdk_cookie"));
}

#[test]
fn detect_kasada_challenge_blocked() {
    let detector = AntibotDetector::new();
    let html = r#"
        <html>
            <head><script src="/ips.js"></script></head>
            <body>
                <div id="kpsdk-container"></div>
            </body>
        </html>
    "#;

    let page = Page::new(html).with_status_code(429);
    let results = detector.detect(&page).expect("detection should succeed");

    assert_eq!(results.len(), 1);
    let ks = &results[0];
    assert_eq!(ks.provider, BotProtectionKind::Kasada);
    assert!(ks.is_blocked);
}

// ---------------------------------------------------------------------------
// 5. PerimeterX / HUMAN Security
// ---------------------------------------------------------------------------

#[test]
fn detect_perimeterx_cookies_and_client_js() {
    let detector = AntibotDetector::new();
    let html = r#"
        <html>
            <head>
                <script src="https://client.perimeterx.net/PX12345/main.min.js"></script>
                <script>window._pxAppId = "PX12345";</script>
            </head>
            <body></body>
        </html>
    "#;
    let cookies = [
        Cookie::new("_px", "px_cookie_val"),
        Cookie::new("_px2", "px2_cookie_val"),
        Cookie::new("_px3", "px3_risk_score"),
    ];

    let page = Page::new(html).with_cookies(cookies);
    let results = detector.detect(&page).expect("detection should succeed");

    assert_eq!(results.len(), 1);
    let px = &results[0];
    assert_eq!(px.provider, BotProtectionKind::PerimeterX);
    assert_eq!(px.confidence, 100);
    assert!(px.signals.iter().any(|s| s.name == "_px"));
    assert!(px.signals.iter().any(|s| s.name == "_px2"));
    assert!(px.signals.iter().any(|s| s.name == "_px3"));
    assert!(px.signals.iter().any(|s| s.name == "perimeterx_client_js"));
}

#[test]
fn detect_perimeterx_captcha_challenge() {
    let detector = AntibotDetector::new();
    let html = r#"
        <html>
            <body>
                <div id="px-captcha"></div>
                <iframe src="https://captcha.px-cdn.net/PX12345/captcha.js"></iframe>
                <p>Access to this page has been denied because we believe you are using automation tools.</p>
            </body>
        </html>
    "#;

    let results = detector.detect_html(html, &[]);
    assert_eq!(results.len(), 1);
    let px = &results[0];
    assert_eq!(px.provider, BotProtectionKind::PerimeterX);
    assert_eq!(px.category, ProtectionCategory::Captcha);
    assert!(px.is_blocked);
    assert!(px.signals.iter().any(|s| s.name == "px_captcha_container"));
    assert!(px.signals.iter().any(|s| s.name == "px_captcha_iframe"));
}

// ---------------------------------------------------------------------------
// 6. Imperva / Incapsula
// ---------------------------------------------------------------------------

#[test]
fn detect_imperva_cookies_and_resource_loader() {
    let detector = AntibotDetector::new();
    let html = r#"
        <html>
            <head>
                <script src="/_Incapsula_Resource?SWKMTDIR=123"></script>
            </head>
            <body></body>
        </html>
    "#;
    let cookies = [
        Cookie::new("visid_incap_12345", "visid_val"),
        Cookie::new("incap_ses_123_456", "session_val"),
        Cookie::new("reese84", "sensor_data"),
    ];

    let page = Page::new(html).with_cookies(cookies);
    let results = detector.detect(&page).expect("detection should succeed");

    assert_eq!(results.len(), 1);
    let imp = &results[0];
    assert_eq!(imp.provider, BotProtectionKind::Imperva);
    assert_eq!(imp.confidence, 100);
    assert!(imp.signals.iter().any(|s| s.name == "visid_incap"));
    assert!(imp.signals.iter().any(|s| s.name == "incap_ses"));
    assert!(imp.signals.iter().any(|s| s.name == "reese84"));
    assert!(imp.signals.iter().any(|s| s.name == "incapsula_resource"));
}

#[test]
fn detect_imperva_incident_block_page() {
    let detector = AntibotDetector::new();
    let html = r#"
        <div id="incapsula-block-page">
            <h2>Request unsuccessful. Incapsula incident ID: 987654321</h2>
        </div>
    "#;

    let results = detector.detect_html(html, &[]);
    assert_eq!(results.len(), 1);
    let imp = &results[0];
    assert_eq!(imp.provider, BotProtectionKind::Imperva);
    assert!(imp.is_blocked);
}

// ---------------------------------------------------------------------------
// 7. AWS WAF
// ---------------------------------------------------------------------------

#[test]
fn detect_aws_waf_token_and_scripts() {
    let detector = AntibotDetector::new();
    let html = r#"
        <script src="https://token.awswaf.com/token.js"></script>
        <script src="https://challenge.awswaf.com/challenge.js"></script>
    "#;
    let cookies = [Cookie::new("aws-waf-token", "token_xyz_123")];

    let results = detector.detect_html(html, &cookies);
    assert_eq!(results.len(), 1);
    let aws = &results[0];
    assert_eq!(aws.provider, BotProtectionKind::AwsWaf);
    assert_eq!(aws.confidence, 100);
    assert!(aws.signals.iter().any(|s| s.name == "aws-waf-token"));
}

#[test]
fn detect_aws_waf_captcha_iframe_and_headers() {
    let detector = AntibotDetector::new();
    let html = r#"
        <div id="aws-waf-captcha">
            <iframe src="https://challenge.awswaf.com/captcha"></iframe>
        </div>
    "#;
    let mut headers = HashMap::new();
    headers.insert("x-amzn-waf-action".to_string(), "captcha".to_string());

    let page = Page::new(html).with_headers(headers);
    let results = detector.detect(&page).expect("detection should succeed");

    assert_eq!(results.len(), 1);
    let aws = &results[0];
    assert_eq!(aws.provider, BotProtectionKind::AwsWaf);
    assert_eq!(aws.category, ProtectionCategory::Captcha);
    assert!(aws.is_blocked);
    assert!(
        aws.signals
            .iter()
            .any(|s| s.name == "aws_waf_captcha_container")
    );
    assert!(aws.signals.iter().any(|s| s.name == "x-amzn-waf-action"));
}

// ---------------------------------------------------------------------------
// 8. FingerprintJS
// ---------------------------------------------------------------------------

#[test]
fn detect_fingerprintjs_library_and_visitor_id() {
    let detector = AntibotDetector::new();
    let html = r#"
        <script src="https://openfpcdn.io/fingerprintjs/v4"></script>
        <script>
            const fpPromise = FingerprintJS.load();
            fpPromise.then(fp => fp.get()).then(result => {
                const visitorId = result.visitorId;
                console.log(visitorId);
            });
        </script>
    "#;
    let cookies = [Cookie::new("_fpjs_visitorId", "fp_vid_123456")];

    let page = Page::new(html).with_cookies(cookies);
    let results = detector.detect(&page).expect("detection should succeed");

    assert_eq!(results.len(), 1);
    let fp = &results[0];
    assert_eq!(fp.provider, BotProtectionKind::FingerprintJs);
    assert_eq!(fp.category, ProtectionCategory::Fingerprinting);
    assert!(!fp.is_blocked); // Fingerprinting libraries don't block by themselves
    assert!(
        fp.signals
            .iter()
            .any(|s| s.name == "fpjs_visitor_id_cookie")
    );
    assert!(fp.signals.iter().any(|s| s.name.contains("OpenFPCDN")));
    assert!(fp.signals.iter().any(|s| s.name.contains("visitorId")));
}

// ---------------------------------------------------------------------------
// 9. Supplementary CAPTCHAs (reCAPTCHA & hCaptcha)
// ---------------------------------------------------------------------------

#[test]
fn detect_recaptcha_and_hcaptcha() {
    let detector = AntibotDetector::new();
    let html = r#"
        <script src="https://www.google.com/recaptcha/api.js"></script>
        <div class="g-recaptcha" data-sitekey="xyz"></div>
        <script src="https://hcaptcha.com/1/api.js"></script>
        <div class="h-captcha" data-sitekey="abc"></div>
    "#;
    let cookies = [Cookie::new("_GRECAPTCHA", "recaptcha_cookie")];

    let results = detector.detect_html(html, &cookies);
    assert_eq!(results.len(), 2);

    let rc = results
        .iter()
        .find(|r| r.provider == BotProtectionKind::ReCaptcha)
        .expect("reCAPTCHA found");
    assert!(rc.is_blocked);
    assert_eq!(rc.category, ProtectionCategory::Captcha);

    let hc = results
        .iter()
        .find(|r| r.provider == BotProtectionKind::HCaptcha)
        .expect("hCaptcha found");
    assert!(hc.is_blocked);
    assert_eq!(hc.category, ProtectionCategory::Captcha);
}

// ---------------------------------------------------------------------------
// 10. Multi-Vendor Protection Stack
// ---------------------------------------------------------------------------

#[test]
fn detect_multi_vendor_stack() {
    let detector = AntibotDetector::new();
    // A site with Cloudflare edge + FingerprintJS telemetry + reCAPTCHA fallback
    let html = r#"
        <html>
            <head>
                <script src="https://challenges.cloudflare.com/turnstile/v0/api.js"></script>
                <script src="https://openfpcdn.io/fingerprintjs/v3"></script>
            </head>
            <body>
                <div class="cf-turnstile"></div>
            </body>
        </html>
    "#;
    let cookies = [
        Cookie::new("cf_clearance", "cf_token"),
        Cookie::new("_fpjs_visitorId", "fp_token"),
    ];

    let page = Page::new(html).with_cookies(cookies);
    let results = detector.detect(&page).expect("detection should succeed");

    assert_eq!(results.len(), 2);
    // Blocked (Cloudflare) should sort ahead of non-blocked (FingerprintJS)
    assert_eq!(results[0].provider, BotProtectionKind::Cloudflare);
    assert!(results[0].is_blocked);
    assert_eq!(results[1].provider, BotProtectionKind::FingerprintJs);
    assert!(!results[1].is_blocked);
}
