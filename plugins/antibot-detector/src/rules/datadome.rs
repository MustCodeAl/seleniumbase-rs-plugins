use super::DetectionContext;
use crate::types::{
    BotProtectionKind, BotProtectionResult, DetectionSignal, ProtectionCategory, SignalKind,
};

pub(crate) fn detect(ctx: &DetectionContext<'_>) -> Option<BotProtectionResult> {
    let mut signals = Vec::new();
    let mut is_blocked = false;

    // 1. Cookies
    for cookie in ctx.cookies {
        let name = cookie.name.trim();
        if name.eq_ignore_ascii_case("datadome") {
            signals.push(DetectionSignal::new(
                SignalKind::Cookie,
                "datadome_cookie",
                &cookie.name,
                100,
            ));
        } else if name.eq_ignore_ascii_case("cid") || name.eq_ignore_ascii_case("datadome-cid") {
            // cid cookie when datadome is also referenced or by itself
            signals.push(DetectionSignal::new(
                SignalKind::Cookie,
                "datadome_cid_cookie",
                &cookie.name,
                85,
            ));
        }
    }

    // 2. Captcha Delivery Iframe
    if ctx.html_lower.contains("geo.captcha-delivery.com/captcha")
        || ctx.html_lower.contains("geo.captcha-delivery.com")
        || ctx.html_lower.contains("ct.captcha-delivery.com")
        || (ctx.html_lower.contains("<iframe") && ctx.html_lower.contains("captcha-delivery.com"))
    {
        signals.push(DetectionSignal::new(
            SignalKind::Iframe,
            "datadome_captcha_iframe",
            "captcha-delivery.com",
            100,
        ));
        is_blocked = true;
    }

    // 3. DataDome / Geetest Scripts
    if ctx.html_lower.contains("js.datadome.co/tags.js")
        || ctx.html_lower.contains("js.datadome.co")
        || ctx.html_lower.contains("api-js.datadome.co")
        || ctx.html_lower.contains("check.datadome.co")
    {
        signals.push(DetectionSignal::new(
            SignalKind::Script,
            "datadome_js_script",
            "js.datadome.co",
            95,
        ));
    }

    // DataDome + GeeTest integration
    if (ctx.html_lower.contains("geetest") && ctx.html_lower.contains("datadome"))
        || ctx.html_lower.contains("data-datadome-geetest")
    {
        signals.push(DetectionSignal::new(
            SignalKind::Script,
            "datadome_geetest_script",
            "DataDome Geetest integration",
            95,
        ));
        is_blocked = true;
    }

    // Client-side sensor markers
    if ctx.html_lower.contains("window.dd =")
        || ctx.html_lower.contains("window.dd=")
        || ctx.html_lower.contains("window._dd_")
        || ctx.html_lower.contains("data-dd-")
        || ctx.html_lower.contains("datadome.init")
    {
        signals.push(DetectionSignal::new(
            SignalKind::Dom,
            "datadome_telemetry_sensor",
            "DataDome client SDK",
            90,
        ));
    }

    // 4. Challenge Markers
    let dd_challenge_markers = [
        (
            "please solve this captcha so that we can be sure that you're a real human",
            "DataDome prompt",
        ),
        ("datadome captcha", "DataDome CAPTCHA marker"),
        ("data-dd-captcha", "data-dd-captcha element"),
        ("datadome-captcha", "datadome-captcha id/class"),
    ];

    for (pattern, name) in dd_challenge_markers {
        if ctx.html_lower.contains(pattern) {
            signals.push(DetectionSignal::new(
                SignalKind::ChallengeMarker,
                name,
                pattern,
                100,
            ));
            is_blocked = true;
        }
    }

    // 5. Response Headers
    for (key, val) in ctx.headers {
        let k = key.to_ascii_lowercase();
        if k == "x-datadome" || k == "x-datadome-cid" || k == "x-datadome-response" {
            signals.push(DetectionSignal::new(
                SignalKind::Header,
                "x-datadome-header",
                format!("{key}: {val}"),
                100,
            ));
            if val.eq_ignore_ascii_case("block") || val.contains("captcha") {
                is_blocked = true;
            }
        }
    }

    if signals.is_empty() {
        return None;
    }

    let confidence = signals.iter().map(|s| s.confidence).max().unwrap_or(0);
    let category = if is_blocked {
        ProtectionCategory::Captcha
    } else {
        ProtectionCategory::BotManagement
    };

    let description = if is_blocked {
        "DataDome CAPTCHA challenge is blocking the page".to_owned()
    } else {
        "DataDome bot protection detected".to_owned()
    };

    Some(BotProtectionResult {
        provider: BotProtectionKind::DataDome,
        category,
        confidence,
        is_blocked,
        description,
        signals,
    })
}
