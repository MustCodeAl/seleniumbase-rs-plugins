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
        let name_lower = name.to_ascii_lowercase();
        if name_lower == "_px" {
            signals.push(DetectionSignal::new(
                SignalKind::Cookie,
                "_px",
                &cookie.name,
                100,
            ));
        } else if name_lower == "_px2" {
            signals.push(DetectionSignal::new(
                SignalKind::Cookie,
                "_px2",
                &cookie.name,
                100,
            ));
        } else if name_lower == "_px3" {
            signals.push(DetectionSignal::new(
                SignalKind::Cookie,
                "_px3",
                &cookie.name,
                100,
            ));
        } else if name_lower.starts_with("_px") {
            signals.push(DetectionSignal::new(
                SignalKind::Cookie,
                "perimeterx_cookie",
                &cookie.name,
                90,
            ));
        }
    }

    // 2. client.js and PerimeterX / HUMAN Scripts
    if ctx.html_lower.contains("client.perimeterx.net")
        || ctx.html_lower.contains("px-cdn.net")
        || ctx.html_lower.contains("humansecurity.com")
        || (ctx.html_lower.contains("client.js")
            && (ctx.html_lower.contains("px") || ctx.html_lower.contains("perimeterx")))
    {
        signals.push(DetectionSignal::new(
            SignalKind::Script,
            "perimeterx_client_js",
            "PerimeterX / HUMAN client.js",
            95,
        ));
    }

    // Window config objects
    let px_configs = [
        ("window._pxparam", "window._pxParam configuration"),
        ("window._pxappid", "window._pxAppId"),
        ("window._pxuuid", "window._pxUuid"),
    ];

    for (pattern, name) in px_configs {
        if ctx.html_lower.contains(pattern) {
            signals.push(DetectionSignal::new(SignalKind::Script, name, pattern, 95));
        }
    }

    // 3. Captcha / Block Page Markers
    if ctx.html_lower.contains("px-captcha") {
        signals.push(DetectionSignal::new(
            SignalKind::Dom,
            "px_captcha_container",
            "px-captcha element",
            100,
        ));
        is_blocked = true;
    }

    if ctx.html_lower.contains("captcha.px-cdn.net") {
        signals.push(DetectionSignal::new(
            SignalKind::Iframe,
            "px_captcha_iframe",
            "captcha.px-cdn.net",
            100,
        ));
        is_blocked = true;
    }

    let px_block_text = [
        (
            "access to this page has been denied because we believe you are using automation tools",
            "PerimeterX block notice",
        ),
        ("please verify you are a human", "HUMAN verification prompt"),
        ("press & hold", "PerimeterX Press & Hold challenge"),
        ("px-blocked", "px-blocked marker"),
    ];

    for (pattern, name) in px_block_text {
        if ctx.html_lower.contains(pattern) {
            signals.push(DetectionSignal::new(
                SignalKind::ChallengeMarker,
                name,
                pattern,
                95,
            ));
            is_blocked = true;
        }
    }

    // 4. Response Headers
    for (key, val) in ctx.headers {
        let k = key.to_ascii_lowercase();
        if k.starts_with("x-px-") {
            signals.push(DetectionSignal::new(
                SignalKind::Header,
                "x-px-header",
                format!("{key}: {val}"),
                100,
            ));
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
        "PerimeterX / HUMAN Security challenge or captcha is blocking access".to_owned()
    } else {
        "PerimeterX / HUMAN Security telemetry client detected".to_owned()
    };

    Some(BotProtectionResult {
        provider: BotProtectionKind::PerimeterX,
        category,
        confidence,
        is_blocked,
        description,
        signals,
    })
}
