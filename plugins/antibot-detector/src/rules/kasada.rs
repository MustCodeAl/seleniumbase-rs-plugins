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
        if name_lower.starts_with("kpsdk") {
            signals.push(DetectionSignal::new(
                SignalKind::Cookie,
                "kpsdk_cookie",
                &cookie.name,
                100,
            ));
        }
    }

    // 2. 149e9513 Signature Hash
    if ctx.html_lower.contains("149e9513") {
        signals.push(DetectionSignal::new(
            SignalKind::Script,
            "kasada_149e9513_path",
            "149e9513 Kasada signature hash",
            100,
        ));
    }

    // 3. ips.js Script
    if ctx.html_lower.contains("/ips.js") || ctx.html_lower.contains("ips.js") {
        signals.push(DetectionSignal::new(
            SignalKind::Script,
            "kasada_ips_js",
            "ips.js Inline Protection System",
            95,
        ));
    }

    // 4. KPSDK DOM & Script Markers
    let kasada_markers = [
        ("window.kpsdk", "KPSDK client object"),
        ("data-kpsdk-cd", "KPSDK client data attribute"),
        ("data-kpsdk-ct", "KPSDK client token attribute"),
        ("kpsdk-container", "KPSDK challenge container"),
        ("kpsdk-ips", "KPSDK IPS attribute"),
    ];

    for (pattern, name) in kasada_markers {
        if ctx.html_lower.contains(pattern) {
            signals.push(DetectionSignal::new(SignalKind::Dom, name, pattern, 95));
        }
    }

    // 5. Block / Challenge status (Kasada commonly returns 429 or 403 when blocking)
    if (ctx.status_code == Some(429) || ctx.status_code == Some(403)) && !signals.is_empty() {
        is_blocked = true;
    }

    if ctx.html_lower.contains("kpsdk-container") || ctx.html_lower.contains("kasada challenge") {
        is_blocked = true;
    }

    // 6. Response Headers
    for (key, val) in ctx.headers {
        let k = key.to_ascii_lowercase();
        if k.starts_with("x-kpsdk-") {
            signals.push(DetectionSignal::new(
                SignalKind::Header,
                "x-kpsdk-header",
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
        "Kasada Inline Protection System is actively challenging/blocking the request".to_owned()
    } else {
        "Kasada (KPSDK / ips.js) bot detection identified".to_owned()
    };

    Some(BotProtectionResult {
        provider: BotProtectionKind::Kasada,
        category,
        confidence,
        is_blocked,
        description,
        signals,
    })
}
