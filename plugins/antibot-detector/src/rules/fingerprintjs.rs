use super::DetectionContext;
use crate::types::{
    BotProtectionKind, BotProtectionResult, DetectionSignal, ProtectionCategory, SignalKind,
};

pub(crate) fn detect(ctx: &DetectionContext<'_>) -> Option<BotProtectionResult> {
    let mut signals = Vec::new();

    // 1. Cookies
    for cookie in ctx.cookies {
        let name = cookie.name.trim();
        let name_lower = name.to_ascii_lowercase();
        if name_lower == "_fpjs_visitorid" || name_lower == "fpjs_visitor_id" {
            signals.push(DetectionSignal::new(
                SignalKind::Cookie,
                "fpjs_visitor_id_cookie",
                &cookie.name,
                95,
            ));
        } else if name_lower.contains("fpjs") {
            signals.push(DetectionSignal::new(
                SignalKind::Cookie,
                "fpjs_cookie",
                &cookie.name,
                85,
            ));
        }
    }

    // 2. fpjs Scripts
    let fpjs_scripts = [
        (
            "@fingerprintjs/fingerprintjs",
            "FingerprintJS npm package import",
        ),
        ("openfpcdn.io", "OpenFPCDN FingerprintJS CDN"),
        ("api.fpjs.io", "FingerprintJS Pro API endpoint"),
        ("cdn.fpjs.io", "FingerprintJS Pro CDN"),
        ("fpjs.min.js", "fpjs.min.js script"),
        ("fingerprint2.js", "fingerprint2.js legacy script"),
        ("fingerprintjs.load", "FingerprintJS.load call"),
        ("fp.get()", "fp.get() fingerprint collector call"),
    ];

    for (pattern, name) in fpjs_scripts {
        if ctx.html_lower.contains(pattern) {
            signals.push(DetectionSignal::new(SignalKind::Script, name, pattern, 95));
        }
    }

    // 3. visitorId variable or attribute
    let visitor_patterns = [
        ("visitorid", "visitorId property/variable"),
        ("data-visitor-id", "data-visitor-id DOM attribute"),
    ];

    for (pattern, name) in visitor_patterns {
        if ctx.html_lower.contains(pattern) {
            signals.push(DetectionSignal::new(SignalKind::Script, name, pattern, 85));
        }
    }

    if signals.is_empty() {
        return None;
    }

    let confidence = signals.iter().map(|s| s.confidence).max().unwrap_or(0);

    Some(BotProtectionResult {
        provider: BotProtectionKind::FingerprintJs,
        category: ProtectionCategory::Fingerprinting,
        confidence,
        is_blocked: false,
        description: "FingerprintJS browser fingerprinting library and telemetry detected"
            .to_owned(),
        signals,
    })
}
