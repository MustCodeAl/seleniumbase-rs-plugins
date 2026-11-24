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
        if name_lower.starts_with("visid_incap") {
            signals.push(DetectionSignal::new(
                SignalKind::Cookie,
                "visid_incap",
                &cookie.name,
                100,
            ));
        } else if name_lower.starts_with("incap_ses") {
            signals.push(DetectionSignal::new(
                SignalKind::Cookie,
                "incap_ses",
                &cookie.name,
                100,
            ));
        } else if name_lower == "___utmvc" {
            signals.push(DetectionSignal::new(
                SignalKind::Cookie,
                "___utmvc",
                &cookie.name,
                90,
            ));
            is_blocked = true;
        } else if name_lower == "reese84" {
            signals.push(DetectionSignal::new(
                SignalKind::Cookie,
                "reese84",
                &cookie.name,
                95,
            ));
        }
    }

    // 2. _Incapsula_Resource Script and Iframe
    if ctx.html_lower.contains("/_incapsula_resource") {
        let kind = if ctx.html_lower.contains("<iframe")
            && ctx.html_lower.contains("/_incapsula_resource")
        {
            is_blocked = true;
            SignalKind::Iframe
        } else {
            SignalKind::Script
        };
        signals.push(DetectionSignal::new(
            kind,
            "incapsula_resource",
            "/_Incapsula_Resource",
            100,
        ));
    }

    // 3. Challenge / Block Markers
    let imperva_markers = [
        (
            "request unsuccessful. incapsula incident id:",
            "Incapsula block incident notice",
        ),
        ("incapsula incident id", "Incapsula incident ID marker"),
        ("incapsula-block-page", "incapsula-block-page id/class"),
        (
            "_incapsula_resource?swkmtdir=",
            "Incapsula challenge script",
        ),
    ];

    for (pattern, name) in imperva_markers {
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

    // 4. Response Headers
    for (key, val) in ctx.headers {
        let k = key.to_ascii_lowercase();
        if k == "x-iinfo" {
            signals.push(DetectionSignal::new(
                SignalKind::Header,
                "x-iinfo",
                format!("{key}: {val}"),
                95,
            ));
        } else if k == "x-cdn" && val.to_ascii_lowercase().contains("incapsula") {
            signals.push(DetectionSignal::new(
                SignalKind::Header,
                "x-cdn-incapsula",
                format!("{key}: {val}"),
                90,
            ));
        }
    }

    if signals.is_empty() {
        return None;
    }

    let confidence = signals.iter().map(|s| s.confidence).max().unwrap_or(0);
    let category = if is_blocked {
        ProtectionCategory::Waf
    } else {
        ProtectionCategory::BotManagement
    };

    let description = if is_blocked {
        "Imperva / Incapsula incident block page active".to_owned()
    } else {
        "Imperva / Incapsula bot protection session active".to_owned()
    };

    Some(BotProtectionResult {
        provider: BotProtectionKind::Imperva,
        category,
        confidence,
        is_blocked,
        description,
        signals,
    })
}
