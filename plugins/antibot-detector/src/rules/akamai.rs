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
        if name.eq_ignore_ascii_case("_abck") {
            signals.push(DetectionSignal::new(
                SignalKind::Cookie,
                "_abck",
                &cookie.name,
                100,
            ));
        } else if name.eq_ignore_ascii_case("bm_sz") {
            signals.push(DetectionSignal::new(
                SignalKind::Cookie,
                "bm_sz",
                &cookie.name,
                95,
            ));
        } else if name.eq_ignore_ascii_case("bm_sv") {
            signals.push(DetectionSignal::new(
                SignalKind::Cookie,
                "bm_sv",
                &cookie.name,
                95,
            ));
        } else if name.starts_with("bm_") || name.starts_with("ak_") {
            signals.push(DetectionSignal::new(
                SignalKind::Cookie,
                "akamai_cookie",
                &cookie.name,
                85,
            ));
        }
    }

    // 2. Telemetry Beacon / Sensor Scripts
    let akamai_scripts = [
        ("/akam/13/", "akamai_sensor_13"),
        ("/akam/11/", "akamai_sensor_11"),
        ("bazadebezolkohpepadr", "akamai_bazadebezolkohpepadr"),
        ("akamaiedge.net", "akamai_edge_script"),
        ("window._abck", "akamai_abck_window"),
        ("window.akamai_bot_detector", "akamai_bot_detector_object"),
        ("_akamai", "akamai_telemetry_var"),
    ];

    for (pattern, name) in akamai_scripts {
        if ctx.html_lower.contains(pattern) {
            signals.push(DetectionSignal::new(SignalKind::Script, name, pattern, 95));
        }
    }

    // 3. Challenge / Access Denied Markers
    let akamai_challenge_markers = [
        ("access denied - akamai", "Akamai Access Denied title"),
        ("reference&#32;&#35;", "Akamai reference error marker"),
        ("reference #", "Akamai incident reference"),
        ("akamaighost", "AkamaiGHost server reference"),
    ];

    for (pattern, name) in akamai_challenge_markers {
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

    // Check for HTTP 403 combined with Akamai markers
    if ctx.status_code == Some(403) && (!signals.is_empty() || ctx.html_lower.contains("denied")) {
        is_blocked = true;
    }

    // 4. Response Headers
    for (key, val) in ctx.headers {
        let k = key.to_ascii_lowercase();
        if k == "x-akamai-transformed" {
            signals.push(DetectionSignal::new(
                SignalKind::Header,
                "x-akamai-transformed",
                format!("{key}: {val}"),
                90,
            ));
        } else if k == "server" && val.contains("AkamaiGHost") {
            signals.push(DetectionSignal::new(
                SignalKind::Header,
                "server_akamaighost",
                "server: AkamaiGHost",
                80,
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
        "Akamai Bot Manager blocked access to this page".to_owned()
    } else {
        "Akamai Bot Manager telemetry and session tokens detected".to_owned()
    };

    Some(BotProtectionResult {
        provider: BotProtectionKind::Akamai,
        category,
        confidence,
        is_blocked,
        description,
        signals,
    })
}
