use super::DetectionContext;
use crate::types::{
    BotProtectionKind, BotProtectionResult, DetectionSignal, ProtectionCategory, SignalKind,
};

pub(crate) fn detect(ctx: &DetectionContext<'_>) -> Option<BotProtectionResult> {
    let mut signals = Vec::new();
    let mut is_blocked = false;
    let mut is_waiting_room = false;

    // 1. Cookies
    for cookie in ctx.cookies {
        let name = cookie.name.trim();
        if name.eq_ignore_ascii_case("cf_clearance") {
            signals.push(DetectionSignal::new(
                SignalKind::Cookie,
                "cf_clearance",
                &cookie.name,
                95,
            ));
        } else if name.eq_ignore_ascii_case("__cf_bm") {
            signals.push(DetectionSignal::new(
                SignalKind::Cookie,
                "__cf_bm",
                &cookie.name,
                95,
            ));
        } else if name.eq_ignore_ascii_case("__cfwaitingroom") {
            signals.push(DetectionSignal::new(
                SignalKind::Cookie,
                "__cfwaitingroom",
                &cookie.name,
                95,
            ));
            is_waiting_room = true;
            is_blocked = true;
        } else if name.starts_with("cf_chl_") {
            signals.push(DetectionSignal::new(
                SignalKind::Cookie,
                "cf_challenge_cookie",
                &cookie.name,
                90,
            ));
            is_blocked = true;
        }
    }

    // 2. Turnstile Iframe & DOM
    if ctx
        .html_lower
        .contains("challenges.cloudflare.com/turnstile")
        || (ctx.html_lower.contains("<iframe") && ctx.html_lower.contains("turnstile"))
    {
        signals.push(DetectionSignal::new(
            SignalKind::Iframe,
            "turnstile_iframe",
            "challenges.cloudflare.com/turnstile",
            95,
        ));
        is_blocked = true;
    } else if ctx
        .html_lower
        .contains("challenges.cloudflare.com/cdn-cgi/challenge-platform")
    {
        signals.push(DetectionSignal::new(
            SignalKind::Iframe,
            "turnstile_challenge_platform",
            "challenges.cloudflare.com/cdn-cgi/challenge-platform",
            95,
        ));
        is_blocked = true;
    }

    if ctx.html_lower.contains("cf-turnstile") {
        signals.push(DetectionSignal::new(
            SignalKind::Dom,
            "cf_turnstile_container",
            "cf-turnstile",
            90,
        ));
    }

    if ctx.html_lower.contains("turnstile/v0/api.js")
        || ctx.html_lower.contains("turnstile.render")
        || ctx.html_lower.contains("window.turnstile")
    {
        signals.push(DetectionSignal::new(
            SignalKind::Script,
            "turnstile_api_script",
            "turnstile API",
            85,
        ));
    }

    // 3. Challenge Page Markers
    let cf_markers = [
        ("cf-ray", "cf-ray marker"),
        ("cf-challenge-running", "cf-challenge-running"),
        ("cf-please-wait", "cf-please-wait"),
        ("cf-browser-verification", "cf-browser-verification"),
        ("cf-im-under-attack", "cf-im-under-attack"),
        ("challenge-stage", "challenge-stage"),
        ("challenge-running", "challenge-running"),
        ("challenge-form", "challenge-form"),
        ("cdn-cgi/challenge-platform", "cdn-cgi/challenge-platform"),
        ("_cf_chl_opt", "_cf_chl_opt config"),
    ];

    for (pattern, name) in cf_markers {
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

    // Text markers indicating active Cloudflare challenge
    let text_markers = [
        ("just a moment...", "Just a moment..."),
        (
            "attention required! | cloudflare",
            "Attention Required! | Cloudflare",
        ),
        (
            "checking your browser before accessing",
            "Checking your browser before accessing",
        ),
        (
            "verify you are human by completing the action below",
            "Verify you are human prompt",
        ),
        (
            "enable javascript and cookies to continue",
            "Enable JavaScript and cookies prompt",
        ),
    ];

    for (pattern, name) in text_markers {
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

    // 4. Waiting Room
    if ctx.html_lower.contains("cf-waiting-room")
        || (ctx.html_lower.contains("waiting room") && ctx.html_lower.contains("you are in line"))
        || ctx.html_lower.contains("waiting-room-container")
    {
        signals.push(DetectionSignal::new(
            SignalKind::Dom,
            "waiting_room",
            "Cloudflare Waiting Room",
            95,
        ));
        is_waiting_room = true;
        is_blocked = true;
    }

    // 5. Response Headers
    for (key, val) in ctx.headers {
        let k = key.to_ascii_lowercase();
        if k == "cf-ray" {
            signals.push(DetectionSignal::new(
                SignalKind::Header,
                "cf-ray",
                format!("cf-ray: {val}"),
                80,
            ));
        } else if k == "cf-mitigated" {
            signals.push(DetectionSignal::new(
                SignalKind::Header,
                "cf-mitigated",
                format!("cf-mitigated: {val}"),
                100,
            ));
            is_blocked = true;
        } else if k == "server" && val.to_ascii_lowercase().contains("cloudflare") {
            signals.push(DetectionSignal::new(
                SignalKind::Header,
                "server_cloudflare",
                "server: cloudflare",
                70,
            ));
        }
    }

    if signals.is_empty() {
        return None;
    }

    let confidence = signals.iter().map(|s| s.confidence).max().unwrap_or(0);
    let category = if is_waiting_room {
        ProtectionCategory::WaitingRoom
    } else if signals
        .iter()
        .any(|s| s.name.contains("turnstile") || s.kind == SignalKind::Iframe)
    {
        ProtectionCategory::Captcha
    } else {
        ProtectionCategory::BotManagement
    };

    let description = if is_waiting_room {
        "Cloudflare Waiting Room detected (visitor queue active)".to_owned()
    } else if is_blocked {
        "Cloudflare challenge / Turnstile verification page active".to_owned()
    } else {
        "Cloudflare bot protection signals identified".to_owned()
    };

    Some(BotProtectionResult {
        provider: BotProtectionKind::Cloudflare,
        category,
        confidence,
        is_blocked,
        description,
        signals,
    })
}
