use super::DetectionContext;
use crate::types::{
    BotProtectionKind, BotProtectionResult, DetectionSignal, ProtectionCategory, SignalKind,
};

pub(crate) fn detect(ctx: &DetectionContext<'_>) -> Vec<BotProtectionResult> {
    let mut results = Vec::new();

    // 1. Google reCAPTCHA
    let mut recaptcha_signals = Vec::new();
    let mut recaptcha_blocked = false;

    for cookie in ctx.cookies {
        if cookie.name.eq_ignore_ascii_case("_grecaptcha") {
            recaptcha_signals.push(DetectionSignal::new(
                SignalKind::Cookie,
                "_grecaptcha",
                &cookie.name,
                95,
            ));
        }
    }

    if ctx.html_lower.contains("google.com/recaptcha")
        || ctx.html_lower.contains("gstatic.com/recaptcha")
        || ctx.html_lower.contains("recaptcha/api.js")
    {
        recaptcha_signals.push(DetectionSignal::new(
            SignalKind::Script,
            "recaptcha_script",
            "google.com/recaptcha",
            95,
        ));
    }

    if ctx.html_lower.contains("g-recaptcha") || ctx.html_lower.contains("g-recaptcha-response") {
        recaptcha_signals.push(DetectionSignal::new(
            SignalKind::Dom,
            "g_recaptcha_dom",
            "g-recaptcha container",
            95,
        ));
        recaptcha_blocked = true;
    }

    if !recaptcha_signals.is_empty() {
        let confidence = recaptcha_signals
            .iter()
            .map(|s| s.confidence)
            .max()
            .unwrap_or(0);
        results.push(BotProtectionResult {
            provider: BotProtectionKind::ReCaptcha,
            category: ProtectionCategory::Captcha,
            confidence,
            is_blocked: recaptcha_blocked,
            description: if recaptcha_blocked {
                "Google reCAPTCHA challenge is active on the page".to_owned()
            } else {
                "Google reCAPTCHA integration detected".to_owned()
            },
            signals: recaptcha_signals,
        });
    }

    // 2. hCaptcha
    let mut hcaptcha_signals = Vec::new();
    let mut hcaptcha_blocked = false;

    if ctx.html_lower.contains("hcaptcha.com/1/api.js")
        || ctx.html_lower.contains("js.hcaptcha.com")
        || ctx.html_lower.contains("newassets.hcaptcha.com")
    {
        hcaptcha_signals.push(DetectionSignal::new(
            SignalKind::Script,
            "hcaptcha_script",
            "hcaptcha.com API script",
            95,
        ));
    }

    if ctx.html_lower.contains("h-captcha") || ctx.html_lower.contains("h-captcha-response") {
        hcaptcha_signals.push(DetectionSignal::new(
            SignalKind::Dom,
            "h_captcha_dom",
            "h-captcha container",
            95,
        ));
        hcaptcha_blocked = true;
    }

    if !hcaptcha_signals.is_empty() {
        let confidence = hcaptcha_signals
            .iter()
            .map(|s| s.confidence)
            .max()
            .unwrap_or(0);
        results.push(BotProtectionResult {
            provider: BotProtectionKind::HCaptcha,
            category: ProtectionCategory::Captcha,
            confidence,
            is_blocked: hcaptcha_blocked,
            description: if hcaptcha_blocked {
                "hCaptcha verification challenge is active on the page".to_owned()
            } else {
                "hCaptcha integration detected".to_owned()
            },
            signals: hcaptcha_signals,
        });
    }

    results
}
