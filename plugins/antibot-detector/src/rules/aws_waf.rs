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
        if name.eq_ignore_ascii_case("aws-waf-token") {
            signals.push(DetectionSignal::new(
                SignalKind::Cookie,
                "aws-waf-token",
                &cookie.name,
                100,
            ));
        }
    }

    // 2. Scripts and SDK
    let aws_scripts = [
        ("token.awswaf.com", "AWS WAF token script"),
        ("challenge.awswaf.com", "AWS WAF challenge script"),
        ("awswaf.js", "awswaf.js SDK"),
        (
            "window.awswafintegration",
            "window.AwsWafIntegration object",
        ),
        ("window.awswafcaptcha", "window.AwsWafCaptcha object"),
    ];

    for (pattern, name) in aws_scripts {
        if ctx.html_lower.contains(pattern) {
            signals.push(DetectionSignal::new(SignalKind::Script, name, pattern, 95));
        }
    }

    // 3. Challenge / Captcha Markers
    if ctx.html_lower.contains("aws-waf-captcha") {
        signals.push(DetectionSignal::new(
            SignalKind::Dom,
            "aws_waf_captcha_container",
            "aws-waf-captcha element",
            95,
        ));
        is_blocked = true;
    }

    if ctx.html_lower.contains("<iframe")
        && (ctx.html_lower.contains("token.awswaf.com")
            || ctx.html_lower.contains("challenge.awswaf.com"))
    {
        signals.push(DetectionSignal::new(
            SignalKind::Iframe,
            "aws_waf_challenge_iframe",
            "AWS WAF challenge iframe",
            100,
        ));
        is_blocked = true;
    }

    // Block markers
    let aws_block_markers = [
        ("403 forbidden", "AWS WAF 403 Forbidden"),
        (
            "amazon cloudfront - access denied",
            "CloudFront / WAF Access Denied",
        ),
    ];

    for (pattern, name) in aws_block_markers {
        if ctx.html_lower.contains(pattern)
            && (ctx.html_lower.contains("waf") || !signals.is_empty())
        {
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
        if k == "x-amzn-waf-action" {
            signals.push(DetectionSignal::new(
                SignalKind::Header,
                "x-amzn-waf-action",
                format!("{key}: {val}"),
                100,
            ));
            if val.eq_ignore_ascii_case("block")
                || val.eq_ignore_ascii_case("challenge")
                || val.eq_ignore_ascii_case("captcha")
            {
                is_blocked = true;
            }
        } else if k == "x-amzn-errortype" && val.to_ascii_lowercase().contains("waf") {
            signals.push(DetectionSignal::new(
                SignalKind::Header,
                "x-amzn-errortype",
                format!("{key}: {val}"),
                100,
            ));
            is_blocked = true;
        }
    }

    if signals.is_empty() {
        return None;
    }

    let confidence = signals.iter().map(|s| s.confidence).max().unwrap_or(0);
    let category = if is_blocked {
        ProtectionCategory::Captcha
    } else {
        ProtectionCategory::Waf
    };

    let description = if is_blocked {
        "AWS WAF Captcha / Challenge is actively blocking the request".to_owned()
    } else {
        "AWS WAF token and integration scripts detected".to_owned()
    };

    Some(BotProtectionResult {
        provider: BotProtectionKind::AwsWaf,
        category,
        confidence,
        is_blocked,
        description,
        signals,
    })
}
