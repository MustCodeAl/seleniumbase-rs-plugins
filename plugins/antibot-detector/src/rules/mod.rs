use std::collections::HashMap;

use crate::types::{BotProtectionResult, Cookie};

pub(crate) mod akamai;
pub(crate) mod aws_waf;
pub(crate) mod captcha;
pub(crate) mod cloudflare;
pub(crate) mod datadome;
pub(crate) mod fingerprintjs;
pub(crate) mod imperva;
pub(crate) mod kasada;
pub(crate) mod perimeterx;

/// The inspection context supplied to each detection heuristic rule.
#[allow(
    dead_code,
    reason = "retained for URL-based heuristics and raw casing access"
)]
pub(crate) struct DetectionContext<'a> {
    pub html: &'a str,
    pub html_lower: String,
    pub cookies: &'a [Cookie],
    pub headers: &'a HashMap<String, String>,
    pub status_code: Option<u16>,
    pub url: Option<&'a str>,
}

impl<'a> DetectionContext<'a> {
    pub fn new(
        html: &'a str,
        cookies: &'a [Cookie],
        headers: &'a HashMap<String, String>,
        status_code: Option<u16>,
        url: Option<&'a str>,
    ) -> Self {
        Self {
            html,
            html_lower: html.to_ascii_lowercase(),
            cookies,
            headers,
            status_code,
            url,
        }
    }
}

/// Evaluates all detection rules against the provided context.
pub(crate) fn evaluate_rules(ctx: &DetectionContext<'_>) -> Vec<BotProtectionResult> {
    let mut results = Vec::new();

    if let Some(cf) = cloudflare::detect(ctx) {
        results.push(cf);
    }
    if let Some(dd) = datadome::detect(ctx) {
        results.push(dd);
    }
    if let Some(ak) = akamai::detect(ctx) {
        results.push(ak);
    }
    if let Some(ks) = kasada::detect(ctx) {
        results.push(ks);
    }
    if let Some(px) = perimeterx::detect(ctx) {
        results.push(px);
    }
    if let Some(imp) = imperva::detect(ctx) {
        results.push(imp);
    }
    if let Some(aws) = aws_waf::detect(ctx) {
        results.push(aws);
    }
    if let Some(fp) = fingerprintjs::detect(ctx) {
        results.push(fp);
    }
    results.extend(captcha::detect(ctx));

    // Sort results by blocked status first, then confidence descending
    results.sort_by(|a, b| {
        b.is_blocked
            .cmp(&a.is_blocked)
            .then_with(|| b.confidence.cmp(&a.confidence))
    });

    results
}
