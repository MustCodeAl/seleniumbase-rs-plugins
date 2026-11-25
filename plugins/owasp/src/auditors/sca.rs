//! Passive client-side Software Composition Analysis (SCA) and EOL advisory lookup.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::auditors::dom::DomSnapshot;
use crate::types::{AuditorKind, Finding, OwaspCategory, Severity};

/// Parsed semantic version `(major, minor, patch)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SemVer {
    /// Major component.
    pub major: u64,
    /// Minor component.
    pub minor: u64,
    /// Patch component.
    pub patch: u64,
}

impl SemVer {
    /// Parses a version string such as `"3.4.1"`, `"v4.17.15"`, or `"18.2.0-rc.1"`.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        let cleaned = raw.trim().trim_start_matches('v').trim_start_matches('V');
        let core = cleaned.split(['-', '+']).next()?;
        let mut parts = core.split('.');
        let major = parts.next()?.parse::<u64>().ok()?;
        let minor = parts
            .next()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        let patch = parts
            .next()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        Some(Self {
            major,
            minor,
            patch,
        })
    }

    /// Tuple convenience constructor.
    #[must_use]
    pub const fn new(major: u64, minor: u64, patch: u64) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }
}

impl fmt::Display for SemVer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Lifecycle/advisory status of a detected client-side library.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ComponentStatus {
    /// No known passive EOL or vulnerable version advisory matched.
    Current,
    /// Older branch with recommended upgrade.
    Outdated,
    /// Known vulnerable or End-of-Life version range.
    VulnerableOrEol,
}

/// Client-side library and version identified passively from DOM, URLs, headers, or globals.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DetectedComponent {
    /// Normalized library name (e.g. `jquery`, `lodash`, `react`, `angular`, `bootstrap`, `vue`).
    pub name: String,
    /// Raw detected version string.
    pub version: String,
    /// Parsed semantic version when available.
    pub semver: Option<SemVer>,
    /// Where the library version was observed (script URL, global variable, DOM attribute, or header).
    pub source: String,
    /// Advisory status.
    pub status: ComponentStatus,
    /// Passive advisory note if outdated/EOL.
    pub advisory: Option<String>,
}

/// Output of passive client-side SCA inspection.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ScaResult {
    /// All detected client-side libraries.
    pub components: Vec<DetectedComponent>,
    /// OWASP `A06:2021` findings for outdated or EOL client libraries.
    pub findings: Vec<Finding>,
}

/// Runs passive client-side SCA across a [`DomSnapshot`] and optional HTTP response headers.
#[must_use]
pub fn audit_sca(snapshot: &DomSnapshot, headers: &[(String, String)]) -> ScaResult {
    let mut detected: Vec<DetectedComponent> = Vec::new();
    let mut findings = Vec::new();

    // 1. Inspect runtime JS globals & DOM markers
    let global_candidates = [
        (
            "jquery",
            snapshot.globals.jquery_version.as_deref(),
            "js:jQuery.fn.jquery",
        ),
        (
            "angularjs",
            snapshot.globals.angular_version.as_deref(),
            "js:angular.version",
        ),
        (
            "angular",
            snapshot.globals.ng_version.as_deref(),
            "dom:[ng-version]",
        ),
        (
            "react",
            snapshot.globals.react_version.as_deref(),
            "js:React.version",
        ),
        (
            "lodash",
            snapshot.globals.lodash_version.as_deref(),
            "js:_.VERSION",
        ),
        (
            "bootstrap",
            snapshot.globals.bootstrap_version.as_deref(),
            "js:bootstrap.VERSION",
        ),
        (
            "vue",
            snapshot.globals.vue_version.as_deref(),
            "js:Vue.version",
        ),
    ];
    for (name, ver_opt, src) in global_candidates {
        if let Some(ver) = ver_opt {
            push_component(&mut detected, name, ver, src);
        }
    }

    // 2. Inspect script & stylesheet URLs
    for script in &snapshot.scripts {
        if let Some(src) = &script.src {
            detect_from_asset_url(src, &mut detected);
        }
    }
    for sheet in &snapshot.stylesheets {
        detect_from_asset_url(&sheet.href, &mut detected);
    }

    // 3. Inspect informative response headers (e.g., X-Powered-By / X-Generator)
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("x-powered-by")
            || name.eq_ignore_ascii_case("x-generator")
            || name.eq_ignore_ascii_case("x-framework")
        {
            detect_from_header(name, value, &mut detected);
        }
    }

    // 4. Evaluate passive advisory table for each detected component
    for comp in &mut detected {
        if let Some((sev, summary, remediation)) = evaluate_advisory(&comp.name, comp.semver) {
            comp.status = if sev >= Severity::Medium {
                ComponentStatus::VulnerableOrEol
            } else {
                ComponentStatus::Outdated
            };
            comp.advisory = Some(summary.clone());

            let rule_id = format!(
                "OWASP-SCA-OUTDATED-{}",
                comp.name.to_ascii_uppercase().replace(['.', '-'], "_")
            );
            findings.push(
                Finding::new(
                    rule_id,
                    format!(
                        "Outdated/EOL client-side library `{}` v{}",
                        comp.name, comp.version
                    ),
                    sev,
                    OwaspCategory::A06VulnerableAndOutdatedComponents,
                    AuditorKind::Sca,
                )
                .cwe(1104)
                .wstg("WSTG-CONF-04")
                .location(snapshot.url.clone())
                .evidence(format!(
                    "component={}@{}, source={}: {}",
                    comp.name, comp.version, comp.source, summary
                ))
                .description(summary)
                .remediation(remediation),
            );
        }
    }

    ScaResult {
        components: detected,
        findings,
    }
}

fn push_component(out: &mut Vec<DetectedComponent>, name: &str, version: &str, source: &str) {
    let clean_ver = version.trim();
    if clean_ver.is_empty() {
        return;
    }
    let semver = SemVer::parse(clean_ver);
    if out.iter().any(|c| c.name == name && c.version == clean_ver) {
        return;
    }
    out.push(DetectedComponent {
        name: name.to_owned(),
        version: clean_ver.to_owned(),
        semver,
        source: source.to_owned(),
        status: ComponentStatus::Current,
        advisory: None,
    });
}

fn detect_from_asset_url(url: &str, out: &mut Vec<DetectedComponent>) {
    let lower = url.to_ascii_lowercase();
    let specs: &[(&str, &[&str])] = &[
        ("jquery", &["jquery", "jquery.min", "jquery.slim"]),
        ("angularjs", &["angularjs", "angular.js", "angular.min.js"]),
        ("angular", &["@angular/core", "angular-core"]),
        (
            "react",
            &[
                "react-dom",
                "react.production",
                "react.development",
                "react@",
            ],
        ),
        ("lodash", &["lodash"]),
        ("bootstrap", &["bootstrap"]),
        ("vue", &["vue.min.js", "vue.global", "vue.esm", "vue@"]),
    ];

    for (lib, needles) in specs {
        if needles.iter().any(|n| lower.contains(n))
            && let Some(ver) = extract_version_near(&lower, lib)
        {
            push_component(out, lib, &ver, url);
        }
    }
    // Special case: CDN paths like `/ajax/libs/angular.js/1.8.2/angular.min.js`
    if lower.contains("angular.js/")
        && let Some(ver) = extract_version_after(&lower, "angular.js/")
    {
        push_component(out, "angularjs", &ver, url);
    }
    if lower.contains("/vue/")
        && let Some(ver) = extract_version_after(&lower, "/vue/")
    {
        push_component(out, "vue", &ver, url);
    }
    if lower.contains("/react/")
        && let Some(ver) = extract_version_after(&lower, "/react/")
    {
        push_component(out, "react", &ver, url);
    }
}

fn detect_from_header(header_name: &str, value: &str, out: &mut Vec<DetectedComponent>) {
    let lower = value.to_ascii_lowercase();
    for lib in ["express", "php", "next.js", "aspnet", "jquery"] {
        if lower.contains(lib)
            && let Some(ver) = extract_first_semver(value)
        {
            push_component(out, lib, &ver, &format!("header:{header_name}"));
        }
    }
}

fn extract_version_near(lower_url: &str, lib: &str) -> Option<String> {
    let key = if lib == "angularjs" { "angular" } else { lib };
    let mut search_from = 0;
    while let Some(rel) = lower_url[search_from..].find(key) {
        let after_idx = search_from + rel + key.len();
        let tail = &lower_url[after_idx..];
        if let Some(rest) = tail
            .strip_prefix('@')
            .or_else(|| tail.strip_prefix('-'))
            .or_else(|| tail.strip_prefix('/'))
            .or_else(|| tail.strip_prefix(".js/"))
            && let Some(ver) = take_leading_semver(rest)
        {
            return Some(ver);
        }
        // Handle `jquery-ui` skip or `lodash.min` etc.
        if let Some(ver) = extract_first_semver(tail.split('?').next().unwrap_or(tail)) {
            return Some(ver);
        }
        search_from = after_idx;
    }
    None
}

fn extract_version_after(lower_url: &str, marker: &str) -> Option<String> {
    let pos = lower_url.find(marker)?;
    take_leading_semver(&lower_url[pos + marker.len()..])
}

fn take_leading_semver(s: &str) -> Option<String> {
    let trimmed = s.trim_start_matches('v');
    let candidate: String = trimmed
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    let clean = candidate.trim_end_matches('.');
    if clean.contains('.') && SemVer::parse(clean).is_some() {
        Some(clean.to_owned())
    } else {
        None
    }
}

fn extract_first_semver(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit()
            && (i == 0 || !bytes[i - 1].is_ascii_alphanumeric())
            && let Some(ver) = take_leading_semver(&s[i..])
        {
            return Some(ver);
        }
        i += 1;
    }
    None
}

fn evaluate_advisory(name: &str, semver: Option<SemVer>) -> Option<(Severity, String, String)> {
    let v = semver?;
    match name {
        "jquery" => {
            if v < SemVer::new(3, 0, 0) {
                Some((
                    Severity::High,
                    format!(
                        "jQuery {v} is End-of-Life (< 3.0.0) and affected by known HTML prefilter XSS vulnerabilities (CVE-2020-11022, CVE-2020-11023, CVE-2019-11358)."
                    ),
                    "Upgrade jQuery to >= 3.7.1.".to_owned(),
                ))
            } else if v < SemVer::new(3, 5, 0) {
                Some((
                    Severity::Medium,
                    format!(
                        "jQuery {v} (< 3.5.0) is affected by HTML prefilter XSS issues (CVE-2020-11022, CVE-2020-11023)."
                    ),
                    "Upgrade jQuery to >= 3.7.1.".to_owned(),
                ))
            } else if v < SemVer::new(3, 7, 1) {
                Some((
                    Severity::Low,
                    format!("jQuery {v} is behind the current 3.7.x maintenance release."),
                    "Update jQuery to >= 3.7.1.".to_owned(),
                ))
            } else {
                None
            }
        }
        "angularjs" => {
            if v.major == 1 {
                Some((
                    Severity::High,
                    format!(
                        "AngularJS {v} (1.x) reached End-of-Life in December 2021 with unpatched XSS/ReDoS vulnerabilities."
                    ),
                    "Migrate from AngularJS 1.x to a supported Angular release or modern maintained framework.".to_owned(),
                ))
            } else {
                None
            }
        }
        "angular" => {
            if v < SemVer::new(16, 0, 0) {
                Some((
                    Severity::Medium,
                    format!("Angular {v} (< 16.0.0) is no longer receiving LTS security fixes."),
                    "Upgrade Angular to a currently supported LTS major version (>= 17.x)."
                        .to_owned(),
                ))
            } else if v < SemVer::new(17, 0, 0) {
                Some((
                    Severity::Low,
                    format!("Angular {v} is an older major release."),
                    "Plan upgrade to Angular >= 18.x.".to_owned(),
                ))
            } else {
                None
            }
        }
        "react" => {
            if v < SemVer::new(17, 0, 0) {
                Some((
                    Severity::Medium,
                    format!("React {v} (< 17.0.0) is an outdated legacy major branch."),
                    "Upgrade React to >= 18.2.0.".to_owned(),
                ))
            } else if v < SemVer::new(18, 0, 0) {
                Some((
                    Severity::Low,
                    format!("React {v} (17.x) is behind current maintained React 18.x+."),
                    "Upgrade React to >= 18.2.0.".to_owned(),
                ))
            } else {
                None
            }
        }
        "lodash" => {
            if v < SemVer::new(4, 17, 21) {
                Some((
                    Severity::High,
                    format!(
                        "Lodash {v} (< 4.17.21) is affected by known prototype pollution and ReDoS/template injection advisories (CVE-2021-23337, CVE-2020-8203)."
                    ),
                    "Upgrade Lodash to >= 4.17.21.".to_owned(),
                ))
            } else {
                None
            }
        }
        "bootstrap" => {
            if v < SemVer::new(4, 0, 0) {
                Some((
                    Severity::High,
                    format!(
                        "Bootstrap {v} (3.x) is End-of-Life and affected by tooltip/popover XSS advisories (CVE-2019-8331)."
                    ),
                    "Upgrade Bootstrap to >= 5.3.3.".to_owned(),
                ))
            } else if v < SemVer::new(5, 0, 0) {
                Some((
                    Severity::Medium,
                    format!("Bootstrap {v} (4.x) reached End-of-Life in January 2023."),
                    "Upgrade Bootstrap to >= 5.3.3.".to_owned(),
                ))
            } else if v < SemVer::new(5, 3, 0) {
                Some((
                    Severity::Low,
                    format!("Bootstrap {v} is behind the 5.3.x release line."),
                    "Update Bootstrap to >= 5.3.3.".to_owned(),
                ))
            } else {
                None
            }
        }
        "vue" => {
            if v < SemVer::new(3, 0, 0) {
                let sev = if v < SemVer::new(2, 7, 0) {
                    Severity::High
                } else {
                    Severity::Medium
                };
                Some((
                    sev,
                    format!("Vue {v} (2.x) reached End-of-Life in December 2023."),
                    "Migrate from Vue 2.x to Vue 3.4+.".to_owned(),
                ))
            } else if v < SemVer::new(3, 4, 0) {
                Some((
                    Severity::Low,
                    format!("Vue {v} is behind current Vue 3.4+ maintenance releases."),
                    "Update Vue to >= 3.4.0.".to_owned(),
                ))
            } else {
                None
            }
        }
        _ => None,
    }
}
