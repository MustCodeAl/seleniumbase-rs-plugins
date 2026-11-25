//! Core domain types for passive OWASP security auditing.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::OwaspError;

/// Normalized finding severity ordered from informational to critical.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Severity {
    /// Informational observation or hardening recommendation.
    Info,
    /// Low-risk posture gap.
    Low,
    /// Medium-risk misconfiguration or outdated component.
    Medium,
    /// High-risk security posture weakness.
    High,
    /// Critical security misconfiguration (e.g. `alg: none` JWT, wildcard CORS with credentials).
    Critical,
}

impl Severity {
    /// Canonical lowercase name of this severity.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    /// SARIF v2.1.0 result `level` string (`error`, `warning`, or `note`).
    #[must_use]
    pub const fn sarif_level(self) -> &'static str {
        match self {
            Self::Critical | Self::High => "error",
            Self::Medium => "warning",
            Self::Low | Self::Info => "note",
        }
    }

    /// Numeric SARIF `security-severity` score string on a 0.0–10.0 scale.
    #[must_use]
    pub const fn security_severity_score(self) -> &'static str {
        match self {
            Self::Critical => "9.0",
            Self::High => "7.5",
            Self::Medium => "5.0",
            Self::Low => "3.0",
            Self::Info => "1.0",
        }
    }

    /// Numeric rank (`0` = Info .. `4` = Critical) for deterministic comparisons.
    #[must_use]
    pub const fn rank(self) -> u8 {
        match self {
            Self::Info => 0,
            Self::Low => 1,
            Self::Medium => 2,
            Self::High => 3,
            Self::Critical => 4,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Severity {
    type Err = OwaspError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "critical" | "crit" => Ok(Self::Critical),
            "high" => Ok(Self::High),
            "medium" | "med" | "moderate" => Ok(Self::Medium),
            "low" => Ok(Self::Low),
            "info" | "informational" | "note" => Ok(Self::Info),
            other => Err(OwaspError::Config(format!("unknown severity `{other}`"))),
        }
    }
}

/// OWASP Top 10:2021 categories (`A01`–`A10`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum OwaspCategory {
    /// A01:2021 – Broken Access Control.
    #[serde(rename = "A01:2021")]
    A01BrokenAccessControl,
    /// A02:2021 – Cryptographic Failures.
    #[serde(rename = "A02:2021")]
    A02CryptographicFailures,
    /// A03:2021 – Injection.
    #[serde(rename = "A03:2021")]
    A03Injection,
    /// A04:2021 – Insecure Design.
    #[serde(rename = "A04:2021")]
    A04InsecureDesign,
    /// A05:2021 – Security Misconfiguration.
    #[serde(rename = "A05:2021")]
    A05SecurityMisconfiguration,
    /// A06:2021 – Vulnerable and Outdated Components.
    #[serde(rename = "A06:2021")]
    A06VulnerableAndOutdatedComponents,
    /// A07:2021 – Identification and Authentication Failures.
    #[serde(rename = "A07:2021")]
    A07IdentificationAndAuthenticationFailures,
    /// A08:2021 – Software and Data Integrity Failures.
    #[serde(rename = "A08:2021")]
    A08SoftwareAndDataIntegrityFailures,
    /// A09:2021 – Security Logging and Monitoring Failures.
    #[serde(rename = "A09:2021")]
    A09SecurityLoggingAndMonitoringFailures,
    /// A10:2021 – Server-Side Request Forgery.
    #[serde(rename = "A10:2021")]
    A10ServerSideRequestForgery,
}

impl OwaspCategory {
    /// All ten OWASP Top 10:2021 categories in canonical order.
    pub const ALL: [Self; 10] = [
        Self::A01BrokenAccessControl,
        Self::A02CryptographicFailures,
        Self::A03Injection,
        Self::A04InsecureDesign,
        Self::A05SecurityMisconfiguration,
        Self::A06VulnerableAndOutdatedComponents,
        Self::A07IdentificationAndAuthenticationFailures,
        Self::A08SoftwareAndDataIntegrityFailures,
        Self::A09SecurityLoggingAndMonitoringFailures,
        Self::A10ServerSideRequestForgery,
    ];

    /// Canonical code (`A01:2021`..`A10:2021`).
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::A01BrokenAccessControl => "A01:2021",
            Self::A02CryptographicFailures => "A02:2021",
            Self::A03Injection => "A03:2021",
            Self::A04InsecureDesign => "A04:2021",
            Self::A05SecurityMisconfiguration => "A05:2021",
            Self::A06VulnerableAndOutdatedComponents => "A06:2021",
            Self::A07IdentificationAndAuthenticationFailures => "A07:2021",
            Self::A08SoftwareAndDataIntegrityFailures => "A08:2021",
            Self::A09SecurityLoggingAndMonitoringFailures => "A09:2021",
            Self::A10ServerSideRequestForgery => "A10:2021",
        }
    }

    /// Short prefix (`A01`..`A10`).
    #[must_use]
    pub const fn short_code(self) -> &'static str {
        match self {
            Self::A01BrokenAccessControl => "A01",
            Self::A02CryptographicFailures => "A02",
            Self::A03Injection => "A03",
            Self::A04InsecureDesign => "A04",
            Self::A05SecurityMisconfiguration => "A05",
            Self::A06VulnerableAndOutdatedComponents => "A06",
            Self::A07IdentificationAndAuthenticationFailures => "A07",
            Self::A08SoftwareAndDataIntegrityFailures => "A08",
            Self::A09SecurityLoggingAndMonitoringFailures => "A09",
            Self::A10ServerSideRequestForgery => "A10",
        }
    }

    /// Human-readable category title.
    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::A01BrokenAccessControl => "Broken Access Control",
            Self::A02CryptographicFailures => "Cryptographic Failures",
            Self::A03Injection => "Injection",
            Self::A04InsecureDesign => "Insecure Design",
            Self::A05SecurityMisconfiguration => "Security Misconfiguration",
            Self::A06VulnerableAndOutdatedComponents => "Vulnerable and Outdated Components",
            Self::A07IdentificationAndAuthenticationFailures => {
                "Identification and Authentication Failures"
            }
            Self::A08SoftwareAndDataIntegrityFailures => "Software and Data Integrity Failures",
            Self::A09SecurityLoggingAndMonitoringFailures => {
                "Security Logging and Monitoring Failures"
            }
            Self::A10ServerSideRequestForgery => "Server-Side Request Forgery",
        }
    }

    /// Reference URL on `owasp.org`.
    #[must_use]
    pub const fn url(self) -> &'static str {
        match self {
            Self::A01BrokenAccessControl => {
                "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"
            }
            Self::A02CryptographicFailures => {
                "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
            }
            Self::A03Injection => "https://owasp.org/Top10/A03_2021-Injection/",
            Self::A04InsecureDesign => "https://owasp.org/Top10/A04_2021-Insecure_Design/",
            Self::A05SecurityMisconfiguration => {
                "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"
            }
            Self::A06VulnerableAndOutdatedComponents => {
                "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"
            }
            Self::A07IdentificationAndAuthenticationFailures => {
                "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"
            }
            Self::A08SoftwareAndDataIntegrityFailures => {
                "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/"
            }
            Self::A09SecurityLoggingAndMonitoringFailures => {
                "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/"
            }
            Self::A10ServerSideRequestForgery => {
                "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/"
            }
        }
    }
}

impl fmt::Display for OwaspCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} - {}", self.code(), self.title())
    }
}

impl FromStr for OwaspCategory {
    type Err = OwaspError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let normalized = s.trim().to_ascii_uppercase();
        let prefix = normalized
            .split([':', '-', ' ', '_'])
            .next()
            .unwrap_or_default();
        match prefix {
            "A01" | "A1" => Ok(Self::A01BrokenAccessControl),
            "A02" | "A2" => Ok(Self::A02CryptographicFailures),
            "A03" | "A3" => Ok(Self::A03Injection),
            "A04" | "A4" => Ok(Self::A04InsecureDesign),
            "A05" | "A5" => Ok(Self::A05SecurityMisconfiguration),
            "A06" | "A6" => Ok(Self::A06VulnerableAndOutdatedComponents),
            "A07" | "A7" => Ok(Self::A07IdentificationAndAuthenticationFailures),
            "A08" | "A8" => Ok(Self::A08SoftwareAndDataIntegrityFailures),
            "A09" | "A9" => Ok(Self::A09SecurityLoggingAndMonitoringFailures),
            "A10" => Ok(Self::A10ServerSideRequestForgery),
            _ => Err(OwaspError::Config(format!("unknown OWASP category `{s}`"))),
        }
    }
}

/// Which passive auditor or engine produced a [`Finding`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum AuditorKind {
    /// HTTP security headers, CSP, CORS, and server banner posture checks.
    Headers,
    /// `Set-Cookie` and cookie attribute posture checks.
    Cookies,
    /// Passive Base64URL JWT header and claims decoder.
    Jwt,
    /// Passive DOM, mixed content, SRI, storage, and `postMessage` checks.
    Dom,
    /// Passive client-side library/version and EOL advisory checks.
    Sca,
    /// Findings imported from or correlated with OWASP Pentest-Kit (PTK).
    Ptk,
}

impl AuditorKind {
    /// Canonical lowercase label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Headers => "headers",
            Self::Cookies => "cookies",
            Self::Jwt => "jwt",
            Self::Dom => "dom",
            Self::Sca => "sca",
            Self::Ptk => "ptk",
        }
    }
}

impl fmt::Display for AuditorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A single defensive passive security audit finding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Finding {
    /// Stable rule identifier (for example `OWASP-HDR-HSTS-MISSING`).
    pub rule_id: String,
    /// Short finding title.
    pub title: String,
    /// Detailed explanation of the observed passive posture weakness.
    pub description: String,
    /// Normalized severity level.
    pub severity: Severity,
    /// Mapped OWASP Top 10:2021 category.
    pub category: OwaspCategory,
    /// Passive auditor that emitted the finding.
    pub auditor: AuditorKind,
    /// Optional MITRE CWE numeric identifier (for example `693` for `CWE-693`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwe: Option<u32>,
    /// Optional OWASP Web Security Testing Guide v4.2 identifier (for example `WSTG-CONF-07`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wstg: Option<String>,
    /// Affected URL, header name, cookie name, storage key, or DOM reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    /// Redacted or structural evidence observed passively.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
    /// Actionable defensive remediation guidance.
    pub remediation: String,
    /// Additional taxonomy or classification tags.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

impl Finding {
    /// Creates a finding with required metadata and empty optional fields.
    #[must_use]
    pub fn new(
        rule_id: impl Into<String>,
        title: impl Into<String>,
        severity: Severity,
        category: OwaspCategory,
        auditor: AuditorKind,
    ) -> Self {
        Self {
            rule_id: rule_id.into(),
            title: title.into(),
            description: String::new(),
            severity,
            category,
            auditor,
            cwe: None,
            wstg: None,
            location: None,
            evidence: None,
            remediation: String::new(),
            tags: Vec::new(),
        }
    }

    /// Sets the detailed description.
    #[must_use]
    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }

    /// Sets the numeric CWE identifier.
    #[must_use]
    pub fn cwe(mut self, cwe: u32) -> Self {
        self.cwe = Some(cwe);
        self
    }

    /// Sets the OWASP WSTG v4.2 test identifier.
    #[must_use]
    pub fn wstg(mut self, wstg: impl Into<String>) -> Self {
        self.wstg = Some(wstg.into());
        self
    }

    /// Sets the finding location (URL, header, cookie, or DOM path).
    #[must_use]
    pub fn location(mut self, location: impl Into<String>) -> Self {
        self.location = Some(location.into());
        self
    }

    /// Sets the redacted/safe structural evidence snippet.
    #[must_use]
    pub fn evidence(mut self, evidence: impl Into<String>) -> Self {
        self.evidence = Some(evidence.into());
        self
    }

    /// Sets remediation guidance.
    #[must_use]
    pub fn remediation(mut self, remediation: impl Into<String>) -> Self {
        self.remediation = remediation.into();
        self
    }

    /// Appends a classification tag.
    #[must_use]
    pub fn tag(mut self, tag: impl Into<String>) -> Self {
        let tag = tag.into();
        if !self.tags.contains(&tag) {
            self.tags.push(tag);
        }
        self
    }

    /// Formatted `CWE-<id>` string when [`Self::cwe`] is present.
    #[must_use]
    pub fn cwe_code(&self) -> Option<String> {
        self.cwe.map(|id| format!("CWE-{id}"))
    }
}

/// Masks sensitive tokens or secret values so reports never persist raw credentials.
#[must_use]
pub fn redact_secret(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let chars: Vec<char> = trimmed.chars().collect();
    if chars.len() <= 8 {
        return "[redacted]".to_owned();
    }
    let prefix: String = chars.iter().take(4).collect();
    let suffix: String = chars.iter().skip(chars.len().saturating_sub(2)).collect();
    format!("{prefix}...{suffix} [len={}]", chars.len())
}

/// Extracts lowercase `scheme://host[:port]` origin from an HTTP(S) URL.
#[must_use]
pub fn url_origin(url: &str) -> Option<String> {
    let (scheme, rest) = url.trim().split_once("://")?;
    let scheme_lower = scheme.to_ascii_lowercase();
    if scheme_lower != "http" && scheme_lower != "https" {
        return None;
    }
    let authority = rest.split(['/', '?', '#']).next()?;
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, h)| h)
        .to_ascii_lowercase();
    if host_port.is_empty() {
        return None;
    }
    let mut normalized = host_port;
    if let Some(colon) = normalized
        .rfind(':')
        .filter(|idx| !normalized[*idx..].contains(']'))
    {
        let default_port = if scheme_lower == "https" { "443" } else { "80" };
        let port = &normalized[colon + 1..];
        if port.is_empty() || port == default_port {
            normalized.truncate(colon);
        }
    }
    Some(format!("{scheme_lower}://{normalized}"))
}

/// Extracts the lowercase hostname (without port) from an HTTP(S) URL.
#[must_use]
pub fn url_host(url: &str) -> Option<String> {
    let origin = url_origin(url)?;
    let (_, authority) = origin.split_once("://")?;
    if authority.starts_with('[') {
        let end = authority.find(']')?;
        return Some(authority[..=end].to_owned());
    }
    Some(
        authority
            .split_once(':')
            .map_or(authority, |(h, _)| h)
            .to_owned(),
    )
}
