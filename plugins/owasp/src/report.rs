//! Audit reporting: severity summary, OWASP Top 10:2021 mapping, Markdown, PTK JSON, and SARIF v2.1.0.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::auditors::sca::DetectedComponent;
use crate::error::{OwaspError, Result};
use crate::ptk::{PtkAgentSnapshot, PtkScanResult};
use crate::types::{Finding, OwaspCategory, Severity};

/// SARIF v2.1.0 JSON Schema URL.
pub const SARIF_SCHEMA_URL: &str = "https://json.schemastore.org/sarif-2.1.0.json";

/// Severity breakdown across an [`OwaspAuditReport`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SeveritySummary {
    /// Total findings.
    pub total: usize,
    /// Critical findings count.
    pub critical: usize,
    /// High findings count.
    pub high: usize,
    /// Medium findings count.
    pub medium: usize,
    /// Low findings count.
    pub low: usize,
    /// Informational findings count.
    pub info: usize,
}

impl SeveritySummary {
    /// Computes severity totals from `findings`.
    #[must_use]
    pub fn from_findings(findings: &[Finding]) -> Self {
        let mut summary = Self {
            total: findings.len(),
            ..Self::default()
        };
        for finding in findings {
            match finding.severity {
                Severity::Critical => summary.critical += 1,
                Severity::High => summary.high += 1,
                Severity::Medium => summary.medium += 1,
                Severity::Low => summary.low += 1,
                Severity::Info => summary.info += 1,
            }
        }
        summary
    }
}

/// Complete defensive OWASP passive security audit report.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct OwaspAuditReport {
    /// Primary audited target URL, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_url: Option<String>,
    /// Unix epoch timestamp in milliseconds when the report was compiled.
    pub generated_at_ms: u64,
    /// Severity breakdown across [`Self::findings`].
    pub summary: SeveritySummary,
    /// Counts grouped by OWASP Top 10:2021 category (`A01:2021`..`A10:2021`).
    pub category_counts: BTreeMap<String, usize>,
    /// Sorted (and optionally deduplicated) passive security findings.
    pub findings: Vec<Finding>,
    /// Client-side libraries detected by passive SCA.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub components: Vec<DetectedComponent>,
    /// Number of network responses observed passively by `on_response`.
    pub observed_responses: usize,
    /// Number of passive PTK modules loaded from `modules.json`.
    pub ptk_modules_loaded: usize,
    /// Optional passive metadata observed from `window.PTK_AGENT` on the page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ptk_agent: Option<PtkAgentSnapshot>,
}

impl OwaspAuditReport {
    /// Compiles an [`OwaspAuditReport`] from findings and metadata, sorting findings
    /// deterministically by descending severity, rule ID, and location.
    #[must_use]
    pub fn from_parts(
        target_url: Option<String>,
        mut findings: Vec<Finding>,
        components: Vec<DetectedComponent>,
        observed_responses: usize,
        ptk_modules_loaded: usize,
        ptk_agent: Option<PtkAgentSnapshot>,
        deduplicate: bool,
    ) -> Self {
        if deduplicate {
            deduplicate_findings(&mut findings);
        }
        sort_findings(&mut findings);
        let summary = SeveritySummary::from_findings(&findings);
        let category_counts = build_category_counts(&findings);

        Self {
            target_url,
            generated_at_ms: now_ms(),
            summary,
            category_counts,
            findings,
            components,
            observed_responses,
            ptk_modules_loaded,
            ptk_agent,
        }
    }

    /// Returns unique OWASP WSTG v4.2 references cited across all findings.
    #[must_use]
    pub fn wstg_references(&self) -> Vec<String> {
        let refs: BTreeSet<String> = self
            .findings
            .iter()
            .filter_map(|f| f.wstg.clone())
            .collect();
        refs.into_iter().collect()
    }

    /// Returns counts for every OWASP Top 10:2021 category (`A01:2021`..`A10:2021`).
    #[must_use]
    pub fn category_breakdown(&self) -> BTreeMap<OwaspCategory, usize> {
        let mut counts = BTreeMap::new();
        for f in &self.findings {
            *counts.entry(f.category).or_insert(0) += 1;
        }
        counts
    }

    /// Renders a clean Markdown executive summary and findings report.
    #[must_use]
    pub fn to_markdown(&self) -> String {
        let mut md = String::new();
        let target = self.target_url.as_deref().unwrap_or("(unspecified target)");
        let _ = writeln!(md, "# OWASP Passive Security Audit Report");
        let _ = writeln!(md);
        let _ = writeln!(md, "- **Target:** `{target}`");
        let _ = writeln!(md, "- **Observed Responses:** {}", self.observed_responses);
        let _ = writeln!(md, "- **PTK Passive Modules:** {}", self.ptk_modules_loaded);
        let _ = writeln!(md, "- **Total Findings:** {}", self.summary.total);
        let _ = writeln!(md);

        let _ = writeln!(md, "## Severity Summary");
        let _ = writeln!(md);
        let _ = writeln!(md, "| Critical | High | Medium | Low | Info | Total |");
        let _ = writeln!(md, "|---:|---:|---:|---:|---:|---:|");
        let _ = writeln!(
            md,
            "| {} | {} | {} | {} | {} | {} |",
            self.summary.critical,
            self.summary.high,
            self.summary.medium,
            self.summary.low,
            self.summary.info,
            self.summary.total
        );
        let _ = writeln!(md);

        if !self.category_counts.is_empty() {
            let _ = writeln!(md, "## OWASP Top 10:2021 Breakdown");
            let _ = writeln!(md);
            let _ = writeln!(md, "| Category | Findings |");
            let _ = writeln!(md, "|---|---:|");
            for (cat, count) in &self.category_counts {
                let _ = writeln!(md, "| {cat} | {count} |");
            }
            let _ = writeln!(md);
        }

        if !self.components.is_empty() {
            let _ = writeln!(md, "## Client-Side Libraries (SCA)");
            let _ = writeln!(md);
            let _ = writeln!(md, "| Library | Version | Status | Source |");
            let _ = writeln!(md, "|---|---|---|---|");
            for comp in &self.components {
                let _ = writeln!(
                    md,
                    "| {} | {} | {:?} | `{}` |",
                    comp.name, comp.version, comp.status, comp.source
                );
            }
            let _ = writeln!(md);
        }

        let _ = writeln!(md, "## Findings");
        let _ = writeln!(md);
        if self.findings.is_empty() {
            let _ = writeln!(md, "No passive security posture issues were detected.");
            return md;
        }

        for (idx, f) in self.findings.iter().enumerate() {
            let _ = writeln!(
                md,
                "### {}. [{}] {} (`{}`)",
                idx + 1,
                f.severity.as_str().to_ascii_uppercase(),
                f.title,
                f.rule_id
            );
            let _ = writeln!(md, "- **OWASP Top 10:** {}", f.category);
            if let Some(cwe) = f.cwe_code() {
                let _ = writeln!(md, "- **CWE:** {cwe}");
            }
            if let Some(wstg) = &f.wstg {
                let _ = writeln!(md, "- **WSTG v4.2:** {wstg}");
            }
            if let Some(loc) = &f.location {
                let _ = writeln!(md, "- **Location:** `{loc}`");
            }
            if let Some(ev) = &f.evidence {
                let _ = writeln!(md, "- **Evidence:** `{ev}`");
            }
            if !f.description.is_empty() {
                let _ = writeln!(md, "- **Description:** {}", f.description);
            }
            if !f.remediation.is_empty() {
                let _ = writeln!(md, "- **Remediation:** {}", f.remediation);
            }
            let _ = writeln!(md);
        }
        md
    }

    /// Exports all findings as a bidirectional [`PtkScanResult`] envelope.
    #[must_use]
    pub fn to_ptk_scan_result(&self) -> PtkScanResult {
        PtkScanResult::from_findings(self.target_url.clone(), &self.findings)
    }

    /// Serializes findings in PTK passive JSON format.
    ///
    /// # Errors
    ///
    /// Returns [`OwaspError::Json`] if serialization fails.
    pub fn to_ptk_json(&self) -> Result<String> {
        self.to_ptk_scan_result().to_json_string()
    }

    /// Serializes findings in pretty-printed PTK passive JSON format.
    ///
    /// # Errors
    ///
    /// Returns [`OwaspError::Json`] if serialization fails.
    pub fn to_ptk_json_pretty(&self) -> Result<String> {
        self.to_ptk_scan_result().to_json_pretty()
    }

    /// Exports the report as a SARIF v2.1.0 JSON [`Value`].
    #[must_use]
    pub fn to_sarif(&self) -> Value {
        let mut rule_indices: BTreeMap<String, usize> = BTreeMap::new();
        let mut rules: Vec<Value> = Vec::new();

        for finding in &self.findings {
            if !rule_indices.contains_key(&finding.rule_id) {
                let idx = rules.len();
                rule_indices.insert(finding.rule_id.clone(), idx);
                let mut tags = vec![
                    "security".to_owned(),
                    "passive".to_owned(),
                    finding.category.code().to_owned(),
                ];
                if let Some(cwe) = finding.cwe_code() {
                    tags.push(cwe);
                }
                if let Some(wstg) = &finding.wstg {
                    tags.push(wstg.clone());
                }
                for t in &finding.tags {
                    if !tags.contains(t) {
                        tags.push(t.clone());
                    }
                }
                let short_desc = finding.title.clone();
                let full_desc = if finding.description.is_empty() {
                    finding.title.clone()
                } else {
                    finding.description.clone()
                };
                rules.push(json!({
                    "id": finding.rule_id,
                    "name": finding.title,
                    "shortDescription": { "text": short_desc },
                    "fullDescription": { "text": full_desc },
                    "help": {
                        "text": finding.remediation,
                        "markdown": format!("**Remediation:** {}", finding.remediation),
                    },
                    "defaultConfiguration": {
                        "level": finding.severity.sarif_level(),
                    },
                    "properties": {
                        "tags": tags,
                        "precision": "high",
                        "security-severity": finding.severity.security_severity_score(),
                        "owasp": finding.category.code(),
                        "cwe": finding.cwe_code(),
                        "wstg": finding.wstg,
                    }
                }));
            }
        }

        let results: Vec<Value> = self
            .findings
            .iter()
            .map(|finding| {
                let rule_index = rule_indices.get(&finding.rule_id).copied().unwrap_or(0);
                let uri = finding
                    .location
                    .as_deref()
                    .or(self.target_url.as_deref())
                    .unwrap_or("about:blank");
                let msg = if finding.description.is_empty() {
                    finding.title.clone()
                } else {
                    format!("{}: {}", finding.title, finding.description)
                };
                let fp_input = format!(
                    "{}|{}|{}",
                    finding.rule_id,
                    uri,
                    finding.evidence.as_deref().unwrap_or("")
                );
                let fingerprint = fnv1a_hex(&fp_input);

                json!({
                    "ruleId": finding.rule_id,
                    "ruleIndex": rule_index,
                    "level": finding.severity.sarif_level(),
                    "message": { "text": msg },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": uri,
                                }
                            },
                            "logicalLocations": [
                                {
                                    "name": uri,
                                    "kind": finding.auditor.as_str(),
                                }
                            ]
                        }
                    ],
                    "partialFingerprints": {
                        "primaryLocationLineHash": fingerprint,
                    },
                    "properties": {
                        "severity": finding.severity.as_str(),
                        "auditor": finding.auditor.as_str(),
                        "owasp": finding.category.code(),
                        "cwe": finding.cwe_code(),
                        "wstg": finding.wstg,
                        "evidence": finding.evidence,
                        "remediation": finding.remediation,
                    }
                })
            })
            .collect();

        json!({
            "$schema": SARIF_SCHEMA_URL,
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "seleniumbase-rs-plugin-owasp",
                            "version": env!("CARGO_PKG_VERSION"),
                            "informationUri": "https://github.com/MustCodeAl/seleniumbase-rs-plugins",
                            "rules": rules,
                        }
                    },
                    "invocations": [
                        {
                            "executionSuccessful": true,
                        }
                    ],
                    "results": results,
                }
            ]
        })
    }

    /// Serializes the SARIF v2.1.0 report as compact JSON.
    ///
    /// # Errors
    ///
    /// Returns [`OwaspError::Json`] if serialization fails.
    pub fn to_sarif_json(&self) -> Result<String> {
        serde_json::to_string(&self.to_sarif()).map_err(|source| OwaspError::Json {
            context: "serializing SARIF v2.1.0 report".to_owned(),
            source,
        })
    }

    /// Serializes the SARIF v2.1.0 report as pretty-printed JSON.
    ///
    /// # Errors
    ///
    /// Returns [`OwaspError::Json`] if serialization fails.
    pub fn to_sarif_json_pretty(&self) -> Result<String> {
        serde_json::to_string_pretty(&self.to_sarif()).map_err(|source| OwaspError::Json {
            context: "serializing SARIF v2.1.0 report".to_owned(),
            source,
        })
    }
}

fn deduplicate_findings(findings: &mut Vec<Finding>) {
    let mut seen: BTreeSet<(String, Option<String>, Option<String>)> = BTreeSet::new();
    findings.retain(|f| {
        let key = (f.rule_id.clone(), f.location.clone(), f.evidence.clone());
        seen.insert(key)
    });
}

fn sort_findings(findings: &mut [Finding]) {
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.rule_id.cmp(&b.rule_id))
            .then_with(|| a.location.cmp(&b.location))
            .then_with(|| a.evidence.cmp(&b.evidence))
    });
}

fn build_category_counts(findings: &[Finding]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for f in findings {
        *counts.entry(f.category.code().to_owned()).or_insert(0) += 1;
    }
    counts
}

fn fnv1a_hex(input: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    format!("{hash:016x}")
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}
