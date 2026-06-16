//! Core data model shared by the check engine and all report renderers.

use serde::Serialize;

/// Outcome of a single check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// The system is in the hardened/expected state.
    Pass,
    /// Not strictly insecure, but worth reviewing.
    Warn,
    /// Insecure state that should be fixed.
    Fail,
    /// Informational only, not scored. Reserved for upcoming inventory checks.
    #[allow(dead_code)]
    Info,
    /// Could not determine state (command failed, not applicable, etc.).
    Skip,
}

impl Status {
    pub fn label(&self) -> &'static str {
        match self {
            Status::Pass => "PASS",
            Status::Warn => "WARN",
            Status::Fail => "FAIL",
            Status::Info => "INFO",
            Status::Skip => "SKIP",
        }
    }
}

/// How much a failing check matters. Drives the hardening score weighting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Weight used in the hardening index. Heavier = matters more.
    pub fn weight(&self) -> u32 {
        match self {
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 4,
            Severity::Critical => 8,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

/// Audit depth. `Paranoia` is a superset of `Baseline`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Profile {
    Baseline,
    Paranoia,
}

/// Which score a finding contributes to. Security failures are real exposure;
/// privacy findings are anti-telemetry tradeoffs scored separately so a normal
/// Mac isn't penalised on security for keeping Spotlight on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Class {
    Security,
    Privacy,
}

/// Logical grouping of checks, used as section headers in reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Category {
    SystemIntegrity,
    Encryption,
    Firewall,
    AppSecurity,
    Account,
    Sharing,
    Network,
    Persistence,
    Updates,
    Privacy,
}

impl Category {
    pub fn title(&self) -> &'static str {
        match self {
            Category::SystemIntegrity => "System Integrity",
            Category::Encryption => "Disk Encryption",
            Category::Firewall => "Firewall",
            Category::AppSecurity => "Application Security",
            Category::Account => "Accounts & Authentication",
            Category::Sharing => "Sharing & Remote Access",
            Category::Network => "Network Exposure",
            Category::Persistence => "Persistence & Profiles",
            Category::Updates => "Software Updates",
            Category::Privacy => "Privacy & Telemetry",
        }
    }

    /// Slug used for `--only`/`--skip` matching, e.g. "privacy".
    pub fn slug(&self) -> &'static str {
        match self {
            Category::SystemIntegrity => "integrity",
            Category::Encryption => "encryption",
            Category::Firewall => "firewall",
            Category::AppSecurity => "appsec",
            Category::Account => "account",
            Category::Sharing => "sharing",
            Category::Network => "network",
            Category::Persistence => "persistence",
            Category::Updates => "updates",
            Category::Privacy => "privacy",
        }
    }

    /// Which score this category feeds.
    pub fn class(&self) -> Class {
        match self {
            Category::Privacy => Class::Privacy,
            _ => Class::Security,
        }
    }

    /// Stable ordering for report sections.
    pub fn all() -> &'static [Category] {
        &[
            Category::SystemIntegrity,
            Category::Encryption,
            Category::Firewall,
            Category::AppSecurity,
            Category::Account,
            Category::Sharing,
            Category::Network,
            Category::Persistence,
            Category::Updates,
            Category::Privacy,
        ]
    }
}

/// Result of running one check.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    /// Stable dotted id, e.g. `filevault.enabled`.
    pub id: String,
    pub category: Category,
    pub title: String,
    pub status: Status,
    pub severity: Severity,
    /// Observed value / short explanation of the current state.
    pub detail: String,
    /// Why this matters (shown in verbose output).
    pub rationale: String,
    /// Suggested remediation command or steps (audit-only: never executed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    /// Optional external reference (CIS benchmark, Apple doc, ...).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
}

/// Builder-ish constructor to keep individual checks terse.
impl Finding {
    pub fn new(
        id: &str,
        category: Category,
        title: &str,
        status: Status,
        severity: Severity,
        detail: impl Into<String>,
    ) -> Self {
        Finding {
            id: id.to_string(),
            category,
            title: title.to_string(),
            status,
            severity,
            detail: detail.into(),
            rationale: String::new(),
            remediation: None,
            reference: None,
        }
    }

    pub fn rationale(mut self, r: &str) -> Self {
        self.rationale = r.to_string();
        self
    }

    pub fn remediation(mut self, r: &str) -> Self {
        self.remediation = Some(r.to_string());
        self
    }

    pub fn reference(mut self, r: &str) -> Self {
        self.reference = Some(r.to_string());
        self
    }

    /// Whether this finding counts toward the hardening score.
    pub fn is_scored(&self) -> bool {
        matches!(self.status, Status::Pass | Status::Warn | Status::Fail)
    }
}

/// Aggregate scoring across all findings.
#[derive(Debug, Clone, Serialize)]
pub struct Score {
    pub passed: usize,
    pub warned: usize,
    pub failed: usize,
    pub skipped: usize,
    pub info: usize,
    /// Hardening index 0-100, weighted by severity.
    pub index: u32,
}

impl Score {
    /// Compute a score over only the findings whose category feeds `class`.
    pub fn compute_for(findings: &[Finding], class: Class) -> Self {
        let mut s = Score {
            passed: 0,
            warned: 0,
            failed: 0,
            skipped: 0,
            info: 0,
            index: 0,
        };
        let mut earned = 0u32;
        let mut possible = 0u32;
        for f in findings {
            if f.category.class() != class {
                continue;
            }
            match f.status {
                Status::Pass => s.passed += 1,
                Status::Warn => s.warned += 1,
                Status::Fail => s.failed += 1,
                Status::Skip => s.skipped += 1,
                Status::Info => s.info += 1,
            }
            if f.is_scored() {
                let w = f.severity.weight();
                possible += w;
                earned += match f.status {
                    Status::Pass => w,
                    // A warning earns partial credit.
                    Status::Warn => w / 2,
                    _ => 0,
                };
            }
        }
        s.index = if possible == 0 {
            100
        } else {
            ((earned as f64 / possible as f64) * 100.0).round() as u32
        };
        s
    }
}

/// Full audit result, what renderers consume.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub tool: &'static str,
    pub version: &'static str,
    pub generated_at: String,
    pub hostname: String,
    pub os_version: String,
    pub profile: Profile,
    /// Whether the scan ran with root privileges (affects how many checks ran).
    pub root: bool,
    /// Security hardening index, always present.
    pub security: Score,
    /// Privacy/anti-telemetry index — only present when privacy findings ran.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privacy: Option<Score>,
    pub findings: Vec<Finding>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(category: Category, status: Status, severity: Severity) -> Finding {
        Finding::new("x", category, "t", status, severity, "")
    }

    #[test]
    fn score_split_isolates_classes() {
        let findings = vec![
            // Security: one critical pass, one high fail.
            f(Category::Encryption, Status::Pass, Severity::Critical),
            f(Category::Firewall, Status::Fail, Severity::High),
            // Privacy: one medium warn (half credit), one low pass.
            f(Category::Privacy, Status::Warn, Severity::Medium),
            f(Category::Privacy, Status::Pass, Severity::Low),
        ];
        let sec = Score::compute_for(&findings, Class::Security);
        let priv_ = Score::compute_for(&findings, Class::Privacy);

        // Security: earned 8 (crit pass) of possible 12 (8 + 4) = 67.
        assert_eq!((sec.passed, sec.failed), (1, 1));
        assert_eq!(sec.index, 67);
        // Privacy: earned warn 2/2=1 + pass 1 = 2 of possible 3 = 67.
        assert_eq!((priv_.passed, priv_.warned), (1, 1));
        assert_eq!(priv_.index, 67);
    }

    #[test]
    fn skip_and_info_are_unscored() {
        let findings = vec![
            f(Category::Account, Status::Skip, Severity::Critical),
            f(Category::Account, Status::Info, Severity::High),
        ];
        // Nothing scored => perfect index, but counts still tallied.
        let sec = Score::compute_for(&findings, Class::Security);
        assert_eq!(sec.index, 100);
        assert_eq!((sec.skipped, sec.info), (1, 1));
    }
}
