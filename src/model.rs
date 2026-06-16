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

/// Logical grouping of checks, used as section headers in reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Category {
    SystemIntegrity,
    Encryption,
    Firewall,
    AppSecurity,
    Sharing,
    Updates,
}

impl Category {
    pub fn title(&self) -> &'static str {
        match self {
            Category::SystemIntegrity => "System Integrity",
            Category::Encryption => "Disk Encryption",
            Category::Firewall => "Firewall",
            Category::AppSecurity => "Application Security",
            Category::Sharing => "Sharing & Remote Access",
            Category::Updates => "Software Updates",
        }
    }

    /// Stable ordering for report sections.
    pub fn all() -> &'static [Category] {
        &[
            Category::SystemIntegrity,
            Category::Encryption,
            Category::Firewall,
            Category::AppSecurity,
            Category::Sharing,
            Category::Updates,
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
    pub fn compute(findings: &[Finding]) -> Self {
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
    pub score: Score,
    pub findings: Vec<Finding>,
}
