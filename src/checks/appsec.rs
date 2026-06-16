//! Application security: Gatekeeper code-signing enforcement.

use crate::model::{Category, Finding, Severity, Status};
use crate::sys;

const CAT: Category = Category::AppSecurity;

pub fn run() -> Vec<Finding> {
    vec![gatekeeper()]
}

/// Gatekeeper enforces that downloaded apps are signed and notarized.
fn gatekeeper() -> Finding {
    match sys::run("spctl", &["--status"]) {
        Some(out) => {
            if out.to_lowercase().contains("assessments enabled") {
                Finding::new(
                    "appsec.gatekeeper",
                    CAT,
                    "Gatekeeper enabled",
                    Status::Pass,
                    Severity::High,
                    out,
                )
                .rationale("Gatekeeper blocks unsigned or un-notarized applications from running by default.")
                .reference("https://support.apple.com/en-us/HT202491")
            } else {
                Finding::new(
                    "appsec.gatekeeper",
                    CAT,
                    "Gatekeeper disabled",
                    Status::Fail,
                    Severity::High,
                    out,
                )
                .rationale("With Gatekeeper off, malicious unsigned apps can launch without warning.")
                .remediation("sudo spctl --master-enable")
                .reference("https://support.apple.com/en-us/HT202491")
            }
        }
        None => Finding::new(
            "appsec.gatekeeper",
            CAT,
            "Gatekeeper status unknown",
            Status::Skip,
            Severity::High,
            "spctl not available or returned no output",
        ),
    }
}
