//! Application security: Gatekeeper code-signing enforcement.

use super::CheckGroup;
use crate::model::{Category, Finding, Profile, Severity, Status};
use crate::sys;

const CAT: Category = Category::AppSecurity;

pub fn groups() -> Vec<CheckGroup> {
    vec![
        CheckGroup { id: "appsec.gatekeeper", category: CAT, profile: Profile::Baseline, run: || vec![gatekeeper()] },
        CheckGroup { id: "appsec.xprotect", category: CAT, profile: Profile::Baseline, run: || vec![xprotect()] },
    ]
}

/// XProtect (built-in malware signature) version — informational, but a very
/// old version can hint that security data updates aren't flowing.
fn xprotect() -> Finding {
    const PLIST: &str =
        "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist";
    match sys::run("defaults", &["read", PLIST, "CFBundleShortVersionString"]) {
        Some(ver) => Finding::new(
            "appsec.xprotect",
            CAT,
            &format!("XProtect version {ver}"),
            Status::Info,
            Severity::Low,
            format!("XProtect malware definitions version {ver}"),
        )
        .rationale("XProtect ships malware signatures with macOS and updates silently. The version is shown for awareness; ensure ConfigDataInstall (security responses) is enabled."),
        None => Finding::new(
            "appsec.xprotect",
            CAT,
            "XProtect version unknown",
            Status::Skip,
            Severity::Low,
            "could not read XProtect Info.plist",
        ),
    }
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
