//! System Integrity Protection and boot security.

use crate::model::{Category, Finding, Severity, Status};
use crate::sys;

const CAT: Category = Category::SystemIntegrity;

pub fn run() -> Vec<Finding> {
    vec![sip()]
}

/// System Integrity Protection — protects system files from tampering even by
/// root. Should be enabled on any non-development machine.
fn sip() -> Finding {
    match sys::run("csrutil", &["status"]) {
        Some(out) => {
            let lower = out.to_lowercase();
            if lower.contains("enabled") {
                Finding::new(
                    "integrity.sip",
                    CAT,
                    "System Integrity Protection enabled",
                    Status::Pass,
                    Severity::Critical,
                    out,
                )
                .rationale("SIP prevents modification of protected system files and processes, even by root. Disabling it removes a core macOS defense.")
                .reference("https://support.apple.com/en-us/HT204899")
            } else {
                Finding::new(
                    "integrity.sip",
                    CAT,
                    "System Integrity Protection disabled",
                    Status::Fail,
                    Severity::Critical,
                    out,
                )
                .rationale("With SIP off, malware running as root can modify system binaries and persist undetected.")
                .remediation("Reboot into Recovery (hold power on Apple Silicon), open Terminal, run: csrutil enable")
                .reference("https://support.apple.com/en-us/HT204899")
            }
        }
        None => Finding::new(
            "integrity.sip",
            CAT,
            "System Integrity Protection status unknown",
            Status::Skip,
            Severity::Critical,
            "csrutil not available or returned no output",
        ),
    }
}
