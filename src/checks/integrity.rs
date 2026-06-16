//! System Integrity Protection and boot security.

use super::CheckGroup;
use crate::model::{Category, Finding, Profile, Severity, Status};
use crate::sys;

const CAT: Category = Category::SystemIntegrity;

pub fn groups() -> Vec<CheckGroup> {
    vec![
        CheckGroup { id: "integrity.sip", category: CAT, profile: Profile::Baseline, run: || vec![sip()] },
        CheckGroup { id: "integrity.sysext", category: CAT, profile: Profile::Paranoia, run: || vec![system_extensions()] },
    ]
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

/// Inventory of activated system/network extensions. Informational: these are
/// legitimate (Little Snitch, Tailscale, ...) but worth eyeballing for anything
/// unexpected, since they run with deep system privileges.
fn system_extensions() -> Finding {
    let out = sys::run("systemextensionsctl", &["list"]).unwrap_or_default();
    let active: Vec<String> = out
        .lines()
        .filter(|l| l.contains("activated enabled"))
        // The human-readable name is the second-to-last column before [state].
        .filter_map(|l| l.split('\t').map(str::trim).find(|c| c.contains('.')))
        .map(|s| s.to_string())
        .collect();

    if active.is_empty() {
        Finding::new(
            "integrity.sysext",
            CAT,
            "No third-party system extensions active",
            Status::Info,
            Severity::Low,
            "systemextensionsctl reports no activated extensions",
        )
    } else {
        Finding::new(
            "integrity.sysext",
            CAT,
            &format!("{} system extension(s) active", active.len()),
            Status::Info,
            Severity::Low,
            active.join(", "),
        )
        .rationale("System extensions run with deep privileges. Confirm each is one you installed intentionally.")
    }
}
