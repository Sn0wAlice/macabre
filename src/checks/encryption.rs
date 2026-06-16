//! Disk encryption (FileVault).

use super::CheckGroup;
use crate::model::{Category, Finding, Profile, Severity, Status};
use crate::sys;

const CAT: Category = Category::Encryption;

pub fn groups() -> Vec<CheckGroup> {
    vec![CheckGroup {
        id: "encryption.filevault",
        category: CAT,
        profile: Profile::Baseline,
        run: || vec![filevault()],
    }]
}

/// FileVault full-disk encryption. Without it, anyone with physical access can
/// read the disk by booting another OS or pulling the drive.
fn filevault() -> Finding {
    match sys::run("fdesetup", &["status"]) {
        Some(out) => {
            if out.to_lowercase().contains("filevault is on") {
                Finding::new(
                    "encryption.filevault",
                    CAT,
                    "FileVault enabled",
                    Status::Pass,
                    Severity::Critical,
                    out,
                )
                .rationale("FileVault encrypts the entire startup disk, protecting data at rest if the device is lost or stolen.")
                .reference("https://support.apple.com/guide/mac-help/mh11785")
            } else {
                Finding::new(
                    "encryption.filevault",
                    CAT,
                    "FileVault disabled",
                    Status::Fail,
                    Severity::Critical,
                    out,
                )
                .rationale("Without full-disk encryption, data is readable by anyone with physical access to the drive.")
                .remediation("Enable in System Settings > Privacy & Security > FileVault, or run: sudo fdesetup enable")
                .reference("https://support.apple.com/guide/mac-help/mh11785")
            }
        }
        None => Finding::new(
            "encryption.filevault",
            CAT,
            "FileVault status unknown",
            Status::Skip,
            Severity::Critical,
            "fdesetup not available or returned no output",
        ),
    }
}
