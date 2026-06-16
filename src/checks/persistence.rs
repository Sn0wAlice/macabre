//! Persistence & configuration profiles: launchd jobs and MDM/profile state.

use super::CheckGroup;
use crate::model::{Category, Finding, Profile, Severity, Status};
use crate::sys;

const CAT: Category = Category::Persistence;

pub fn groups() -> Vec<CheckGroup> {
    vec![
        CheckGroup { id: "persistence.launchd", category: CAT, profile: Profile::Paranoia, run: || vec![launchd_jobs()] },
        CheckGroup { id: "persistence.profiles", category: CAT, profile: Profile::Paranoia, run: || vec![config_profiles()] },
    ]
}

/// A launchd plist filename counts as third-party if its reverse-DNS label is
/// not an Apple one. Apple labels start with `com.apple.`.
pub fn is_third_party_label(filename: &str) -> bool {
    let base = filename.strip_suffix(".plist").unwrap_or(filename);
    !base.starts_with("com.apple.") && !base.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_third_party_labels() {
        assert!(!is_third_party_label("com.apple.something.plist"));
        assert!(is_third_party_label("com.google.keystone.agent.plist"));
        assert!(is_third_party_label("mega.mac.megaupdater.plist"));
        assert!(!is_third_party_label(".plist")); // empty label
    }
}

/// Inventory third-party launchd jobs across the standard directories. These are
/// the classic persistence locations; legitimate apps live here too, so this is
/// an awareness check rather than a verdict.
fn launchd_jobs() -> Finding {
    let home = std::env::var("HOME").unwrap_or_default();
    let dirs = [
        "/Library/LaunchAgents".to_string(),
        "/Library/LaunchDaemons".to_string(),
        format!("{home}/Library/LaunchAgents"),
        format!("{home}/Library/LaunchDaemons"),
    ];
    let mut third_party = Vec::new();
    for dir in &dirs {
        for name in sys::list_dir(dir) {
            if name.ends_with(".plist") && is_third_party_label(&name) {
                let label = name.strip_suffix(".plist").unwrap_or(&name);
                third_party.push(label.to_string());
            }
        }
    }
    third_party.sort();
    third_party.dedup();

    if third_party.is_empty() {
        Finding::new("persistence.launchd", CAT, "No third-party launchd jobs found",
            Status::Pass, Severity::Medium, "only Apple launchd jobs in standard locations")
    } else {
        Finding::new("persistence.launchd", CAT,
            &format!("{} third-party launchd job(s)", third_party.len()),
            Status::Info, Severity::Medium, third_party.join(", "))
            .rationale("LaunchAgents/Daemons are the most common macOS persistence mechanism. Review the list and confirm each belongs to software you installed.")
    }
}

/// Configuration profiles & MDM enrollment. Unexpected profiles can silently
/// change security policy; informational unless the host is unexpectedly managed.
fn config_profiles() -> Finding {
    let enrollment = sys::run("profiles", &["status", "-type", "enrollment"]).unwrap_or_default();
    let mdm = enrollment.to_lowercase().contains("mdm enrollment: yes");
    let profiles = sys::run("profiles", &["list"]).unwrap_or_default();
    let none_installed = profiles.to_lowercase().contains("no configuration profiles");

    let detail = format!(
        "MDM: {} · {}",
        if mdm { "enrolled" } else { "not enrolled" },
        if none_installed { "no configuration profiles" } else { "profiles present" }
    );

    if mdm || !none_installed {
        Finding::new("persistence.profiles", CAT, "Configuration profiles / MDM present",
            Status::Info, Severity::Medium, detail)
            .rationale("Profiles and MDM can enforce or weaken security policy. Confirm any management is expected (work device) and not unknown.")
    } else {
        Finding::new("persistence.profiles", CAT, "No configuration profiles or MDM",
            Status::Pass, Severity::Low, detail)
    }
}
