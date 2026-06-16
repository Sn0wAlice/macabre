//! Automatic software update settings.

use super::CheckGroup;
use crate::model::{Category, Finding, Profile, Severity, Status};
use crate::sys;

const CAT: Category = Category::Updates;
const DOMAIN: &str = "/Library/Preferences/com.apple.SoftwareUpdate";

/// (id, title, defaults key, severity, rationale)
const PREFS: &[(&str, &str, &str, Severity, &str)] = &[
    ("updates.autocheck", "Automatically check for updates", "AutomaticCheckEnabled", Severity::Medium,
     "macOS should automatically check for updates so security patches are surfaced promptly."),
    ("updates.autodownload", "Automatically download updates", "AutomaticDownload", Severity::Low,
     "Downloading updates automatically shortens the window before a patch can be installed."),
    ("updates.installsecurity", "Install security responses & system files", "ConfigDataInstall", Severity::High,
     "Critical security responses (XProtect, system data files) should install automatically."),
    ("updates.critical", "Install critical security updates", "CriticalUpdateInstall", Severity::High,
     "Critical/rapid security updates should install without waiting for manual action."),
    ("updates.installos", "Install macOS updates automatically", "AutomaticallyInstallMacOSUpdates", Severity::Medium,
     "Installing OS updates automatically ensures kernel and framework patches land without manual action."),
];

pub fn groups() -> Vec<CheckGroup> {
    vec![CheckGroup {
        id: "updates.auto",
        category: CAT,
        profile: Profile::Baseline,
        run: all_prefs,
    }]
}

/// Evaluate every SoftwareUpdate preference in [`PREFS`].
fn all_prefs() -> Vec<Finding> {
    PREFS
        .iter()
        .map(|&(id, title, key, severity, rationale)| bool_pref(id, title, key, severity, rationale))
        .collect()
}

/// Read a boolean `SoftwareUpdate` preference. `1`/`true` => PASS, otherwise a
/// severity-scaled finding. Missing key is treated as "not enabled".
fn bool_pref(id: &str, title: &str, key: &str, severity: Severity, rationale: &str) -> Finding {
    let val = sys::defaults_read(DOMAIN, key);
    let enabled = matches!(val.as_deref(), Some("1") | Some("true"));
    if enabled {
        Finding::new(id, CAT, &format!("{title}: on"), Status::Pass, severity, "enabled")
            .rationale(rationale)
    } else {
        let observed = val.unwrap_or_else(|| "not set".to_string());
        Finding::new(
            id,
            CAT,
            &format!("{title}: off"),
            Status::Warn,
            severity,
            format!("value: {observed}"),
        )
        .rationale(rationale)
        .remediation(&format!(
            "sudo defaults write {DOMAIN} {key} -bool true"
        ))
    }
}
