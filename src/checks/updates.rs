//! Automatic software update settings.
//!
//! On modern macOS several of these keys are *absent by default* while the
//! feature is still on (the OS uses its built-in default). Treating an absent
//! key as "off" produces false WARNs, so we treat absent as the macOS default
//! (enabled) and use the authoritative `softwareupdate --schedule` for the
//! automatic-check state.

use super::CheckGroup;
use crate::model::{Category, Finding, Profile, Severity, Status};
use crate::sys;

const CAT: Category = Category::Updates;
const DOMAIN: &str = "/Library/Preferences/com.apple.SoftwareUpdate";

/// (id, title, defaults key, severity, rationale). Automatic-check is handled
/// separately via `softwareupdate --schedule`.
const PREFS: &[(&str, &str, &str, Severity, &str)] = &[
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

/// Evaluate the automatic-check state plus every SoftwareUpdate preference.
fn all_prefs() -> Vec<Finding> {
    let mut v = vec![auto_check()];
    v.extend(
        PREFS
            .iter()
            .map(|&(id, title, key, severity, rationale)| bool_pref(id, title, key, severity, rationale)),
    );
    v
}

/// Automatic update checking. `softwareupdate --schedule` is authoritative here
/// because the `AutomaticCheckEnabled` key is often absent while checks are on.
fn auto_check() -> Finding {
    const ID: &str = "updates.autocheck";
    const TITLE: &str = "Automatically check for updates";
    const RATIONALE: &str =
        "macOS should automatically check for updates so security patches are surfaced promptly.";

    let sched = sys::run("softwareupdate", &["--schedule"]).unwrap_or_default().to_lowercase();
    let state = if sched.contains("turned on") {
        Some(true)
    } else if sched.contains("turned off") {
        Some(false)
    } else {
        // Fall back to the defaults key; absent => macOS default (on).
        match sys::defaults_read(DOMAIN, "AutomaticCheckEnabled").as_deref() {
            Some("1") | Some("true") => Some(true),
            Some(_) => Some(false),
            None => None,
        }
    };

    match state {
        Some(true) => Finding::new(ID, CAT, &format!("{TITLE}: on"), Status::Pass, Severity::Medium,
            "softwareupdate --schedule: on").rationale(RATIONALE),
        Some(false) => Finding::new(ID, CAT, &format!("{TITLE}: off"), Status::Warn, Severity::Medium,
            "automatic checking is turned off").rationale(RATIONALE)
            .remediation("sudo softwareupdate --schedule on"),
        None => Finding::new(ID, CAT, &format!("{TITLE}: on (default)"), Status::Pass, Severity::Medium,
            "not configured; macOS default is enabled").rationale(RATIONALE),
    }
}

/// Read a boolean `SoftwareUpdate` preference. `1`/`true` => PASS; an explicit
/// `0`/`false` => WARN; an *absent* key => macOS default (enabled) => PASS, since
/// on modern macOS these are on unless deliberately disabled.
fn bool_pref(id: &str, title: &str, key: &str, severity: Severity, rationale: &str) -> Finding {
    match sys::defaults_read(DOMAIN, key).as_deref() {
        Some("1") | Some("true") => {
            Finding::new(id, CAT, &format!("{title}: on"), Status::Pass, severity, "enabled")
                .rationale(rationale)
        }
        Some(other) => {
            let other = other.to_string();
            Finding::new(id, CAT, &format!("{title}: off"), Status::Warn, severity,
                format!("value: {other}"))
                .rationale(rationale)
                .remediation(&format!("sudo defaults write {DOMAIN} {key} -bool true"))
        }
        None => Finding::new(id, CAT, &format!("{title}: on (default)"), Status::Pass, severity,
            "not set; macOS default is enabled")
            .rationale(rationale),
    }
}
