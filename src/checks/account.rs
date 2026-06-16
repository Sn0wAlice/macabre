//! Accounts & authentication posture.

use super::CheckGroup;
use crate::model::{Category, Finding, Profile, Severity, Status};
use crate::sys;

const CAT: Category = Category::Account;
const LOGINWINDOW: &str = "/Library/Preferences/com.apple.loginwindow";

pub fn groups() -> Vec<CheckGroup> {
    vec![
        CheckGroup { id: "account.autologin", category: CAT, profile: Profile::Baseline, run: || vec![auto_login()] },
        CheckGroup { id: "account.guest", category: CAT, profile: Profile::Baseline, run: || vec![guest()] },
        CheckGroup { id: "account.root", category: CAT, profile: Profile::Baseline, run: || vec![root_account()] },
        CheckGroup { id: "account.admin", category: CAT, profile: Profile::Baseline, run: || vec![admin_session()] },
        CheckGroup { id: "account.screenlock", category: CAT, profile: Profile::Baseline, run: || vec![screen_lock()] },
    ]
}

/// Automatic login bypasses the login password entirely — must be off.
fn auto_login() -> Finding {
    match sys::defaults_read(LOGINWINDOW, "autoLoginUser") {
        Some(user) if !user.is_empty() => Finding::new("account.autologin", CAT,
            "Automatic login is enabled", Status::Fail, Severity::High,
            format!("auto-login user: {user}"))
            .rationale("Automatic login lets anyone who powers on the Mac reach the desktop without a password, defeating FileVault's at-rest protection in practice.")
            .remediation("sudo defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser  (or System Settings > Users & Groups > Automatic login: Off)"),
        // Key absent => auto-login is off (the hardened default).
        _ => Finding::new("account.autologin", CAT, "Automatic login is disabled", Status::Pass,
            Severity::High, "no autoLoginUser configured")
            .rationale("Login requires authentication on boot."),
    }
}

/// The Guest account allows unauthenticated local access.
fn guest() -> Finding {
    let enabled = matches!(sys::defaults_read(LOGINWINDOW, "GuestEnabled").as_deref(), Some("1") | Some("true"));
    if enabled {
        Finding::new("account.guest", CAT, "Guest account is enabled", Status::Warn, Severity::Medium,
            "GuestEnabled = 1")
            .rationale("The Guest account permits unauthenticated local logins.")
            .remediation("sudo defaults write /Library/Preferences/com.apple.loginwindow GuestEnabled -bool false")
    } else {
        Finding::new("account.guest", CAT, "Guest account is disabled", Status::Pass, Severity::Medium,
            "GuestEnabled is off")
    }
}

/// The root account should remain disabled (no password hash, shown as `*`).
fn root_account() -> Finding {
    match sys::run("dscl", &[".", "-read", "/Users/root", "Password"]) {
        Some(out) => {
            // "Password: *" => disabled; "Password: ********" => enabled.
            let disabled = out.split_whitespace().nth(1) == Some("*");
            if disabled {
                Finding::new("account.root", CAT, "Root account is disabled", Status::Pass,
                    Severity::High, "root has no password hash (*)")
                    .rationale("A disabled root account removes a powerful, often-targeted login.")
            } else {
                Finding::new("account.root", CAT, "Root account is enabled", Status::Warn,
                    Severity::High, "root has a password set")
                    .rationale("An enabled root account is a high-value login target; prefer sudo from an admin account.")
                    .remediation("Disable in Directory Utility, or: sudo dsenableroot -d")
            }
        }
        None => Finding::new("account.root", CAT, "Root account status unknown", Status::Skip,
            Severity::High, "dscl returned no output"),
    }
}

/// Daily-driver account being an admin is a (mild) risk — informational.
fn admin_session() -> Finding {
    let groups = sys::run("id", &["-Gn"]).unwrap_or_default();
    let is_admin = groups.split_whitespace().any(|g| g == "admin");
    if is_admin {
        Finding::new("account.admin", CAT, "Current account is an administrator", Status::Warn,
            Severity::Low, "current user is in the 'admin' group")
            .rationale("Using an admin account day-to-day means malware you run inherits admin rights. Consider a separate standard account for daily use.")
    } else {
        Finding::new("account.admin", CAT, "Current account is a standard user", Status::Pass,
            Severity::Low, "current user is not in the 'admin' group")
    }
}

/// Require password shortly after sleep/screensaver. On modern macOS this lives
/// behind a per-user/TCC-protected domain and often reads empty → best-effort.
fn screen_lock() -> Finding {
    let ask = sys::defaults_read("com.apple.screensaver", "askForPassword");
    match ask.as_deref() {
        Some("1") | Some("true") => {
            let delay = sys::defaults_read("com.apple.screensaver", "askForPasswordDelay")
                .unwrap_or_else(|| "0".into());
            Finding::new("account.screenlock", CAT, "Password required after screensaver",
                Status::Pass, Severity::Medium, format!("askForPassword on, delay {delay}s"))
                .rationale("Locking shortly after the screen sleeps stops walk-up access to an unlocked session.")
        }
        Some(_) => Finding::new("account.screenlock", CAT, "Screen lock password not required",
            Status::Warn, Severity::Medium, "askForPassword is off")
            .rationale("Without this, the screensaver/sleep does not lock the session.")
            .remediation("System Settings > Lock Screen > Require password after screen saver begins: immediately"),
        // Empty: modern macOS hides this setting from `defaults` — can't assess.
        None => Finding::new("account.screenlock", CAT,
            "Screen lock setting not readable", Status::Skip, Severity::Medium,
            "askForPassword not exposed via defaults on this macOS — verify in System Settings > Lock Screen"),
    }
}
