//! Privacy & anti-telemetry checks (paranoia profile, Privacy score class).
//!
//! Here the "hardened" state is the privacy-maximising one — Spotlight indexing
//! off, Siri off, no personalised ads, analytics not auto-submitted, etc. These
//! are tradeoffs (they disable convenience features), so they're scored in a
//! separate Privacy index and never as security FAILs.

use super::CheckGroup;
use crate::model::{Category, Finding, Profile, Severity, Status};
use crate::sys;

const CAT: Category = Category::Privacy;

pub fn groups() -> Vec<CheckGroup> {
    vec![
        CheckGroup { id: "privacy.spotlight", category: CAT, profile: Profile::Paranoia, run: || vec![spotlight()] },
        CheckGroup { id: "privacy.siri", category: CAT, profile: Profile::Paranoia, run: || vec![siri()] },
        CheckGroup { id: "privacy.ads", category: CAT, profile: Profile::Paranoia, run: || vec![personalized_ads()] },
        CheckGroup { id: "privacy.analytics", category: CAT, profile: Profile::Paranoia, run: || vec![analytics()] },
        CheckGroup { id: "privacy.airdrop", category: CAT, profile: Profile::Paranoia, run: || vec![airdrop()] },
        CheckGroup { id: "privacy.securekbd", category: CAT, profile: Profile::Paranoia, run: || vec![secure_keyboard()] },
        CheckGroup { id: "privacy.safari", category: CAT, profile: Profile::Paranoia, run: || vec![safari_suggestions()] },
    ]
}

/// Spotlight indexing builds a local content index and (with Suggestions) can
/// send queries to Apple. Paranoid stance: turn indexing off.
fn spotlight() -> Finding {
    match sys::run("mdutil", &["-s", "/"]) {
        Some(out) if out.to_lowercase().contains("indexing enabled") => Finding::new(
            "privacy.spotlight", CAT, "Spotlight indexing is enabled", Status::Warn,
            Severity::Medium, out.replace('\n', " "))
            .rationale("Spotlight indexes file contents locally and, with Siri Suggestions, can transmit query data to Apple.")
            .remediation("Disable indexing: sudo mdutil -i off -a   ⚠️ this breaks Spotlight/Finder search and app launch-by-search."),
        Some(out) => Finding::new("privacy.spotlight", CAT, "Spotlight indexing is disabled",
            Status::Pass, Severity::Medium, out.replace('\n', " "))
            .rationale("No local content index is being maintained."),
        None => skip("privacy.spotlight", "Spotlight indexing", "mdutil returned no output"),
    }
}

/// Siri/Assistant collects voice and usage data. Hardened: disabled.
fn siri() -> Finding {
    hardened_bool(
        "privacy.siri", "Siri / Assistant",
        "com.apple.assistant.support", "Assistant Enabled",
        false, Severity::Medium,
        "Siri sends audio and request data to Apple for processing.",
        "Disable in System Settings > Apple Intelligence & Siri.",
    )
}

/// Personalised (Apple) advertising. Hardened: off.
fn personalized_ads() -> Finding {
    hardened_bool(
        "privacy.ads", "Personalized Apple ads",
        "com.apple.AdLib", "allowApplePersonalizedAdvertising",
        false, Severity::Low,
        "Personalised advertising profiles your usage to target ads.",
        "Disable in System Settings > Privacy & Security > Apple Advertising.",
    )
}

/// Auto-submission of Mac analytics/diagnostics to Apple. Hardened: off.
fn analytics() -> Finding {
    let path = "/Library/Application Support/CrashReporter/DiagnosticMessagesHistory.plist";
    let on = matches!(sys::defaults_read(path, "AutoSubmit").as_deref(), Some("1") | Some("true"));
    if on {
        Finding::new("privacy.analytics", CAT, "Mac analytics auto-submit is on", Status::Warn,
            Severity::Low, "AutoSubmit = 1")
            .rationale("Diagnostic & usage data is sent to Apple automatically.")
            .remediation("Disable in System Settings > Privacy & Security > Analytics & Improvements > Share Mac Analytics.")
    } else {
        Finding::new("privacy.analytics", CAT, "Mac analytics auto-submit is off", Status::Pass,
            Severity::Low, "AutoSubmit disabled / not set")
    }
}

/// AirDrop discoverability. Hardened: "Off" (or Contacts Only), not "Everyone".
fn airdrop() -> Finding {
    match sys::defaults_read("com.apple.sharingd", "DiscoverableMode") {
        Some(mode) => {
            let m = mode.to_lowercase();
            if m.contains("off") || m.contains("contacts") {
                Finding::new("privacy.airdrop", CAT, &format!("AirDrop discoverability: {mode}"),
                    Status::Pass, Severity::Low, format!("DiscoverableMode = {mode}"))
                    .rationale("The host is not broadly discoverable over AirDrop.")
            } else {
                Finding::new("privacy.airdrop", CAT, &format!("AirDrop discoverable: {mode}"),
                    Status::Warn, Severity::Low, format!("DiscoverableMode = {mode}"))
                    .rationale("'Everyone' makes the Mac discoverable to nearby strangers.")
                    .remediation("Set AirDrop to 'Contacts Only' or 'No One' (Control Center > AirDrop).")
            }
        }
        None => skip("privacy.airdrop", "AirDrop discoverability", "DiscoverableMode not set"),
    }
}

/// Secure Keyboard Entry in Terminal blocks other processes from reading
/// keystrokes (anti-keylogger). Hardened: on.
fn secure_keyboard() -> Finding {
    let on = matches!(sys::defaults_read_app("Terminal", "SecureKeyboardEntry").as_deref(), Some("1") | Some("true"));
    if on {
        Finding::new("privacy.securekbd", CAT, "Terminal Secure Keyboard Entry is on", Status::Pass,
            Severity::Low, "SecureKeyboardEntry = 1")
            .rationale("Other processes cannot observe keystrokes typed in Terminal.")
    } else {
        Finding::new("privacy.securekbd", CAT, "Terminal Secure Keyboard Entry is off", Status::Warn,
            Severity::Low, "SecureKeyboardEntry off / not set")
            .rationale("Without it, another process could log keystrokes entered in Terminal.")
            .remediation("Terminal > menu > Secure Keyboard Entry (or: defaults write -app Terminal SecureKeyboardEntry -bool true)")
    }
}

/// Safari search-engine suggestions send keystrokes to the search provider.
/// Safari's container is TCC-protected, so reads often fail → best-effort SKIP.
fn safari_suggestions() -> Finding {
    match sys::defaults_read("com.apple.Safari", "SuppressSearchSuggestions") {
        Some(v) if v == "1" || v == "true" => Finding::new("privacy.safari", CAT,
            "Safari search suggestions suppressed", Status::Pass, Severity::Low,
            "SuppressSearchSuggestions = 1"),
        Some(_) => Finding::new("privacy.safari", CAT, "Safari search suggestions enabled",
            Status::Warn, Severity::Low, "SuppressSearchSuggestions off")
            .rationale("Search suggestions transmit typed queries to the search provider.")
            .remediation("Safari > Settings > Search > uncheck 'Include search engine suggestions'."),
        None => skip("privacy.safari", "Safari search suggestions",
            "Safari preferences are TCC-protected — verify in Safari > Settings > Search"),
    }
}

/// Generic boolean privacy preference where `hardened_value` is the desired
/// state. PASS when observed == hardened_value.
fn hardened_bool(
    id: &str,
    title: &str,
    domain: &str,
    key: &str,
    hardened_value: bool,
    severity: Severity,
    rationale: &str,
    remediation: &str,
) -> Finding {
    match sys::defaults_read(domain, key) {
        Some(v) => {
            let on = v == "1" || v == "true";
            if on == hardened_value {
                Finding::new(id, CAT, &format!("{title}: hardened"), Status::Pass, severity,
                    format!("{key} = {v}"))
                    .rationale(rationale)
            } else {
                Finding::new(id, CAT, &format!("{title}: not hardened"), Status::Warn, severity,
                    format!("{key} = {v}"))
                    .rationale(rationale)
                    .remediation(remediation)
            }
        }
        None => skip(id, title, &format!("{key} not set")),
    }
}

fn skip(id: &str, title: &str, detail: &str) -> Finding {
    Finding::new(id, CAT, &format!("{title}: not assessable"), Status::Skip, Severity::Low, detail.to_string())
}
