//! Sharing & remote access services.
//!
//! Each enabled service widens the network attack surface. Detection is *per
//! service* because a daemon being registered in launchd does NOT mean the
//! toggle is on: some daemons (cupsd, ARD's privilege proxy, NetworkSharing)
//! ship registered-but-idle on every Mac. We therefore use the right signal for
//! each service — registration, actually-running state, or a dedicated config
//! flag — to avoid false positives. When SSH is on we also audit `sshd_config`.

use super::CheckGroup;
use crate::model::{Category, Finding, Profile, Severity, Status};
use crate::sys;

const CAT: Category = Category::Sharing;

/// How to tell whether a sharing service is actually enabled.
#[derive(Clone, Copy)]
enum Detect {
    /// The launchd job is registered only while the toggle is on (smbd, sshd,
    /// screensharing, AppleFileServer, AEServer). Registration ⇒ enabled.
    Registered,
    /// The job is always registered; it only *runs* when the toggle is on (ARD,
    /// Internet Sharing). We require a running/active state, not mere presence.
    Active,
    /// Printer Sharing: cupsd is always present for local printing; the real
    /// flag is cupsctl's `_share_printers`.
    Printer,
}

/// (id, title, launchd label, severity, detect, rationale, remediation)
const SERVICES: &[(&str, &str, &str, Severity, Detect, &str, &str)] = &[
    ("sharing.ssh", "Remote Login (SSH)", "com.openssh.sshd", Severity::High, Detect::Registered,
     "SSH exposes a remote shell; if enabled it should be firewalled and key-only.",
     "Disable in System Settings > General > Sharing > Remote Login, or: sudo systemsetup -setremotelogin off"),
    ("sharing.screen", "Screen Sharing", "com.apple.screensharing", Severity::High, Detect::Registered,
     "Screen Sharing exposes the desktop over VNC; a common lateral-movement target.",
     "Disable in System Settings > General > Sharing > Screen Sharing"),
    ("sharing.ard", "Remote Management (ARD)", "com.apple.RemoteDesktop.PrivilegeProxy", Severity::High, Detect::Active,
     "Apple Remote Desktop allows full remote control; high-value target if exposed.",
     "Disable in System Settings > General > Sharing > Remote Management"),
    ("sharing.smb", "File Sharing (SMB)", "com.apple.smbd", Severity::Medium, Detect::Registered,
     "File Sharing exposes SMB shares; misconfiguration can leak data.",
     "Disable in System Settings > General > Sharing > File Sharing"),
    ("sharing.afp", "File Sharing (AFP)", "com.apple.AppleFileServer", Severity::Medium, Detect::Registered,
     "Legacy Apple Filing Protocol sharing; deprecated and best left off.",
     "Disable in System Settings > General > Sharing > File Sharing"),
    ("sharing.printer", "Printer Sharing", "org.cups.cupsd", Severity::Low, Detect::Printer,
     "Printer sharing exposes CUPS over the network.",
     "Disable in System Settings > General > Sharing > Printer Sharing"),
    ("sharing.internet", "Internet Sharing", "com.apple.NetworkSharing", Severity::Medium, Detect::Active,
     "Internet Sharing turns the Mac into a router/AP, bridging networks.",
     "Disable in System Settings > General > Sharing > Internet Sharing"),
    ("sharing.remoteapple", "Remote Apple Events", "com.apple.AEServer", Severity::Medium, Detect::Registered,
     "Remote Apple Events lets remote hosts send AppleScript commands.",
     "Disable in System Settings > General > Sharing > Remote Apple Events"),
];

pub fn groups() -> Vec<CheckGroup> {
    vec![
        CheckGroup { id: "sharing.services", category: CAT, profile: Profile::Baseline, run: all_services },
        CheckGroup { id: "sharing.contentcache", category: CAT, profile: Profile::Baseline, run: || vec![content_caching()] },
        CheckGroup { id: "sharing.sshd", category: CAT, profile: Profile::Baseline, run: sshd_config },
    ]
}

/// Probe every sharing service in [`SERVICES`].
fn all_services() -> Vec<Finding> {
    SERVICES
        .iter()
        .map(|&(id, title, label, severity, detect, rationale, remediation)| {
            service(id, title, label, severity, detect, rationale, remediation)
        })
        .collect()
}

/// `launchctl print system/<label>`, or None if not registered.
fn launchd_print(label: &str) -> Option<String> {
    sys::run("launchctl", &["print", &format!("system/{label}")])
}

/// Whether a registered launchd job is actually running/active (vs idle), parsed
/// from `state = running` or a non-zero `active count`.
fn parse_active(out: &str) -> bool {
    if out.contains("state = running") {
        return true;
    }
    out.lines()
        .find_map(|l| l.trim().strip_prefix("active count = ").and_then(|n| n.trim().parse::<u32>().ok()))
        .map(|n| n > 0)
        .unwrap_or(false)
}

/// cupsctl's `_share_printers` flag (None if cupsctl is unavailable).
fn printer_sharing() -> Option<bool> {
    let out = sys::run("cupsctl", &[])?;
    Some(out.lines().any(|l| l.trim() == "_share_printers=1"))
}

/// Resolve a service to (enabled, observed-detail), or None to SKIP.
fn service_state(label: &str, detect: Detect) -> Option<(bool, String)> {
    match detect {
        Detect::Registered => {
            let on = launchd_print(label).is_some();
            Some((on, format!("daemon {label} is {}", if on { "loaded" } else { "not loaded" })))
        }
        Detect::Active => match launchd_print(label) {
            Some(out) => {
                let on = parse_active(&out);
                Some((on, format!("daemon {label} is {}", if on { "running" } else { "registered but idle" })))
            }
            // Not even registered ⇒ definitely off.
            None => Some((false, format!("daemon {label} is not loaded"))),
        },
        Detect::Printer => printer_sharing()
            .map(|on| (on, format!("cupsctl _share_printers={}", if on { 1 } else { 0 }))),
    }
}

/// A service that's on is reported WARN (it expands the attack surface but may
/// be intentional); off is the hardened default → PASS. Undetectable → SKIP.
fn service(
    id: &str,
    title: &str,
    label: &str,
    severity: Severity,
    detect: Detect,
    rationale: &str,
    remediation: &str,
) -> Finding {
    match service_state(label, detect) {
        Some((true, detail)) => Finding::new(id, CAT, &format!("{title} is enabled"),
            Status::Warn, severity, detail)
            .rationale(rationale)
            .remediation(remediation),
        Some((false, detail)) => Finding::new(id, CAT, &format!("{title} is disabled"),
            Status::Pass, severity, detail)
            .rationale(rationale),
        None => Finding::new(id, CAT, &format!("{title} status unknown"),
            Status::Skip, severity, "detection signal unavailable")
            .rationale(rationale),
    }
}

/// Content Caching shares cached Apple content on the LAN and advertises the host.
fn content_caching() -> Finding {
    let on = matches!(
        sys::defaults_read("/Library/Preferences/com.apple.AssetCache.plist", "Activated").as_deref(),
        Some("1") | Some("true")
    );
    if on {
        Finding::new("sharing.contentcache", CAT, "Content Caching is enabled", Status::Warn,
            Severity::Low, "AssetCache Activated = 1")
            .rationale("Content Caching advertises the host on the LAN and serves cached content to other devices.")
            .remediation("sudo AssetCacheManagerUtil deactivate")
    } else {
        Finding::new("sharing.contentcache", CAT, "Content Caching is disabled", Status::Pass,
            Severity::Low, "not activated")
    }
}

/// If SSH is enabled, audit `sshd_config` for permissive auth. Skipped entirely
/// when SSH is off (nothing exposed) or the config is unreadable.
fn sshd_config() -> Vec<Finding> {
    let ssh_on = sys::run("launchctl", &["print", "system/com.openssh.sshd"]).is_some();
    if !ssh_on {
        return vec![Finding::new(
            "sharing.sshd",
            CAT,
            "SSH hardening not applicable (SSH off)",
            Status::Skip,
            Severity::High,
            "Remote Login is disabled",
        )];
    }
    let cfg = match std::fs::read_to_string("/etc/ssh/sshd_config") {
        Ok(c) => c,
        Err(_) => {
            return vec![Finding::new("sharing.sshd", CAT, "sshd_config unreadable", Status::Skip,
                Severity::High, "could not read /etc/ssh/sshd_config")]
        }
    };
    vec![
        sshd_directive(&cfg, "sharing.sshd.rootlogin", "SSH PermitRootLogin",
            "permitrootlogin", &["no", "prohibit-password"], Severity::High,
            "Root must not be able to log in directly over SSH.",
            "Set 'PermitRootLogin no' in /etc/ssh/sshd_config"),
        sshd_directive(&cfg, "sharing.sshd.passwordauth", "SSH PasswordAuthentication",
            "passwordauthentication", &["no"], Severity::High,
            "Password auth over SSH is brute-forceable; use keys only.",
            "Set 'PasswordAuthentication no' in /etc/ssh/sshd_config"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Status;

    fn dir(cfg: &str) -> Status {
        sshd_directive(cfg, "id", "t", "permitrootlogin", &["no", "prohibit-password"],
            Severity::High, "", "").status
    }

    #[test]
    fn sshd_good_value_passes() {
        assert_eq!(dir("PermitRootLogin no\n"), Status::Pass);
        assert_eq!(dir("permitrootlogin prohibit-password\n"), Status::Pass);
    }

    #[test]
    fn sshd_bad_value_fails() {
        assert_eq!(dir("PermitRootLogin yes\n"), Status::Fail);
    }

    #[test]
    fn sshd_commented_and_absent_warn() {
        assert_eq!(dir("# PermitRootLogin no\n"), Status::Warn);
        assert_eq!(dir("Port 22\n"), Status::Warn);
    }

    #[test]
    fn sshd_last_uncommented_wins() {
        assert_eq!(dir("PermitRootLogin yes\nPermitRootLogin no\n"), Status::Pass);
    }

    #[test]
    fn active_state_distinguishes_idle_from_running() {
        // Registered-but-idle daemon (the false-positive case) → not active.
        assert!(!parse_active("\tactive count = 0\n\tstate = not running\n"));
        // Actually running.
        assert!(parse_active("\tactive count = 1\n\tstate = running\n"));
        // Active count alone is enough.
        assert!(parse_active("\tactive count = 3\n"));
    }
}

/// Parse a single sshd directive (last uncommented occurrence wins, like sshd)
/// and PASS if its value is in `good`.
fn sshd_directive(
    cfg: &str,
    id: &str,
    title: &str,
    key: &str,
    good: &[&str],
    severity: Severity,
    rationale: &str,
    remediation: &str,
) -> Finding {
    let value = cfg
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let k = it.next()?;
            if k.eq_ignore_ascii_case(key) {
                it.next().map(|v| v.to_lowercase())
            } else {
                None
            }
        })
        .last();

    match value {
        Some(v) if good.contains(&v.as_str()) => Finding::new(id, CAT,
            &format!("{title}: {v}"), Status::Pass, severity, format!("{key} {v}"))
            .rationale(rationale),
        Some(v) => Finding::new(id, CAT, &format!("{title}: {v}"), Status::Fail, severity,
            format!("{key} {v}"))
            .rationale(rationale)
            .remediation(remediation),
        // Not set => sshd default, which for these is the insecure/permissive side.
        None => Finding::new(id, CAT, &format!("{title}: default"), Status::Warn, severity,
            format!("{key} not set (using sshd default)"))
            .rationale(rationale)
            .remediation(remediation),
    }
}
