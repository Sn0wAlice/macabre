//! Sharing & remote access services.
//!
//! Each enabled service widens the network attack surface. We detect whether
//! the relevant system daemon is loaded via `launchctl print`. When SSH is on,
//! we additionally audit `sshd_config` for permissive settings.

use super::CheckGroup;
use crate::model::{Category, Finding, Profile, Severity, Status};
use crate::sys;

const CAT: Category = Category::Sharing;

/// (id, title, launchd label, severity, rationale, remediation)
const SERVICES: &[(&str, &str, &str, Severity, &str, &str)] = &[
    ("sharing.ssh", "Remote Login (SSH)", "com.openssh.sshd", Severity::High,
     "SSH exposes a remote shell; if enabled it should be firewalled and key-only.",
     "Disable in System Settings > General > Sharing > Remote Login, or: sudo systemsetup -setremotelogin off"),
    ("sharing.screen", "Screen Sharing", "com.apple.screensharing", Severity::High,
     "Screen Sharing exposes the desktop over VNC; a common lateral-movement target.",
     "Disable in System Settings > General > Sharing > Screen Sharing"),
    ("sharing.ard", "Remote Management (ARD)", "com.apple.RemoteDesktop.PrivilegeProxy", Severity::High,
     "Apple Remote Desktop allows full remote control; high-value target if exposed.",
     "Disable in System Settings > General > Sharing > Remote Management"),
    ("sharing.smb", "File Sharing (SMB)", "com.apple.smbd", Severity::Medium,
     "File Sharing exposes SMB shares; misconfiguration can leak data.",
     "Disable in System Settings > General > Sharing > File Sharing"),
    ("sharing.afp", "File Sharing (AFP)", "com.apple.AppleFileServer", Severity::Medium,
     "Legacy Apple Filing Protocol sharing; deprecated and best left off.",
     "Disable in System Settings > General > Sharing > File Sharing"),
    ("sharing.printer", "Printer Sharing", "org.cups.cupsd", Severity::Low,
     "Printer sharing exposes CUPS over the network.",
     "Disable in System Settings > General > Sharing > Printer Sharing"),
    ("sharing.internet", "Internet Sharing", "com.apple.NetworkSharing", Severity::Medium,
     "Internet Sharing turns the Mac into a router/AP, bridging networks.",
     "Disable in System Settings > General > Sharing > Internet Sharing"),
    ("sharing.remoteapple", "Remote Apple Events", "com.apple.AEServer", Severity::Medium,
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
        .map(|&(id, title, label, severity, rationale, remediation)| {
            service(id, title, label, severity, rationale, remediation)
        })
        .collect()
}

/// Generic loaded-daemon probe. A loaded service is reported WARN (it expands
/// the attack surface but may be intentional); off is the hardened default → PASS.
fn service(
    id: &str,
    title: &str,
    label: &str,
    severity: Severity,
    rationale: &str,
    remediation: &str,
) -> Finding {
    let loaded = sys::run("launchctl", &["print", &format!("system/{label}")]).is_some();
    if loaded {
        Finding::new(id, CAT, &format!("{title} is enabled"), Status::Warn, severity,
            format!("daemon {label} is loaded"))
            .rationale(rationale)
            .remediation(remediation)
    } else {
        Finding::new(id, CAT, &format!("{title} is disabled"), Status::Pass, severity,
            format!("daemon {label} is not loaded"))
            .rationale(rationale)
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
