//! Sharing & remote access services.
//!
//! Each service that's enabled widens the attack surface. We detect whether the
//! relevant system daemon is loaded via `launchctl print`.

use crate::model::{Category, Finding, Severity, Status};
use crate::sys;

const CAT: Category = Category::Sharing;

pub fn run() -> Vec<Finding> {
    vec![
        service(
            "sharing.ssh",
            "Remote Login (SSH)",
            "com.openssh.sshd",
            Severity::High,
            "SSH exposes a remote shell; if enabled it should be firewalled and key-only.",
            "Disable in System Settings > General > Sharing > Remote Login, or: sudo systemsetup -setremotelogin off",
        ),
        service(
            "sharing.screen",
            "Screen Sharing",
            "com.apple.screensharing",
            Severity::High,
            "Screen Sharing exposes the desktop over VNC; a common lateral-movement target.",
            "Disable in System Settings > General > Sharing > Screen Sharing",
        ),
        service(
            "sharing.ard",
            "Remote Management (ARD)",
            "com.apple.RemoteDesktop.PrivilegeProxy",
            Severity::High,
            "Apple Remote Desktop allows full remote control; high-value target if exposed.",
            "Disable in System Settings > General > Sharing > Remote Management",
        ),
        service(
            "sharing.smb",
            "File Sharing (SMB)",
            "com.apple.smbd",
            Severity::Medium,
            "File Sharing exposes SMB shares; misconfiguration can leak data.",
            "Disable in System Settings > General > Sharing > File Sharing",
        ),
    ]
}

/// Generic loaded-daemon probe. A loaded service is reported as a FAIL/WARN
/// because each enabled service expands the network attack surface; a service
/// that's off is the hardened default and reported PASS.
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
        Finding::new(
            id,
            CAT,
            &format!("{title} is enabled"),
            // Off-by-default services being on is worth flagging, but it may be
            // intentional — surface as a warning rather than a hard failure.
            Status::Warn,
            severity,
            format!("daemon {label} is loaded"),
        )
        .rationale(rationale)
        .remediation(remediation)
    } else {
        Finding::new(
            id,
            CAT,
            &format!("{title} is disabled"),
            Status::Pass,
            severity,
            format!("daemon {label} is not loaded"),
        )
        .rationale(rationale)
    }
}
