//! Application firewall (ALF) and stealth mode.
//!
//! macOS ships a built-in inbound application firewall, but many users run a
//! third-party firewall instead (Little Snitch, LuLu, Murus/Vallum) — these
//! also, or primarily, handle *outbound* connection control. When the built-in
//! firewall is off we therefore check whether a third-party firewall is active
//! before flagging the host as unprotected.

use super::CheckGroup;
use crate::model::{Category, Finding, Profile, Severity, Status};
use crate::sys;

const CAT: Category = Category::Firewall;
const FW: &str = "/usr/libexec/ApplicationFirewall/socketfilterfw";

/// Known third-party firewalls: (display name, system-extension bundle-id
/// substring, daemon process-path substring used as a fallback signal).
const KNOWN_THIRD_PARTY: &[(&str, &str, &str)] = &[
    ("Little Snitch", "at.obdev.littlesnitch", "at.obdev.littlesnitch.daemon"),
    ("LuLu", "com.objective-see.lulu", "com.objective-see.lulu"),
    ("Murus", "com.murusfirewall", "murus"),
    ("Vallum", "com.murus.vallum", "vallum"),
];

/// An active third-party firewall and how we detected it.
struct ThirdParty {
    name: String,
    evidence: String,
}

pub fn groups() -> Vec<CheckGroup> {
    vec![
        // One group: detect built-in + third-party state once, emit several findings.
        CheckGroup { id: "firewall.state", category: CAT, profile: Profile::Baseline, run: state_findings },
        CheckGroup { id: "firewall.allowsigned", category: CAT, profile: Profile::Paranoia, run: || vec![allow_signed()] },
    ]
}

/// Built-in + third-party detection done once, yielding the enabled, stealth,
/// and block-all findings.
fn state_findings() -> Vec<Finding> {
    let builtin = builtin_state();
    let third_party = detect_third_party();
    vec![
        firewall_enabled(builtin, third_party.as_ref()),
        stealth_mode(builtin, third_party.as_ref()),
        block_all(),
    ]
}

/// Tri-state result of probing the built-in firewall.
#[derive(Clone, Copy, PartialEq)]
enum Builtin {
    On,
    Off,
    Unknown,
}

fn builtin_state() -> Builtin {
    match sys::run_lossy(FW, &["--getglobalstate"]) {
        Some(out) => {
            let lower = out.to_lowercase();
            // "Firewall is enabled. (State = 1)" / "... (State = 2)"
            if lower.contains("enabled") || lower.contains("state = 1") || lower.contains("state = 2")
            {
                Builtin::On
            } else {
                Builtin::Off
            }
        }
        None => Builtin::Unknown,
    }
}

/// Look for an active third-party firewall.
///
/// Preferred signal is an *activated + enabled* system extension (the modern
/// network-extension model both Little Snitch 5+ and LuLu use); a running
/// daemon process is the fallback for older/PF-based tools.
fn detect_third_party() -> Option<ThirdParty> {
    let exts = sys::run("systemextensionsctl", &["list"]).unwrap_or_default();
    for (name, sysext, proc) in KNOWN_THIRD_PARTY {
        for line in exts.lines() {
            if line.contains(sysext) && line.contains("activated enabled") {
                return Some(ThirdParty {
                    name: name.to_string(),
                    evidence: format!("system extension active: {sysext}"),
                });
            }
        }
        // Fallback: a matching daemon is running.
        if sys::process_running(proc) {
            return Some(ThirdParty {
                name: name.to_string(),
                evidence: format!("daemon running: {proc}"),
            });
        }
    }
    None
}

/// Inbound protection: the built-in firewall, OR a third-party firewall taking
/// over the role.
fn firewall_enabled(builtin: Builtin, third_party: Option<&ThirdParty>) -> Finding {
    match builtin {
        Builtin::On => Finding::new(
            "firewall.enabled",
            CAT,
            "Application firewall enabled",
            Status::Pass,
            Severity::High,
            "built-in firewall is on",
        )
        .rationale("The firewall blocks unsolicited inbound connections to services and apps."),

        // Built-in is off (or unreadable) — a third-party firewall covers it.
        _ if third_party.is_some() => {
            let tp = third_party.unwrap();
            Finding::new(
                "firewall.enabled",
                CAT,
                &format!("Firewall active via {}", tp.name),
                Status::Pass,
                Severity::High,
                format!("built-in firewall off; {} active ({})", tp.name, tp.evidence),
            )
            .rationale("A third-party firewall is handling connection filtering in place of the built-in ALF (and typically adds outbound/per-app control the built-in firewall lacks).")
        }

        Builtin::Off => Finding::new(
            "firewall.enabled",
            CAT,
            "Application firewall disabled",
            Status::Fail,
            Severity::High,
            "built-in firewall is off and no third-party firewall detected",
        )
        .rationale("With no firewall, any listening service is reachable from the network.")
        .remediation("sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on")
        .reference("https://support.apple.com/guide/mac-help/mh34041"),

        Builtin::Unknown => Finding::new(
            "firewall.enabled",
            CAT,
            "Firewall status unknown",
            Status::Skip,
            Severity::High,
            "socketfilterfw not available and no third-party firewall detected",
        ),
    }
}

/// Stealth mode drops ICMP/probe traffic so the host doesn't respond to scans.
/// This is a feature of the *built-in* firewall, so it's only meaningful when
/// the built-in firewall is the one in charge.
fn stealth_mode(builtin: Builtin, third_party: Option<&ThirdParty>) -> Finding {
    // When a third-party firewall is in charge, the Apple stealth setting no
    // longer reflects the host's behavior — don't score it.
    if builtin != Builtin::On {
        if let Some(tp) = third_party {
            return Finding::new(
                "firewall.stealth",
                CAT,
                "Stealth mode managed by third-party firewall",
                Status::Skip,
                Severity::Medium,
                format!("built-in stealth N/A; {} is in charge of filtering", tp.name),
            )
            .rationale("The built-in stealth-mode setting only applies to the Apple firewall; with a third-party firewall active, configure probe/ICMP behavior there instead.");
        }
    }

    match sys::run_lossy(FW, &["--getstealthmode"]) {
        Some(out) => {
            if out.to_lowercase().contains("enabled") {
                Finding::new(
                    "firewall.stealth",
                    CAT,
                    "Stealth mode enabled",
                    Status::Pass,
                    Severity::Medium,
                    out,
                )
                .rationale("Stealth mode makes the host ignore ICMP pings and connection probes, reducing its visibility to scanners.")
            } else {
                Finding::new(
                    "firewall.stealth",
                    CAT,
                    "Stealth mode disabled",
                    Status::Warn,
                    Severity::Medium,
                    out,
                )
                .rationale("Without stealth mode the host responds to pings and port probes, making reconnaissance easier.")
                .remediation("sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on")
            }
        }
        None => Finding::new(
            "firewall.stealth",
            CAT,
            "Stealth mode status unknown",
            Status::Skip,
            Severity::Medium,
            "socketfilterfw not available",
        ),
    }
}

/// "Block all incoming connections" — strictest built-in firewall mode. Off is
/// the usual default; on is hardened but breaks inbound services. Informational.
fn block_all() -> Finding {
    match sys::run_lossy(FW, &["--getblockall"]) {
        Some(out) if out.to_lowercase().contains("set to enabled") => Finding::new(
            "firewall.blockall",
            CAT,
            "Block all incoming connections enabled",
            Status::Pass,
            Severity::Low,
            out,
        )
        .rationale("Block-all mode rejects every inbound connection except those essential to basic services — the strictest inbound posture."),
        Some(out) => Finding::new(
            "firewall.blockall",
            CAT,
            "Block all incoming connections disabled",
            Status::Info,
            Severity::Low,
            out,
        )
        .rationale("Optional hardening: blocks all inbound connections. Off by default; enabling it can break inbound services you rely on."),
        None => Finding::new(
            "firewall.blockall",
            CAT,
            "Block-all status unknown",
            Status::Skip,
            Severity::Low,
            "socketfilterfw not available",
        ),
    }
}

/// Whether the firewall auto-allows signed software. Convenient, but a stricter
/// stance requires explicit approval of each listening app.
fn allow_signed() -> Finding {
    match sys::run_lossy(FW, &["--getallowsigned"]) {
        Some(out) => {
            // Two lines: built-in signed + downloaded signed. "ENABLED" => auto-allow.
            if out.to_uppercase().contains("ENABLED") {
                Finding::new(
                    "firewall.allowsigned",
                    CAT,
                    "Firewall auto-allows signed software",
                    Status::Warn,
                    Severity::Low,
                    out.replace('\n', " · "),
                )
                .rationale("Auto-allowing signed software means new signed apps can listen without prompting. Paranoid stance: disable and approve each app explicitly.")
                .remediation("sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setallowsigned off --setallowsignedapp off")
            } else {
                Finding::new(
                    "firewall.allowsigned",
                    CAT,
                    "Firewall requires explicit app approval",
                    Status::Pass,
                    Severity::Low,
                    out.replace('\n', " · "),
                )
            }
        }
        None => Finding::new(
            "firewall.allowsigned",
            CAT,
            "Auto-allow-signed status unknown",
            Status::Skip,
            Severity::Low,
            "socketfilterfw not available",
        ),
    }
}
