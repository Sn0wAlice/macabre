//! Network exposure: wake-on-LAN, externally-reachable listening ports.

use super::CheckGroup;
use crate::model::{Category, Finding, Profile, Severity, Status};
use crate::sys;

const CAT: Category = Category::Network;

pub fn groups() -> Vec<CheckGroup> {
    vec![
        CheckGroup { id: "network.wol", category: CAT, profile: Profile::Baseline, run: || vec![wake_on_lan()] },
        CheckGroup { id: "network.listeners", category: CAT, profile: Profile::Paranoia, run: || vec![listeners()] },
    ]
}

/// Wake-on-LAN ("Wake for network access") lets the Mac be woken by network
/// traffic — convenient but a remote-attack enabler on untrusted networks.
fn wake_on_lan() -> Finding {
    let pmset = sys::run("pmset", &["-g"]).unwrap_or_default();
    let womp_on = pmset
        .lines()
        .find(|l| l.trim_start().starts_with("womp"))
        .map(|l| l.split_whitespace().nth(1) == Some("1"))
        .unwrap_or(false);
    if womp_on {
        Finding::new("network.wol", CAT, "Wake for network access enabled", Status::Warn,
            Severity::Low, "pmset womp = 1")
            .rationale("Wake-on-LAN lets the machine be woken remotely; on untrusted networks this enlarges the window for remote attacks.")
            .remediation("sudo pmset -a womp 0")
    } else {
        Finding::new("network.wol", CAT, "Wake for network access disabled", Status::Pass,
            Severity::Low, "pmset womp = 0")
    }
}

/// A non-loopback listening socket: the process and the address it binds.
#[derive(Debug, PartialEq)]
pub struct Listener {
    pub process: String,
    pub addr: String,
}

/// Parse `lsof -nP -iTCP -sTCP:LISTEN` output, keeping only listeners bound to
/// a non-loopback address (reachable from other hosts).
pub fn parse_listeners(lsof: &str) -> Vec<Listener> {
    let mut out = Vec::new();
    for line in lsof.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 9 {
            continue;
        }
        let process = cols[0];
        let name = cols[8]; // NAME column, e.g. "*:49166" or "127.0.0.1:6463"
        let host = name.rsplit_once(':').map(|(h, _)| h).unwrap_or(name);
        let loopback = matches!(host, "127.0.0.1" | "localhost" | "[::1]" | "::1");
        if !loopback {
            out.push(Listener { process: process.to_string(), addr: name.to_string() });
        }
    }
    out.sort_by(|a, b| (a.process.clone(), a.addr.clone()).cmp(&(b.process.clone(), b.addr.clone())));
    out.dedup_by(|a, b| a.process == b.process && a.addr == b.addr);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_only_non_loopback_listeners() {
        let lsof = "\
COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
Discord 111 a 30u IPv4 0x1 0t0 TCP 127.0.0.1:6463 (LISTEN)
Spotify 222 a 40u IPv4 0x2 0t0 TCP *:49501 (LISTEN)
rapportd 333 a 5u IPv6 0x3 0t0 TCP [::1]:7000 (LISTEN)
shared 444 a 6u IPv4 0x4 0t0 TCP 192.168.1.5:445 (LISTEN)";
        let got = parse_listeners(lsof);
        // Loopback (127.0.0.1, [::1]) dropped; * and routable IP kept.
        assert_eq!(got.len(), 2);
        assert!(got.iter().any(|l| l.process == "Spotify" && l.addr == "*:49501"));
        assert!(got.iter().any(|l| l.process == "shared" && l.addr == "192.168.1.5:445"));
    }

    #[test]
    fn dedups_repeated_listeners() {
        let lsof = "\
H
Spotify 1 a 1u IPv4 0x1 0t0 TCP *:49501 (LISTEN)
Spotify 1 a 2u IPv4 0x1 0t0 TCP *:49501 (LISTEN)";
        assert_eq!(parse_listeners(lsof).len(), 1);
    }
}

/// Inventory of services listening on non-loopback addresses (reachable from
/// the network). Deep/paranoia: noisy but high signal.
fn listeners() -> Finding {
    let lsof = sys::run("lsof", &["-nP", "-iTCP", "-sTCP:LISTEN"]).unwrap_or_default();
    let found = parse_listeners(&lsof);
    if found.is_empty() {
        Finding::new("network.listeners", CAT, "No services listening on external interfaces",
            Status::Pass, Severity::Medium, "only loopback listeners (or none)")
            .rationale("Nothing is reachable from the network on TCP.")
    } else {
        let list = found
            .iter()
            .map(|l| format!("{} ({})", l.addr, l.process))
            .collect::<Vec<_>>()
            .join(", ");
        Finding::new("network.listeners", CAT,
            &format!("{} service(s) listening on external interfaces", found.len()),
            Status::Warn, Severity::Medium, list)
            .rationale("These sockets accept connections from other hosts. Confirm each is intended; close or firewall the rest.")
            .remediation("Identify the owning app and disable its network listener, or block it in your firewall (e.g. Little Snitch).")
    }
}
