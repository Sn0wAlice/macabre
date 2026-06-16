//! Check engine: each submodule contributes a set of read-only checks.
//!
//! To add a check, write a function returning a [`Finding`] in the relevant
//! category module and push it from that module's `run()`. To add a whole
//! category, create a module and register it in [`run_all`].

use crate::model::Finding;

mod appsec;
mod encryption;
mod firewall;
mod integrity;
mod sharing;
mod updates;

/// Run every registered check and collect findings.
///
/// Checks run sequentially; each shells out to fast inspection commands, so the
/// full sweep stays well under a second on a normal system.
pub fn run_all() -> Vec<Finding> {
    let mut findings = Vec::new();
    findings.extend(integrity::run());
    findings.extend(encryption::run());
    findings.extend(firewall::run());
    findings.extend(appsec::run());
    findings.extend(sharing::run());
    findings.extend(updates::run());
    findings
}
