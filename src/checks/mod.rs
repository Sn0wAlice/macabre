//! Check engine: a registry of check *groups*, each tagged with a category and
//! the minimum profile at which it runs.
//!
//! To add a check, write a function returning `Vec<Finding>` in the relevant
//! category module and register it from that module's `groups()`. A group can
//! emit several findings so it can do shared detection once (e.g. firewall
//! probes system extensions a single time, then yields enabled + stealth).

use crate::model::{Category, Finding, Profile};

mod account;
mod appsec;
mod encryption;
mod firewall;
mod integrity;
mod network;
mod persistence;
mod privacy;
mod sharing;
mod updates;

/// A registered unit of work. `run` may return multiple findings.
pub struct CheckGroup {
    pub id: &'static str,
    pub category: Category,
    /// Minimum profile required to run this group.
    pub profile: Profile,
    pub run: fn() -> Vec<Finding>,
}

/// Every registered group, in no particular order (rendering sorts by category).
pub fn registry() -> Vec<CheckGroup> {
    let mut g = Vec::new();
    g.extend(integrity::groups());
    g.extend(encryption::groups());
    g.extend(firewall::groups());
    g.extend(appsec::groups());
    g.extend(account::groups());
    g.extend(sharing::groups());
    g.extend(network::groups());
    g.extend(persistence::groups());
    g.extend(updates::groups());
    g.extend(privacy::groups());
    g
}

/// A group matches a `--only`/`--skip` token if the token equals its category
/// slug or its id (or a dotted prefix of its id).
fn matches(group: &CheckGroup, token: &str) -> bool {
    let t = token.trim().to_lowercase();
    group.category.slug() == t || group.id == t || group.id.starts_with(&format!("{t}."))
}

/// Run the registry under `profile`, honouring optional `--only`/`--skip`
/// category/id filters, and collect all findings.
pub fn run(profile: Profile, only: &[String], skip: &[String]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for group in registry() {
        if group.profile > profile {
            continue;
        }
        if !only.is_empty() && !only.iter().any(|t| matches(&group, t)) {
            continue;
        }
        if skip.iter().any(|t| matches(&group, t)) {
            continue;
        }
        findings.extend((group.run)());
    }
    findings
}
