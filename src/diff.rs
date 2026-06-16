//! Compare two saved JSON reports (`macabre -f json -o …`) over time.
//!
//! Decoupled from the live `model` types on purpose: we deserialize a minimal
//! snapshot of the persisted JSON so the in-memory model stays free of
//! `Deserialize`/lifetime concerns. Findings are matched by their stable `id`.

use owo_colors::OwoColorize;
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Deserialize)]
struct Snapshot {
    #[serde(default)]
    hostname: String,
    #[serde(default)]
    generated_at: String,
    security: ScoreSnap,
    #[serde(default)]
    privacy: Option<ScoreSnap>,
    findings: Vec<FindingSnap>,
}

#[derive(Deserialize, Clone, Copy)]
struct ScoreSnap {
    index: u32,
}

#[derive(Deserialize, Clone)]
struct FindingSnap {
    id: String,
    title: String,
    status: String,
    #[serde(default)]
    category: String,
}

/// Higher is more hardened. Skip/Info are neutral (rank 0) so toggling in/out of
/// "not assessable" isn't reported as an improvement or regression.
fn rank(status: &str) -> i8 {
    match status {
        "pass" => 3,
        "warn" => 2,
        "fail" => 1,
        _ => 0, // skip, info
    }
}

fn load(path: &str) -> Result<Snapshot, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    serde_json::from_str(&raw).map_err(|e| format!("{path}: not a macabre JSON report ({e})"))
}

/// Entry point for `macabre diff <old> <new>`. Returns the process exit code:
/// non-zero when something regressed (handy for CI gates).
pub fn run(old_path: &str, new_path: &str, verbose: bool) -> i32 {
    let (old, new) = match (load(old_path), load(new_path)) {
        (Ok(o), Ok(n)) => (o, n),
        (Err(e), _) | (_, Err(e)) => {
            eprintln!("error: {e}");
            return 2;
        }
    };

    let old_f: BTreeMap<&str, &FindingSnap> = old.findings.iter().map(|f| (f.id.as_str(), f)).collect();
    let new_f: BTreeMap<&str, &FindingSnap> = new.findings.iter().map(|f| (f.id.as_str(), f)).collect();

    println!("{}", "═".repeat(64).bright_black());
    println!(
        "  {} {} → {}",
        "macabre diff".bold(),
        short(&old.generated_at).bright_black(),
        short(&new.generated_at).bright_black()
    );
    if !new.hostname.is_empty() {
        println!("  {}", new.hostname.cyan());
    }
    println!("{}", "═".repeat(64).bright_black());

    score_line("Security index", old.security.index, new.security.index);
    if let (Some(o), Some(n)) = (old.privacy, new.privacy) {
        score_line("Privacy index ", o.index, n.index);
    }
    println!();

    let mut regressed = Vec::new();
    let mut improved = Vec::new();
    let mut added = Vec::new();
    let mut removed = Vec::new();

    // Transitions for ids present in both reports.
    for (id, nf) in &new_f {
        match old_f.get(id) {
            Some(of) => {
                let (or, nr) = (rank(&of.status), rank(&nf.status));
                if nr < or {
                    regressed.push((*nf, of.status.clone()));
                } else if nr > or {
                    improved.push((*nf, of.status.clone()));
                }
            }
            None => added.push(*nf),
        }
    }
    for (id, of) in &old_f {
        if !new_f.contains_key(id) {
            removed.push(*of);
        }
    }

    section("REGRESSED", &regressed, |f, prev| {
        format!("  {} {}  {}", "▼".red().bold(), transition(prev, &f.status), label(f))
    });
    section("IMPROVED", &improved, |f, prev| {
        format!("  {} {}  {}", "▲".green().bold(), transition(prev, &f.status), label(f))
    });
    section_simple("NEW", &added, "+".yellow().to_string());
    section_simple("REMOVED", &removed, "−".bright_black().to_string());

    if regressed.is_empty() && improved.is_empty() && added.is_empty() && removed.is_empty() {
        println!("  {}", "No changes in findings.".bright_black());
    }

    if verbose {
        let unchanged = new_f.len() - improved.len() - regressed.len() - added.len();
        println!("\n  {} unchanged", unchanged.to_string().bright_black());
    }
    println!("{}", "═".repeat(64).bright_black());

    if regressed.is_empty() { 0 } else { 1 }
}

fn score_line(label: &str, old: u32, new: u32) {
    let delta = new as i32 - old as i32;
    let arrow = match delta.cmp(&0) {
        std::cmp::Ordering::Greater => format!("+{delta}").green().to_string(),
        std::cmp::Ordering::Less => delta.to_string().red().to_string(),
        std::cmp::Ordering::Equal => "±0".bright_black().to_string(),
    };
    println!("  {}  {} → {}  ({})", label.bold(), old, new.bold(), arrow);
}

fn section(
    title: &str,
    items: &[(&FindingSnap, String)],
    fmt: impl Fn(&FindingSnap, &str) -> String,
) {
    if items.is_empty() {
        return;
    }
    println!("  {} ({})", title.bold(), items.len());
    for (f, prev) in items {
        println!("{}", fmt(f, prev));
    }
    println!();
}

fn section_simple(title: &str, items: &[&FindingSnap], marker: String) {
    if items.is_empty() {
        return;
    }
    println!("  {} ({})", title.bold(), items.len());
    for f in items {
        println!("  {} {} {}", marker, status_tag(&f.status), label(f));
    }
    println!();
}

fn transition(old: &str, new: &str) -> String {
    format!("{}→{}", status_tag(old), status_tag(new))
}

fn status_tag(status: &str) -> String {
    let up = status.to_uppercase();
    match status {
        "pass" => up.green().to_string(),
        "warn" => up.yellow().to_string(),
        "fail" => up.red().to_string(),
        _ => up.bright_black().to_string(),
    }
}

fn label(f: &FindingSnap) -> String {
    if f.category.is_empty() {
        f.title.clone()
    } else {
        format!("{} {}", f.title, format!("[{}]", f.category).bright_black())
    }
}

/// Trim a timestamp to "YYYY-MM-DD HH:MM" for compact headers.
fn short(ts: &str) -> String {
    ts.chars().take(16).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rank_orders_states() {
        assert!(rank("pass") > rank("warn"));
        assert!(rank("warn") > rank("fail"));
        assert_eq!(rank("skip"), rank("info"));
        assert_eq!(rank("skip"), 0);
    }
}
