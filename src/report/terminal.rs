//! Colored terminal report, inspired by lynis/htop: grouped sections, a colored
//! status badge per check, and a hardening-index gauge at the end.

use crate::model::{Category, Finding, Report, Status};
use owo_colors::{OwoColorize, Style};

/// Print the full report to stdout. `verbose` adds rationale + remediation lines
/// under each finding; otherwise only failures/warnings show their fix.
pub fn print_terminal(report: &Report, verbose: bool) {
    header(report);

    for cat in Category::all() {
        let items: Vec<&Finding> =
            report.findings.iter().filter(|f| f.category == *cat).collect();
        if items.is_empty() {
            continue;
        }
        println!("\n  {}", cat.title().bold().underline());
        for f in &items {
            print_finding(f, verbose);
        }
    }

    summary(report);
}

fn header(report: &Report) {
    let line = "═".repeat(64);
    println!("{}", line.bright_black());
    println!(
        "  {} {}  ·  {}",
        "macabre".bold().bright_magenta(),
        format!("v{}", report.version).bright_black(),
        "macOS hardening audit".bright_black()
    );
    println!(
        "  {}  ·  {}  ·  {}",
        report.hostname.cyan(),
        report.os_version,
        report.generated_at.bright_black()
    );
    println!("{}", line.bright_black());
}

fn print_finding(f: &Finding, verbose: bool) {
    println!("  {} {}", badge(f.status), f.title);
    // Detail line, dimmed, indented under the badge.
    if !f.detail.is_empty() {
        println!("       {}", f.detail.bright_black());
    }
    // Always surface fixes for actionable findings; in verbose mode show
    // rationale + remediation for everything.
    let actionable = matches!(f.status, Status::Fail | Status::Warn);
    if verbose && !f.rationale.is_empty() {
        println!("       {} {}", "why:".bright_black(), f.rationale.bright_black());
    }
    if let Some(rem) = &f.remediation {
        if verbose || actionable {
            println!("       {} {}", "fix:".yellow(), rem.bright_yellow());
        }
    }
    if verbose {
        if let Some(r) = &f.reference {
            println!("       {} {}", "ref:".bright_black(), r.blue());
        }
    }
}

/// Right-padded colored status badge, e.g. `[ PASS ]`.
fn badge(status: Status) -> String {
    let style = match status {
        Status::Pass => Style::new().green().bold(),
        Status::Warn => Style::new().yellow().bold(),
        Status::Fail => Style::new().red().bold(),
        Status::Info => Style::new().blue().bold(),
        Status::Skip => Style::new().bright_black().bold(),
    };
    format!("[ {} ]", format!("{:^4}", status.label()).style(style))
}

fn summary(report: &Report) {
    let sc = &report.score;
    println!("\n{}", "─".repeat(64).bright_black());
    println!(
        "  {}  {}   {}  {}   {}  {}   {}  {}",
        "pass".green(),
        sc.passed.bold(),
        "warn".yellow(),
        sc.warned.bold(),
        "fail".red(),
        sc.failed.bold(),
        "skip".bright_black(),
        sc.skipped.bold(),
    );
    println!("\n  {} {}", "Hardening index".bold(), gauge(sc.index));
    println!("{}", "─".repeat(64).bright_black());
}

/// A 40-cell gauge colored by band: red < 50, yellow < 80, green otherwise.
fn gauge(index: u32) -> String {
    const WIDTH: u32 = 40;
    let filled = (index * WIDTH / 100).min(WIDTH);
    let empty = WIDTH - filled;
    let bar = format!(
        "{}{}",
        "█".repeat(filled as usize),
        "░".repeat(empty as usize)
    );
    let colored = if index < 50 {
        bar.red().to_string()
    } else if index < 80 {
        bar.yellow().to_string()
    } else {
        bar.green().to_string()
    };
    format!("{} {}", colored, format!("{index}/100").bold())
}
