//! macabre — a read-only macOS hardening & security audit scanner.
//!
//! Runs a suite of checks against local security settings, scores the host with
//! a weighted "hardening index", and reports findings to the terminal or to
//! JSON / Markdown / HTML. It only inspects state — it never changes anything;
//! failing checks include the command you'd run to fix them.
//!
//! `--paranoia` adds a deep scan: anti-telemetry/privacy checks (scored in a
//! separate Privacy index) plus deep inventory (external listeners, third-party
//! launchd jobs, configuration profiles).

mod checks;
mod model;
mod report;
mod sys;

use clap::{Parser, ValueEnum};
use model::{Class, Profile, Report, Score, Status};
use report::Format;
use std::process::ExitCode;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser, Debug)]
#[command(
    name = "macabre",
    version = VERSION,
    about = "macOS hardening & security audit scanner (read-only)"
)]
struct Cli {
    /// Output format. Defaults to a colored terminal report.
    #[arg(short, long, value_enum, default_value_t = OutFormat::Term)]
    format: OutFormat,

    /// Write the report to a file instead of stdout.
    #[arg(short, long, value_name = "PATH")]
    output: Option<String>,

    /// Show rationale, remediation, and references for every finding (terminal).
    #[arg(short, long)]
    verbose: bool,

    /// Deep scan: add privacy/anti-telemetry checks and deep inventory.
    #[arg(short, long)]
    paranoia: bool,

    /// Only run these categories or check ids (comma-separated).
    #[arg(long, value_name = "CATS", value_delimiter = ',')]
    only: Vec<String>,

    /// Skip these categories or check ids (comma-separated).
    #[arg(long, value_name = "CATS", value_delimiter = ',')]
    skip: Vec<String>,

    /// List all registered checks (id, category, profile) and exit.
    #[arg(long)]
    list: bool,

    /// Exit non-zero if any security check fails (useful in CI / monitoring).
    #[arg(long)]
    strict: bool,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum OutFormat {
    /// Colored terminal report (default).
    Term,
    Json,
    #[value(name = "md", alias = "markdown")]
    Markdown,
    Html,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    if cli.list {
        list_checks();
        return ExitCode::SUCCESS;
    }

    let profile = if cli.paranoia { Profile::Paranoia } else { Profile::Baseline };
    let findings = checks::run(profile, &cli.only, &cli.skip);

    let security = Score::compute_for(&findings, Class::Security);
    let privacy = if findings.iter().any(|f| f.category.class() == Class::Privacy) {
        Some(Score::compute_for(&findings, Class::Privacy))
    } else {
        None
    };
    // Strict mode only cares about real security failures.
    let security_fails = findings
        .iter()
        .filter(|f| f.category.class() == Class::Security && f.status == Status::Fail)
        .count();

    let report = Report {
        tool: "macabre",
        version: VERSION,
        generated_at: chrono::Local::now().format("%Y-%m-%d %H:%M:%S %z").to_string(),
        hostname: sys::hostname(),
        os_version: sys::os_version(),
        profile,
        root: sys::is_root(),
        security,
        privacy,
        findings,
    };

    match cli.format {
        OutFormat::Term => {
            // The terminal renderer prints directly (colors, no buffering).
            // When an output file is requested, fall back to plain Markdown so
            // we don't write ANSI escapes to a file.
            if let Some(path) = &cli.output {
                write_out(path, &report::render(&report, Format::Markdown));
            } else {
                report::print_terminal(&report, cli.verbose);
            }
        }
        other => {
            let fmt = match other {
                OutFormat::Json => Format::Json,
                OutFormat::Markdown => Format::Markdown,
                OutFormat::Html => Format::Html,
                OutFormat::Term => unreachable!(),
            };
            let rendered = report::render(&report, fmt);
            match &cli.output {
                Some(path) => write_out(path, &rendered),
                None => println!("{rendered}"),
            }
        }
    }

    if cli.strict && security_fails > 0 {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// Print the registry grouped by category, then exit.
fn list_checks() {
    let mut groups = checks::registry();
    groups.sort_by_key(|g| (g.category as u8, g.id));
    println!("macabre v{VERSION} — registered checks\n");
    for cat in model::Category::all() {
        let in_cat: Vec<_> = groups.iter().filter(|g| g.category == *cat).collect();
        if in_cat.is_empty() {
            continue;
        }
        println!("{} [{}]", cat.title(), cat.slug());
        for g in in_cat {
            let prof = match g.profile {
                Profile::Baseline => "baseline",
                Profile::Paranoia => "paranoia",
            };
            println!("  {:<28} {}", g.id, prof);
        }
        println!();
    }
}

fn write_out(path: &str, contents: &str) {
    match std::fs::write(path, contents) {
        Ok(()) => eprintln!("report written to {path}"),
        Err(e) => eprintln!("error: could not write {path}: {e}"),
    }
}
