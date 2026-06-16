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
mod diff;
mod model;
mod report;
mod sys;
mod sysinfo;
mod tui;

use clap::{Parser, Subcommand, ValueEnum};
use model::{Class, Profile, Report, Score, Status};
use report::Format;
use std::process::ExitCode;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser, Debug)]
#[command(
    name = "macabre",
    version = VERSION,
    about = "macOS hardening & security audit scanner (read-only)",
    disable_help_subcommand = true
)]
struct Cli {
    /// Output format. Defaults to a colored terminal report.
    #[arg(short, long, value_enum, default_value_t = OutFormat::Term, global = true)]
    format: OutFormat,

    /// Write the report to a file instead of stdout.
    #[arg(short, long, value_name = "PATH")]
    output: Option<String>,

    /// Show rationale, remediation, and references for every finding (terminal).
    #[arg(short, long, global = true)]
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

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Compare two saved JSON reports (`macabre -f json -o …`) over time.
    Diff {
        /// Earlier report.
        old: String,
        /// Later report.
        new: String,
    },
    /// Live full-screen dashboard (re-runs the scan interactively).
    Tui,
    /// Dump hardware & resources (chip, cores, RAM, storage, battery health).
    Sysinfo,
    /// Show a full overview of commands, options, profiles, and examples.
    Help,
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
    let profile = if cli.paranoia { Profile::Paranoia } else { Profile::Baseline };

    match &cli.command {
        Some(Command::Diff { old, new }) => {
            return ExitCode::from(diff::run(old, new, cli.verbose) as u8);
        }
        Some(Command::Tui) => {
            return match tui::run(profile) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("tui error: {e}");
                    ExitCode::FAILURE
                }
            };
        }
        Some(Command::Sysinfo) => {
            return ExitCode::from(sysinfo::run(cli.format == OutFormat::Json) as u8);
        }
        Some(Command::Help) => {
            print_help();
            return ExitCode::SUCCESS;
        }
        None => {}
    }

    if cli.list {
        list_checks();
        return ExitCode::SUCCESS;
    }

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

/// Rich, colored overview of everything macabre can do.
fn print_help() {
    use owo_colors::OwoColorize;

    let n = checks::registry().len();
    let cats = model::Category::all().len();

    println!("{}", "═".repeat(64).bright_black());
    println!(
        "  {} {}  ·  {}",
        "macabre".bold().bright_magenta(),
        format!("v{VERSION}").bright_black(),
        "macOS hardening & security audit scanner".bright_black()
    );
    println!(
        "  {}",
        format!("{n} check groups across {cats} categories · read-only, never changes anything")
            .bright_black()
    );
    println!("{}", "═".repeat(64).bright_black());

    let head = |t: &str| println!("\n{}", t.bold().underline());
    let item = |k: &str, d: &str| println!("  {:<24} {}", k.cyan(), d);

    head("USAGE");
    println!("  {}", "macabre [OPTIONS] [COMMAND]".bright_yellow());

    head("COMMANDS");
    item("(default)", "Run the audit and print a colored terminal report");
    item("tui", "Live full-screen dashboard (auto-refreshing)");
    item("sysinfo", "Dump hardware & resources (specs, battery health)");
    item("diff <old> <new>", "Compare two saved JSON reports over time");
    item("help", "Show this overview");

    head("SCAN OPTIONS");
    item("-p, --paranoia", "Deep scan: + privacy/anti-telemetry + inventory");
    item("-f, --format <FMT>", "term (default), json, md, html");
    item("-o, --output <PATH>", "Write the report to a file");
    item("-v, --verbose", "Show rationale, remediation, and references");
    item("    --only <CATS>", "Only run these categories/ids (comma-separated)");
    item("    --skip <CATS>", "Skip these categories/ids (comma-separated)");
    item("    --list", "List every registered check and exit");
    item("    --strict", "Exit non-zero if any *security* check FAILs (CI)");
    item("    --help / --version", "Standard clap help / version");

    head("PROFILES");
    item("baseline", "Security posture (default)");
    item("paranoia", "Baseline + privacy/anti-telemetry + deep inventory");

    head("SCORING");
    println!("  Two indices, severity-weighted: {} (always) and {} (paranoia).",
        "Security".green(), "Privacy".magenta());

    head("EXAMPLES");
    let ex = |c: &str, d: &str| println!("  {:<34} {}", c.bright_yellow(), format!("# {d}").bright_black());
    ex("macabre", "baseline terminal report");
    ex("sudo macabre --paranoia -v", "full deep scan, verbose, as root");
    ex("macabre --only firewall,privacy", "just these categories");
    ex("macabre -f json -o today.json", "save a snapshot");
    ex("macabre diff old.json today.json", "see what changed");
    ex("macabre tui --paranoia", "live dashboard");
    ex("macabre --list", "see all checks");

    println!("\n  {} {}", "repo:".bright_black(), "https://github.com/Sn0wAlice/macabre".blue());
    println!("{}", "═".repeat(64).bright_black());
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
