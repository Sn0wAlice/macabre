//! macabre — a read-only macOS hardening & security audit scanner.
//!
//! Runs a suite of checks against local security settings, scores the host with
//! a weighted "hardening index", and reports findings to the terminal or to
//! JSON / Markdown / HTML. It only inspects state — it never changes anything;
//! failing checks include the command you'd run to fix them.

mod checks;
mod model;
mod report;
mod sys;

use clap::{Parser, ValueEnum};
use model::{Report, Score};
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

    /// Exit non-zero if any check fails (useful in CI / monitoring).
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

    let findings = checks::run_all();
    let score = Score::compute(&findings);
    let failed = score.failed;

    let report = Report {
        tool: "macabre",
        version: VERSION,
        generated_at: chrono::Local::now().format("%Y-%m-%d %H:%M:%S %z").to_string(),
        hostname: sys::hostname(),
        os_version: sys::os_version(),
        score,
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

    if cli.strict && failed > 0 {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn write_out(path: &str, contents: &str) {
    match std::fs::write(path, contents) {
        Ok(()) => eprintln!("report written to {path}"),
        Err(e) => eprintln!("error: could not write {path}: {e}"),
    }
}
