//! Markdown report — shareable/archivable, grouped by category.

use crate::model::{Category, Report, Status};
use std::fmt::Write;

pub fn render(report: &Report) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "# macabre — macOS hardening report\n");
    let _ = writeln!(s, "- **Host:** {}", report.hostname);
    let _ = writeln!(s, "- **OS:** {}", report.os_version);
    let _ = writeln!(s, "- **Generated:** {}", report.generated_at);
    let _ = writeln!(s, "- **Tool:** {} v{}\n", report.tool, report.version);

    let sc = &report.score;
    let _ = writeln!(s, "## Hardening index: {}/100\n", sc.index);
    let _ = writeln!(
        s,
        "| Pass | Warn | Fail | Skip | Info |\n|---|---|---|---|---|\n| {} | {} | {} | {} | {} |\n",
        sc.passed, sc.warned, sc.failed, sc.skipped, sc.info
    );

    for cat in Category::all() {
        let items: Vec<_> = report.findings.iter().filter(|f| f.category == *cat).collect();
        if items.is_empty() {
            continue;
        }
        let _ = writeln!(s, "## {}\n", cat.title());
        for f in items {
            let _ = writeln!(s, "### {} {}", status_icon(f.status), f.title);
            let _ = writeln!(
                s,
                "- **Status:** {} · **Severity:** {} · `{}`",
                f.status.label(),
                f.severity.label(),
                f.id
            );
            let _ = writeln!(s, "- **Detail:** {}", f.detail);
            if !f.rationale.is_empty() {
                let _ = writeln!(s, "- **Why:** {}", f.rationale);
            }
            if let Some(r) = &f.remediation {
                let _ = writeln!(s, "- **Fix:**\n  ```sh\n  {r}\n  ```");
            }
            if let Some(r) = &f.reference {
                let _ = writeln!(s, "- **Reference:** {r}");
            }
            let _ = writeln!(s);
        }
    }
    s
}

fn status_icon(status: Status) -> &'static str {
    match status {
        Status::Pass => "✅",
        Status::Warn => "⚠️",
        Status::Fail => "❌",
        Status::Info => "ℹ️",
        Status::Skip => "⏭️",
    }
}
