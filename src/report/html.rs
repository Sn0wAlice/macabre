//! Self-contained HTML report (inline CSS, no external assets).

use crate::model::{Category, Finding, Report, Status};
use std::fmt::Write;

pub fn render(report: &Report) -> String {
    let mut s = String::new();
    let sc = &report.security;
    let _ = write!(
        s,
        r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>macabre report — {host}</title>
<style>
:root {{ color-scheme: dark; }}
* {{ box-sizing: border-box; }}
body {{ margin:0; font:15px/1.5 -apple-system,BlinkMacSystemFont,system-ui,sans-serif;
  background:#0c0d10; color:#e6e7ea; padding:2rem; }}
.wrap {{ max-width:900px; margin:0 auto; }}
h1 {{ font-size:1.5rem; margin:0 0 .25rem; }}
.meta {{ color:#9aa0aa; font-size:.85rem; margin-bottom:1.5rem; }}
.score {{ display:flex; align-items:center; gap:1.5rem; background:#14161b;
  border:1px solid #23262e; border-radius:12px; padding:1.25rem 1.5rem; margin-bottom:1.5rem; }}
.idx {{ font-size:3rem; font-weight:700; line-height:1; }}
.tally span {{ display:inline-block; margin-right:1rem; font-size:.85rem; }}
.bar {{ height:8px; border-radius:4px; background:#23262e; overflow:hidden; flex:1; }}
.bar > i {{ display:block; height:100%; background:linear-gradient(90deg,#e0563f,#e0a93f,#3fae6a); }}
h2 {{ font-size:1.05rem; margin:1.75rem 0 .5rem; border-bottom:1px solid #23262e; padding-bottom:.35rem; }}
.f {{ background:#14161b; border:1px solid #23262e; border-left-width:4px;
  border-radius:8px; padding:.9rem 1.1rem; margin:.6rem 0; }}
.f.pass {{ border-left-color:#3fae6a; }} .f.warn {{ border-left-color:#e0a93f; }}
.f.fail {{ border-left-color:#e0563f; }} .f.skip,.f.info {{ border-left-color:#5a6072; }}
.f h3 {{ margin:0 0 .35rem; font-size:1rem; }}
.tag {{ font-size:.7rem; text-transform:uppercase; letter-spacing:.04em; padding:.1rem .45rem;
  border-radius:4px; background:#23262e; color:#c2c6cf; margin-left:.5rem; }}
.why {{ color:#9aa0aa; font-size:.88rem; margin:.35rem 0; }}
code,pre {{ background:#0c0d10; border:1px solid #23262e; border-radius:6px;
  padding:.15rem .4rem; font-size:.82rem; }}
pre {{ padding:.7rem .9rem; overflow-x:auto; }}
a {{ color:#6ea8fe; }}
</style></head><body><div class="wrap">
<h1>macabre — macOS hardening report</h1>
<div class="meta">{host} · {os} · {generated} · {tool} v{version}</div>
<div class="score">
  <div class="idx">{idx}<span style="font-size:1rem;color:#9aa0aa">/100</span></div>
  <div style="flex:1">
    <div class="bar"><i style="width:{idx}%"></i></div>
    <div class="tally" style="margin-top:.6rem">
      <span style="color:#3fae6a">✔ {passed} pass</span>
      <span style="color:#e0a93f">▲ {warned} warn</span>
      <span style="color:#e0563f">✘ {failed} fail</span>
      <span style="color:#9aa0aa">⏭ {skipped} skip</span>
    </div>
  </div>
</div>
"#,
        host = esc(&report.hostname),
        os = esc(&report.os_version),
        generated = esc(&report.generated_at),
        tool = report.tool,
        version = report.version,
        idx = sc.index,
        passed = sc.passed,
        warned = sc.warned,
        failed = sc.failed,
        skipped = sc.skipped,
    );

    if let Some(p) = &report.privacy {
        let _ = write!(
            s,
            r#"<div class="score">
  <div class="idx">{idx}<span style="font-size:1rem;color:#9aa0aa">/100</span></div>
  <div style="flex:1">
    <div style="font-size:.8rem;color:#9aa0aa;margin-bottom:.4rem">Privacy index (anti-telemetry)</div>
    <div class="bar"><i style="width:{idx}%"></i></div>
    <div class="tally" style="margin-top:.6rem">
      <span style="color:#3fae6a">✔ {passed} hardened</span>
      <span style="color:#e0a93f">▲ {warned} exposed</span>
      <span style="color:#9aa0aa">⏭ {skipped} n/a</span>
    </div>
  </div>
</div>
"#,
            idx = p.index,
            passed = p.passed,
            warned = p.warned,
            skipped = p.skipped,
        );
    }

    for cat in Category::all() {
        let items: Vec<_> = report.findings.iter().filter(|f| f.category == *cat).collect();
        if items.is_empty() {
            continue;
        }
        let _ = write!(s, "<h2>{}</h2>\n", esc(cat.title()));
        for f in items {
            render_finding(&mut s, f);
        }
    }

    let _ = write!(s, "</div></body></html>\n");
    s
}

fn render_finding(s: &mut String, f: &Finding) {
    let cls = match f.status {
        Status::Pass => "pass",
        Status::Warn => "warn",
        Status::Fail => "fail",
        Status::Skip => "skip",
        Status::Info => "info",
    };
    let _ = write!(
        s,
        r#"<div class="f {cls}"><h3>{title}<span class="tag">{status}</span><span class="tag">{sev}</span></h3>"#,
        title = esc(&f.title),
        status = f.status.label(),
        sev = f.severity.label(),
    );
    let _ = write!(s, "<div>{}</div>", esc(&f.detail));
    if !f.rationale.is_empty() {
        let _ = write!(s, r#"<div class="why">{}</div>"#, esc(&f.rationale));
    }
    if let Some(r) = &f.remediation {
        let _ = write!(s, "<pre>{}</pre>", esc(r));
    }
    if let Some(r) = &f.reference {
        let _ = write!(s, r#"<div class="why"><a href="{u}">{u}</a></div>"#, u = esc(r));
    }
    let _ = write!(s, "</div>\n");
}

/// Minimal HTML entity escaping for untrusted command output.
fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
