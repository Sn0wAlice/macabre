//! Thin wrappers around system commands used by checks.
//!
//! Everything here is strictly read-only: we shell out to inspection tools
//! (`defaults`, `csrutil`, `fdesetup`, `system_profiler`, ...) and never mutate
//! system state.

use std::process::Command;

/// Run a command and return trimmed stdout on success.
///
/// Returns `None` if the binary is missing or exits non-zero. We deliberately
/// swallow stderr details here; checks decide what a missing result means.
pub fn run(cmd: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(cmd).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Like [`run`] but also returns output when the command exits non-zero.
///
/// Some tools (e.g. `socketfilterfw`) return non-zero while still printing the
/// state we want to parse.
pub fn run_lossy(cmd: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(cmd).args(args).output().ok()?;
    let mut s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        s = String::from_utf8_lossy(&out.stderr).trim().to_string();
    }
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// Read a `defaults` value from a (optionally global) domain.
pub fn defaults_read(domain: &str, key: &str) -> Option<String> {
    run("defaults", &["read", domain, key])
}

/// Read a `defaults` value from an app by bundle/app name (`defaults read -app`).
pub fn defaults_read_app(app: &str, key: &str) -> Option<String> {
    run("defaults", &["read", "-app", app, key])
}

/// Whether the current process is running as root (euid 0).
///
/// Cached: the euid can't change during a run, and several checks consult it.
pub fn is_root() -> bool {
    use std::sync::OnceLock;
    static ROOT: OnceLock<bool> = OnceLock::new();
    *ROOT.get_or_init(|| run("id", &["-u"]).as_deref() == Some("0"))
}

/// Whether a process whose command line contains `needle` is running.
pub fn process_running(needle: &str) -> bool {
    run("pgrep", &["-f", needle]).is_some()
}

/// List `.plist`-ish entries in a directory (file names only). Empty if the
/// directory is missing or unreadable.
pub fn list_dir(path: &str) -> Vec<String> {
    match std::fs::read_dir(path) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().into_string().ok())
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// Current hostname.
pub fn hostname() -> String {
    run("scutil", &["--get", "ComputerName"])
        .or_else(|| run("hostname", &[]))
        .unwrap_or_else(|| "unknown".to_string())
}

/// macOS product + build version, e.g. "macOS 26.5.1 (25F80)".
pub fn os_version() -> String {
    let product = run("sw_vers", &["-productVersion"]).unwrap_or_default();
    let build = run("sw_vers", &["-buildVersion"]).unwrap_or_default();
    if product.is_empty() {
        "unknown".to_string()
    } else if build.is_empty() {
        format!("macOS {product}")
    } else {
        format!("macOS {product} ({build})")
    }
}
