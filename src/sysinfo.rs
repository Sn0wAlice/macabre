//! `macabre sysinfo` — a fast, read-only dump of the machine's real hardware.
//!
//! The point is verification: confirm a Mac actually has the chip, cores, RAM,
//! storage, and (crucially for a used laptop) the battery health a seller
//! claims. Everything comes from `sysctl`, `system_profiler`, and `df`; nothing
//! is changed.

use crate::sys;
use owo_colors::OwoColorize;
use serde::Serialize;
use std::collections::HashMap;

#[derive(Serialize, Default)]
pub struct SysInfo {
    model: String,
    model_id: String,
    chip: String,
    serial: String,
    hardware_uuid: String,
    cpu_cores: String,
    logical_cpus: String,
    memory: String,
    gpu: String,
    gpu_cores: String,
    storage_total: String,
    storage_free: String,
    storage_used_pct: String,
    os: String,
    uptime: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    battery: Option<Battery>,
}

#[derive(Serialize, Default)]
pub struct Battery {
    condition: String,
    max_capacity: String,
    cycle_count: String,
    charge: String,
    charging: String,
}

/// Entry point for `macabre sysinfo`. `json` selects machine-readable output.
pub fn run(json: bool) -> i32 {
    let info = gather();
    if json {
        println!("{}", serde_json::to_string_pretty(&info).unwrap_or_default());
    } else {
        render(&info);
    }
    0
}

fn gather() -> SysInfo {
    // One system_profiler call for the three datatypes we need (faster than 3).
    let sp = sys::run(
        "system_profiler",
        &["SPHardwareDataType", "SPPowerDataType", "SPDisplaysDataType"],
    )
    .unwrap_or_default();
    let sections = split_sections(&sp);
    let hw = sections.get("Hardware").map(String::as_str).unwrap_or("");
    let power = sections.get("Power").map(String::as_str).unwrap_or("");
    let gfx = sections
        .get("Graphics/Displays")
        .map(String::as_str)
        .unwrap_or("");

    let mut info = SysInfo {
        model: field(hw, "Model Name:").unwrap_or_else(|| "unknown".into()),
        model_id: sys::sysctl("hw.model")
            .or_else(|| field(hw, "Model Identifier:"))
            .unwrap_or_default(),
        chip: field(hw, "Chip:")
            .or_else(|| field(hw, "Processor Name:"))
            .or_else(|| sys::sysctl("machdep.cpu.brand_string"))
            .unwrap_or_else(|| "unknown".into()),
        serial: field(hw, "Serial Number (system):").unwrap_or_default(),
        hardware_uuid: field(hw, "Hardware UUID:").unwrap_or_default(),
        cpu_cores: cpu_cores(),
        logical_cpus: sys::sysctl("hw.logicalcpu").unwrap_or_default(),
        memory: sys::sysctl("hw.memsize")
            .and_then(|b| b.parse::<u64>().ok())
            .map(gib)
            .unwrap_or_else(|| "unknown".into()),
        gpu: field(gfx, "Chipset Model:").unwrap_or_else(|| "unknown".into()),
        gpu_cores: field(gfx, "Total Number of Cores:").unwrap_or_default(),
        os: sys::os_version(),
        uptime: uptime(),
        ..Default::default()
    };

    storage(&mut info);

    // Battery only meaningful on portables; SPPowerDataType has a cycle count there.
    if let Some(cc) = field(power, "Cycle Count:") {
        info.battery = Some(Battery {
            condition: field(power, "Condition:").unwrap_or_default(),
            max_capacity: field(power, "Maximum Capacity:").unwrap_or_default(),
            cycle_count: cc,
            charge: field(power, "State of Charge (%):").unwrap_or_default(),
            charging: field(power, "Charging:").unwrap_or_default(),
        });
    }

    info
}

/// Split `system_profiler` text into top-level sections keyed by their header
/// (a non-indented line ending in `:`), e.g. "Hardware", "Power".
fn split_sections(text: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let mut current: Option<String> = None;
    let mut buf = String::new();
    for line in text.lines() {
        let is_header = !line.starts_with(char::is_whitespace)
            && line.trim_end().ends_with(':')
            && !line.trim().is_empty();
        if is_header {
            if let Some(h) = current.take() {
                map.insert(h, std::mem::take(&mut buf));
            }
            current = Some(line.trim_end().trim_end_matches(':').to_string());
        } else if current.is_some() {
            buf.push_str(line);
            buf.push('\n');
        }
    }
    if let Some(h) = current {
        map.insert(h, buf);
    }
    map
}

/// Extract the value of the first `Label: value` line in `section`.
fn field(section: &str, label: &str) -> Option<String> {
    section
        .lines()
        .find_map(|l| l.trim().strip_prefix(label).map(|v| v.trim().to_string()))
        .filter(|v| !v.is_empty())
}

/// CPU core summary, e.g. "12 (8P + 4E)" on Apple Silicon, "8" otherwise.
fn cpu_cores() -> String {
    let phys = sys::sysctl("hw.physicalcpu").unwrap_or_default();
    let p = sys::sysctl("hw.perflevel0.physicalcpu");
    let e = sys::sysctl("hw.perflevel1.physicalcpu");
    match (p, e) {
        (Some(p), Some(e)) if !p.is_empty() && !e.is_empty() => format!("{phys} ({p}P + {e}E)"),
        _ => phys,
    }
}

/// Real free/total space of the data volume (decimal GB, matching marketing).
fn storage(info: &mut SysInfo) {
    let out = sys::run("df", &["-k", "/System/Volumes/Data"])
        .or_else(|| sys::run("df", &["-k", "/"]))
        .unwrap_or_default();
    if let Some(line) = out.lines().nth(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() >= 5 {
            let kb = |i: usize| cols[i].parse::<u64>().unwrap_or(0) * 1024;
            info.storage_total = gb(kb(1));
            info.storage_free = gb(kb(3));
            info.storage_used_pct = cols[4].to_string();
        }
    }
}

/// Uptime from `kern.boottime`, formatted "Nd Nh Nm".
fn uptime() -> String {
    let bt = match sys::sysctl("kern.boottime") {
        Some(s) => s,
        None => return String::new(),
    };
    // e.g. "{ sec = 1718000000, usec = 0 } ..."
    let boot = bt
        .split("sec = ")
        .nth(1)
        .and_then(|s| s.split(|c: char| !c.is_ascii_digit()).next())
        .and_then(|s| s.parse::<i64>().ok());
    let Some(boot) = boot else { return String::new() };
    let secs = (chrono::Local::now().timestamp() - boot).max(0);
    let (d, h, m) = (secs / 86400, (secs % 86400) / 3600, (secs % 3600) / 60);
    format!("{d}d {h}h {m}m")
}

/// Bytes → power-of-two GiB (for RAM, which comes in 8/16/32 sizes).
fn gib(bytes: u64) -> String {
    format!("{} GB", (bytes as f64 / 1024.0 / 1024.0 / 1024.0).round() as u64)
}

/// Bytes → decimal GB (for storage, advertised in decimal units).
fn gb(bytes: u64) -> String {
    let g = bytes as f64 / 1_000_000_000.0;
    if g >= 1000.0 {
        format!("{:.2} TB", g / 1000.0)
    } else {
        format!("{:.0} GB", g)
    }
}

fn render(i: &SysInfo) {
    let line = "═".repeat(64);
    println!("{}", line.bright_black());
    println!(
        "  {} {}  ·  {}",
        "macabre sysinfo".bold().bright_magenta(),
        format!("v{}", env!("CARGO_PKG_VERSION")).bright_black(),
        "hardware & resources".bright_black()
    );
    println!("{}", line.bright_black());

    let head = |t: &str| println!("\n  {}", t.bold().underline());
    let row = |k: &str, v: &str| {
        if !v.is_empty() {
            println!("  {:<16} {}", k.cyan(), v);
        }
    };

    head("Machine");
    row("Model", &i.model);
    row("Identifier", &i.model_id);
    row("Chip", &i.chip);
    row("Serial", &i.serial);
    row("Hardware UUID", &i.hardware_uuid);

    head("Compute");
    row("CPU cores", &i.cpu_cores);
    row("Logical CPUs", &i.logical_cpus);
    row("Memory", &i.memory);
    let gpu = if i.gpu_cores.is_empty() {
        i.gpu.clone()
    } else {
        format!("{} ({} cores)", i.gpu, i.gpu_cores)
    };
    row("GPU", &gpu);

    head("Storage");
    row("Total", &i.storage_total);
    row("Free", &i.storage_free);
    row("Used", &i.storage_used_pct);

    head("System");
    row("macOS", &i.os);
    row("Uptime", &i.uptime);

    if let Some(b) = &i.battery {
        head("Battery");
        // Colorize condition / capacity since they're the anti-scam signal.
        let cond = match b.condition.as_str() {
            "Normal" => b.condition.green().to_string(),
            "" => String::new(),
            _ => b.condition.yellow().to_string(),
        };
        row("Condition", &cond);
        row("Max capacity", &b.max_capacity);
        row("Cycle count", &b.cycle_count);
        row("Charge", &b.charge);
        row("Charging", &b.charging);
    }

    if !i.serial.is_empty() {
        println!(
            "\n  {} verify coverage at {}",
            "tip:".bright_black(),
            "https://checkcoverage.apple.com".blue()
        );
    }
    println!("{}", line.bright_black());
}
