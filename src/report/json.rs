//! JSON output. The `Report` model derives `Serialize`, so this is a direct
//! pretty-print — suitable for piping into monitoring or diffing over time.

use crate::model::Report;

pub fn render(report: &Report) -> String {
    serde_json::to_string_pretty(report)
        .unwrap_or_else(|e| format!("{{\"error\":\"serialization failed: {e}\"}}"))
}
