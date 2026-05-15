use tenable_rs::api::was::WasScanSummary;
use tenable_rs::types::scan::ScanSummary;

#[cfg_attr(not(feature = "tenable"), allow(dead_code))]
pub enum TuiScan {
    Vm(ScanSummary),
    Was(WasScanSummary),
}

impl TuiScan {
    pub fn display_name(&self) -> &str {
        match self {
            TuiScan::Vm(s) => &s.name,
            TuiScan::Was(s) => s.name.as_deref().unwrap_or("<unnamed>"),
        }
    }

    pub fn kind_label(&self) -> &str {
        match self {
            TuiScan::Vm(_) => "VM",
            TuiScan::Was(_) => "WAS",
        }
    }

    pub fn status_str(&self) -> &str {
        match self {
            TuiScan::Vm(s) => s.status.as_str(),
            TuiScan::Was(s) => s.status.as_deref().unwrap_or("unknown"),
        }
    }

    /// "running" | "completed" | "canceled" | "other" — used by the UI for colour selection.
    pub fn status_color_hint(&self) -> &str {
        match self.status_str().to_ascii_lowercase().as_str() {
            "running" => "running",
            "completed" => "completed",
            "canceled" | "cancelled" | "empty" => "canceled",
            _ => "other",
        }
    }

    /// Unix timestamp for time-based filtering.
    /// VM: last_modification_date (already i64).
    /// WAS: finalized_at parsed from RFC-3339.
    pub fn last_modified_timestamp(&self) -> Option<i64> {
        match self {
            // Treat 0 (Unix epoch) as absent — scans that have never run report 0.
            TuiScan::Vm(s) => s.last_modification_date.filter(|&ts| ts > 0),
            TuiScan::Was(s) => s.finalized_at.as_deref().and_then(|t| {
                chrono::DateTime::parse_from_rfc3339(t)
                    .ok()
                    .map(|dt| dt.timestamp())
            }),
        }
    }

    /// Human-readable date string for display (YYYY-MM-DD), or empty.
    pub fn date_str(&self) -> String {
        self.last_modified_timestamp()
            .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0))
            .map(|dt| dt.format("%Y-%m-%d").to_string())
            .unwrap_or_default()
    }

    pub fn vm_id(&self) -> Option<i64> {
        match self {
            TuiScan::Vm(s) => Some(s.id),
            TuiScan::Was(_) => None,
        }
    }

    pub fn is_vm(&self) -> bool {
        matches!(self, TuiScan::Vm(_))
    }

    pub fn is_was(&self) -> bool {
        matches!(self, TuiScan::Was(_))
    }
}
