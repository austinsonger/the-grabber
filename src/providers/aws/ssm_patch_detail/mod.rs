mod maintenance_window;
mod patch_detail;
mod patch_execution;
mod patch_summary;

pub use maintenance_window::SsmMaintenanceWindowCollector;
pub use patch_detail::SsmPatchDetailCollector;
pub use patch_execution::SsmPatchExecutionCollector;
pub use patch_summary::SsmPatchSummaryCollector;

pub(super) fn epoch_to_rfc3339(secs: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(secs, 0)
        .map(|c| c.to_rfc3339())
        .unwrap_or_default()
}
