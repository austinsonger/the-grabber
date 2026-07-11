pub mod assets;
pub mod audit_log;
pub mod compliance;
pub mod scans;
pub mod users;
pub mod vulns;
pub mod was;

pub use assets::AssetsApi;
pub use audit_log::AuditLogApi;
pub use compliance::ComplianceApi;
pub use scans::ScansApi;
pub use users::UsersApi;
pub use vulns::VulnsApi;
pub use was::WasApi;

/// Build the request body for a bulk export call.
///
/// Wraps filters in the `{"filters": ...}` envelope Tenable expects,
/// or returns an empty object when no filters are provided.
pub(crate) fn export_body(filters: Option<serde_json::Value>) -> serde_json::Value {
    filters
        .map(|f| serde_json::json!({ "filters": f }))
        .unwrap_or_else(|| serde_json::json!({}))
}
