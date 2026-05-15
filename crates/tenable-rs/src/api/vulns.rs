use crate::api::export_body;
use crate::client::TenableClient;
use crate::error::TenableError;
use crate::export::ExportJob;
use crate::types::vulnerability::VulnFinding;

pub struct VulnsApi<'c>(pub(crate) &'c TenableClient);

impl<'c> VulnsApi<'c> {
    /// Start a vulnerability export.
    ///
    /// `filters` is an optional JSON object following the Tenable export filter schema.
    /// Pass `None` to export all vulnerabilities.
    pub async fn export(
        &self,
        filters: Option<serde_json::Value>,
    ) -> Result<ExportJob<VulnFinding>, TenableError> {
        let body = export_body(filters);
        self.0
            .start_export("/vulns/export", "/vulns/export", &body)
            .await
    }

    /// Convenience: start an export and collect all records in one call.
    pub async fn export_all(
        &self,
        filters: Option<serde_json::Value>,
    ) -> Result<Vec<VulnFinding>, TenableError> {
        self.export(filters).await?.collect_all().await
    }
}
