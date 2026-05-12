use crate::api::export_body;
use crate::client::TenableClient;
use crate::error::TenableError;
use crate::export::ExportJob;
use crate::types::compliance::ComplianceFinding;

pub struct ComplianceApi<'c>(pub(crate) &'c TenableClient);

impl<'c> ComplianceApi<'c> {
    /// Start a compliance findings export.
    pub async fn export(
        &self,
        filters: Option<serde_json::Value>,
    ) -> Result<ExportJob<ComplianceFinding>, TenableError> {
        let body = export_body(filters);
        self.0.start_export("/compliance/export", "/compliance/export", &body).await
    }

    /// Convenience: start an export and collect all records in one call.
    pub async fn export_all(
        &self,
        filters: Option<serde_json::Value>,
    ) -> Result<Vec<ComplianceFinding>, TenableError> {
        self.export(filters).await?.collect_all().await
    }
}

