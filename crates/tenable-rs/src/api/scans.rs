use crate::client::TenableClient;
use crate::error::TenableError;
use crate::export::check_response;
use crate::types::scan::{ScanDetails, ScanSummary};

pub struct ScansApi<'c>(pub(crate) &'c TenableClient);

impl<'c> ScansApi<'c> {
    /// List all scans (summary view).
    pub async fn list(&self) -> Result<Vec<ScanSummary>, TenableError> {
        let resp = self.0.get("/scans").await?;
        let resp = check_response(resp).await?;
        #[derive(serde::Deserialize)]
        struct ListResponse {
            scans: Vec<ScanSummary>,
        }
        let body: ListResponse = resp.json().await?;
        Ok(body.scans)
    }

    /// Get full details for a specific scan by ID.
    pub async fn details(&self, scan_id: i64) -> Result<ScanDetails, TenableError> {
        let resp = self.0.get(&format!("/scans/{}", scan_id)).await?;
        let resp = check_response(resp).await?;
        Ok(resp.json().await?)
    }
}
