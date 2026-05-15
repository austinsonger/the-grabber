use crate::client::TenableClient;
use crate::error::TenableError;
use crate::export::check_response;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasScanSummary {
    pub scan_id: String,
    pub name: Option<String>,
    pub application_uri: Option<String>,
    pub status: Option<String>,
    pub finalized_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasVulnerability {
    pub finding_id: String,
    pub plugin_id: Option<i64>,
    pub name: Option<String>,
    pub severity: Option<String>,
    pub url: Option<String>,
    pub remediation: Option<String>,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
}

pub struct WasApi<'c>(pub(crate) &'c TenableClient);

impl<'c> WasApi<'c> {
    /// List all WAS scans, paginating through all results.
    pub async fn list_scans(&self) -> Result<Vec<WasScanSummary>, TenableError> {
        #[derive(Deserialize)]
        struct Response {
            scans: Vec<WasScanSummary>,
        }
        const PAGE: usize = 100;
        let mut all: Vec<WasScanSummary> = Vec::new();
        let mut offset = 0usize;
        loop {
            let url = format!("/was/v2/scans?limit={}&offset={}", PAGE, offset);
            let resp = self.0.get(&url).await?;
            let resp = check_response(resp).await?;
            let page: Response = resp.json().await?;
            let got = page.scans.len();
            all.extend(page.scans);
            if got < PAGE {
                break;
            }
            offset += PAGE;
        }
        Ok(all)
    }

    /// List vulnerabilities for a specific WAS scan.
    pub async fn list_vulns(&self, scan_id: &str) -> Result<Vec<WasVulnerability>, TenableError> {
        let resp = self
            .0
            .get(&format!("/was/v2/scans/{}/vulnerabilities", scan_id))
            .await?;
        let resp = check_response(resp).await?;
        #[derive(Deserialize)]
        struct Response {
            vulnerabilities: Vec<WasVulnerability>,
        }
        Ok(resp.json::<Response>().await?.vulnerabilities)
    }
}
