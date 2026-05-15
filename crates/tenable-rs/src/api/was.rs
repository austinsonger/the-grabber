use crate::api::export_body;
use crate::client::TenableClient;
use crate::error::TenableError;
use crate::export::{check_response, ExportJob};
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

/// A single WAS finding from the v1 bulk export API.
/// Matches the chunk schema at /was/v1/export/vulns/{uuid}/chunks/{id}.
#[derive(Debug, Clone, Deserialize)]
pub struct WasFinding {
    pub finding_id: String,
    pub url: Option<String>,
    pub state: Option<String>,
    pub severity: Option<String>,
    pub severity_id: Option<i32>,
    pub first_found: Option<String>,
    pub last_found: Option<String>,
    pub indexed_at: Option<String>,
    pub output: Option<String>,
    pub proof: Option<String>,
    pub payload: Option<String>,
    pub http_method: Option<String>,
    pub input_type: Option<String>,
    pub input_name: Option<String>,
    pub plugin: Option<WasPlugin>,
    pub scan: Option<WasScanRef>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WasPlugin {
    pub id: Option<i64>,
    pub name: Option<String>,
    pub risk_factor: Option<String>,
    pub cvss_base_score: Option<f64>,
    pub cvss3_base_score: Option<f64>,
    pub vpr_score: Option<f64>,
    pub cve: Option<Vec<String>>,
    pub description: Option<String>,
    pub solution: Option<String>,
    pub synopsis: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WasScanRef {
    pub scan_id: Option<String>,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
}

pub struct WasApi<'c>(pub(crate) &'c TenableClient);

impl<'c> WasApi<'c> {
    /// List all WAS scans by enumerating configs then fetching scans per config.
    ///
    /// The WAS v2 API has no flat scan-list endpoint. Scans belong to configs
    /// (scan configurations). We POST to configs/search to enumerate all configs,
    /// then POST to each config's scans/search endpoint. Both steps paginate via
    /// limit/offset and are made fail-safe (errors skip rather than abort).
    pub async fn list_scans(&self) -> Result<Vec<WasScanSummary>, TenableError> {
        #[derive(Deserialize)]
        struct ConfigPage {
            pagination: PaginationMeta,
            items: Vec<ConfigItem>,
        }
        #[derive(Deserialize)]
        struct PaginationMeta {
            total: usize,
        }
        #[derive(Deserialize)]
        struct ConfigItem {
            config_id: String,
        }
        #[derive(Deserialize)]
        struct ScanPage {
            items: Vec<WasScanSummary>,
        }

        const PAGE: usize = 100;
        let mut all_configs: Vec<String> = Vec::new();

        // Paginate through all configs.
        let mut offset = 0usize;
        loop {
            let url = format!("/was/v2/configs/search?limit={}&offset={}", PAGE, offset);
            let resp = match self.0.post(&url, &serde_json::json!({})).await {
                Ok(r) => r,
                Err(_) => break,
            };
            let resp = match check_response(resp).await {
                Ok(r) => r,
                Err(_) => break,
            };
            let page: ConfigPage = match resp.json().await {
                Ok(p) => p,
                Err(_) => break,
            };
            let got = page.items.len();
            let total = page.pagination.total;
            all_configs.extend(page.items.into_iter().map(|c| c.config_id));
            if got < PAGE || all_configs.len() >= total {
                break;
            }
            offset += PAGE;
        }

        // For each config, paginate through its scans and deduplicate by scan_id.
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut all: Vec<WasScanSummary> = Vec::new();

        for config_id in &all_configs {
            let mut scan_offset = 0usize;
            loop {
                let url = format!(
                    "/was/v2/configs/{}/scans/search?limit={}&offset={}",
                    config_id, PAGE, scan_offset
                );
                let resp = match self.0.post(&url, &serde_json::json!({})).await {
                    Ok(r) => r,
                    Err(_) => break,
                };
                let resp = match check_response(resp).await {
                    Ok(r) => r,
                    Err(_) => break,
                };
                let page: ScanPage = match resp.json().await {
                    Ok(p) => p,
                    Err(_) => break,
                };
                let got = page.items.len();
                for scan in page.items {
                    if seen.insert(scan.scan_id.clone()) {
                        all.push(scan);
                    }
                }
                if got < PAGE {
                    break;
                }
                scan_offset += PAGE;
            }
        }

        Ok(all)
    }

    /// Bulk-export all WAS findings using the v1 export API.
    ///
    /// Follows the same ExportJob<T> protocol as VM vulns:
    ///   POST /was/v1/export/vulns → poll status → download chunks.
    /// Pass `None` to export all findings with no filter.
    pub async fn export(
        &self,
        filters: Option<serde_json::Value>,
    ) -> Result<ExportJob<WasFinding>, TenableError> {
        let body = export_body(filters);
        self.0
            .start_export("/was/v1/export/vulns", "/was/v1/export/vulns", &body)
            .await
    }

    /// Convenience: trigger a WAS export and collect all findings in one call.
    pub async fn export_all(
        &self,
        filters: Option<serde_json::Value>,
    ) -> Result<Vec<WasFinding>, TenableError> {
        self.export(filters).await?.collect_all().await
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
