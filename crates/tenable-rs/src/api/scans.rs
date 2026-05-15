use crate::client::TenableClient;
use crate::error::TenableError;
use crate::export::check_response;
use crate::types::scan::{ScanDetails, ScanSummary};

pub struct ScansApi<'c>(pub(crate) &'c TenableClient);

#[derive(serde::Deserialize)]
struct FolderEntry {
    id: i64,
    #[serde(rename = "type")]
    kind: String,
}

impl<'c> ScansApi<'c> {
    /// List all scans across every non-trash folder.
    ///
    /// The `/scans` endpoint without a `folder_id` returns only the "My Scans"
    /// folder.  To surface scans from custom and shared folders we enumerate
    /// all folders first, then fetch each one and deduplicate by scan ID.
    pub async fn list(&self) -> Result<Vec<ScanSummary>, TenableError> {
        #[derive(serde::Deserialize)]
        struct FolderList {
            folders: Vec<FolderEntry>,
        }
        #[derive(serde::Deserialize)]
        struct ScanList {
            scans: Option<Vec<ScanSummary>>,
        }

        // Get all folders.
        let resp = self.0.get("/scans/folders").await?;
        let resp = check_response(resp).await?;
        let folder_list: FolderList = resp.json().await?;

        let mut seen: std::collections::HashSet<i64> = std::collections::HashSet::new();
        let mut all: Vec<ScanSummary> = Vec::new();

        for folder in &folder_list.folders {
            if folder.kind == "trash" {
                continue;
            }
            let url = format!("/scans?folder_id={}", folder.id);
            let resp = match self.0.get(&url).await {
                Ok(r) => r,
                Err(_) => continue,
            };
            let resp = match check_response(resp).await {
                Ok(r) => r,
                Err(_) => continue,
            };
            let page: ScanList = match resp.json().await {
                Ok(p) => p,
                Err(_) => continue,
            };
            for scan in page.scans.unwrap_or_default() {
                if seen.insert(scan.id) {
                    all.push(scan);
                }
            }
        }

        // Fall back to the default endpoint if no folders were returned.
        if all.is_empty() {
            let resp = self.0.get("/scans").await?;
            let resp = check_response(resp).await?;
            #[derive(serde::Deserialize)]
            struct DefaultList {
                scans: Option<Vec<ScanSummary>>,
            }
            let body: DefaultList = resp.json().await?;
            all = body.scans.unwrap_or_default();
        }

        Ok(all)
    }

    /// Get full details for a specific scan by ID.
    pub async fn details(&self, scan_id: i64) -> Result<ScanDetails, TenableError> {
        let resp = self.0.get(&format!("/scans/{}", scan_id)).await?;
        let resp = check_response(resp).await?;
        Ok(resp.json().await?)
    }
}
