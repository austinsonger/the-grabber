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
    /// Tries folder-based enumeration first (surfaces custom/shared folders).
    /// Falls back to the bare `/scans` endpoint (returns "My Scans") if the
    /// folders API is unavailable or returns nothing.
    pub async fn list(&self) -> Result<Vec<ScanSummary>, TenableError> {
        if let Ok(scans) = self.list_from_all_folders().await {
            if !scans.is_empty() {
                return Ok(scans);
            }
        }

        // Fallback: bare /scans returns the "My Scans" folder.
        #[derive(serde::Deserialize)]
        struct DefaultList {
            scans: Option<Vec<ScanSummary>>,
        }
        let resp = self.0.get("/scans").await?;
        let resp = check_response(resp).await?;
        let body: DefaultList = resp.json().await?;
        Ok(body.scans.unwrap_or_default())
    }

    async fn list_from_all_folders(&self) -> Result<Vec<ScanSummary>, TenableError> {
        #[derive(serde::Deserialize)]
        struct FolderList {
            folders: Vec<FolderEntry>,
        }
        #[derive(serde::Deserialize)]
        struct ScanList {
            scans: Option<Vec<ScanSummary>>,
        }

        let resp = self.0.get("/folders").await?;
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

        Ok(all)
    }

    /// Get full details for a specific scan by ID.
    pub async fn details(&self, scan_id: i64) -> Result<ScanDetails, TenableError> {
        let resp = self.0.get(&format!("/scans/{}", scan_id)).await?;
        let resp = check_response(resp).await?;
        Ok(resp.json().await?)
    }
}
