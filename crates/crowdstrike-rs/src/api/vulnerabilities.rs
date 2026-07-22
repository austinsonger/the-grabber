use serde::Deserialize;

use crate::client::CrowdStrikeClient;
use crate::error::CrowdStrikeError;
use crate::types::vulnerability::Vulnerability;

pub struct VulnerabilitiesApi<'c>(pub(crate) &'c CrowdStrikeClient);

#[derive(Debug, Deserialize, Default)]
struct Pagination {
    #[serde(default)]
    after: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct Meta {
    #[serde(default)]
    pagination: Pagination,
}

#[derive(Debug, Deserialize)]
struct VulnResponse {
    #[serde(default)]
    resources: Vec<Vulnerability>,
    #[serde(default)]
    meta: Meta,
}

impl<'c> VulnerabilitiesApi<'c> {
    /// GET /spotlight/combined/vulnerabilities/v1 — Spotlight vulnerability
    /// findings, `after`-cursor paginated (max `limit` 5000 per Falcon docs;
    /// 400 is used here to keep individual pages small and retry-friendly).
    pub async fn list_all(&self) -> Result<Vec<Vulnerability>, CrowdStrikeError> {
        let mut all = Vec::new();
        let mut after: Option<String> = None;
        loop {
            let mut path = "/spotlight/combined/vulnerabilities/v1?limit=400".to_string();
            if let Some(ref a) = after {
                path.push_str(&format!("&after={a}"));
            }
            let resp = self.0.get(&path).await?;
            if !resp.status().is_success() {
                let status = resp.status().as_u16();
                let message = resp.text().await.unwrap_or_default();
                return Err(CrowdStrikeError::Api { status, message });
            }
            let page: VulnResponse = resp.json().await?;
            let is_empty = page.resources.is_empty();
            all.extend(page.resources);
            after = page.meta.pagination.after.filter(|a| !a.is_empty());
            if after.is_none() || is_empty {
                break;
            }
        }
        Ok(all)
    }
}
