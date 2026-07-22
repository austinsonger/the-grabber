use serde::Deserialize;
use serde_json::json;

use crate::client::CrowdStrikeClient;
use crate::error::CrowdStrikeError;
use crate::types::alert::Alert;

pub struct AlertsApi<'c>(pub(crate) &'c CrowdStrikeClient);

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
struct AlertsResponse {
    #[serde(default)]
    resources: Vec<Alert>,
    #[serde(default)]
    meta: Meta,
}

impl<'c> AlertsApi<'c> {
    /// POST /alerts/combined/alerts/v1 — detections + incidents (CrowdStrike's
    /// unified Alerts collection), filtered by `created_timestamp` between
    /// `since` and `until` (both RFC3339), `after`-cursor paginated.
    pub async fn list_all(&self, since: &str, until: &str) -> Result<Vec<Alert>, CrowdStrikeError> {
        let filter = format!("created_timestamp:['{since}'+TO+'{until}']");
        let mut all = Vec::new();
        let mut after: Option<String> = None;
        loop {
            let mut body = json!({
                "filter": filter,
                "limit": 1000,
                "sort": "created_timestamp|asc",
            });
            if let Some(ref a) = after {
                body["after"] = json!(a);
            }
            let resp = self
                .0
                .post_json("/alerts/combined/alerts/v1", &body)
                .await?;
            if !resp.status().is_success() {
                let status = resp.status().as_u16();
                let message = resp.text().await.unwrap_or_default();
                return Err(CrowdStrikeError::Api { status, message });
            }
            let page: AlertsResponse = resp.json().await?;
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
