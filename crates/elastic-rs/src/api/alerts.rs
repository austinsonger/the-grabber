use crate::client::{check_response, ElasticClient};
use crate::error::ElasticError;
use crate::types::alert::{Alert, EsSearchResponse};

/// Bounded result cap for a single alert search — matches the existing
/// bounded-fetch precedent used by other time-windowed findings collectors
/// (e.g. AWS GuardDuty caps at 500 findings per collection run).
const MAX_ALERTS: u32 = 1000;
const ALERTS_INDEX: &str = ".alerts-security.alerts-*";

pub struct AlertsApi<'c>(pub(crate) &'c ElasticClient);

impl<'c> AlertsApi<'c> {
    /// Search `.alerts-security.alerts-*` for alerts with `@timestamp`
    /// between `start` and `end` (RFC 3339 strings), newest first, capped at
    /// `MAX_ALERTS` documents.
    pub async fn search_range(&self, start: &str, end: &str) -> Result<Vec<Alert>, ElasticError> {
        let body = serde_json::json!({
            "size": MAX_ALERTS,
            "sort": [{ "@timestamp": "desc" }],
            "query": {
                "range": {
                    "@timestamp": { "gte": start, "lte": end }
                }
            }
        });

        let path = format!("/{ALERTS_INDEX}/_search");
        let resp = check_response(self.0.es_post(&path, &body).await?).await?;
        let parsed: EsSearchResponse = resp.json().await?;
        Ok(parsed
            .hits
            .hits
            .into_iter()
            .map(|h| Alert {
                id: h.id,
                index: h.index,
                source: h.source,
            })
            .collect())
    }
}
