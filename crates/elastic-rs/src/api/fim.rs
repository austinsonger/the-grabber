use crate::client::{check_response, ElasticClient};
use crate::error::ElasticError;
use crate::types::alert::EsSearchResponse;
use crate::types::fim::FimEvent;

/// Bounded result cap, matching the alerts search's precedent.
const MAX_EVENTS: u32 = 1000;
const FIM_INDEX: &str = "logs-file_integrity.event-*";

pub struct FimApi<'c>(pub(crate) &'c ElasticClient);

impl<'c> FimApi<'c> {
    /// Search the File Integrity Monitoring data stream for events with
    /// `@timestamp` between `start` and `end` (RFC 3339 strings), newest
    /// first, capped at `MAX_EVENTS` documents. Returns an empty vec (not an
    /// error) if the customer hasn't deployed the FIM integration — the
    /// index pattern simply matches zero documents.
    pub async fn search_range(&self, start: &str, end: &str) -> Result<Vec<FimEvent>, ElasticError> {
        let body = serde_json::json!({
            "size": MAX_EVENTS,
            "sort": [{ "@timestamp": "desc" }],
            "query": {
                "range": {
                    "@timestamp": { "gte": start, "lte": end }
                }
            }
        });
        let path = format!("/{FIM_INDEX}/_search");
        let resp = check_response(self.0.es_post(&path, &body).await?).await?;
        let parsed: EsSearchResponse = resp.json().await?;
        Ok(parsed
            .hits
            .hits
            .into_iter()
            .map(|h| FimEvent {
                id: h.id,
                source: h.source,
            })
            .collect())
    }
}
