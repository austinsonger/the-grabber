use crate::client::JumpCloudClient;
use crate::error::JumpCloudError;
use crate::types::insight_alert::InsightAlert;
use crate::types::insight_event::InsightEvent;
use crate::types::pagination::{InsightsAlertsQuery, InsightsEventsQuery};

pub struct InsightsApi<'a>(pub(crate) &'a JumpCloudClient);

impl<'a> InsightsApi<'a> {
    /// POST /insights/directory/v1/events — cursor pagination via `search_after`.
    /// The `search_after` cursor is echoed in the last event's `_sort` field
    /// (or the response header `X-Search_After`); we mirror the field-based
    /// approach and stop when a page returns fewer than `limit` items.
    pub async fn events(
        &self,
        query: &InsightsEventsQuery,
    ) -> Result<Vec<InsightEvent>, JumpCloudError> {
        let mut out: Vec<InsightEvent> = Vec::new();
        let mut q = query.clone();
        loop {
            let page: Vec<InsightEvent> = self
                .0
                .post_json("/insights/directory/v1/events", &q)
                .await?;
            let got = page.len();
            let cursor = page
                .last()
                .and_then(|e| e.raw.get("_sort").cloned())
                .and_then(|v| v.as_array().cloned());
            out.extend(page);
            if got < q.limit as usize {
                break;
            }
            match cursor {
                Some(sa) => q.search_after = Some(sa),
                None => break,
            }
        }
        Ok(out)
    }

    /// GET /insights/directory/v1/alerts — bounded by start/end.
    pub async fn alerts(
        &self,
        query: &InsightsAlertsQuery,
    ) -> Result<Vec<InsightAlert>, JumpCloudError> {
        let path = format!(
            "/insights/directory/v1/alerts?start_time={}&end_time={}&limit={}",
            urlencoding_encode(&query.start_time),
            urlencoding_encode(&query.end_time),
            query.limit
        );
        self.0.list_v2_cursor(&path).await
    }
}

fn urlencoding_encode(s: &str) -> String {
    // Minimal encoder for ISO-8601 timestamps: only `:` and `+` need escaping.
    s.replace(':', "%3A").replace('+', "%2B")
}
