use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use okta_rs::OktaClient;

use crate::evidence::CsvCollector;

pub struct OktaThreatInsightDetectionsCollector {
    client: OktaClient,
}

impl OktaThreatInsightDetectionsCollector {
    pub fn new(client: OktaClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for OktaThreatInsightDetectionsCollector {
    fn name(&self) -> &str {
        "Okta ThreatInsight Detections"
    }
    fn filename_prefix(&self) -> &str {
        "Okta_ThreatInsight_Detections"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Event ID",
            "Published",
            "Event Type",
            "Severity",
            "Actor IP",
            "Outcome",
            "Display Message",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let since_iso = dates
            .map(|(s, _)| DateTime::<Utc>::from_timestamp(s, 0).unwrap_or_else(Utc::now))
            .unwrap_or_else(|| Utc::now() - chrono::Duration::days(90))
            .to_rfc3339();

        let events = match self.client.threat_insight().detections(&since_iso).await {
            Ok(e) => e,
            Err(okta_rs::OktaError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };

        let rows = events
            .into_iter()
            .map(|event| {
                let actor_ip = event
                    .client
                    .get("ipAddress")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                vec![
                    event.uuid,
                    event.published,
                    event.event_type,
                    event.severity.unwrap_or_default(),
                    actor_ip,
                    event
                        .outcome
                        .as_ref()
                        .map(|o| o.result.clone())
                        .unwrap_or_default(),
                    event.display_message,
                ]
            })
            .collect();

        Ok(rows)
    }
}
