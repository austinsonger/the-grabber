use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use okta_rs::OktaClient;

use crate::evidence::CsvCollector;

pub struct OktaDeprovisioningTimelinessCollector {
    client: OktaClient,
}

impl OktaDeprovisioningTimelinessCollector {
    pub fn new(client: OktaClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for OktaDeprovisioningTimelinessCollector {
    fn name(&self) -> &str {
        "Okta Deprovisioning Timeliness"
    }
    fn filename_prefix(&self) -> &str {
        "Okta_Deprovisioning_Timeliness"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Event ID",
            "Published",
            "Actor Type",
            "Actor Name",
            "Target Type",
            "Target Login",
            "Event Type",
            "Outcome",
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

        let events = match self
            .client
            .lifecycle()
            .events_all("user.lifecycle.deactivate", &since_iso)
            .await
        {
            Ok(e) => e,
            Err(okta_rs::OktaError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };

        let rows = events
            .into_iter()
            .map(|e| {
                let target_arr = e.target.as_array();
                let first_target = target_arr.and_then(|a| a.first());
                let target_type = first_target
                    .and_then(|t| t.get("type"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let target_login = first_target
                    .and_then(|t| t.get("alternateId"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                let actor = e.actor.as_ref();
                let actor_type = actor
                    .and_then(|a| a.actor_type.clone())
                    .unwrap_or_default();
                let actor_name = actor
                    .and_then(|a| a.display_name.clone())
                    .unwrap_or_default();

                vec![
                    e.uuid,
                    e.published,
                    actor_type,
                    actor_name,
                    target_type,
                    target_login,
                    e.event_type,
                    e.outcome
                        .as_ref()
                        .map(|o| o.result.clone())
                        .unwrap_or_default(),
                ]
            })
            .collect();

        Ok(rows)
    }
}
