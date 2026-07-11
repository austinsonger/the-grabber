use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use okta_rs::OktaClient;
use serde_json::Value;

use crate::evidence::CsvCollector;

pub struct OktaSystemLogCollector {
    pub(crate) client: OktaClient,
}

impl OktaSystemLogCollector {
    pub fn new(client: OktaClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for OktaSystemLogCollector {
    fn name(&self) -> &str {
        "Okta System Log"
    }

    fn filename_prefix(&self) -> &str {
        "Okta_System_Log_Events"
    }

    fn headers(&self) -> &'static [&'static str] {
        &[
            "Event UUID",
            "Published",
            "Event Type",
            "Display Message",
            "Severity",
            "Outcome Result",
            "Outcome Reason",
            "Actor ID",
            "Actor Display Name",
            "Actor Alternate ID",
            "Actor Type",
            "Client IP",
            "Client User Agent",
            "Target Summary",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let (start_secs, end_secs) = match dates {
            Some(d) => d,
            None => {
                // No date range provided → default to last 90 days.
                let now = Utc::now();
                let start = now - chrono::Duration::days(90);
                (start.timestamp(), now.timestamp())
            }
        };
        let since = DateTime::<Utc>::from_timestamp(start_secs, 0)
            .unwrap_or_else(Utc::now)
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string();
        let until = DateTime::<Utc>::from_timestamp(end_secs, 0)
            .unwrap_or_else(Utc::now)
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string();

        let events = match self
            .client
            .system_log()
            .events_all(&since, &until, None)
            .await
        {
            Ok(e) => e,
            Err(okta_rs::OktaError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };

        let rows = events
            .into_iter()
            .map(|e| {
                let client_ip = e
                    .client
                    .get("ipAddress")
                    .and_then(Value::as_str)
                    .map(String::from)
                    .unwrap_or_default();
                let client_ua = e
                    .client
                    .get("userAgent")
                    .and_then(|ua| ua.get("rawUserAgent"))
                    .and_then(Value::as_str)
                    .map(String::from)
                    .unwrap_or_default();
                let target_summary = e
                    .target
                    .as_array()
                    .map(|arr| {
                        arr.iter()
                            .map(|t| {
                                let typ = t.get("type").and_then(Value::as_str).unwrap_or("");
                                let name = t
                                    .get("displayName")
                                    .and_then(Value::as_str)
                                    .or_else(|| t.get("alternateId").and_then(Value::as_str))
                                    .unwrap_or("");
                                format!("{}:{}", typ, name)
                            })
                            .collect::<Vec<_>>()
                            .join("; ")
                    })
                    .unwrap_or_default();

                vec![
                    e.uuid,
                    e.published,
                    e.event_type,
                    e.display_message,
                    e.severity.unwrap_or_default(),
                    e.outcome
                        .as_ref()
                        .map(|o| o.result.clone())
                        .unwrap_or_default(),
                    e.outcome
                        .as_ref()
                        .and_then(|o| o.reason.clone())
                        .unwrap_or_default(),
                    e.actor.as_ref().map(|a| a.id.clone()).unwrap_or_default(),
                    e.actor
                        .as_ref()
                        .and_then(|a| a.display_name.clone())
                        .unwrap_or_default(),
                    e.actor
                        .as_ref()
                        .and_then(|a| a.alternate_id.clone())
                        .unwrap_or_default(),
                    e.actor
                        .as_ref()
                        .and_then(|a| a.actor_type.clone())
                        .unwrap_or_default(),
                    client_ip,
                    client_ua,
                    target_summary,
                ]
            })
            .collect();

        Ok(rows)
    }
}
