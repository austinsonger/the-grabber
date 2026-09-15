use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use crowdstrike_rs::CrowdStrikeClient;
use serde_json::Value;

use crate::evidence::CsvCollector;

pub struct CrowdStrikeAlertsCollector {
    client: CrowdStrikeClient,
}

impl CrowdStrikeAlertsCollector {
    pub fn new(client: CrowdStrikeClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for CrowdStrikeAlertsCollector {
    fn name(&self) -> &str {
        "CrowdStrike Alerts"
    }
    fn filename_prefix(&self) -> &str {
        "CrowdStrike_Alerts"
    }

    fn headers(&self) -> &'static [&'static str] {
        &[
            "Alert ID",
            "Composite ID",
            "Created",
            "Updated",
            "Status",
            "Severity",
            "Severity Name",
            "Type",
            "Product",
            "Tactic",
            "Technique",
            "Description",
            "Device Hostname",
            "Device ID",
            "Agent ID",
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
            .to_rfc3339();
        let until = DateTime::<Utc>::from_timestamp(end_secs, 0)
            .unwrap_or_else(Utc::now)
            .to_rfc3339();

        let alerts = match self.client.alerts().list_all(&since, &until).await {
            Ok(a) => a,
            Err(crowdstrike_rs::CrowdStrikeError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };

        let rows = alerts
            .into_iter()
            .map(|a| {
                let device_hostname = a
                    .device
                    .get("hostname")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                let device_id = a
                    .device
                    .get("device_id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                vec![
                    a.id,
                    a.composite_id.unwrap_or_default(),
                    a.created_timestamp.unwrap_or_default(),
                    a.updated_timestamp.unwrap_or_default(),
                    a.status.unwrap_or_default(),
                    a.severity.map(|s| s.to_string()).unwrap_or_default(),
                    a.severity_name.unwrap_or_default(),
                    a.alert_type.unwrap_or_default(),
                    a.product.unwrap_or_default(),
                    a.tactic.unwrap_or_default(),
                    a.technique.unwrap_or_default(),
                    a.description.unwrap_or_default(),
                    device_hostname,
                    device_id,
                    a.agent_id.unwrap_or_default(),
                ]
            })
            .collect();
        Ok(rows)
    }
}
