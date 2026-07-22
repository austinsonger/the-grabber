use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};

use elastic_rs::ElasticClient;

use crate::evidence::CsvCollector;

pub struct ElasticAlertsCollector {
    client: ElasticClient,
}

impl ElasticAlertsCollector {
    pub fn new(client: ElasticClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for ElasticAlertsCollector {
    fn name(&self) -> &str {
        "Elastic Security Alerts"
    }

    fn filename_prefix(&self) -> &str {
        "Elastic_Security_Alerts"
    }

    fn headers(&self) -> &'static [&'static str] {
        &[
            "Alert ID",
            "Rule Name",
            "Rule UUID",
            "Severity",
            "Risk Score",
            "Workflow Status",
            "Host Name",
            "User Name",
            "Timestamp",
            "Reason",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        // Non-AWS Collectors runs always supply a date window (the TUI wizard
        // seeds it with a 3-month default even for providers that skip the
        // SetDates screen); fall back to the last 90 days if this collector
        // is ever invoked without one.
        let (start_secs, end_secs) = dates.unwrap_or_else(|| {
            let now = Utc::now();
            (
                (now - chrono::Duration::days(90)).timestamp(),
                now.timestamp(),
            )
        });
        let start = DateTime::<Utc>::from_timestamp(start_secs, 0)
            .unwrap_or_else(Utc::now)
            .to_rfc3339();
        let end = DateTime::<Utc>::from_timestamp(end_secs, 0)
            .unwrap_or_else(Utc::now)
            .to_rfc3339();

        let alerts = self.client.alerts().search_range(&start, &end).await?;

        let rows = alerts
            .into_iter()
            .map(|a| {
                vec![
                    a.id.clone(),
                    a.field_string("kibana.alert.rule.name"),
                    a.field_string("kibana.alert.rule.uuid"),
                    a.field_string("kibana.alert.severity"),
                    a.field_string("kibana.alert.risk_score"),
                    a.field_string("kibana.alert.workflow_status"),
                    a.field_string("host.name"),
                    a.field_string("user.name"),
                    a.field_string("@timestamp"),
                    a.field_string("kibana.alert.reason"),
                ]
            })
            .collect();

        Ok(rows)
    }
}
