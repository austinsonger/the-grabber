//! Jira incident external-reporting tickets — evidences the SLA for
//! notifying external stakeholders/authorities after an incident is
//! internally reported (IR-06a., IR-06b. family).

use anyhow::Result;
use async_trait::async_trait;
use jira_rs::JiraClient;

use crate::evidence::CsvCollector;

pub struct JiraIrExternalReportingCollector {
    client: JiraClient,
    project_key: String,
}

impl JiraIrExternalReportingCollector {
    pub fn new(client: JiraClient, project_key: String) -> Self {
        Self { client, project_key }
    }
}

#[async_trait]
impl CsvCollector for JiraIrExternalReportingCollector {
    fn name(&self) -> &str { "Jira IR External Reporting SLA" }
    fn filename_prefix(&self) -> &str { "Jira_IR_External_Reporting_SLA" }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Ticket", "Summary", "Status", "Internal Report Time",
            "External Notify Time", "Hours To Notify", "SLA Met (72hr)",
        ]
    }
    async fn collect_rows(
        &self,
        _account_id: &str, _region: &str, _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let jql = format!(
            "project = {} AND labels = external-reporting",
            self.project_key
        );
        let issues = self.client.jql_sla().search(&jql, &["labels", "priority"]).await?;
        let mut rows = Vec::with_capacity(issues.len());
        for i in issues {
            let external_notify_time = i.first_transition_at.clone().unwrap_or_default();
            let hours_to_notify = match (
                chrono::DateTime::parse_from_rfc3339(&i.created).ok(),
                (!external_notify_time.is_empty())
                    .then(|| chrono::DateTime::parse_from_rfc3339(&external_notify_time).ok())
                    .flatten(),
            ) {
                (Some(a), Some(b)) => Some((b - a).num_minutes() as f64 / 60.0),
                _ => None,
            };
            let sla_met = hours_to_notify
                .map(|h| if h <= 72.0 { "YES" } else { "NO" })
                .unwrap_or("N/A").to_string();
            rows.push(vec![
                i.key, i.summary, i.status,
                i.created,
                external_notify_time,
                hours_to_notify.map(|h| format!("{h:.1}")).unwrap_or_default(),
                sla_met,
            ]);
        }
        Ok(rows)
    }
}
