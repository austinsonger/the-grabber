//! Jira sanctions-ISSO-notification tickets — evidences the SLA for
//! notifying the ISSO after personnel sanctions are initiated
//! (PS-08 family).

use anyhow::Result;
use async_trait::async_trait;
use jira_rs::JiraClient;

use crate::evidence::CsvCollector;

pub struct JiraSanctionsIssoNotifyCollector {
    client: JiraClient,
    project_key: String,
}

impl JiraSanctionsIssoNotifyCollector {
    pub fn new(client: JiraClient, project_key: String) -> Self {
        Self { client, project_key }
    }
}

#[async_trait]
impl CsvCollector for JiraSanctionsIssoNotifyCollector {
    fn name(&self) -> &str { "Jira Sanctions ISSO Notify" }
    fn filename_prefix(&self) -> &str { "Jira_Sanctions_ISSO_Notify" }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Ticket", "Summary", "Status", "Reporter", "ISSO Notified",
            "Hours To Notify", "SLA Met (24hr)",
        ]
    }
    async fn collect_rows(
        &self,
        _account_id: &str, _region: &str, _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let jql = format!(
            "project = {} AND labels = sanctions-isso",
            self.project_key
        );
        let issues = self.client.jql_sla().search(&jql, &["labels", "priority"]).await?;
        let mut rows = Vec::with_capacity(issues.len());
        for i in issues {
            let isso_notified = i.first_transition_at.clone().unwrap_or_default();
            let hours_to_notify = match (
                chrono::DateTime::parse_from_rfc3339(&i.created).ok(),
                (!isso_notified.is_empty())
                    .then(|| chrono::DateTime::parse_from_rfc3339(&isso_notified).ok())
                    .flatten(),
            ) {
                (Some(a), Some(b)) => Some((b - a).num_minutes() as f64 / 60.0),
                _ => None,
            };
            let sla_met = hours_to_notify
                .map(|h| if h <= 24.0 { "YES" } else { "NO" })
                .unwrap_or("N/A").to_string();
            rows.push(vec![
                i.key, i.summary, i.status,
                i.reporter.unwrap_or_default(),
                isso_notified,
                hours_to_notify.map(|h| format!("{h:.1}")).unwrap_or_default(),
                sla_met,
            ]);
        }
        Ok(rows)
    }
}
