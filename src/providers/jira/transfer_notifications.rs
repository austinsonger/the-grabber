//! Jira transfer-notification tickets — evidences that a user's
//! internal transfer notice was raised with lead time before the
//! effective date (PS-05 family).

use anyhow::Result;
use async_trait::async_trait;
use jira_rs::JiraClient;

use crate::evidence::CsvCollector;

pub struct JiraTransferNotificationsCollector {
    client: JiraClient,
    project_key: String,
}

impl JiraTransferNotificationsCollector {
    pub fn new(client: JiraClient, project_key: String) -> Self {
        Self { client, project_key }
    }
}

#[async_trait]
impl CsvCollector for JiraTransferNotificationsCollector {
    fn name(&self) -> &str { "Jira Transfer Notifications" }
    fn filename_prefix(&self) -> &str { "Jira_Transfer_Notifications" }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Ticket", "Summary", "Status", "User", "Effective Date",
            "Created", "Hours Before Effective",
        ]
    }
    async fn collect_rows(
        &self,
        _account_id: &str, _region: &str, _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let jql = format!("project = {}", self.project_key);
        let issues = self.client.jql_sla().search(&jql, &["labels", "priority", "duedate"]).await?;
        let mut rows = Vec::with_capacity(issues.len());
        for i in issues {
            let effective_date = i.extra.get("duedate").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let hours_before_effective = match (
                (!effective_date.is_empty())
                    .then(|| chrono::DateTime::parse_from_rfc3339(&effective_date).ok())
                    .flatten(),
                chrono::DateTime::parse_from_rfc3339(&i.created).ok(),
            ) {
                (Some(due), Some(created)) => Some((due - created).num_minutes() as f64 / 60.0),
                _ => None,
            };
            rows.push(vec![
                i.key, i.summary, i.status,
                i.reporter.unwrap_or_default(),
                effective_date,
                i.created,
                hours_before_effective.map(|h| format!("{h:.1}")).unwrap_or_default(),
            ]);
        }
        Ok(rows)
    }
}
