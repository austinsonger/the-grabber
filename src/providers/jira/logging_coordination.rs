//! Jira audit-event selection coordination tickets — evidences the
//! logging/auditing coordination workflow (AU family).

use anyhow::Result;
use async_trait::async_trait;
use jira_rs::JiraClient;

use crate::evidence::CsvCollector;

pub struct JiraLoggingCoordinationCollector {
    client: JiraClient,
    project_key: String,
}

impl JiraLoggingCoordinationCollector {
    pub fn new(client: JiraClient, project_key: String) -> Self {
        Self { client, project_key }
    }
}

#[async_trait]
impl CsvCollector for JiraLoggingCoordinationCollector {
    fn name(&self) -> &str { "Jira Logging Coordination" }
    fn filename_prefix(&self) -> &str { "Jira_Logging_Coordination" }
    fn headers(&self) -> &'static [&'static str] {
        &["Ticket", "Summary", "Status", "Owner", "Created", "Resolved"]
    }
    async fn collect_rows(
        &self,
        _account_id: &str, _region: &str, _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let jql = format!(
            "project = {} AND labels = audit-event-selection",
            self.project_key
        );
        let issues = self.client.jql_sla().search(&jql, &["labels", "priority"]).await?;
        let mut rows = Vec::with_capacity(issues.len());
        for i in issues {
            rows.push(vec![
                i.key, i.summary, i.status,
                i.assignee.unwrap_or_default(),
                i.created,
                i.resolved.unwrap_or_default(),
            ]);
        }
        Ok(rows)
    }
}
