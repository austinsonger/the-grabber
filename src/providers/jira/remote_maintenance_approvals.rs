//! Jira remote-maintenance-session tickets — evidences approval and
//! duration of remote maintenance sessions (MA-04 family).

use anyhow::Result;
use async_trait::async_trait;
use jira_rs::JiraClient;

use crate::evidence::CsvCollector;

pub struct JiraRemoteMaintenanceApprovalsCollector {
    client: JiraClient,
    project_key: String,
}

impl JiraRemoteMaintenanceApprovalsCollector {
    pub fn new(client: JiraClient, project_key: String) -> Self {
        Self { client, project_key }
    }
}

#[async_trait]
impl CsvCollector for JiraRemoteMaintenanceApprovalsCollector {
    fn name(&self) -> &str { "Jira Remote Maintenance Approvals" }
    fn filename_prefix(&self) -> &str { "Jira_Remote_Maintenance_Approvals" }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Ticket", "Summary", "Status", "Requestor", "Approver",
            "Session Start", "Session End", "Duration Hours",
        ]
    }
    async fn collect_rows(
        &self,
        _account_id: &str, _region: &str, _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let jql = format!(
            "project = {} AND labels = remote-maintenance",
            self.project_key
        );
        let issues = self.client.jql_sla().search(&jql, &["labels", "priority"]).await?;
        let mut rows = Vec::with_capacity(issues.len());
        for i in issues {
            rows.push(vec![
                i.key, i.summary, i.status,
                i.reporter.unwrap_or_default(),
                i.first_transition_by.unwrap_or_default(),
                i.first_transition_at.clone().unwrap_or_default(),
                i.resolved.unwrap_or_default(),
                i.duration_hours.map(|h| format!("{h:.1}")).unwrap_or_default(),
            ]);
        }
        Ok(rows)
    }
}
