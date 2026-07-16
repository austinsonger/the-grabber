//! Jira data-reassignment tickets — evidences reassignment of a
//! departing user's data/asset ownership to a new owner (PS-04 family).

use anyhow::Result;
use async_trait::async_trait;
use jira_rs::JiraClient;

use crate::evidence::CsvCollector;

pub struct JiraDataReassignmentCollector {
    client: JiraClient,
    project_key: String,
}

impl JiraDataReassignmentCollector {
    pub fn new(client: JiraClient, project_key: String) -> Self {
        Self { client, project_key }
    }
}

#[async_trait]
impl CsvCollector for JiraDataReassignmentCollector {
    fn name(&self) -> &str { "Jira Data Reassignment" }
    fn filename_prefix(&self) -> &str { "Jira_Data_Reassignment" }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Ticket", "Summary", "Status", "Original Owner", "Reassigned To",
            "Created", "Resolved",
        ]
    }
    async fn collect_rows(
        &self,
        _account_id: &str, _region: &str, _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let jql = format!(
            "project = {} AND labels = data-reassignment",
            self.project_key
        );
        let issues = self.client.jql_sla().search(&jql, &["labels", "priority"]).await?;
        let mut rows = Vec::with_capacity(issues.len());
        for i in issues {
            rows.push(vec![
                i.key, i.summary, i.status,
                i.reporter.unwrap_or_default(),
                i.assignee.unwrap_or_default(),
                i.created,
                i.resolved.unwrap_or_default(),
            ]);
        }
        Ok(rows)
    }
}
