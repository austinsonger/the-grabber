//! Jira remote-access request tickets — evidences approval workflow for
//! remote access grants (AC family).

use anyhow::Result;
use async_trait::async_trait;
use jira_rs::JiraClient;

use crate::evidence::CsvCollector;

pub struct JiraRemoteAccessApprovalsCollector {
    client: JiraClient,
    project_key: String,
}

impl JiraRemoteAccessApprovalsCollector {
    pub fn new(client: JiraClient, project_key: String) -> Self {
        Self {
            client,
            project_key,
        }
    }
}

#[async_trait]
impl CsvCollector for JiraRemoteAccessApprovalsCollector {
    fn name(&self) -> &str {
        "Jira Remote Access Approvals"
    }
    fn filename_prefix(&self) -> &str {
        "Jira_Remote_Access_Approvals"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Ticket",
            "Summary",
            "Status",
            "Requestor",
            "Approver",
            "Created",
            "Resolved",
            "Duration Hours",
        ]
    }
    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let jql = format!(
            "project = {} AND issuetype = \"Access Request\" AND labels = remote-access",
            self.project_key
        );
        let issues = self
            .client
            .jql_sla()
            .search(&jql, &["labels", "priority"])
            .await?;
        let mut rows = Vec::with_capacity(issues.len());
        for i in issues {
            rows.push(vec![
                i.key,
                i.summary,
                i.status,
                i.reporter.unwrap_or_default(),
                i.first_transition_by.unwrap_or_default(),
                i.created,
                i.resolved.unwrap_or_default(),
                i.duration_hours
                    .map(|h| format!("{h:.1}"))
                    .unwrap_or_default(),
            ]);
        }
        Ok(rows)
    }
}
