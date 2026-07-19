//! Jira external-system connection tickets — evidences approval workflow
//! for connections to external systems (CA family).

use anyhow::Result;
use async_trait::async_trait;
use jira_rs::JiraClient;

use crate::evidence::CsvCollector;

pub struct JiraExternalSystemApprovalsCollector {
    client: JiraClient,
    project_key: String,
}

impl JiraExternalSystemApprovalsCollector {
    pub fn new(client: JiraClient, project_key: String) -> Self {
        Self {
            client,
            project_key,
        }
    }
}

#[async_trait]
impl CsvCollector for JiraExternalSystemApprovalsCollector {
    fn name(&self) -> &str {
        "Jira External System Approvals"
    }
    fn filename_prefix(&self) -> &str {
        "Jira_External_System_Approvals"
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
        ]
    }
    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let jql = format!(
            "project = {} AND labels = external-system",
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
            ]);
        }
        Ok(rows)
    }
}
