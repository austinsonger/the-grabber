//! Jira need-to-know approval tickets — evidences approval workflow for
//! access to specially protected information (PS-03(03) family).

use anyhow::Result;
use async_trait::async_trait;
use jira_rs::JiraClient;

use crate::evidence::CsvCollector;

pub struct JiraSpecialProtectionApprovalsCollector {
    client: JiraClient,
    project_key: String,
}

impl JiraSpecialProtectionApprovalsCollector {
    pub fn new(client: JiraClient, project_key: String) -> Self {
        Self {
            client,
            project_key,
        }
    }
}

#[async_trait]
impl CsvCollector for JiraSpecialProtectionApprovalsCollector {
    fn name(&self) -> &str {
        "Jira Special Protection Approvals"
    }
    fn filename_prefix(&self) -> &str {
        "Jira_Special_Protection_Approvals"
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
            "project = {} AND labels = need-to-know-approval",
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
