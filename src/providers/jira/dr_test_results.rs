//! Jira DR test-result tickets — evidences disaster-recovery test outcomes
//! against RTO/RPO targets (CP-07 / CP-10 family).

use anyhow::Result;
use async_trait::async_trait;
use jira_rs::JiraClient;

use crate::evidence::CsvCollector;

pub struct JiraDrTestResultsCollector {
    client: JiraClient,
    project_key: String,
}

impl JiraDrTestResultsCollector {
    pub fn new(client: JiraClient, project_key: String) -> Self {
        Self {
            client,
            project_key,
        }
    }
}

#[async_trait]
impl CsvCollector for JiraDrTestResultsCollector {
    fn name(&self) -> &str {
        "Jira DR Test Results"
    }
    fn filename_prefix(&self) -> &str {
        "Jira_DR_Test_Results"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Ticket",
            "Summary",
            "Test Date",
            "RTO Target Hours",
            "RTO Actual Hours",
            "RPO Target Hours",
            "RPO Actual Hours",
            "Reviewer",
        ]
    }
    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let jql = format!(
            "project = {} AND issuetype = \"DR Test\" AND status = Done",
            self.project_key
        );
        let issues = self
            .client
            .jql_sla()
            .search(&jql, &["labels", "priority"])
            .await?;
        let mut rows = Vec::with_capacity(issues.len());
        for i in issues {
            // TODO: map RTO/RPO custom fields per tenant
            rows.push(vec![
                i.key,
                i.summary,
                i.resolved.unwrap_or_default(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                i.assignee.unwrap_or_default(),
            ]);
        }
        Ok(rows)
    }
}
