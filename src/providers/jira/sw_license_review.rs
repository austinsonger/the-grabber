//! Jira software-license-review tickets — evidences periodic review of
//! installed software licenses (CM-10 family).

use anyhow::Result;
use async_trait::async_trait;
use jira_rs::JiraClient;

use crate::evidence::CsvCollector;

pub struct JiraSwLicenseReviewCollector {
    client: JiraClient,
    project_key: String,
}

impl JiraSwLicenseReviewCollector {
    pub fn new(client: JiraClient, project_key: String) -> Self {
        Self { client, project_key }
    }
}

#[async_trait]
impl CsvCollector for JiraSwLicenseReviewCollector {
    fn name(&self) -> &str { "Jira SW License Review" }
    fn filename_prefix(&self) -> &str { "Jira_SW_License_Review" }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Ticket", "Summary", "Status", "Software Name", "License Type",
            "Reviewer", "Created", "Resolved",
        ]
    }
    async fn collect_rows(
        &self,
        _account_id: &str, _region: &str, _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let jql = format!(
            "project = {} AND labels = software-license",
            self.project_key
        );
        let issues = self.client.jql_sla().search(&jql, &["labels", "priority"]).await?;
        let mut rows = Vec::with_capacity(issues.len());
        for i in issues {
            rows.push(vec![
                i.key, i.summary, i.status,
                String::new(),
                String::new(),
                i.assignee.unwrap_or_default(),
                i.created,
                i.resolved.unwrap_or_default(),
            ]);
        }
        Ok(rows)
    }
}
