//! Jira allowlist-review tickets — evidences periodic review of the
//! authorized software allowlist (CM-07(05) family).

use anyhow::Result;
use async_trait::async_trait;
use jira_rs::JiraClient;

use crate::evidence::CsvCollector;

pub struct JiraAllowlistReviewCollector {
    client: JiraClient,
    project_key: String,
}

impl JiraAllowlistReviewCollector {
    pub fn new(client: JiraClient, project_key: String) -> Self {
        Self { client, project_key }
    }
}

#[async_trait]
impl CsvCollector for JiraAllowlistReviewCollector {
    fn name(&self) -> &str { "Jira Allowlist Review" }
    fn filename_prefix(&self) -> &str { "Jira_Allowlist_Review" }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Ticket", "Summary", "Status", "Reviewer", "Created", "Resolved",
            "Days Since Created",
        ]
    }
    async fn collect_rows(
        &self,
        _account_id: &str, _region: &str, _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let jql = format!(
            "project = {} AND labels = allowlist-review",
            self.project_key
        );
        let issues = self.client.jql_sla().search(&jql, &["labels", "priority"]).await?;
        let mut rows = Vec::with_capacity(issues.len());
        for i in issues {
            let days_since_created = chrono::DateTime::parse_from_rfc3339(&i.created)
                .ok()
                .map(|c| (chrono::Utc::now() - c.with_timezone(&chrono::Utc)).num_days().to_string())
                .unwrap_or_default();
            rows.push(vec![
                i.key, i.summary, i.status,
                i.assignee.unwrap_or_default(),
                i.created,
                i.resolved.unwrap_or_default(),
                days_since_created,
            ]);
        }
        Ok(rows)
    }
}
