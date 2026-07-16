//! Jira public content review tickets — evidences pre-publication review
//! of externally-facing content (SI/marketing review workflow).

use anyhow::Result;
use async_trait::async_trait;
use jira_rs::JiraClient;

use crate::evidence::CsvCollector;

pub struct JiraPublicContentReviewCollector {
    client: JiraClient,
    project_key: String,
}

impl JiraPublicContentReviewCollector {
    pub fn new(client: JiraClient, project_key: String) -> Self {
        Self { client, project_key }
    }
}

#[async_trait]
impl CsvCollector for JiraPublicContentReviewCollector {
    fn name(&self) -> &str { "Jira Public Content Review" }
    fn filename_prefix(&self) -> &str { "Jira_Public_Content_Review" }
    fn headers(&self) -> &'static [&'static str] {
        &["Ticket", "Summary", "Status", "Reviewer", "Created", "Resolved"]
    }
    async fn collect_rows(
        &self,
        _account_id: &str, _region: &str, _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let jql = format!(
            "project = {} AND issuetype = \"Content Review\"",
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
