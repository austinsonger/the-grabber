//! Jira ISA / internal-connection annual review tickets — evidences the
//! annual review of interconnection security agreements (CA-03 family).

use anyhow::Result;
use async_trait::async_trait;
use jira_rs::JiraClient;

use crate::evidence::CsvCollector;

pub struct JiraIsaAnnualReviewCollector {
    client: JiraClient,
    project_key: String,
}

impl JiraIsaAnnualReviewCollector {
    pub fn new(client: JiraClient, project_key: String) -> Self {
        Self { client, project_key }
    }
}

#[async_trait]
impl CsvCollector for JiraIsaAnnualReviewCollector {
    fn name(&self) -> &str { "Jira ISA Annual Review" }
    fn filename_prefix(&self) -> &str { "Jira_ISA_Annual_Review" }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Ticket", "Summary", "Status", "Owner", "Created", "Resolved",
            "Duration Days",
        ]
    }
    async fn collect_rows(
        &self,
        _account_id: &str, _region: &str, _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let jql = format!(
            "project = {} AND (labels = isa-review OR labels = internal-connection-review)",
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
                i.duration_hours.map(|h| format!("{:.1}", h / 24.0)).unwrap_or_default(),
            ]);
        }
        Ok(rows)
    }
}
