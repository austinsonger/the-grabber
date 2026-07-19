//! Jira change tickets by type — evidences change record retention across
//! the full project (CM family).

use anyhow::Result;
use async_trait::async_trait;
use jira_rs::JiraClient;

use crate::evidence::CsvCollector;

pub struct JiraChangeRetentionCollector {
    client: JiraClient,
    project_key: String,
}

impl JiraChangeRetentionCollector {
    pub fn new(client: JiraClient, project_key: String) -> Self {
        Self {
            client,
            project_key,
        }
    }
}

#[async_trait]
impl CsvCollector for JiraChangeRetentionCollector {
    fn name(&self) -> &str {
        "Jira Change Retention"
    }
    fn filename_prefix(&self) -> &str {
        "Jira_Change_Retention"
    }
    fn headers(&self) -> &'static [&'static str] {
        &["Ticket", "Summary", "Status", "Type", "Created", "Resolved"]
    }
    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let jql = format!("project = {}", self.project_key);
        let issues = self.client.jql_sla().search(&jql, &["issuetype"]).await?;
        let mut rows = Vec::with_capacity(issues.len());
        for i in issues {
            let issue_type = i
                .extra
                .get("issuetype")
                .and_then(|v| v.get("name"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            rows.push(vec![
                i.key,
                i.summary,
                i.status,
                issue_type,
                i.created,
                i.resolved.unwrap_or_default(),
            ]);
        }
        Ok(rows)
    }
}
