//! Jira contingency-plan-test finding tickets — evidences POA&M tracking
//! of deficiencies identified during CP testing (CP-04c. family).

use anyhow::Result;
use async_trait::async_trait;
use jira_rs::JiraClient;

use crate::evidence::CsvCollector;

pub struct JiraCpTestPoamCollector {
    client: JiraClient,
    project_key: String,
}

impl JiraCpTestPoamCollector {
    pub fn new(client: JiraClient, project_key: String) -> Self {
        Self {
            client,
            project_key,
        }
    }
}

#[async_trait]
impl CsvCollector for JiraCpTestPoamCollector {
    fn name(&self) -> &str {
        "Jira CP Test POAM"
    }
    fn filename_prefix(&self) -> &str {
        "Jira_CP_Test_POAM"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Ticket", "Summary", "Status", "Owner", "Due Date", "Created", "Resolved",
        ]
    }
    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let jql = format!(
            "project = {} AND labels = cp-test-finding",
            self.project_key
        );
        let issues = self
            .client
            .jql_sla()
            .search(&jql, &["labels", "priority", "duedate"])
            .await?;
        let mut rows = Vec::with_capacity(issues.len());
        for i in issues {
            let due_date = i
                .extra
                .get("duedate")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            rows.push(vec![
                i.key,
                i.summary,
                i.status,
                i.assignee.unwrap_or_default(),
                due_date,
                i.created,
                i.resolved.unwrap_or_default(),
            ]);
        }
        Ok(rows)
    }
}
