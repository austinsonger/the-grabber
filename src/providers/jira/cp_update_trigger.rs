//! Jira contingency-plan-update tickets — evidences the triggering event
//! and resulting update to the Contingency Plan (CP-02 family).

use anyhow::Result;
use async_trait::async_trait;
use jira_rs::JiraClient;

use crate::evidence::CsvCollector;

pub struct JiraCpUpdateTriggerCollector {
    client: JiraClient,
    project_key: String,
}

impl JiraCpUpdateTriggerCollector {
    pub fn new(client: JiraClient, project_key: String) -> Self {
        Self {
            client,
            project_key,
        }
    }
}

#[async_trait]
impl CsvCollector for JiraCpUpdateTriggerCollector {
    fn name(&self) -> &str {
        "Jira CP Update Trigger"
    }
    fn filename_prefix(&self) -> &str {
        "Jira_CP_Update_Trigger"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Ticket", "Summary", "Status", "Trigger", "Created", "Resolved",
        ]
    }
    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let jql = format!(
            "project = {} AND labels = contingency-plan-update",
            self.project_key
        );
        let issues = self
            .client
            .jql_sla()
            .search(&jql, &["labels", "priority"])
            .await?;
        let mut rows = Vec::with_capacity(issues.len());
        for i in issues {
            let trigger = i
                .extra
                .get("labels")
                .and_then(|v| v.as_array())
                .and_then(|arr| arr.first())
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            rows.push(vec![
                i.key,
                i.summary,
                i.status,
                trigger,
                i.created,
                i.resolved.unwrap_or_default(),
            ]);
        }
        Ok(rows)
    }
}
