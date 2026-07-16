//! Jira incident tickets across all severities — evidences that the rigor
//! and scope of investigation is commensurate with incident severity
//! (IR-04d. family).

use anyhow::Result;
use async_trait::async_trait;
use jira_rs::JiraClient;

use crate::evidence::CsvCollector;

pub struct JiraIrSeverityVsRigorCollector {
    client: JiraClient,
    project_key: String,
}

impl JiraIrSeverityVsRigorCollector {
    pub fn new(client: JiraClient, project_key: String) -> Self {
        Self { client, project_key }
    }
}

#[async_trait]
impl CsvCollector for JiraIrSeverityVsRigorCollector {
    fn name(&self) -> &str { "Jira IR Severity vs Rigor" }
    fn filename_prefix(&self) -> &str { "Jira_IR_Severity_vs_Rigor" }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Ticket", "Summary", "Priority", "Status", "Investigator",
            "Created", "Resolved", "Duration Hours",
        ]
    }
    async fn collect_rows(
        &self,
        _account_id: &str, _region: &str, _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let jql = format!("project = {}", self.project_key);
        let issues = self.client.jql_sla().search(&jql, &["labels", "priority"]).await?;
        let mut rows = Vec::with_capacity(issues.len());
        for i in issues {
            let priority = i.extra.get("priority")
                .and_then(|v| v.get("name"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            rows.push(vec![
                i.key, i.summary,
                priority,
                i.status,
                i.assignee.unwrap_or_default(),
                i.created,
                i.resolved.unwrap_or_default(),
                i.duration_hours.map(|h| format!("{h:.1}")).unwrap_or_default(),
            ]);
        }
        Ok(rows)
    }
}
