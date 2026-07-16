//! Jira incident tickets referencing CP activation — evidences
//! coordination of incident handling with contingency planning
//! activities (IR-04b. family).

use anyhow::Result;
use async_trait::async_trait;
use jira_rs::JiraClient;

use crate::evidence::CsvCollector;

pub struct JiraIrCpCoordinationCollector {
    client: JiraClient,
    project_key: String,
}

impl JiraIrCpCoordinationCollector {
    pub fn new(client: JiraClient, project_key: String) -> Self {
        Self { client, project_key }
    }
}

#[async_trait]
impl CsvCollector for JiraIrCpCoordinationCollector {
    fn name(&self) -> &str { "Jira IR CP Coordination" }
    fn filename_prefix(&self) -> &str { "Jira_IR_CP_Coordination" }
    fn headers(&self) -> &'static [&'static str] {
        &["Ticket", "Summary", "Status", "Created", "Resolved", "Duration Hours"]
    }
    async fn collect_rows(
        &self,
        _account_id: &str, _region: &str, _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let jql = format!(
            "project = {} AND text ~ \"CP activation\"",
            self.project_key
        );
        let issues = self.client.jql_sla().search(&jql, &["labels", "priority"]).await?;
        let mut rows = Vec::with_capacity(issues.len());
        for i in issues {
            rows.push(vec![
                i.key, i.summary, i.status,
                i.created,
                i.resolved.unwrap_or_default(),
                i.duration_hours.map(|h| format!("{h:.1}")).unwrap_or_default(),
            ]);
        }
        Ok(rows)
    }
}
