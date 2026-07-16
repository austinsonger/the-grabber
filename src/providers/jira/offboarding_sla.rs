//! Jira offboarding tickets — proves PS-04 24hr access-revocation SLA
//! end-to-end. Pair with Okta_Deprovisioning_Timeliness (Plan 3).

use anyhow::Result;
use async_trait::async_trait;
use jira_rs::JiraClient;

use crate::evidence::CsvCollector;

pub struct JiraOffboardingSlaCollector {
    client: JiraClient,
    project_key: String,
}

impl JiraOffboardingSlaCollector {
    pub fn new(client: JiraClient, project_key: String) -> Self {
        Self { client, project_key }
    }
}

#[async_trait]
impl CsvCollector for JiraOffboardingSlaCollector {
    fn name(&self) -> &str { "Jira Offboarding SLA" }
    fn filename_prefix(&self) -> &str { "Jira_Offboarding_SLA" }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Ticket", "Summary", "Status", "Assignee", "Reporter",
            "Created", "Resolved", "Duration Hours", "SLA Met (24hr)",
        ]
    }
    async fn collect_rows(
        &self,
        _account_id: &str, _region: &str, _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let jql = format!(
            "project = {} AND issuetype = \"Offboarding\" AND resolved is not EMPTY ORDER BY created DESC",
            self.project_key
        );
        let issues = self.client.jql_sla().search(&jql, &["labels", "priority"]).await?;
        let mut rows = Vec::with_capacity(issues.len());
        for i in issues {
            let sla_met = i.duration_hours
                .map(|h| if h <= 24.0 { "YES" } else { "NO" })
                .unwrap_or("N/A").to_string();
            rows.push(vec![
                i.key, i.summary, i.status,
                i.assignee.unwrap_or_default(),
                i.reporter.unwrap_or_default(),
                i.created,
                i.resolved.unwrap_or_default(),
                i.duration_hours.map(|h| format!("{h:.1}")).unwrap_or_default(),
                sla_met,
            ]);
        }
        Ok(rows)
    }
}
