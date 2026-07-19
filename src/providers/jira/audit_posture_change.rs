//! Jira audit-review-adjustment tickets — evidences audit posture changes
//! made in response to a triggering indicator (AU-06 family).

use anyhow::Result;
use async_trait::async_trait;
use jira_rs::JiraClient;

use crate::evidence::CsvCollector;

pub struct JiraAuditPostureChangeCollector {
    client: JiraClient,
    project_key: String,
}

impl JiraAuditPostureChangeCollector {
    pub fn new(client: JiraClient, project_key: String) -> Self {
        Self {
            client,
            project_key,
        }
    }
}

#[async_trait]
impl CsvCollector for JiraAuditPostureChangeCollector {
    fn name(&self) -> &str {
        "Jira Audit Posture Change"
    }
    fn filename_prefix(&self) -> &str {
        "Jira_Audit_Posture_Change"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Ticket",
            "Summary",
            "Status",
            "Trigger Indicator",
            "Created",
            "Resolved",
        ]
    }
    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let jql = format!(
            "project = {} AND labels = audit-review-adjustment",
            self.project_key
        );
        let issues = self
            .client
            .jql_sla()
            .search(&jql, &["labels", "priority"])
            .await?;
        let mut rows = Vec::with_capacity(issues.len());
        for i in issues {
            let trigger_indicator = i
                .extra
                .get("labels")
                .map(|v| v.to_string())
                .unwrap_or_default();
            rows.push(vec![
                i.key,
                i.summary,
                i.status,
                trigger_indicator,
                i.created,
                i.resolved.unwrap_or_default(),
            ]);
        }
        Ok(rows)
    }
}
