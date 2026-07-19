//! Jira baseline-deviation tickets — evidences approved exceptions to
//! configuration baselines (CM-06 family).

use anyhow::Result;
use async_trait::async_trait;
use jira_rs::JiraClient;

use crate::evidence::CsvCollector;

pub struct JiraBaselineExceptionsCollector {
    client: JiraClient,
    project_key: String,
}

impl JiraBaselineExceptionsCollector {
    pub fn new(client: JiraClient, project_key: String) -> Self {
        Self {
            client,
            project_key,
        }
    }
}

#[async_trait]
impl CsvCollector for JiraBaselineExceptionsCollector {
    fn name(&self) -> &str {
        "Jira Baseline Exceptions"
    }
    fn filename_prefix(&self) -> &str {
        "Jira_Baseline_Exceptions"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Ticket",
            "Summary",
            "Status",
            "Owner",
            "Config Rule",
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
            "project = {} AND issuetype = \"Baseline Deviation\"",
            self.project_key
        );
        let issues = self
            .client
            .jql_sla()
            .search(&jql, &["labels", "priority"])
            .await?;
        let mut rows = Vec::with_capacity(issues.len());
        for i in issues {
            let config_rule = i
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
                i.assignee.unwrap_or_default(),
                config_rule,
                i.created,
                i.resolved.unwrap_or_default(),
            ]);
        }
        Ok(rows)
    }
}
