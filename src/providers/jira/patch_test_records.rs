//! Jira patch-test tickets — evidences that patches were validated in
//! a test environment before production rollout (SI-02c. family).

use anyhow::Result;
use async_trait::async_trait;
use jira_rs::JiraClient;

use crate::evidence::CsvCollector;

pub struct JiraPatchTestRecordsCollector {
    client: JiraClient,
    project_key: String,
}

impl JiraPatchTestRecordsCollector {
    pub fn new(client: JiraClient, project_key: String) -> Self {
        Self {
            client,
            project_key,
        }
    }
}

#[async_trait]
impl CsvCollector for JiraPatchTestRecordsCollector {
    fn name(&self) -> &str {
        "Jira Patch Test Records"
    }
    fn filename_prefix(&self) -> &str {
        "Jira_Patch_Test_Records"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Ticket",
            "Summary",
            "Status",
            "Patch ID",
            "Test Result",
            "Tested By",
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
            "project = {} AND labels = patch AND labels = test-env",
            self.project_key
        );
        let issues = self
            .client
            .jql_sla()
            .search(&jql, &["labels", "priority"])
            .await?;
        let mut rows = Vec::with_capacity(issues.len());
        for i in issues {
            let patch_id = i
                .extra
                .get("labels")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str())
                        .filter(|s| *s != "patch" && *s != "test-env")
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            let test_result = i.status.clone();
            rows.push(vec![
                i.key,
                i.summary,
                i.status,
                patch_id,
                test_result,
                i.assignee.unwrap_or_default(),
                i.created,
                i.resolved.unwrap_or_default(),
            ]);
        }
        Ok(rows)
    }
}
