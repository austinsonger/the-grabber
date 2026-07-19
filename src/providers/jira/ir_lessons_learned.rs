//! Jira incident lessons-learned tickets — evidences closure of the
//! post-incident lessons-learned review (IR-04c.[02] family).

use anyhow::Result;
use async_trait::async_trait;
use jira_rs::JiraClient;

use crate::evidence::CsvCollector;

pub struct JiraIrLessonsLearnedCollector {
    client: JiraClient,
    project_key: String,
}

impl JiraIrLessonsLearnedCollector {
    pub fn new(client: JiraClient, project_key: String) -> Self {
        Self {
            client,
            project_key,
        }
    }
}

#[async_trait]
impl CsvCollector for JiraIrLessonsLearnedCollector {
    fn name(&self) -> &str {
        "Jira IR Lessons Learned Closure"
    }
    fn filename_prefix(&self) -> &str {
        "Jira_IR_Lessons_Learned_Closure"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Ticket", "Summary", "Status", "Reviewer", "Created", "Resolved",
        ]
    }
    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let jql = format!(
            "project = {} AND labels = lessons-learned",
            self.project_key
        );
        let issues = self
            .client
            .jql_sla()
            .search(&jql, &["labels", "priority"])
            .await?;
        let mut rows = Vec::with_capacity(issues.len());
        for i in issues {
            rows.push(vec![
                i.key,
                i.summary,
                i.status,
                i.assignee.unwrap_or_default(),
                i.created,
                i.resolved.unwrap_or_default(),
            ]);
        }
        Ok(rows)
    }
}
