use anyhow::Result;
use async_trait::async_trait;
use jira_rs::JiraClient;

use crate::evidence::CsvCollector;

pub struct JiraIssuesCollector {
    client: JiraClient,
}

impl JiraIssuesCollector {
    pub fn new(client: JiraClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for JiraIssuesCollector {
    fn name(&self) -> &str {
        "Jira Issues"
    }
    fn filename_prefix(&self) -> &str {
        "Jira_Issues"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Issue Key",
            "Summary",
            "Type",
            "Status",
            "Priority",
            "Assignee",
            "Reporter",
            "Created",
            "Updated",
            "Resolved",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let jql = match dates {
            Some((start_secs, end_secs)) => {
                let start = chrono::DateTime::<chrono::Utc>::from_timestamp(start_secs, 0)
                    .map(|d| d.format("%Y-%m-%d").to_string())
                    .unwrap_or_default();
                let end = chrono::DateTime::<chrono::Utc>::from_timestamp(end_secs, 0)
                    .map(|d| d.format("%Y-%m-%d").to_string())
                    .unwrap_or_default();
                format!("updated >= \"{}\" AND updated <= \"{}\"", start, end)
            }
            None => String::new(),
        };
        let issues = match self.client.issues().search(&jql).await {
            Ok(i) => i,
            Err(jira_rs::JiraError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };
        let rows = issues
            .into_iter()
            .map(|i| {
                let f = i.fields;
                vec![
                    i.key,
                    f.summary.unwrap_or_default(),
                    f.issuetype.map(|t| t.name).unwrap_or_default(),
                    f.status.map(|s| s.name).unwrap_or_default(),
                    f.priority.map(|p| p.name).unwrap_or_default(),
                    f.assignee.map(|u| u.display_name).unwrap_or_default(),
                    f.reporter.map(|u| u.display_name).unwrap_or_default(),
                    f.created.unwrap_or_default(),
                    f.updated.unwrap_or_default(),
                    f.resolutiondate.unwrap_or_default(),
                ]
            })
            .collect();
        Ok(rows)
    }
}
