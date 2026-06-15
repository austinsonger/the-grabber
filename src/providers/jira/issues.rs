use anyhow::Result;
use async_trait::async_trait;
use jira_rs::JiraClient;

use crate::evidence::CsvCollector;

pub struct JiraIssuesCollector {
    client: JiraClient,
    project_keys: Vec<String>,
}

impl JiraIssuesCollector {
    pub fn new(client: JiraClient) -> Self {
        Self {
            client,
            project_keys: Vec::new(),
        }
    }

    pub fn with_projects(client: JiraClient, project_keys: Vec<String>) -> Self {
        Self {
            client,
            project_keys,
        }
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
            "Resolution",
            "Assignee",
            "Reporter",
            "Parent",
            "Labels",
            "Components",
            "Fix Versions",
            "Created",
            "Updated",
            "Resolved",
            "Due Date",
            "Description",
            "Comments",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut clauses: Vec<String> = Vec::new();
        if !self.project_keys.is_empty() {
            let list = self
                .project_keys
                .iter()
                .map(|k| format!("\"{}\"", k))
                .collect::<Vec<_>>()
                .join(", ");
            clauses.push(format!("project in ({})", list));
        }
        if let Some((start_secs, end_secs)) = dates {
            let start = chrono::DateTime::<chrono::Utc>::from_timestamp(start_secs, 0)
                .map(|d| d.format("%Y-%m-%d").to_string())
                .unwrap_or_default();
            let end = chrono::DateTime::<chrono::Utc>::from_timestamp(end_secs, 0)
                .map(|d| d.format("%Y-%m-%d").to_string())
                .unwrap_or_default();
            clauses.push(format!(
                "updated >= \"{}\" AND updated <= \"{}\"",
                start, end
            ));
        }
        let jql = clauses.join(" AND ");
        let issues = match self.client.issues().search(&jql).await {
            Ok(i) => i,
            Err(jira_rs::JiraError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };
        let rows = issues
            .into_iter()
            .map(|i| {
                let f = i.fields;
                let description = f
                    .description
                    .as_ref()
                    .map(jira_rs::types::issue::adf_to_plain_text)
                    .unwrap_or_default();
                let comments = f
                    .comment
                    .as_ref()
                    .map(|c| {
                        c.comments
                            .iter()
                            .map(|cmt| {
                                let author = cmt
                                    .author
                                    .as_ref()
                                    .map(|a| a.display_name.as_str())
                                    .unwrap_or("");
                                let when = cmt.created.as_deref().unwrap_or("");
                                let body = cmt
                                    .body
                                    .as_ref()
                                    .map(jira_rs::types::issue::adf_to_plain_text)
                                    .unwrap_or_default();
                                format!("[{} @ {}] {}", author, when, body)
                            })
                            .collect::<Vec<_>>()
                            .join("\n---\n")
                    })
                    .unwrap_or_default();
                let labels = f.labels.join(", ");
                let components = f
                    .components
                    .iter()
                    .map(|c| c.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                let fix_versions = f
                    .fix_versions
                    .iter()
                    .map(|c| c.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                vec![
                    i.key,
                    f.summary.unwrap_or_default(),
                    f.issuetype.map(|t| t.name).unwrap_or_default(),
                    f.status.map(|s| s.name).unwrap_or_default(),
                    f.priority.map(|p| p.name).unwrap_or_default(),
                    f.resolution.map(|r| r.name).unwrap_or_default(),
                    f.assignee.map(|u| u.display_name).unwrap_or_default(),
                    f.reporter.map(|u| u.display_name).unwrap_or_default(),
                    f.parent.map(|p| p.key).unwrap_or_default(),
                    labels,
                    components,
                    fix_versions,
                    f.created.unwrap_or_default(),
                    f.updated.unwrap_or_default(),
                    f.resolutiondate.unwrap_or_default(),
                    f.duedate.unwrap_or_default(),
                    description,
                    comments,
                ]
            })
            .collect();
        Ok(rows)
    }
}
