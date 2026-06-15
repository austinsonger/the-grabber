use serde::Deserialize;
use serde_json::json;

use crate::client::JiraClient;
use crate::error::JiraError;
use crate::types::issue::JiraIssue;

pub struct IssuesApi<'c>(pub(crate) &'c JiraClient);

#[derive(Deserialize)]
struct JqlPage {
    #[serde(default)]
    issues: Vec<JiraIssue>,
    #[serde(rename = "nextPageToken", default)]
    next_page_token: Option<String>,
}

impl<'c> IssuesApi<'c> {
    /// POST /rest/api/3/search/jql — JQL search with cursor pagination.
    ///
    /// `jql` is the JQL string; pass an empty string to list every accessible issue.
    pub async fn search(&self, jql: &str) -> Result<Vec<JiraIssue>, JiraError> {
        let fields = vec![
            "summary",
            "status",
            "priority",
            "issuetype",
            "assignee",
            "reporter",
            "created",
            "updated",
            "resolutiondate",
            "duedate",
            "resolution",
            "labels",
            "components",
            "fixVersions",
            "parent",
            "description",
            "comment",
        ];
        let mut all = Vec::new();
        let mut next_token: Option<String> = None;
        loop {
            let mut body = json!({
                "jql": jql,
                "fields": fields,
                "maxResults": 100,
            });
            if let Some(tok) = &next_token {
                body["nextPageToken"] = json!(tok);
            }
            let resp = self.0.post_json("/rest/api/3/search/jql", body).await?;
            if !resp.status().is_success() {
                let status = resp.status().as_u16();
                let message = resp.text().await.unwrap_or_default();
                return Err(JiraError::Api { status, message });
            }
            let page: JqlPage = resp.json().await?;
            let empty = page.issues.is_empty();
            all.extend(page.issues);
            match page.next_page_token {
                Some(tok) if !empty => next_token = Some(tok),
                _ => break,
            }
        }
        Ok(all)
    }
}
