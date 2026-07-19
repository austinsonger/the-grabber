//! Paginated JQL executor with changelog-derived SLA timing. Extracts:
//! - created / resolved timestamps and duration_hours
//! - first status transition and its author (approver)
//! - a bag of arbitrary requested fields (labels, priority, custom fields)

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::client::JiraClient;
use crate::error::JiraError;

pub struct JqlSlaApi<'c>(pub(crate) &'c JiraClient);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlaIssue {
    pub key: String,
    pub summary: String,
    pub status: String,
    pub reporter: Option<String>,
    pub assignee: Option<String>,
    pub created: String,
    pub resolved: Option<String>,
    pub duration_hours: Option<f64>,
    pub first_transition_at: Option<String>,
    pub first_transition_by: Option<String>,
    /// Free-form extra fields (labels, priority, custom fields, …).
    #[serde(default)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Deserialize)]
struct JqlPage {
    #[serde(default)]
    issues: Vec<serde_json::Value>,
    #[serde(rename = "nextPageToken", default)]
    next_page_token: Option<String>,
}

impl<'c> JqlSlaApi<'c> {
    /// Execute a JQL query. `extra_fields` = additional Jira field names to
    /// project into `SlaIssue.extra` (e.g. `["labels", "priority", "customfield_10001"]`).
    /// Changelog is expanded so first-transition timing is available.
    pub async fn search(
        &self,
        jql: &str,
        extra_fields: &[&str],
    ) -> Result<Vec<SlaIssue>, JiraError> {
        let mut fields: Vec<&str> = vec![
            "summary",
            "status",
            "reporter",
            "assignee",
            "created",
            "resolutiondate",
        ];
        fields.extend_from_slice(extra_fields);

        let mut all: Vec<SlaIssue> = Vec::new();
        let mut next_token: Option<String> = None;

        loop {
            let mut body = json!({
                "jql": jql,
                "fields": fields,
                "expand": ["changelog"],
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

            for issue in page.issues {
                if let Some(sla) = extract_sla(&issue, extra_fields) {
                    all.push(sla);
                }
            }

            match page.next_page_token {
                Some(tok) if !empty => next_token = Some(tok),
                _ => break,
            }
        }
        Ok(all)
    }
}

fn extract_sla(issue: &serde_json::Value, extra_fields: &[&str]) -> Option<SlaIssue> {
    let key = issue.get("key")?.as_str()?.to_string();
    let fields = issue.get("fields")?;

    let summary = fields
        .get("summary")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let status = fields
        .get("status")
        .and_then(|s| s.get("name"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let reporter = fields
        .get("reporter")
        .and_then(|r| r.get("displayName"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let assignee = fields
        .get("assignee")
        .and_then(|a| a.get("displayName"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let created = fields
        .get("created")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let resolved = fields
        .get("resolutiondate")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let duration_hours = match (created.as_str(), resolved.as_deref()) {
        (c, Some(r)) if !c.is_empty() && !r.is_empty() => {
            let a = chrono::DateTime::parse_from_rfc3339(c).ok()?;
            let b = chrono::DateTime::parse_from_rfc3339(r).ok()?;
            Some((b - a).num_minutes() as f64 / 60.0)
        }
        _ => None,
    };

    let (first_transition_at, first_transition_by) = issue
        .get("changelog")
        .and_then(|c| c.get("histories"))
        .and_then(|h| h.as_array())
        .and_then(|hists| {
            hists.iter().find_map(|h| {
                let items = h.get("items")?.as_array()?;
                let is_status_change = items
                    .iter()
                    .any(|it| it.get("field").and_then(|v| v.as_str()) == Some("status"));
                if is_status_change {
                    let at = h.get("created")?.as_str()?.to_string();
                    let who = h
                        .get("author")
                        .and_then(|a| a.get("displayName"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    Some((Some(at), Some(who)))
                } else {
                    None
                }
            })
        })
        .unwrap_or((None, None));

    let mut extra = serde_json::Map::new();
    for f in extra_fields {
        if let Some(v) = fields.get(*f) {
            extra.insert(f.to_string(), v.clone());
        }
    }

    Some(SlaIssue {
        key,
        summary,
        status,
        reporter,
        assignee,
        created,
        resolved,
        duration_hours,
        first_transition_at,
        first_transition_by,
        extra,
    })
}
