//! Jira firewall-exception tickets — evidences the duration a
//! firewall/network exception has remained active (SC-07 family).

use anyhow::Result;
use async_trait::async_trait;
use jira_rs::JiraClient;

use crate::evidence::CsvCollector;

pub struct JiraFirewallExceptionDurationCollector {
    client: JiraClient,
    project_key: String,
}

impl JiraFirewallExceptionDurationCollector {
    pub fn new(client: JiraClient, project_key: String) -> Self {
        Self {
            client,
            project_key,
        }
    }
}

#[async_trait]
impl CsvCollector for JiraFirewallExceptionDurationCollector {
    fn name(&self) -> &str {
        "Jira Firewall Exception Duration"
    }
    fn filename_prefix(&self) -> &str {
        "Jira_Firewall_Exception_Duration"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Ticket",
            "Summary",
            "Status",
            "Requestor",
            "Approver",
            "Created",
            "Expiration Date",
            "Days Active",
        ]
    }
    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let jql = format!("project = {} AND labels = fw-exception", self.project_key);
        let issues = self
            .client
            .jql_sla()
            .search(&jql, &["labels", "priority", "duedate"])
            .await?;
        let mut rows = Vec::with_capacity(issues.len());
        for i in issues {
            let expiration_date = i
                .extra
                .get("duedate")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let days_active = chrono::DateTime::parse_from_rfc3339(&i.created)
                .ok()
                .map(|c| {
                    (chrono::Utc::now() - c.with_timezone(&chrono::Utc))
                        .num_days()
                        .to_string()
                })
                .unwrap_or_default();
            rows.push(vec![
                i.key,
                i.summary,
                i.status,
                i.reporter.unwrap_or_default(),
                i.first_transition_by.unwrap_or_default(),
                i.created,
                expiration_date,
                days_active,
            ]);
        }
        Ok(rows)
    }
}
