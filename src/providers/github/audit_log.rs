use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use github_rs::{GithubClient, GithubError};

use crate::evidence::CsvCollector;

pub struct GithubAuditLogCollector {
    pub(crate) client: GithubClient,
}

impl GithubAuditLogCollector {
    pub fn new(client: GithubClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for GithubAuditLogCollector {
    fn name(&self) -> &str {
        "GitHub Org Audit Log"
    }
    fn filename_prefix(&self) -> &str {
        "Github_Org_Audit_Log"
    }
    fn headers(&self) -> &'static [&'static str] {
        &["Action", "Actor", "User", "Org", "Created At", "Document ID"]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let (start_secs, end_secs) = match dates {
            Some(d) => d,
            None => {
                let now = Utc::now();
                let start = now - chrono::Duration::days(90);
                (start.timestamp(), now.timestamp())
            }
        };
        let since = DateTime::<Utc>::from_timestamp(start_secs, 0)
            .unwrap_or_else(Utc::now)
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        let until = DateTime::<Utc>::from_timestamp(end_secs, 0)
            .unwrap_or_else(Utc::now)
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();

        // Requires GitHub Enterprise Cloud — any other plan 403s/404s here.
        let events = match self.client.audit_log().events(&since, &until).await {
            Ok(e) => e,
            Err(GithubError::Api { status: 403, .. }) => return Ok(vec![]),
            Err(GithubError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };

        Ok(events
            .into_iter()
            .map(|e| {
                let created_at = e
                    .created_at
                    .and_then(|ms| DateTime::<Utc>::from_timestamp_millis(ms))
                    .map(|dt| dt.to_rfc3339())
                    .unwrap_or_default();
                vec![
                    e.action,
                    e.actor.unwrap_or_default(),
                    e.user.unwrap_or_default(),
                    e.org.unwrap_or_default(),
                    created_at,
                    e.document_id.unwrap_or_default(),
                ]
            })
            .collect())
    }
}
