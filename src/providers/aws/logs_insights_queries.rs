use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_cloudwatchlogs::Client as CwlClient;

use crate::evidence::CsvCollector;

// ══════════════════════════════════════════════════════════════════════════════
// CloudWatch Logs Insights Saved Queries
// ══════════════════════════════════════════════════════════════════════════════

pub struct LogsInsightsSavedQueriesCollector {
    client: CwlClient,
}

impl LogsInsightsSavedQueriesCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: CwlClient::new(config),
        }
    }
}

fn fmt_millis(ms: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(ms)
        .map(|c| c.to_rfc3339())
        .unwrap_or_default()
}

fn truncate_query(s: &str) -> String {
    let collapsed = s.replace('\n', " ").replace('\r', " ");
    if collapsed.chars().count() <= 500 {
        collapsed
    } else {
        collapsed.chars().take(500).collect()
    }
}

#[async_trait]
impl CsvCollector for LogsInsightsSavedQueriesCollector {
    fn name(&self) -> &str {
        "CloudWatch Logs Insights Saved Queries"
    }
    fn filename_prefix(&self) -> &str {
        "CloudWatch_LogsInsights_SavedQueries"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Query Name",
            "Query Definition ID",
            "Last Modified",
            "Log Groups",
            "Query String Excerpt",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        let mut next_token: Option<String> = None;
        loop {
            let mut req = self.client.describe_query_definitions();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: CloudWatch Logs describe_query_definitions: {e:#}");
                    break;
                }
            };
            for qd in resp.query_definitions() {
                let name = qd.name().unwrap_or("").to_string();
                let id = qd.query_definition_id().unwrap_or("").to_string();
                let last_modified = qd.last_modified().map(fmt_millis).unwrap_or_default();
                let log_groups = qd.log_group_names().join(", ");
                let query_excerpt = truncate_query(qd.query_string().unwrap_or(""));

                rows.push(vec![name, id, last_modified, log_groups, query_excerpt]);
            }
            match resp.next_token() {
                Some(t) if !t.is_empty() => next_token = Some(t.to_string()),
                _ => break,
            }
        }

        Ok(rows)
    }
}
