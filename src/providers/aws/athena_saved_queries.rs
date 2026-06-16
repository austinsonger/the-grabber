use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_athena::Client as AthenaClient;

use crate::evidence::CsvCollector;

// ══════════════════════════════════════════════════════════════════════════════
// Athena Saved (Named) Queries — filtered to log-review queries
// ══════════════════════════════════════════════════════════════════════════════

const LOG_KEYWORDS: &[&str] = &[
    "cloudtrail",
    "vpc_flow",
    "vpcflow",
    "flow_logs",
    "waf_logs",
    "wafv2",
    "securityhub",
    "guardduty",
];

pub struct AthenaSavedQueriesCollector {
    client: AthenaClient,
}

impl AthenaSavedQueriesCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: AthenaClient::new(config),
        }
    }
}

fn excerpt(stmt: &str) -> String {
    let normalized: String = stmt
        .chars()
        .map(|c| if c == '\n' || c == '\r' { ' ' } else { c })
        .collect();
    if normalized.chars().count() > 500 {
        normalized.chars().take(500).collect()
    } else {
        normalized
    }
}

#[async_trait]
impl CsvCollector for AthenaSavedQueriesCollector {
    fn name(&self) -> &str {
        "Athena Log-Review Saved Queries"
    }
    fn filename_prefix(&self) -> &str {
        "Athena_LogReview_Queries"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "WorkGroup",
            "Query Name",
            "Query ID",
            "Database",
            "Description",
            "Last Executed",
            "Query Statement Excerpt",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        // Enumerate work groups via list_work_groups pagination.
        let mut workgroups: Vec<String> = Vec::new();
        let mut wg_paginator = self.client.list_work_groups().into_paginator().send();
        while let Some(page) = wg_paginator.next().await {
            let resp = match page {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: Athena list_work_groups: {e:#}");
                    break;
                }
            };
            for wg in resp.work_groups() {
                if let Some(name) = wg.name() {
                    workgroups.push(name.to_string());
                }
            }
        }

        for wg_name in &workgroups {
            // Collect all named query IDs for this work group.
            let mut query_ids: Vec<String> = Vec::new();
            let mut nq_paginator = self
                .client
                .list_named_queries()
                .work_group(wg_name)
                .into_paginator()
                .send();
            while let Some(page) = nq_paginator.next().await {
                let resp = match page {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("  WARN: Athena list_named_queries [{wg_name}]: {e:#}");
                        break;
                    }
                };
                for id in resp.named_query_ids() {
                    query_ids.push(id.to_string());
                }
            }

            // Athena's batch_get_named_query accepts up to 50 ids per call.
            for chunk in query_ids.chunks(50) {
                let resp = match self
                    .client
                    .batch_get_named_query()
                    .set_named_query_ids(Some(chunk.to_vec()))
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("  WARN: Athena batch_get_named_query [{wg_name}]: {e:#}");
                        continue;
                    }
                };

                for nq in resp.named_queries() {
                    let stmt = nq.query_string();
                    let stmt_lc = stmt.to_lowercase();
                    if !LOG_KEYWORDS.iter().any(|kw| stmt_lc.contains(kw)) {
                        continue;
                    }

                    let name = nq.name().to_string();
                    let database = nq.database().to_string();
                    let description = nq.description().unwrap_or("").to_string();
                    let qid = nq.named_query_id().unwrap_or("").to_string();

                    rows.push(vec![
                        wg_name.clone(),
                        name,
                        qid,
                        database,
                        description,
                        "N/A".to_string(),
                        excerpt(stmt),
                    ]);
                }
            }
        }

        Ok(rows)
    }
}
