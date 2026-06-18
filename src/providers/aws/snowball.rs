use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_snowball::Client as SnowballClient;
use chrono::{TimeZone, Utc};

use crate::evidence::CsvCollector;

// ══════════════════════════════════════════════════════════════════════════════
// Snowball Jobs Collector — list_jobs() with type, state, snowball type, created.
// ══════════════════════════════════════════════════════════════════════════════

pub struct SnowballJobsCollector {
    client: SnowballClient,
}

impl SnowballJobsCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: SnowballClient::new(config),
        }
    }
}

fn is_benign(err: &str) -> bool {
    err.contains("AccessDenied")
        || err.contains("AccessDeniedException")
        || err.contains("UnauthorizedOperation")
        || err.contains("not available")
        || err.contains("UnknownEndpoint")
        || err.contains("dispatch failure")
        || err.contains("InvalidAction")
        || err.contains("OptInRequired")
}

#[async_trait]
impl CsvCollector for SnowballJobsCollector {
    fn name(&self) -> &str {
        "Snowball Jobs"
    }
    fn filename_prefix(&self) -> &str {
        "Snowball_Jobs"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Job ID",
            "State",
            "Job Type",
            "Snowball Type",
            "Created",
            "Description",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows: Vec<Vec<String>> = Vec::new();

        let mut paginator = self.client.list_jobs().into_paginator().send();
        while let Some(page) = paginator.next().await {
            let resp = match page {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e:#}");
                    if is_benign(&msg) {
                        return Ok(rows);
                    }
                    eprintln!("  WARN: Snowball list_jobs: {msg}");
                    break;
                }
            };
            for j in resp.job_list_entries() {
                if j.is_master() {
                    continue;
                }
                let id = j.job_id().unwrap_or("").to_string();
                let state = j
                    .job_state()
                    .map(|s| s.as_str().to_string())
                    .unwrap_or_default();
                let jtype = j
                    .job_type()
                    .map(|t| t.as_str().to_string())
                    .unwrap_or_default();
                let stype = j
                    .snowball_type()
                    .map(|t| t.as_str().to_string())
                    .unwrap_or_default();
                let created = j
                    .creation_date()
                    .and_then(|d| Utc.timestamp_opt(d.secs(), 0).single())
                    .map(|d| d.to_rfc3339())
                    .unwrap_or_default();
                let desc = j.description().unwrap_or("").to_string();
                rows.push(vec![id, state, jtype, stype, created, desc]);
            }
        }

        Ok(rows)
    }
}
