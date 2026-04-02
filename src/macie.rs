use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_macie2::Client as MacieClient;

use crate::evidence::CsvCollector;

fn fmt_macie_dt(dt: &aws_sdk_macie2::primitives::DateTime) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(dt.secs(), 0)
        .map(|c| c.to_rfc3339())
        .unwrap_or_default()
}

pub struct MacieCollector {
    client: MacieClient,
}

impl MacieCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: MacieClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for MacieCollector {
    fn name(&self) -> &str { "Macie Findings" }
    fn filename_prefix(&self) -> &str { "Macie_Findings" }
    fn headers(&self) -> &'static [&'static str] {
        &["Finding ID", "Finding Type", "Resource ARN", "Severity", "Count", "Created At"]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut next_token: Option<String> = None;
        let mut all_finding_ids: Vec<String> = Vec::new();

        // ── 1. Page through list_findings to collect IDs ──────────────────────
        loop {
            let mut req = self.client
                .list_findings()
                .max_results(50);
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: Macie list_findings: {e:#}");
                    return Ok(rows);
                }
            };

            all_finding_ids.extend(resp.finding_ids().iter().map(|s| s.to_string()));

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() { break; }
        }

        // ── 2. Get findings in batches of 25 ────────────────────────────────
        for chunk in all_finding_ids.chunks(25) {
            let resp = match self.client
                .get_findings()
                .set_finding_ids(Some(chunk.to_vec()))
                .send()
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: Macie get_findings: {e:#}");
                    continue;
                }
            };

            for finding in resp.findings() {
                let id = finding.id().unwrap_or("").to_string();
                let finding_type = finding.r#type()
                    .map(|t| t.as_str().to_string())
                    .unwrap_or_default();

                let resource_arn = finding.resources_affected()
                    .and_then(|r| r.s3_bucket())
                    .and_then(|b| b.arn())
                    .unwrap_or("")
                    .to_string();

                let severity = finding.severity()
                    .and_then(|s| s.description())
                    .map(|d| d.as_str().to_string())
                    .unwrap_or_default();

                let count = finding.count()
                    .map(|n| n.to_string())
                    .unwrap_or_default();

                let created_at = finding.created_at()
                    .map(fmt_macie_dt)
                    .unwrap_or_default();

                rows.push(vec![
                    id,
                    finding_type,
                    resource_arn,
                    severity,
                    count,
                    created_at,
                ]);
            }
        }

        Ok(rows)
    }
}
