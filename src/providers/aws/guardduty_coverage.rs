use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_guardduty::Client as GdClient;

use crate::evidence::CsvCollector;

// ══════════════════════════════════════════════════════════════════════════════
// GuardDuty Coverage Collector
// ══════════════════════════════════════════════════════════════════════════════

pub struct GuardDutyCoverageCollector {
    client: GdClient,
}

impl GuardDutyCoverageCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: GdClient::new(config),
        }
    }
}

fn fmt_dt(dt: &aws_sdk_guardduty::primitives::DateTime) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(dt.secs(), dt.subsec_nanos())
        .map(|c| c.to_rfc3339())
        .unwrap_or_default()
}

#[async_trait]
impl CsvCollector for GuardDutyCoverageCollector {
    fn name(&self) -> &str {
        "GuardDuty Coverage"
    }
    fn filename_prefix(&self) -> &str {
        "GuardDuty_Coverage"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Detector ID",
            "Resource ID",
            "Resource Type",
            "Coverage Status",
            "Issue",
            "Updated At",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        let detectors = self
            .client
            .list_detectors()
            .send()
            .await
            .context("GuardDuty list_detectors")?;

        for detector_id in detectors.detector_ids() {
            let mut next_token: Option<String> = None;
            loop {
                let mut req = self.client.list_coverage().detector_id(detector_id);
                if let Some(ref t) = next_token {
                    req = req.next_token(t);
                }
                let resp = match req.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("  WARN: GuardDuty list_coverage {detector_id}: {e:#}");
                        break;
                    }
                };

                for cov in resp.resources() {
                    let resource_id = cov.resource_id().unwrap_or("").to_string();
                    let resource_type = cov
                        .resource_details()
                        .and_then(|d| d.resource_type())
                        .map(|t| t.as_str().to_string())
                        .unwrap_or_default();
                    let status = cov
                        .coverage_status()
                        .map(|s| s.as_str().to_string())
                        .unwrap_or_default();
                    let issue = cov.issue().unwrap_or("").to_string();
                    let updated_at = cov.updated_at().map(fmt_dt).unwrap_or_default();

                    rows.push(vec![
                        detector_id.to_string(),
                        resource_id,
                        resource_type,
                        status,
                        issue,
                        updated_at,
                    ]);
                }

                match resp.next_token() {
                    Some(t) if !t.is_empty() => next_token = Some(t.to_string()),
                    _ => break,
                }
            }
        }

        Ok(rows)
    }
}
