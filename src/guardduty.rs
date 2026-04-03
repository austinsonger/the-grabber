use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_guardduty::Client as GdClient;
use aws_sdk_guardduty::types::{Condition, FindingCriteria};

use crate::evidence::CsvCollector;

pub struct GuardDutyCollector {
    client: GdClient,
}

impl GuardDutyCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: GdClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for GuardDutyCollector {
    fn name(&self) -> &str { "GuardDuty Findings" }
    fn filename_prefix(&self) -> &str { "GuardDuty_Findings" }
    fn headers(&self) -> &'static [&'static str] {
        &["Finding ID", "Type", "Severity", "Resource", "Region", "Created At", "Status"]
    }

    async fn collect_rows(&self, _account_id: &str, region: &str, dates: Option<(i64, i64)>) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        let detectors = self.client
            .list_detectors()
            .send()
            .await
            .context("GuardDuty list_detectors")?;

        for detector_id in detectors.detector_ids() {
            const MAX_FINDINGS: usize = 500;
            let mut next_token: Option<String> = None;
            let mut all_finding_ids: Vec<String> = Vec::new();

            loop {
                // Build criteria: non-archived, optionally date-filtered.
                let mut criteria = FindingCriteria::builder()
                    .criterion(
                        "service.archived",
                        Condition::builder().equals("false").build(),
                    );
                if let Some((start, end)) = dates {
                    // GuardDuty createdAt is stored as epoch milliseconds in the criterion.
                    criteria = criteria
                        .criterion(
                            "createdAt",
                            Condition::builder()
                                .greater_than_or_equal(start * 1000)
                                .less_than_or_equal(end * 1000)
                                .build(),
                        );
                }

                let mut req = self.client
                    .list_findings()
                    .detector_id(detector_id)
                    .max_results(50)
                    .finding_criteria(criteria.build());
                if let Some(ref t) = next_token {
                    req = req.next_token(t);
                }
                let resp = req.send().await.context("GuardDuty list_findings")?;
                all_finding_ids.extend(resp.finding_ids().iter().map(|s| s.to_string()));
                next_token = resp.next_token().map(|s| s.to_string());
                if next_token.is_none() || all_finding_ids.len() >= MAX_FINDINGS { break; }
            }
            all_finding_ids.truncate(MAX_FINDINGS);

            for chunk in all_finding_ids.chunks(50) {
                let resp = match self.client
                    .get_findings()
                    .detector_id(detector_id)
                    .set_finding_ids(Some(chunk.to_vec()))
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("  WARN: GuardDuty get_findings: {e:#}");
                        continue;
                    }
                };

                for finding in resp.findings() {
                    let id       = finding.id().unwrap_or("").to_string();
                    let f_type   = finding.r#type().unwrap_or("").to_string();
                    let severity = finding.severity()
                        .map(|s| s.to_string())
                        .unwrap_or_default();
                    let resource = finding.resource()
                        .and_then(|r| r.resource_type())
                        .unwrap_or("")
                        .to_string();
                    let created  = finding.created_at().unwrap_or("").to_string();
                    let status   = if finding.service()
                        .and_then(|s| s.archived())
                        .unwrap_or(false)
                    { "ARCHIVED" } else { "ACTIVE" }.to_string();

                    rows.push(vec![id, f_type, severity, resource, region.to_string(), created, status]);
                }
            }
        }

        Ok(rows)
    }
}
