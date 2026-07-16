//! `guardduty:GetCoverageStatistics` + `ListCoverage` — emits per-resource
//! runtime-monitoring coverage for EKS, ECS, and EC2 so auditors can prove
//! HIPS/HIDS deployment percentage per FedRAMP SC-07(12).

use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_guardduty::Client as GdClient;

use crate::evidence::CsvCollector;

pub struct GuardDutyRuntimeCoverageCollector {
    client: GdClient,
}

impl GuardDutyRuntimeCoverageCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: GdClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for GuardDutyRuntimeCoverageCollector {
    fn name(&self) -> &str {
        "GuardDuty Runtime Coverage"
    }
    fn filename_prefix(&self) -> &str {
        "GuardDuty_Runtime_Coverage"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Detector ID",
            "Resource Type",
            "Resource ID",
            "Coverage Status",
            "Issue",
            "Updated At",
            "Region",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows: Vec<Vec<String>> = Vec::new();

        let mut det_next: Option<String> = None;
        let mut detectors: Vec<String> = Vec::new();
        loop {
            let mut req = self.client.list_detectors();
            if let Some(t) = det_next.as_ref() {
                req = req.next_token(t);
            }
            let resp = req.send().await.context("guardduty:ListDetectors")?;
            detectors.extend(resp.detector_ids().iter().cloned());
            det_next = resp.next_token().map(|s| s.to_string());
            if det_next.is_none() {
                break;
            }
        }

        for det in &detectors {
            let mut cov_next: Option<String> = None;
            loop {
                let mut req = self.client.list_coverage().detector_id(det);
                if let Some(t) = cov_next.as_ref() {
                    req = req.next_token(t);
                }
                let resp = req
                    .send()
                    .await
                    .with_context(|| format!("guardduty:ListCoverage {det}"))?;
                for r in resp.resources() {
                    rows.push(vec![
                        det.clone(),
                        r.resource_details()
                            .and_then(|d| d.resource_type())
                            .map(|s| s.as_str().to_string())
                            .unwrap_or_default(),
                        r.resource_id().unwrap_or("").into(),
                        r.coverage_status()
                            .map(|s| s.as_str().to_string())
                            .unwrap_or_default(),
                        r.issue().unwrap_or("").into(),
                        r.updated_at()
                            .map(|t| t.to_string())
                            .unwrap_or_default(),
                        region.into(),
                    ]);
                }
                cov_next = resp.next_token().map(|s| s.to_string());
                if cov_next.is_none() {
                    break;
                }
            }
        }
        Ok(rows)
    }
}
