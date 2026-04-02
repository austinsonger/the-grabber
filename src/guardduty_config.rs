use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_guardduty::Client as GdClient;

use crate::evidence::CsvCollector;

// ══════════════════════════════════════════════════════════════════════════════
// 1. GuardDuty Config Collector
// ══════════════════════════════════════════════════════════════════════════════

pub struct GuardDutyConfigCollector {
    client: GdClient,
}

impl GuardDutyConfigCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: GdClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for GuardDutyConfigCollector {
    fn name(&self) -> &str { "GuardDuty Configuration" }
    fn filename_prefix(&self) -> &str { "GuardDuty_Config" }
    fn headers(&self) -> &'static [&'static str] {
        &["Detector ID", "Status", "S3 Protection", "EKS Audit Logs", "Malware Protection", "Created At"]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        let detectors = self.client
            .list_detectors()
            .send()
            .await
            .context("GuardDuty list_detectors")?;

        for detector_id in detectors.detector_ids() {
            let resp = match self.client
                .get_detector()
                .detector_id(detector_id)
                .send()
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: GuardDuty get_detector {detector_id}: {e:#}");
                    continue;
                }
            };

            let status = resp.status()
                .map(|s| s.as_str().to_string())
                .unwrap_or_default();

            let ds = resp.data_sources();

            let s3_protection = ds
                .and_then(|d| d.s3_logs())
                .and_then(|s| s.status())
                .map(|s| s.as_str().to_string())
                .unwrap_or_default();

            let eks_audit = ds
                .and_then(|d| d.kubernetes())
                .and_then(|k| k.audit_logs())
                .and_then(|a| a.status())
                .map(|s| s.as_str().to_string())
                .unwrap_or_default();

            let malware = ds
                .and_then(|d| d.malware_protection())
                .and_then(|m| m.scan_ec2_instance_with_findings())
                .and_then(|e| e.ebs_volumes())
                .and_then(|v| v.status())
                .map(|s| s.as_str().to_string())
                .unwrap_or_default();

            let created_at = resp.created_at().unwrap_or("").to_string();

            rows.push(vec![
                detector_id.to_string(),
                status,
                s3_protection,
                eks_audit,
                malware,
                created_at,
            ]);
        }

        Ok(rows)
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// 2. GuardDuty Suppression Collector
// ══════════════════════════════════════════════════════════════════════════════

pub struct GuardDutySuppressionCollector {
    client: GdClient,
}

impl GuardDutySuppressionCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: GdClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for GuardDutySuppressionCollector {
    fn name(&self) -> &str { "GuardDuty Suppression Rules" }
    fn filename_prefix(&self) -> &str { "GuardDuty_Suppression" }
    fn headers(&self) -> &'static [&'static str] {
        &["Detector ID", "Rule Name", "Action", "Description", "Filter Criteria Summary"]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        let detectors = self.client
            .list_detectors()
            .send()
            .await
            .context("GuardDuty list_detectors")?;

        for detector_id in detectors.detector_ids() {
            let filters_resp = match self.client
                .list_filters()
                .detector_id(detector_id)
                .send()
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: GuardDuty list_filters for {detector_id}: {e:#}");
                    continue;
                }
            };

            for filter_name in filters_resp.filter_names() {
                let filter_resp = match self.client
                    .get_filter()
                    .detector_id(detector_id)
                    .filter_name(filter_name)
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("  WARN: GuardDuty get_filter {filter_name}: {e:#}");
                        continue;
                    }
                };

                let action = filter_resp.action()
                    .map(|a| a.as_str().to_string())
                    .unwrap_or_default();

                let description = filter_resp.description()
                    .unwrap_or("")
                    .to_string();

                let criteria_summary = filter_resp.finding_criteria()
                    .map(|fc| {
                        fc.criterion()
                            .map(|c| c.keys().cloned().collect::<Vec<_>>().join(", "))
                            .unwrap_or_default()
                    })
                    .unwrap_or_default();

                rows.push(vec![
                    detector_id.to_string(),
                    filter_name.to_string(),
                    action,
                    description,
                    criteria_summary,
                ]);
            }
        }

        Ok(rows)
    }
}
