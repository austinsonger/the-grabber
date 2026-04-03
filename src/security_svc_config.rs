use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_guardduty::Client as GdClient;
use aws_sdk_securityhub::Client as ShClient;
use aws_sdk_config::Client as CfgClient;

use crate::evidence::CsvCollector;

// ══════════════════════════════════════════════════════════════════════════════
// 1. GuardDuty Full Configuration
// ══════════════════════════════════════════════════════════════════════════════

pub struct GuardDutyFullConfigCollector {
    client: GdClient,
}

impl GuardDutyFullConfigCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: GdClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for GuardDutyFullConfigCollector {
    fn name(&self) -> &str { "GuardDuty Full Configuration" }
    fn filename_prefix(&self) -> &str { "GuardDuty_Full_Config" }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Detector ID", "Status", "Finding Publishing Frequency",
            "S3 Logs", "EKS Audit Logs", "Malware Protection", "Created At",
        ]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str, _dates: Option<(i64, i64)>) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        let detectors = self.client
            .list_detectors()
            .send()
            .await
            .context("GuardDuty list_detectors")?;

        for detector_id in detectors.detector_ids() {
            let resp = match self.client.get_detector().detector_id(detector_id).send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: GuardDuty get_detector {detector_id}: {e:#}");
                    continue;
                }
            };

            let status = resp.status()
                .map(|s| s.as_str().to_string())
                .unwrap_or_default();

            let publish_freq = resp.finding_publishing_frequency()
                .map(|f| f.as_str().to_string())
                .unwrap_or_default();

            let created_at = resp.created_at().unwrap_or("").to_string();

            #[allow(deprecated)]
            let ds = resp.data_sources();

            #[allow(deprecated)]
            let s3_logs = ds
                .and_then(|d| d.s3_logs())
                .and_then(|s| s.status())
                .map(|s| s.as_str().to_string())
                .unwrap_or_default();

            #[allow(deprecated)]
            let eks_audit = ds
                .and_then(|d| d.kubernetes())
                .and_then(|k| k.audit_logs())
                .and_then(|a| a.status())
                .map(|s| s.as_str().to_string())
                .unwrap_or_default();

            #[allow(deprecated)]
            let malware = ds
                .and_then(|d| d.malware_protection())
                .and_then(|m| m.scan_ec2_instance_with_findings())
                .and_then(|e| e.ebs_volumes())
                .and_then(|v| v.status())
                .map(|s| s.as_str().to_string())
                .unwrap_or_default();

            rows.push(vec![
                detector_id.to_string(),
                status,
                publish_freq,
                s3_logs,
                eks_audit,
                malware,
                created_at,
            ]);
        }

        Ok(rows)
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// 2. Security Hub Configuration
// ══════════════════════════════════════════════════════════════════════════════

pub struct SecurityHubConfigCollector {
    client: ShClient,
}

impl SecurityHubConfigCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: ShClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for SecurityHubConfigCollector {
    fn name(&self) -> &str { "Security Hub Configuration" }
    fn filename_prefix(&self) -> &str { "SecurityHub_Config" }
    fn headers(&self) -> &'static [&'static str] {
        &["Hub ARN", "Auto Enable Controls", "Subscribed Standards", "Subscribed At"]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str, _dates: Option<(i64, i64)>) -> Result<Vec<Vec<String>>> {
        let hub_resp = match self.client.describe_hub().send().await {
            Ok(r) => r,
            Err(e) => {
                eprintln!("  WARN: SecurityHub describe_hub (not enabled?): {e:#}");
                return Ok(vec![]);
            }
        };

        let hub_arn        = hub_resp.hub_arn().unwrap_or("").to_string();
        let auto_enable    = hub_resp.auto_enable_controls().unwrap_or(false).to_string();
        let subscribed_at  = hub_resp.subscribed_at().unwrap_or("").to_string();

        // Get subscribed standards
        let standards = match self.client.get_enabled_standards().send().await {
            Ok(r) => r.standards_subscriptions()
                .iter()
                .filter_map(|s| s.standards_arn())
                .map(|arn| {
                    // Extract human-readable name from ARN
                    // e.g. arn:aws:securityhub:::standards/aws-foundational-security-best-practices/v/1.0.0
                    arn.split('/').nth(1).unwrap_or(arn).to_string()
                })
                .collect::<Vec<_>>()
                .join(", "),
            Err(_) => String::new(),
        };

        Ok(vec![vec![hub_arn, auto_enable, standards, subscribed_at]])
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// 3. AWS Config Recorder
// ══════════════════════════════════════════════════════════════════════════════

pub struct AwsConfigRecorderCollector {
    client: CfgClient,
}

impl AwsConfigRecorderCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: CfgClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for AwsConfigRecorderCollector {
    fn name(&self) -> &str { "AWS Config Recorder" }
    fn filename_prefix(&self) -> &str { "AWS_Config_Recorder" }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Recorder Name", "Role ARN", "All Supported", "Include Global Resources",
            "Recording", "Last Status", "Last Status Change",
        ]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str, _dates: Option<(i64, i64)>) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        let recorders = match self.client
            .describe_configuration_recorders()
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                eprintln!("  WARN: Config describe_configuration_recorders: {e:#}");
                return Ok(rows);
            }
        };

        // Get recorder statuses
        let statuses = match self.client
            .describe_configuration_recorder_status()
            .send()
            .await
        {
            Ok(r) => r.configuration_recorders_status()
                .iter()
                .map(|s| (
                    s.name().unwrap_or("").to_string(),
                    s.recording().to_string(),
                    s.last_status().map(|ls| ls.as_str().to_string()).unwrap_or_default(),
                    s.last_status_change_time()
                        .map(|dt| {
                            chrono::DateTime::<chrono::Utc>::from_timestamp(dt.secs(), 0)
                                .map(|c| c.to_rfc3339())
                                .unwrap_or_default()
                        })
                        .unwrap_or_default(),
                ))
                .collect::<Vec<_>>(),
            Err(_) => vec![],
        };

        for recorder in recorders.configuration_recorders() {
            let name     = recorder.name().unwrap_or("default").to_string();
            let role_arn = recorder.role_arn().unwrap_or("").to_string();

            let all_supported = recorder.recording_group()
                .map(|rg| rg.all_supported().to_string())
                .unwrap_or_default();
            let include_global = recorder.recording_group()
                .map(|rg| rg.include_global_resource_types().to_string())
                .unwrap_or_default();

            let (recording, last_status, last_change) = statuses.iter()
                .find(|(n, _, _, _)| n == &name)
                .map(|(_, r, s, c)| (r.clone(), s.clone(), c.clone()))
                .unwrap_or_default();

            rows.push(vec![
                name, role_arn, all_supported, include_global,
                recording, last_status, last_change,
            ]);
        }

        Ok(rows)
    }
}
