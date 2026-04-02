use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_ssm::Client as SsmClient;

use crate::evidence::CsvCollector;

fn fmt_ssm_dt(dt: &aws_sdk_ssm::primitives::DateTime) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(dt.secs(), 0)
        .map(|c| c.to_rfc3339())
        .unwrap_or_default()
}

// ══════════════════════════════════════════════════════════════════════════════
// 1. SSM Patch Baselines
// ══════════════════════════════════════════════════════════════════════════════

pub struct SsmPatchBaselineCollector {
    client: SsmClient,
}

impl SsmPatchBaselineCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: SsmClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for SsmPatchBaselineCollector {
    fn name(&self) -> &str { "SSM Patch Baselines" }
    fn filename_prefix(&self) -> &str { "SSM_Patch_Baseline_Config" }
    fn headers(&self) -> &'static [&'static str] {
        &["Baseline ID", "Name", "Operating System", "Default Baseline", "Approved Patches", "Patch Rules Summary"]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut next_token: Option<String> = None;

        loop {
            let mut req = self.client.describe_patch_baselines();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = req.send().await.context("SSM describe_patch_baselines")?;

            for identity in resp.baseline_identities() {
                let baseline_id = identity.baseline_id().unwrap_or("").to_string();
                let name        = identity.baseline_name().unwrap_or("").to_string();
                let os          = identity.operating_system()
                    .map(|o| o.as_str().to_string())
                    .unwrap_or_default();
                let is_default  = identity.default_baseline().to_string();

                // Get full details for patch rules and approved patches
                let (approved_patches, patch_rules) = match self.client
                    .get_patch_baseline()
                    .baseline_id(&baseline_id)
                    .send()
                    .await
                {
                    Ok(r) => {
                        let approved: Vec<String> = r.approved_patches()
                            .iter()
                            .map(|s| s.to_string())
                            .collect();

                        let rules: Vec<String> = r.approval_rules()
                            .map(|ar| ar.patch_rules())
                            .unwrap_or_default()
                            .iter()
                            .map(|rule| {
                                let approve_after = rule.approve_after_days()
                                    .map(|n| format!("after={n}d"))
                                    .unwrap_or_default();
                                let compliance = rule.compliance_level()
                                    .map(|c| c.as_str().to_string())
                                    .unwrap_or_default();
                                format!("compliance={compliance},{approve_after}")
                            })
                            .collect();

                        (approved.join(", "), rules.join(" | "))
                    }
                    Err(e) => {
                        eprintln!("  WARN: SSM get_patch_baseline {baseline_id}: {e:#}");
                        (String::new(), String::new())
                    }
                };

                rows.push(vec![baseline_id, name, os, is_default, approved_patches, patch_rules]);
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() { break; }
        }

        Ok(rows)
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// 2. SSM Parameter Store Config
// ══════════════════════════════════════════════════════════════════════════════

pub struct SsmParameterConfigCollector {
    client: SsmClient,
}

impl SsmParameterConfigCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: SsmClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for SsmParameterConfigCollector {
    fn name(&self) -> &str { "SSM Parameter Store Config" }
    fn filename_prefix(&self) -> &str { "SSM_Parameter_Config" }
    fn headers(&self) -> &'static [&'static str] {
        &["Name", "Type", "KMS Key ID", "Last Modified", "Description", "Tier"]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut next_token: Option<String> = None;

        loop {
            let mut req = self.client.describe_parameters();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = req.send().await.context("SSM describe_parameters")?;

            for param in resp.parameters() {
                let name         = param.name().unwrap_or("").to_string();
                let param_type   = param.r#type()
                    .map(|t| t.as_str().to_string())
                    .unwrap_or_default();
                let kms_key      = param.key_id().unwrap_or("").to_string();
                let last_mod     = param.last_modified_date()
                    .map(fmt_ssm_dt)
                    .unwrap_or_default();
                let description  = param.description().unwrap_or("").to_string();
                let tier         = param.tier()
                    .map(|t| t.as_str().to_string())
                    .unwrap_or_default();

                rows.push(vec![name, param_type, kms_key, last_mod, description, tier]);
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() { break; }
        }

        Ok(rows)
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// 3. EC2 Time Sync Config (via SSM Inventory)
// ══════════════════════════════════════════════════════════════════════════════

pub struct TimeSyncConfigCollector {
    client: SsmClient,
}

impl TimeSyncConfigCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: SsmClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for TimeSyncConfigCollector {
    fn name(&self) -> &str { "EC2 Time Sync Config (SSM)" }
    fn filename_prefix(&self) -> &str { "Time_Sync_Config" }
    fn headers(&self) -> &'static [&'static str] {
        &["Instance ID", "Computer Name", "Platform", "SSM Ping Status", "Time Source Note"]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut next_token: Option<String> = None;

        loop {
            let mut req = self.client.describe_instance_information();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: SSM describe_instance_information: {e:#}");
                    break;
                }
            };

            for info in resp.instance_information_list() {
                let instance_id   = info.instance_id().unwrap_or("").to_string();
                let computer_name = info.computer_name().unwrap_or("").to_string();
                let platform      = info.platform_type()
                    .map(|p| p.as_str().to_string())
                    .unwrap_or_default();
                let ping_status   = info.ping_status()
                    .map(|p| p.as_str().to_string())
                    .unwrap_or_default();

                // Time sync config requires SSM Run Command to retrieve (chronyc / timedatectl).
                // AWS EC2 instances default to the AWS Time Sync Service (169.254.169.123).
                // A full NTP audit requires running: `chronyc sources` or `w32tm /query /peers`
                let time_note = if platform.to_lowercase().contains("windows") {
                    "Verify via: w32tm /query /peers (SSM Run Command)".to_string()
                } else {
                    "Verify via: chronyc sources (SSM Run Command)".to_string()
                };

                rows.push(vec![instance_id, computer_name, platform, ping_status, time_note]);
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() { break; }
        }

        Ok(rows)
    }
}
