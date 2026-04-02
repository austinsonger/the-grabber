use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_kms::Client as KmsClient;
use aws_sdk_ec2::Client as Ec2Client;

use crate::evidence::CsvCollector;

// ══════════════════════════════════════════════════════════════════════════════
// 1. KMS Key Configuration (full policy)
// ══════════════════════════════════════════════════════════════════════════════

pub struct KmsKeyConfigCollector {
    client: KmsClient,
}

impl KmsKeyConfigCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: KmsClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for KmsKeyConfigCollector {
    fn name(&self) -> &str { "KMS Key Configuration" }
    fn filename_prefix(&self) -> &str { "KMS_Key_Configuration" }
    fn headers(&self) -> &'static [&'static str] {
        &["Key ID", "Key ARN", "Enabled", "Key Usage", "Origin", "Key State", "Rotation Enabled", "Key Policy"]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut next_marker: Option<String> = None;

        loop {
            let mut req = self.client.list_keys();
            if let Some(ref m) = next_marker {
                req = req.marker(m);
            }
            let resp = req.send().await.context("KMS list_keys")?;

            for entry in resp.keys() {
                let key_id = entry.key_id().unwrap_or("").to_string();

                let desc = match self.client.describe_key().key_id(&key_id).send().await {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("  WARN: KMS describe_key {key_id}: {e:#}");
                        continue;
                    }
                };

                let meta = match desc.key_metadata() {
                    Some(m) => m,
                    None => continue,
                };

                // Skip AWS-managed keys
                if meta.key_manager()
                    .map(|m| m.as_str() == "AWS")
                    .unwrap_or(false)
                {
                    continue;
                }

                let key_arn     = meta.arn().unwrap_or("").to_string();
                let enabled     = meta.enabled().to_string();
                let key_usage   = meta.key_usage().map(|u| u.as_str().to_string()).unwrap_or_default();
                let origin      = meta.origin().map(|o| o.as_str().to_string()).unwrap_or_default();
                let key_state   = meta.key_state().map(|s| s.as_str().to_string()).unwrap_or_default();

                let rotation = match self.client
                    .get_key_rotation_status()
                    .key_id(&key_id)
                    .send()
                    .await
                {
                    Ok(r) => r.key_rotation_enabled().to_string(),
                    Err(_) => "Unknown".to_string(),
                };

                let policy = match self.client
                    .get_key_policy()
                    .key_id(&key_id)
                    .policy_name("default")
                    .send()
                    .await
                {
                    Ok(r) => r.policy().unwrap_or("").to_string(),
                    Err(_) => String::new(),
                };

                rows.push(vec![key_id, key_arn, enabled, key_usage, origin, key_state, rotation, policy]);
            }

            next_marker = if resp.truncated() { resp.next_marker().map(|s| s.to_string()) } else { None };
            if next_marker.is_none() { break; }
        }

        Ok(rows)
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// 2. EBS Default Encryption (account-level per region)
// ══════════════════════════════════════════════════════════════════════════════

pub struct EbsEncryptionConfigCollector {
    client: Ec2Client,
}

impl EbsEncryptionConfigCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: Ec2Client::new(config) }
    }
}

#[async_trait]
impl CsvCollector for EbsEncryptionConfigCollector {
    fn name(&self) -> &str { "EBS Encryption Config" }
    fn filename_prefix(&self) -> &str { "EBS_Encryption_Config" }
    fn headers(&self) -> &'static [&'static str] {
        &["Region", "EBS Encryption By Default", "Default KMS Key ID"]
    }

    async fn collect_rows(&self, _account_id: &str, region: &str) -> Result<Vec<Vec<String>>> {
        let enabled = match self.client.get_ebs_encryption_by_default().send().await {
            Ok(r) => r.ebs_encryption_by_default().unwrap_or(false).to_string(),
            Err(e) => {
                eprintln!("  WARN: EC2 get_ebs_encryption_by_default: {e:#}");
                "Unknown".to_string()
            }
        };

        let kms_key = match self.client.get_ebs_default_kms_key_id().send().await {
            Ok(r) => r.kms_key_id().unwrap_or("aws/ebs (default)").to_string(),
            Err(_) => "aws/ebs (default)".to_string(),
        };

        Ok(vec![vec![region.to_string(), enabled, kms_key]])
    }
}
