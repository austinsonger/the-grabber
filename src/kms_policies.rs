use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_kms::Client as KmsClient;
use aws_sdk_ec2::Client as Ec2Client;

use crate::evidence::CsvCollector;

// ══════════════════════════════════════════════════════════════════════════════
// 1. KMS Key Policy Collector
// ══════════════════════════════════════════════════════════════════════════════

pub struct KmsKeyPolicyCollector {
    client: KmsClient,
}

impl KmsKeyPolicyCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: KmsClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for KmsKeyPolicyCollector {
    fn name(&self) -> &str { "KMS Key Policies" }
    fn filename_prefix(&self) -> &str { "KMS_KeyPolicies" }
    fn headers(&self) -> &'static [&'static str] {
        &["Key ID", "Key ARN", "Key State", "Rotation Enabled", "Key Usage", "Policy Allows External Access"]
    }

    async fn collect_rows(&self, account_id: &str, _region: &str) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut next_marker: Option<String> = None;

        loop {
            let mut req = self.client.list_keys();
            if let Some(ref m) = next_marker {
                req = req.marker(m);
            }
            let resp = req.send().await.context("KMS list_keys")?;

            for key_entry in resp.keys() {
                let key_id = key_entry.key_id().unwrap_or("").to_string();

                // describe_key to check if customer managed
                let desc_resp = match self.client
                    .describe_key()
                    .key_id(&key_id)
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("  WARN: KMS describe_key {key_id}: {e:#}");
                        continue;
                    }
                };

                let meta = match desc_resp.key_metadata() {
                    Some(m) => m,
                    None => continue,
                };

                // Skip AWS managed keys
                let key_manager = meta.key_manager()
                    .map(|m| m.as_str())
                    .unwrap_or("");
                if key_manager != "CUSTOMER" {
                    continue;
                }

                let key_arn = meta.arn().unwrap_or("").to_string();
                let key_state = meta.key_state()
                    .map(|s| s.as_str().to_string())
                    .unwrap_or_default();
                let key_usage = meta.key_usage()
                    .map(|u| u.as_str().to_string())
                    .unwrap_or_default();

                // Rotation status
                let rotation_enabled = match self.client
                    .get_key_rotation_status()
                    .key_id(&key_id)
                    .send()
                    .await
                {
                    Ok(r) => r.key_rotation_enabled().to_string(),
                    Err(_) => "false".to_string(),
                };

                // Key policy
                let external_access = match self.client
                    .get_key_policy()
                    .key_id(&key_id)
                    .policy_name("default")
                    .send()
                    .await
                {
                    Ok(r) => {
                        let policy = r.policy().unwrap_or("");
                        check_external_access(policy, account_id)
                    }
                    Err(e) => {
                        eprintln!("  WARN: KMS get_key_policy {key_id}: {e:#}");
                        "Unknown".to_string()
                    }
                };

                rows.push(vec![
                    key_id,
                    key_arn,
                    key_state,
                    rotation_enabled,
                    key_usage,
                    external_access,
                ]);
            }

            if resp.truncated() {
                next_marker = resp.next_marker().map(|s| s.to_string());
            } else {
                break;
            }
        }

        Ok(rows)
    }
}

/// Check if the KMS key policy grants access to principals outside the account.
/// Simple heuristic: count "arn:aws:iam::" occurrences vs those containing account_id.
fn check_external_access(policy: &str, account_id: &str) -> String {
    if policy.is_empty() {
        return "No".to_string();
    }
    let total_iam_arns = policy.matches("arn:aws:iam::").count();
    if total_iam_arns == 0 {
        return "No".to_string();
    }
    let own_account_arns = policy.matches(account_id).count();
    // If there are IAM ARN references that don't match our account, flag it
    // Also check for wildcard principals
    if policy.contains("\"Principal\":\"*\"") || policy.contains("\"AWS\":\"*\"") {
        return "Yes".to_string();
    }
    if own_account_arns < total_iam_arns {
        "Yes".to_string()
    } else {
        "No".to_string()
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// 2. EBS Default Encryption Collector
// ══════════════════════════════════════════════════════════════════════════════

pub struct EbsDefaultEncryptionCollector {
    ec2_client: Ec2Client,
}

impl EbsDefaultEncryptionCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            ec2_client: Ec2Client::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for EbsDefaultEncryptionCollector {
    fn name(&self) -> &str { "EBS Default Encryption" }
    fn filename_prefix(&self) -> &str { "EBS_DefaultEncryption" }
    fn headers(&self) -> &'static [&'static str] {
        &["Region", "Default Encryption Enabled", "KMS Key ID"]
    }

    async fn collect_rows(&self, _account_id: &str, region: &str) -> Result<Vec<Vec<String>>> {
        let enc_resp = match self.ec2_client
            .get_ebs_encryption_by_default()
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                eprintln!("  WARN: EC2 get_ebs_encryption_by_default: {e:#}");
                return Ok(vec![vec![region.to_string(), "Unknown".to_string(), String::new()]]);
            }
        };

        let enabled = enc_resp.ebs_encryption_by_default().unwrap_or(false).to_string();

        let kms_key_id = match self.ec2_client
            .get_ebs_default_kms_key_id()
            .send()
            .await
        {
            Ok(r) => r.kms_key_id().unwrap_or("").to_string(),
            Err(e) => {
                eprintln!("  WARN: EC2 get_ebs_default_kms_key_id: {e:#}");
                String::new()
            }
        };

        Ok(vec![vec![region.to_string(), enabled, kms_key_id]])
    }
}
