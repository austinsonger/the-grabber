use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_s3::Client as S3Client;

use crate::evidence::CsvCollector;

// ══════════════════════════════════════════════════════════════════════════════
// 1. S3 Bucket Encryption Config
// ══════════════════════════════════════════════════════════════════════════════

pub struct S3EncryptionConfigCollector {
    client: S3Client,
}

impl S3EncryptionConfigCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: S3Client::new(config) }
    }
}

#[async_trait]
impl CsvCollector for S3EncryptionConfigCollector {
    fn name(&self) -> &str { "S3 Bucket Encryption Config" }
    fn filename_prefix(&self) -> &str { "S3_Encryption_Config" }
    fn headers(&self) -> &'static [&'static str] {
        &["Bucket Name", "SSE Algorithm", "KMS Master Key ID", "Bucket Key Enabled"]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let buckets = self.client.list_buckets().send().await
            .context("S3 list_buckets")?;

        for bucket in buckets.buckets() {
            let name = bucket.name().unwrap_or("").to_string();

            let (algo, key_id, bucket_key) = match self.client
                .get_bucket_encryption()
                .bucket(&name)
                .send()
                .await
            {
                Ok(r) => {
                    let rule = r.server_side_encryption_configuration()
                        .and_then(|c| c.rules().first());
                    let apply = rule.and_then(|r| r.apply_server_side_encryption_by_default());
                    let algo = apply
                        .map(|a| a.sse_algorithm().as_str().to_string())
                        .unwrap_or_else(|| "None".to_string());
                    let key = apply
                        .and_then(|a| a.kms_master_key_id())
                        .unwrap_or("")
                        .to_string();
                    let bk = rule
                        .and_then(|r| r.bucket_key_enabled())
                        .unwrap_or(false)
                        .to_string();
                    (algo, key, bk)
                }
                Err(e) => {
                    let msg = format!("{e}");
                    if msg.contains("ServerSideEncryptionConfigurationNotFound")
                        || msg.contains("NoSuchBucket")
                    {
                        ("None".to_string(), String::new(), "false".to_string())
                    } else {
                        eprintln!("  WARN: S3 get_bucket_encryption {name}: {e:#}");
                        ("Error".to_string(), String::new(), String::new())
                    }
                }
            };

            rows.push(vec![name, algo, key_id, bucket_key]);
        }

        Ok(rows)
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// 2. S3 Bucket Policy (raw document)
// ══════════════════════════════════════════════════════════════════════════════

pub struct S3BucketPolicyDetailCollector {
    client: S3Client,
}

impl S3BucketPolicyDetailCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: S3Client::new(config) }
    }
}

#[async_trait]
impl CsvCollector for S3BucketPolicyDetailCollector {
    fn name(&self) -> &str { "S3 Bucket Policy" }
    fn filename_prefix(&self) -> &str { "S3_Bucket_Policy" }
    fn headers(&self) -> &'static [&'static str] {
        &["Bucket Name", "Has Policy", "Policy Document"]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let buckets = self.client.list_buckets().send().await
            .context("S3 list_buckets")?;

        for bucket in buckets.buckets() {
            let name = bucket.name().unwrap_or("").to_string();

            let (has_policy, policy_doc) = match self.client
                .get_bucket_policy()
                .bucket(&name)
                .send()
                .await
            {
                Ok(r) => {
                    let doc = r.policy().unwrap_or("").to_string();
                    ("Yes".to_string(), doc)
                }
                Err(e) => {
                    let msg = format!("{e}");
                    if msg.contains("NoSuchBucketPolicy") || msg.contains("NoSuchBucket") {
                        ("No".to_string(), String::new())
                    } else {
                        eprintln!("  WARN: S3 get_bucket_policy {name}: {e:#}");
                        ("Error".to_string(), String::new())
                    }
                }
            };

            rows.push(vec![name, has_policy, policy_doc]);
        }

        Ok(rows)
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// 3. S3 Public Access Block
// ══════════════════════════════════════════════════════════════════════════════

pub struct S3PublicAccessBlockCollector {
    client: S3Client,
}

impl S3PublicAccessBlockCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: S3Client::new(config) }
    }
}

#[async_trait]
impl CsvCollector for S3PublicAccessBlockCollector {
    fn name(&self) -> &str { "S3 Public Access Block" }
    fn filename_prefix(&self) -> &str { "S3_Public_Access_Block" }
    fn headers(&self) -> &'static [&'static str] {
        &["Bucket Name", "Block Public ACLs", "Ignore Public ACLs", "Block Public Policy", "Restrict Public Buckets"]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let buckets = self.client.list_buckets().send().await
            .context("S3 list_buckets")?;

        for bucket in buckets.buckets() {
            let name = bucket.name().unwrap_or("").to_string();

            let (bpa, ipa, bpp, rpb) = match self.client
                .get_public_access_block()
                .bucket(&name)
                .send()
                .await
            {
                Ok(r) => {
                    let cfg = r.public_access_block_configuration();
                    (
                        cfg.and_then(|c| c.block_public_acls()).unwrap_or(false).to_string(),
                        cfg.and_then(|c| c.ignore_public_acls()).unwrap_or(false).to_string(),
                        cfg.and_then(|c| c.block_public_policy()).unwrap_or(false).to_string(),
                        cfg.and_then(|c| c.restrict_public_buckets()).unwrap_or(false).to_string(),
                    )
                }
                Err(e) => {
                    let msg = format!("{e}");
                    if msg.contains("NoSuchPublicAccessBlockConfiguration") || msg.contains("NoSuchBucket") {
                        ("false".to_string(), "false".to_string(), "false".to_string(), "false".to_string())
                    } else {
                        eprintln!("  WARN: S3 get_public_access_block {name}: {e:#}");
                        ("Error".to_string(), "Error".to_string(), "Error".to_string(), "Error".to_string())
                    }
                }
            };

            rows.push(vec![name, bpa, ipa, bpp, rpb]);
        }

        Ok(rows)
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// 4. S3 Logging Configuration
// ══════════════════════════════════════════════════════════════════════════════

pub struct S3LoggingConfigCollector {
    client: S3Client,
}

impl S3LoggingConfigCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: S3Client::new(config) }
    }
}

#[async_trait]
impl CsvCollector for S3LoggingConfigCollector {
    fn name(&self) -> &str { "S3 Logging Configuration" }
    fn filename_prefix(&self) -> &str { "S3_Logging_Config" }
    fn headers(&self) -> &'static [&'static str] {
        &["Bucket Name", "Logging Enabled", "Target Bucket", "Target Prefix"]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let buckets = self.client.list_buckets().send().await
            .context("S3 list_buckets")?;

        for bucket in buckets.buckets() {
            let name = bucket.name().unwrap_or("").to_string();

            let (enabled, target_bucket, target_prefix) = match self.client
                .get_bucket_logging()
                .bucket(&name)
                .send()
                .await
            {
                Ok(r) => {
                    match r.logging_enabled() {
                        Some(le) => (
                            "Yes".to_string(),
                            le.target_bucket().to_string(),
                            le.target_prefix().to_string(),
                        ),
                        None => ("No".to_string(), String::new(), String::new()),
                    }
                }
                Err(e) => {
                    eprintln!("  WARN: S3 get_bucket_logging {name}: {e:#}");
                    ("Error".to_string(), String::new(), String::new())
                }
            };

            rows.push(vec![name, enabled, target_bucket, target_prefix]);
        }

        Ok(rows)
    }
}
