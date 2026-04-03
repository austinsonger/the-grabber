use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_s3::Client as S3Client;

use crate::evidence::CsvCollector;

pub struct S3BucketLoggingCollector {
    client: S3Client,
}

impl S3BucketLoggingCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: S3Client::new(config) }
    }
}

#[async_trait]
impl CsvCollector for S3BucketLoggingCollector {
    fn name(&self) -> &str { "S3 Bucket Access Logging" }
    fn filename_prefix(&self) -> &str { "S3_Bucket_Access_Logging" }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Bucket Name", "Bucket ARN",
            "Storage Encrypted", "Encryption Type",
            "Block Public Access", "MFA Delete",
            "Logging", "KMS Key ID", "Region",
        ]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str, _dates: Option<(i64, i64)>) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        let buckets_resp = self.client
            .list_buckets()
            .send()
            .await
            .context("S3 list_buckets")?;

        for bucket in buckets_resp.buckets() {
            let name = bucket.name().unwrap_or("").to_string();
            let arn  = format!("arn:aws:s3:::{name}");

            // Region
            let region = match self.client
                .get_bucket_location()
                .bucket(&name)
                .send()
                .await
            {
                Ok(r) => r.location_constraint()
                    .map(|lc| lc.as_str().to_string())
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "us-east-1".to_string()),
                Err(_) => "".to_string(),
            };

            // Encryption
            let (encrypted, enc_type, kms_key) = match self.client
                .get_bucket_encryption()
                .bucket(&name)
                .send()
                .await
            {
                Ok(e) => {
                    let rule = e.server_side_encryption_configuration()
                        .and_then(|c| c.rules().first());
                    let (enc_type, kms) = rule
                        .and_then(|r| r.apply_server_side_encryption_by_default())
                        .map(|d| (
                            d.sse_algorithm().as_str().to_string(),
                            d.kms_master_key_id().unwrap_or("").to_string(),
                        ))
                        .unwrap_or_default();
                    ("Encrypted".to_string(), enc_type, kms)
                }
                Err(_) => ("Not Encrypted".to_string(), "".to_string(), "".to_string()),
            };

            // Block public access
            let block_public = match self.client
                .get_public_access_block()
                .bucket(&name)
                .send()
                .await
            {
                Ok(r) => {
                    let cfg = r.public_access_block_configuration();
                    let all_blocked = cfg.map(|c| {
                        c.block_public_acls().unwrap_or(false)
                            && c.ignore_public_acls().unwrap_or(false)
                            && c.block_public_policy().unwrap_or(false)
                            && c.restrict_public_buckets().unwrap_or(false)
                    }).unwrap_or(false);
                    if all_blocked { "Enabled" } else { "Partial/Disabled" }.to_string()
                }
                Err(_) => "Disabled".to_string(),
            };

            // MFA Delete
            let mfa_delete = match self.client
                .get_bucket_versioning()
                .bucket(&name)
                .send()
                .await
            {
                Ok(v) => v.mfa_delete()
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_else(|| "Disabled".to_string()),
                Err(_) => "".to_string(),
            };

            // Access logging
            let logging = match self.client
                .get_bucket_logging()
                .bucket(&name)
                .send()
                .await
            {
                Ok(l) => {
                    if l.logging_enabled().is_some() { "Enabled" } else { "Disabled" }.to_string()
                }
                Err(_) => "".to_string(),
            };

            rows.push(vec![
                name, arn, encrypted, enc_type,
                block_public, mfa_delete, logging, kms_key, region,
            ]);
        }

        Ok(rows)
    }
}
