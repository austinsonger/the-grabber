use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_s3::Client as S3Client;

use crate::evidence::CsvCollector;

pub struct S3BucketConfigCollector {
    client: S3Client,
}

impl S3BucketConfigCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: S3Client::new(config) }
    }
}

#[async_trait]
impl CsvCollector for S3BucketConfigCollector {
    fn name(&self) -> &str { "S3 Buckets Config" }
    fn filename_prefix(&self) -> &str { "S3_Buckets_Config" }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Bucket Name", "Public Access Block", "Versioning",
            "Encryption", "Logging", "Policy", "Region",
        ]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str, _dates: Option<(i64, i64)>) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        let buckets = self.client
            .list_buckets()
            .send()
            .await
            .context("S3 list_buckets (config)")?;

        for bucket in buckets.buckets() {
            let name = bucket.name().unwrap_or("").to_string();

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

            // Public Access Block
            let public_access = match self.client
                .get_public_access_block()
                .bucket(&name)
                .send()
                .await
            {
                Ok(r) => {
                    let cfg = r.public_access_block_configuration();
                    let all = cfg.map(|c| {
                        c.block_public_acls().unwrap_or(false)
                            && c.ignore_public_acls().unwrap_or(false)
                            && c.block_public_policy().unwrap_or(false)
                            && c.restrict_public_buckets().unwrap_or(false)
                    }).unwrap_or(false);
                    if all { "Fully Blocked" } else { "Partial/Disabled" }.to_string()
                }
                Err(_) => "Disabled".to_string(),
            };

            // Versioning
            let versioning = match self.client
                .get_bucket_versioning()
                .bucket(&name)
                .send()
                .await
            {
                Ok(r) => r.status()
                    .map(|s| s.as_str().to_string())
                    .unwrap_or_else(|| "Disabled".to_string()),
                Err(_) => "".to_string(),
            };

            // Encryption
            let encryption = match self.client
                .get_bucket_encryption()
                .bucket(&name)
                .send()
                .await
            {
                Ok(r) => r.server_side_encryption_configuration()
                    .and_then(|c| c.rules().first())
                    .and_then(|rule| rule.apply_server_side_encryption_by_default())
                    .map(|d| d.sse_algorithm().as_str().to_string())
                    .unwrap_or_else(|| "None".to_string()),
                Err(_) => "None".to_string(),
            };

            // Logging
            let logging = match self.client
                .get_bucket_logging()
                .bucket(&name)
                .send()
                .await
            {
                Ok(r) => if r.logging_enabled().is_some() { "Enabled" } else { "Disabled" }.to_string(),
                Err(_) => "".to_string(),
            };

            // Policy (check for existence)
            let policy = match self.client
                .get_bucket_policy_status()
                .bucket(&name)
                .send()
                .await
            {
                Ok(r) => {
                    let is_public = r.policy_status()
                        .and_then(|s| s.is_public())
                        .unwrap_or(false);
                    if is_public { "Public Policy" } else { "Policy Exists (Private)" }.to_string()
                }
                Err(_) => "No Policy".to_string(),
            };

            rows.push(vec![
                name, public_access, versioning, encryption, logging, policy, region,
            ]);
        }

        Ok(rows)
    }
}
