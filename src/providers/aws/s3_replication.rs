use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_s3::Client as S3Client;

use crate::evidence::CsvCollector;

// ══════════════════════════════════════════════════════════════════════════════
// S3 Bucket Replication Collector
// ══════════════════════════════════════════════════════════════════════════════

pub struct S3ReplicationCollector {
    client: S3Client,
}

impl S3ReplicationCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: S3Client::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for S3ReplicationCollector {
    fn name(&self) -> &str {
        "S3 Bucket Replication"
    }
    fn filename_prefix(&self) -> &str {
        "S3_Replication_Config"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Source Bucket",
            "Rule ID",
            "Status",
            "Priority",
            "Destination Bucket",
            "Destination Account",
            "KMS Key",
            "RTC Enabled",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        let buckets_resp = self
            .client
            .list_buckets()
            .send()
            .await
            .context("S3 list_buckets")?;

        for bucket in buckets_resp.buckets() {
            let bucket_name = bucket.name().unwrap_or("").to_string();
            if bucket_name.is_empty() {
                continue;
            }

            // Filter buckets to those in the target region.
            let loc = match self
                .client
                .get_bucket_location()
                .bucket(&bucket_name)
                .send()
                .await
            {
                Ok(r) => r
                    .location_constraint()
                    .map(|lc| lc.as_str().to_string())
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "us-east-1".to_string()),
                Err(_) => continue,
            };
            if loc != _region {
                continue;
            }

            let replication = match self
                .client
                .get_bucket_replication()
                .bucket(&bucket_name)
                .send()
                .await
            {
                Ok(resp) => resp,
                Err(e) => {
                    let msg = format!("{e}");
                    if msg.contains("ReplicationConfigurationNotFoundError")
                        || msg.contains("NoSuchReplicationConfiguration")
                        || msg.contains("NotImplemented")
                        || msg.contains("404")
                    {
                        continue;
                    }
                    eprintln!("  WARN: S3 get_bucket_replication {bucket_name}: {e:#}");
                    continue;
                }
            };

            let Some(cfg) = replication.replication_configuration() else {
                continue;
            };

            for rule in cfg.rules() {
                let rule_id = rule.id().unwrap_or("").to_string();
                let status = rule.status().as_str().to_string();
                let priority = rule.priority().map(|p| p.to_string()).unwrap_or_default();

                let (dest_bucket, dest_account, kms_key, rtc) =
                    if let Some(dest) = rule.destination() {
                        let bucket = dest.bucket().to_string();
                        let account = dest.account().unwrap_or("").to_string();
                        let kms = dest
                            .encryption_configuration()
                            .and_then(|e| e.replica_kms_key_id())
                            .unwrap_or("")
                            .to_string();
                        let rtc_enabled = dest
                            .replication_time()
                            .map(|rt| rt.status().as_str().to_string())
                            .unwrap_or_else(|| "Disabled".to_string());
                        (bucket, account, kms, rtc_enabled)
                    } else {
                        (
                            String::new(),
                            String::new(),
                            String::new(),
                            "Disabled".to_string(),
                        )
                    };

                rows.push(vec![
                    bucket_name.clone(),
                    rule_id,
                    status,
                    priority,
                    dest_bucket,
                    dest_account,
                    kms_key,
                    rtc,
                ]);
            }
        }

        Ok(rows)
    }
}
