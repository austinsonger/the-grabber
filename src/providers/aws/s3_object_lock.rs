use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_s3::Client as S3Client;

use crate::evidence::CsvCollector;

// ══════════════════════════════════════════════════════════════════════════════
// S3 Object Lock Configuration Collector
// ══════════════════════════════════════════════════════════════════════════════

pub struct S3ObjectLockCollector {
    client: S3Client,
}

impl S3ObjectLockCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: S3Client::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for S3ObjectLockCollector {
    fn name(&self) -> &str {
        "S3 Object Lock Configuration"
    }
    fn filename_prefix(&self) -> &str {
        "S3_ObjectLock_Config"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Bucket Name",
            "Object Lock Enabled",
            "Default Mode",
            "Default Retention Days",
            "Default Retention Years",
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

            let (enabled, mode, days, years) = match self
                .client
                .get_object_lock_configuration()
                .bucket(&bucket_name)
                .send()
                .await
            {
                Ok(resp) => {
                    if let Some(cfg) = resp.object_lock_configuration() {
                        let en = cfg
                            .object_lock_enabled()
                            .map(|e| e.as_str().to_string())
                            .unwrap_or_else(|| "No".to_string());
                        let (m, d, y) = if let Some(retention) =
                            cfg.rule().and_then(|r| r.default_retention())
                        {
                            let mode = retention
                                .mode()
                                .map(|m| m.as_str().to_string())
                                .unwrap_or_default();
                            let days = retention.days().map(|d| d.to_string()).unwrap_or_default();
                            let years =
                                retention.years().map(|y| y.to_string()).unwrap_or_default();
                            (mode, days, years)
                        } else {
                            (String::new(), String::new(), String::new())
                        };
                        (en, m, d, y)
                    } else {
                        (
                            "No".to_string(),
                            String::new(),
                            String::new(),
                            String::new(),
                        )
                    }
                }
                Err(e) => {
                    let msg = format!("{e}");
                    if msg.contains("ObjectLockConfigurationNotFoundError") || msg.contains("404") {
                        (
                            "No".to_string(),
                            String::new(),
                            String::new(),
                            String::new(),
                        )
                    } else {
                        eprintln!("  WARN: S3 get_object_lock_configuration {bucket_name}: {e:#}");
                        continue;
                    }
                }
            };

            rows.push(vec![bucket_name, enabled, mode, days, years]);
        }

        Ok(rows)
    }
}
