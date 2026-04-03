use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_cloudwatchlogs::Client as CwlClient;

use crate::evidence::CsvCollector;

// ══════════════════════════════════════════════════════════════════════════════
// 1. CloudWatch Log Group Configuration
// ══════════════════════════════════════════════════════════════════════════════

pub struct CwLogGroupConfigCollector {
    client: CwlClient,
}

impl CwLogGroupConfigCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: CwlClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for CwLogGroupConfigCollector {
    fn name(&self) -> &str { "CloudWatch Log Group Config" }
    fn filename_prefix(&self) -> &str { "CloudWatch_Log_Group_Config" }
    fn headers(&self) -> &'static [&'static str] {
        &["Log Group Name", "Retention In Days", "KMS Key ID", "Stored Bytes", "Created At"]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str, _dates: Option<(i64, i64)>) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut next_token: Option<String> = None;

        loop {
            let mut req = self.client.describe_log_groups();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = req.send().await.context("CloudWatchLogs describe_log_groups")?;

            for lg in resp.log_groups() {
                let name      = lg.log_group_name().unwrap_or("").to_string();
                let retention = lg.retention_in_days()
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "Never Expire".to_string());
                let kms_key   = lg.kms_key_id().unwrap_or("").to_string();
                let stored    = lg.stored_bytes()
                    .map(|n| n.to_string())
                    .unwrap_or_default();
                let created   = lg.creation_time()
                    .map(|ts| {
                        chrono::DateTime::<chrono::Utc>::from_timestamp(ts / 1000, 0)
                            .map(|c| c.to_rfc3339())
                            .unwrap_or_default()
                    })
                    .unwrap_or_default();

                rows.push(vec![name, retention, kms_key, stored, created]);
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() { break; }
        }

        Ok(rows)
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// 2. Metric Filter Configuration
// ══════════════════════════════════════════════════════════════════════════════

pub struct MetricFilterConfigCollector {
    client: CwlClient,
}

impl MetricFilterConfigCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: CwlClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for MetricFilterConfigCollector {
    fn name(&self) -> &str { "Metric Filter Configuration" }
    fn filename_prefix(&self) -> &str { "Metric_Filter_Config" }
    fn headers(&self) -> &'static [&'static str] {
        &["Filter Name", "Log Group Name", "Filter Pattern", "Metric Transformations"]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str, _dates: Option<(i64, i64)>) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut next_token: Option<String> = None;

        loop {
            let mut req = self.client.describe_metric_filters();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = req.send().await.context("CloudWatchLogs describe_metric_filters")?;

            for mf in resp.metric_filters() {
                let filter_name  = mf.filter_name().unwrap_or("").to_string();
                let log_group    = mf.log_group_name().unwrap_or("").to_string();
                let pattern      = mf.filter_pattern().unwrap_or("").to_string();
                let transforms: Vec<String> = mf.metric_transformations().iter().map(|t| {
                    format!(
                        "{}→{}/{}(default={})",
                        t.metric_name(),
                        t.metric_namespace(),
                        t.metric_value(),
                        t.default_value().map(|v| v.to_string()).unwrap_or_else(|| "None".to_string()),
                    )
                }).collect();

                rows.push(vec![filter_name, log_group, pattern, transforms.join(" | ")]);
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() { break; }
        }

        Ok(rows)
    }
}
