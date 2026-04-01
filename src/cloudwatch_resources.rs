use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_cloudwatch::Client as CwClient;
use aws_sdk_cloudwatchlogs::Client as CwlClient;

use crate::evidence::CsvCollector;

// ---------------------------------------------------------------------------
// CloudWatch Alarms
// ---------------------------------------------------------------------------

pub struct CloudWatchAlarmCollector {
    client: CwClient,
}

impl CloudWatchAlarmCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: CwClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for CloudWatchAlarmCollector {
    fn name(&self) -> &str { "CloudWatch Alarms" }
    fn filename_prefix(&self) -> &str { "CloudWatch_Alarms" }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Alarm Name", "Metric", "Threshold",
            "Comparison Operator", "Actions Enabled", "State",
        ]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut next_token: Option<String> = None;

        loop {
            let mut req = self.client.describe_alarms();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = req.send().await.context("CloudWatch describe_alarms")?;

            for alarm in resp.metric_alarms() {
                let name      = alarm.alarm_name().unwrap_or("").to_string();
                let metric    = alarm.metric_name().unwrap_or("").to_string();
                let threshold = alarm.threshold()
                    .map(|t| t.to_string())
                    .unwrap_or_default();
                let comparison = alarm.comparison_operator()
                    .map(|c| c.as_str().to_string())
                    .unwrap_or_default();
                let actions_enabled = if alarm.actions_enabled().unwrap_or(false) { "Yes" } else { "No" }.to_string();
                let state     = alarm.state_value()
                    .map(|s| s.as_str().to_string())
                    .unwrap_or_default();

                rows.push(vec![name, metric, threshold, comparison, actions_enabled, state]);
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() { break; }
        }

        Ok(rows)
    }
}

// ---------------------------------------------------------------------------
// CloudWatch Log Groups
// ---------------------------------------------------------------------------

pub struct CloudWatchLogGroupCollector {
    client: CwlClient,
}

impl CloudWatchLogGroupCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: CwlClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for CloudWatchLogGroupCollector {
    fn name(&self) -> &str { "CloudWatch Log Groups" }
    fn filename_prefix(&self) -> &str { "CloudWatch_Log_Groups" }
    fn headers(&self) -> &'static [&'static str] {
        &["Log Group Name", "Retention Days", "KMS Key ARN", "Stored Bytes", "Region"]
    }

    async fn collect_rows(&self, _account_id: &str, region: &str) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut next_token: Option<String> = None;

        loop {
            let mut req = self.client.describe_log_groups();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = req.send().await.context("CloudWatchLogs describe_log_groups")?;

            for lg in resp.log_groups() {
                let name       = lg.log_group_name().unwrap_or("").to_string();
                let retention  = lg.retention_in_days()
                    .map(|d| d.to_string())
                    .unwrap_or_else(|| "Never Expire".to_string());
                let kms_key    = lg.kms_key_id().unwrap_or("").to_string();
                let stored     = lg.stored_bytes()
                    .map(|b| b.to_string())
                    .unwrap_or_default();

                rows.push(vec![name, retention, kms_key, stored, region.to_string()]);
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() { break; }
        }

        Ok(rows)
    }
}
