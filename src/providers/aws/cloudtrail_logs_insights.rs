//! CloudWatch Logs Insights query against the CloudTrail-associated log
//! group. Demonstrates on-demand search/sort/filter over defined event
//! fields without altering the underlying (immutable) CloudTrail records,
//! for FedRAMP AU-07(01)/AU-07a./AU-07b.

use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_cloudtrail::Client as CtClient;
use aws_sdk_cloudwatchlogs::types::QueryStatus;
use aws_sdk_cloudwatchlogs::Client as CwlClient;

use crate::evidence::JsonCollector;

const POLL_INTERVAL_SECS: u64 = 3;
const MAX_POLL_ATTEMPTS: u32 = 20; // 1 minute
const QUERY_STRING: &str =
    "fields @timestamp, eventName, eventSource, userIdentity.arn, sourceIPAddress | sort @timestamp desc | limit 100";

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Extracts the log group name from a CloudWatch Logs log group ARN, e.g.
/// `arn:aws:logs:us-east-1:123456789012:log-group:my-trail-logs:*` -> `my-trail-logs`.
fn log_group_name_from_arn(arn: &str) -> Option<String> {
    let after_prefix = arn.split_once(":log-group:")?.1;
    let name = after_prefix.split(':').next()?;
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

pub struct CloudTrailLogsInsightsCollector {
    cloudtrail: CtClient,
    logs: CwlClient,
}

impl CloudTrailLogsInsightsCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            cloudtrail: CtClient::new(config),
            logs: CwlClient::new(config),
        }
    }

    async fn resolve_log_group(&self) -> Result<Option<String>> {
        let resp = self
            .cloudtrail
            .describe_trails()
            .include_shadow_trails(false)
            .send()
            .await
            .context("CloudTrail describe_trails")?;

        for trail in resp.trail_list() {
            if let Some(arn) = trail.cloud_watch_logs_log_group_arn() {
                if let Some(name) = log_group_name_from_arn(arn) {
                    return Ok(Some(name));
                }
            }
        }
        Ok(None)
    }

    async fn poll_query(
        &self,
        query_id: &str,
    ) -> Result<aws_sdk_cloudwatchlogs::operation::get_query_results::GetQueryResultsOutput> {
        let interval = tokio::time::Duration::from_secs(POLL_INTERVAL_SECS);

        for attempt in 1..=MAX_POLL_ATTEMPTS {
            let resp = self
                .logs
                .get_query_results()
                .query_id(query_id)
                .send()
                .await
                .context("CloudWatch Logs get_query_results")?;

            match resp.status() {
                Some(QueryStatus::Complete) => return Ok(resp),
                Some(QueryStatus::Failed) | Some(QueryStatus::Cancelled) => {
                    anyhow::bail!("Logs Insights query ended with status {:?}", resp.status());
                }
                _ => {
                    if attempt == MAX_POLL_ATTEMPTS {
                        anyhow::bail!(
                            "Logs Insights query timed out after {MAX_POLL_ATTEMPTS} attempts"
                        );
                    }
                    tokio::time::sleep(interval).await;
                }
            }
        }

        anyhow::bail!("Logs Insights polling loop exited unexpectedly")
    }
}

#[async_trait]
impl JsonCollector for CloudTrailLogsInsightsCollector {
    fn name(&self) -> &str {
        "CloudTrail Logs Insights Query"
    }
    fn filename_prefix(&self) -> &str {
        "CloudTrail_Logs_Insights_Query"
    }

    async fn collect_records(
        &self,
        _account_id: &str,
        _region: &str,
    ) -> Result<Vec<serde_json::Value>> {
        let log_group = match self.resolve_log_group().await? {
            Some(g) => g,
            None => {
                eprintln!(
                    "  WARN: no CloudTrail trail has a CloudWatch Logs log group configured; \
                     Logs Insights requires trail -> CloudWatch Logs delivery"
                );
                return Ok(vec![]);
            }
        };

        let end_secs = now_secs();
        let start_secs = end_secs - 7 * 24 * 3600;

        let start_resp = self
            .logs
            .start_query()
            .log_group_name(&log_group)
            .start_time(start_secs)
            .end_time(end_secs)
            .query_string(QUERY_STRING)
            .send()
            .await
            .context("CloudWatch Logs start_query")?;

        let query_id = start_resp
            .query_id()
            .context("start_query response missing query_id")?
            .to_string();

        let results = self.poll_query(&query_id).await?;

        let mut records = Vec::new();
        for row in results.results() {
            let mut obj = serde_json::Map::new();
            for field in row {
                if let (Some(k), Some(v)) = (field.field(), field.value()) {
                    obj.insert(k.to_string(), serde_json::Value::String(v.to_string()));
                }
            }
            records.push(serde_json::Value::Object(obj));
        }

        records.push(serde_json::json!({
            "_query_meta": {
                "log_group": log_group,
                "query_string": QUERY_STRING,
                "start_time": start_secs,
                "end_time": end_secs,
                "record_count": results.results().len(),
            }
        }));

        Ok(records)
    }
}
