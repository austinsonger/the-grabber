use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_cloudwatch::Client as CwClient;
use aws_sdk_cloudwatchlogs::Client as CwlClient;

use crate::evidence::CsvCollector;

pub struct MetricFilterAlarmCollector {
    cw_client:  CwClient,
    cwl_client: CwlClient,
}

impl MetricFilterAlarmCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            cw_client:  CwClient::new(config),
            cwl_client: CwlClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for MetricFilterAlarmCollector {
    fn name(&self) -> &str { "Log Metric Filters and Alarms" }
    fn filename_prefix(&self) -> &str { "Log_Metric_Filters_and_Alarms" }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Metric Filter Name",
            "Metric Filter Namespace",
            "Metric Filter Metric",
            "Alarms",
            "Alarm Actions",
            "Cloud Watch Logs Log Group ARN",
        ]
    }

    async fn collect_rows(&self, account_id: &str, region: &str) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut next_token: Option<String> = None;

        loop {
            let mut req = self.cwl_client.describe_metric_filters();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = req.send().await.context("CloudWatchLogs describe_metric_filters")?;

            for filter in resp.metric_filters() {
                let filter_name = filter.filter_name().unwrap_or("").to_string();
                let log_group   = filter.log_group_name().unwrap_or("").to_string();

                // Construct log group ARN.
                let log_group_arn = if log_group.is_empty() {
                    "".to_string()
                } else {
                    format!("arn:aws:logs:{region}:{account_id}:log-group:{log_group}")
                };

                // Get the first metric transformation for namespace/metric.
                let (namespace, metric_name) = filter.metric_transformations()
                    .first()
                    .map(|t| (
                        t.metric_namespace().to_string(),
                        t.metric_name().to_string(),
                    ))
                    .unwrap_or_default();

                // Find alarms referencing this metric.
                let (alarm_names, alarm_actions) = if !metric_name.is_empty() {
                    match self.cw_client
                        .describe_alarms_for_metric()
                        .metric_name(&metric_name)
                        .namespace(&namespace)
                        .send()
                        .await
                    {
                        Ok(ar) => {
                            let names: Vec<String> = ar.metric_alarms()
                                .iter()
                                .filter_map(|a| a.alarm_name())
                                .map(|s| s.to_string())
                                .collect();
                            let actions: Vec<String> = ar.metric_alarms()
                                .iter()
                                .flat_map(|a| a.alarm_actions())
                                .map(|s| s.to_string())
                                .collect();
                            (names.join(", "), actions.join(", "))
                        }
                        Err(_) => ("".to_string(), "".to_string()),
                    }
                } else {
                    ("".to_string(), "".to_string())
                };

                rows.push(vec![
                    filter_name, namespace, metric_name,
                    alarm_names, alarm_actions, log_group_arn,
                ]);
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() { break; }
        }

        Ok(rows)
    }
}
