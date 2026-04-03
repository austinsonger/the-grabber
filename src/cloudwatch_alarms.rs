use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_cloudwatch::Client as CwClient;

use crate::evidence::CsvCollector;

pub struct CloudWatchConfigAlarmsCollector {
    client: CwClient,
}

impl CloudWatchConfigAlarmsCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: CwClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for CloudWatchConfigAlarmsCollector {
    fn name(&self) -> &str { "CloudWatch Alarms for Config Changes" }
    fn filename_prefix(&self) -> &str { "Change_Alerts_Config" }
    fn headers(&self) -> &'static [&'static str] {
        &["Alarm Name", "Metric Name", "Namespace", "Threshold",
          "Comparison Operator", "Actions Enabled", "Alarm Actions"]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str, _dates: Option<(i64, i64)>) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut next_token: Option<String> = None;

        loop {
            let mut req = self.client.describe_alarms();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: CloudWatch describe_alarms: {e:#}");
                    break;
                }
            };

            for alarm in resp.metric_alarms() {
                let alarm_name  = alarm.alarm_name().unwrap_or("").to_string();
                let metric_name = alarm.metric_name().unwrap_or("").to_string();
                let namespace   = alarm.namespace().unwrap_or("").to_string();
                let threshold   = alarm.threshold()
                    .map(|t| format!("{t}"))
                    .unwrap_or_default();
                let comparison  = alarm.comparison_operator()
                    .map(|c| c.as_str().to_string())
                    .unwrap_or_default();
                let actions_enabled = alarm.actions_enabled()
                    .unwrap_or(false)
                    .to_string();
                let actions: Vec<&str> = alarm.alarm_actions()
                    .iter()
                    .map(|s| s.as_str())
                    .collect();

                rows.push(vec![
                    alarm_name, metric_name, namespace, threshold,
                    comparison, actions_enabled, actions.join("; "),
                ]);
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() { break; }
        }

        Ok(rows)
    }
}
