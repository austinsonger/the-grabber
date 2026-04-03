use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_sns::Client as SnsClient;

use crate::evidence::CsvCollector;

pub struct SnsSubscriptionCollector {
    client: SnsClient,
}

impl SnsSubscriptionCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: SnsClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for SnsSubscriptionCollector {
    fn name(&self) -> &str { "SNS Topic Subscribers" }
    fn filename_prefix(&self) -> &str { "SNS_Topic_Subscribers" }
    fn headers(&self) -> &'static [&'static str] {
        &["Subscription ID", "SNS Topic Name", "SNS Topic ARN", "Region"]
    }

    async fn collect_rows(&self, _account_id: &str, region: &str, _dates: Option<(i64, i64)>) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut next_token: Option<String> = None;

        loop {
            let mut req = self.client.list_subscriptions();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = req.send().await.context("SNS list_subscriptions")?;

            for sub in resp.subscriptions() {
                let sub_arn   = sub.subscription_arn().unwrap_or("").to_string();
                let topic_arn = sub.topic_arn().unwrap_or("").to_string();
                let topic_name = topic_arn
                    .split(':')
                    .last()
                    .unwrap_or("")
                    .to_string();

                rows.push(vec![sub_arn, topic_name, topic_arn, region.to_string()]);
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() { break; }
        }

        Ok(rows)
    }
}
