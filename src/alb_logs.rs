use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_elasticloadbalancingv2::Client as ElbClient;
use aws_sdk_elasticloadbalancingv2::types::LoadBalancerTypeEnum;

use crate::evidence::CsvCollector;

pub struct AlbLogsCollector {
    client: ElbClient,
}

impl AlbLogsCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: ElbClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for AlbLogsCollector {
    fn name(&self) -> &str { "ALB Access Log Configuration" }
    fn filename_prefix(&self) -> &str { "ALB_AccessLogs" }
    fn headers(&self) -> &'static [&'static str] {
        &["ALB Name", "ALB ARN", "Scheme", "Access Logs Enabled", "Access Logs S3 Bucket", "Access Logs S3 Prefix"]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut marker: Option<String> = None;

        loop {
            let mut req = self.client.describe_load_balancers();
            if let Some(ref m) = marker {
                req = req.marker(m);
            }
            let resp = req.send().await.context("ELBv2 describe_load_balancers")?;

            for lb in resp.load_balancers() {
                // Only process Application Load Balancers
                if lb.r#type() != Some(&LoadBalancerTypeEnum::Application) {
                    continue;
                }

                let lb_name = lb.load_balancer_name().unwrap_or("").to_string();
                let lb_arn = lb.load_balancer_arn().unwrap_or("").to_string();
                let scheme = lb.scheme()
                    .map(|s| s.as_str().to_string())
                    .unwrap_or_default();

                let attrs_resp = match self.client
                    .describe_load_balancer_attributes()
                    .load_balancer_arn(&lb_arn)
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("  WARN: ELBv2 describe_load_balancer_attributes for {lb_name}: {e:#}");
                        rows.push(vec![lb_name, lb_arn, scheme, String::new(), String::new(), String::new()]);
                        continue;
                    }
                };

                let attrs: std::collections::HashMap<String, String> = attrs_resp.attributes()
                    .iter()
                    .map(|a| (
                        a.key().unwrap_or("").to_string(),
                        a.value().unwrap_or("").to_string(),
                    ))
                    .collect();

                let enabled = attrs.get("access_logs.s3.enabled")
                    .map(|s| s.as_str())
                    .unwrap_or("false")
                    .to_string();
                let bucket = attrs.get("access_logs.s3.bucket")
                    .map(|s| s.as_str())
                    .unwrap_or("")
                    .to_string();
                let prefix = attrs.get("access_logs.s3.prefix")
                    .map(|s| s.as_str())
                    .unwrap_or("")
                    .to_string();

                rows.push(vec![lb_name, lb_arn, scheme, enabled, bucket, prefix]);
            }

            marker = resp.next_marker().map(|s| s.to_string());
            if marker.is_none() { break; }
        }

        Ok(rows)
    }
}
