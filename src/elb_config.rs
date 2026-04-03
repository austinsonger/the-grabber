use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_elasticloadbalancingv2::Client as ElbClient;

use crate::evidence::CsvCollector;

pub struct ElbFullConfigCollector {
    client: ElbClient,
}

impl ElbFullConfigCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: ElbClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for ElbFullConfigCollector {
    fn name(&self) -> &str { "Load Balancer Configuration" }
    fn filename_prefix(&self) -> &str { "Load_Balancer_Config" }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "LB Name", "LB ARN", "Type", "Scheme", "VPC ID",
            "Security Groups", "Listeners", "SSL Policies",
        ]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str, _dates: Option<(i64, i64)>) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut marker: Option<String> = None;

        loop {
            let mut req = self.client.describe_load_balancers();
            if let Some(ref m) = marker {
                req = req.marker(m);
            }
            let resp = req.send().await.context("ELBv2 describe_load_balancers")?;

            for lb in resp.load_balancers() {
                let lb_name = lb.load_balancer_name().unwrap_or("").to_string();
                let lb_arn  = lb.load_balancer_arn().unwrap_or("").to_string();
                let lb_type = lb.r#type()
                    .map(|t| t.as_str().to_string())
                    .unwrap_or_default();
                let scheme  = lb.scheme()
                    .map(|s| s.as_str().to_string())
                    .unwrap_or_default();
                let vpc_id  = lb.vpc_id().unwrap_or("").to_string();
                let sgs: Vec<String> = lb.security_groups()
                    .iter()
                    .map(|s| s.to_string())
                    .collect();

                // Get listeners for this LB
                let (listener_summary, ssl_policies) = if lb_arn.is_empty() {
                    (String::new(), String::new())
                } else {
                    match self.client
                        .describe_listeners()
                        .load_balancer_arn(&lb_arn)
                        .send()
                        .await
                    {
                        Ok(r) => {
                            let mut listener_parts: Vec<String> = Vec::new();
                            let mut ssl_parts: Vec<String> = Vec::new();

                            for listener in r.listeners() {
                                let port    = listener.port()
                                    .map(|p| p.to_string())
                                    .unwrap_or_default();
                                let proto   = listener.protocol()
                                    .map(|p| p.as_str().to_string())
                                    .unwrap_or_default();
                                let action  = listener.default_actions().first()
                                    .and_then(|a| a.r#type())
                                    .map(|t| t.as_str())
                                    .unwrap_or("forward");
                                listener_parts.push(format!("{proto}:{port}({action})"));

                                if let Some(ssl) = listener.ssl_policy() {
                                    ssl_parts.push(ssl.to_string());
                                }
                            }

                            (listener_parts.join("; "), ssl_parts.join(", "))
                        }
                        Err(e) => {
                            eprintln!("  WARN: ELBv2 describe_listeners {lb_name}: {e:#}");
                            (String::new(), String::new())
                        }
                    }
                };

                rows.push(vec![
                    lb_name,
                    lb_arn,
                    lb_type,
                    scheme,
                    vpc_id,
                    sgs.join(", "),
                    listener_summary,
                    ssl_policies,
                ]);
            }

            marker = resp.next_marker().map(|s| s.to_string());
            if marker.is_none() { break; }
        }

        Ok(rows)
    }
}
