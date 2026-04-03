use std::collections::HashMap;

use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_elasticloadbalancingv2::Client as ElbClient;

use crate::evidence::CsvCollector;

// ---------------------------------------------------------------------------
// Load Balancers
// ---------------------------------------------------------------------------

pub struct LoadBalancerCollector {
    client: ElbClient,
}

impl LoadBalancerCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: ElbClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for LoadBalancerCollector {
    fn name(&self) -> &str { "Load Balancers" }
    fn filename_prefix(&self) -> &str { "Load_Balancers" }
    fn headers(&self) -> &'static [&'static str] {
        &["Name", "Balancer Type", "ARN", "Region"]
    }

    async fn collect_rows(&self, _account_id: &str, region: &str, _dates: Option<(i64, i64)>) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut marker: Option<String> = None;

        loop {
            let mut req = self.client.describe_load_balancers();
            if let Some(ref m) = marker {
                req = req.marker(m);
            }
            let resp = req.send().await.context("ELBv2 describe_load_balancers")?;

            for lb in resp.load_balancers() {
                let name      = lb.load_balancer_name().unwrap_or("").to_string();
                let lb_type   = lb.r#type().map(|t| t.as_str().to_string()).unwrap_or_default();
                let arn       = lb.load_balancer_arn().unwrap_or("").to_string();
                rows.push(vec![name, lb_type, arn, region.to_string()]);
            }

            marker = resp.next_marker().map(|s| s.to_string());
            if marker.is_none() { break; }
        }

        Ok(rows)
    }
}

// ---------------------------------------------------------------------------
// Load Balancer Listeners
// ---------------------------------------------------------------------------

pub struct LoadBalancerListenerCollector {
    client: ElbClient,
}

impl LoadBalancerListenerCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: ElbClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for LoadBalancerListenerCollector {
    fn name(&self) -> &str { "Load Balancer Listeners" }
    fn filename_prefix(&self) -> &str { "Load_Balancer_Listeners" }
    fn headers(&self) -> &'static [&'static str] {
        &["Balancer Name", "ARN", "Certificate ID", "Protocol", "Region"]
    }

    async fn collect_rows(&self, _account_id: &str, region: &str, _dates: Option<(i64, i64)>) -> Result<Vec<Vec<String>>> {
        // First build a map from LB ARN → LB name.
        let mut lb_names: HashMap<String, String> = HashMap::new();
        let mut marker: Option<String> = None;
        loop {
            let mut req = self.client.describe_load_balancers();
            if let Some(ref m) = marker {
                req = req.marker(m);
            }
            let resp = req.send().await.context("ELBv2 describe_load_balancers")?;
            for lb in resp.load_balancers() {
                if let (Some(arn), Some(name)) = (lb.load_balancer_arn(), lb.load_balancer_name()) {
                    lb_names.insert(arn.to_string(), name.to_string());
                }
            }
            marker = resp.next_marker().map(|s| s.to_string());
            if marker.is_none() { break; }
        }

        let mut rows = Vec::new();

        // Fetch listeners for each load balancer.
        for (lb_arn, lb_name) in &lb_names {
            let mut l_marker: Option<String> = None;
            loop {
                let mut req = self.client
                    .describe_listeners()
                    .load_balancer_arn(lb_arn);
                if let Some(ref m) = l_marker {
                    req = req.marker(m);
                }
                let resp = match req.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("  WARN: ELBv2 describe_listeners for {lb_name}: {e:#}");
                        break;
                    }
                };

                for listener in resp.listeners() {
                    let listener_arn = listener.listener_arn().unwrap_or("").to_string();
                    let protocol     = listener.protocol()
                        .map(|p| p.as_str().to_string())
                        .unwrap_or_default();
                    let cert_id      = listener.certificates()
                        .first()
                        .and_then(|c| c.certificate_arn())
                        .unwrap_or("")
                        .to_string();

                    rows.push(vec![
                        lb_name.clone(), listener_arn, cert_id,
                        protocol, region.to_string(),
                    ]);
                }

                l_marker = resp.next_marker().map(|s| s.to_string());
                if l_marker.is_none() { break; }
            }
        }

        Ok(rows)
    }
}
