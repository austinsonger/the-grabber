use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_ec2::Client as Ec2Client;

use crate::evidence::CsvCollector;

pub struct VpcEndpointCollector {
    client: Ec2Client,
}

impl VpcEndpointCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: Ec2Client::new(config) }
    }
}

#[async_trait]
impl CsvCollector for VpcEndpointCollector {
    fn name(&self) -> &str { "VPC Endpoints" }
    fn filename_prefix(&self) -> &str { "VPC_Endpoints_Config" }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Endpoint ID", "VPC ID", "Service Name", "Endpoint Type",
            "State", "Private DNS Enabled", "Has Policy",
        ]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str, _dates: Option<(i64, i64)>) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut next_token: Option<String> = None;

        loop {
            let mut req = self.client.describe_vpc_endpoints();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = req.send().await.context("EC2 describe_vpc_endpoints")?;

            for ep in resp.vpc_endpoints() {
                let ep_id        = ep.vpc_endpoint_id().unwrap_or("").to_string();
                let vpc_id       = ep.vpc_id().unwrap_or("").to_string();
                let service_name = ep.service_name().unwrap_or("").to_string();
                let ep_type      = ep.vpc_endpoint_type()
                    .map(|t| t.as_str().to_string())
                    .unwrap_or_default();
                let state        = ep.state()
                    .map(|s| s.as_str().to_string())
                    .unwrap_or_default();
                let private_dns  = ep.private_dns_enabled()
                    .unwrap_or(false)
                    .to_string();
                let has_policy   = ep.policy_document()
                    .map(|p| if p.is_empty() { "No" } else { "Yes" })
                    .unwrap_or("No")
                    .to_string();

                rows.push(vec![ep_id, vpc_id, service_name, ep_type, state, private_dns, has_policy]);
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() { break; }
        }

        Ok(rows)
    }
}
