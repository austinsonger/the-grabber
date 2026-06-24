use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_ec2::types::VpcAttributeName;
use aws_sdk_ec2::Client as Ec2Client;

use crate::evidence::CsvCollector;

pub struct VpcConfigCollector {
    client: Ec2Client,
}

impl VpcConfigCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: Ec2Client::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for VpcConfigCollector {
    fn name(&self) -> &str {
        "VPC Configuration"
    }
    fn filename_prefix(&self) -> &str {
        "VPC_Config"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "VPC ID",
            "CIDR Block",
            "State",
            "Instance Tenancy",
            "Enable DNS Support",
            "Enable DNS Hostnames",
            "Is Default",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut next_token: Option<String> = None;

        loop {
            let mut req = self.client.describe_vpcs();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = req.send().await.context("EC2 describe_vpcs")?;

            for vpc in resp.vpcs() {
                let vpc_id = vpc.vpc_id().unwrap_or("").to_string();
                let cidr = vpc.cidr_block().unwrap_or("").to_string();
                let state = vpc
                    .state()
                    .map(|s| s.as_str().to_string())
                    .unwrap_or_default();
                let tenancy = vpc
                    .instance_tenancy()
                    .map(|t| t.as_str().to_string())
                    .unwrap_or_default();
                let is_default = vpc.is_default().unwrap_or(false).to_string();

                // DNS attributes require separate API calls
                let dns_support = match self
                    .client
                    .describe_vpc_attribute()
                    .vpc_id(&vpc_id)
                    .attribute(VpcAttributeName::EnableDnsSupport)
                    .send()
                    .await
                {
                    Ok(r) => r
                        .enable_dns_support()
                        .and_then(|a| a.value())
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "Unknown".to_string()),
                    Err(_) => "Unknown".to_string(),
                };

                let dns_hostnames = match self
                    .client
                    .describe_vpc_attribute()
                    .vpc_id(&vpc_id)
                    .attribute(VpcAttributeName::EnableDnsHostnames)
                    .send()
                    .await
                {
                    Ok(r) => r
                        .enable_dns_hostnames()
                        .and_then(|a| a.value())
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "Unknown".to_string()),
                    Err(_) => "Unknown".to_string(),
                };

                rows.push(vec![
                    vpc_id,
                    cidr,
                    state,
                    tenancy,
                    dns_support,
                    dns_hostnames,
                    is_default,
                ]);
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() {
                break;
            }
        }

        Ok(rows)
    }
}
