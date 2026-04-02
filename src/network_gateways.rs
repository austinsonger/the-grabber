use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_ec2::Client as Ec2Client;
use aws_sdk_ec2::types::Filter;

use crate::evidence::CsvCollector;

// ══════════════════════════════════════════════════════════════════════════════
// 1. Internet Gateway Collector
// ══════════════════════════════════════════════════════════════════════════════

pub struct InternetGatewayCollector {
    client: Ec2Client,
}

impl InternetGatewayCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: Ec2Client::new(config) }
    }
}

#[async_trait]
impl CsvCollector for InternetGatewayCollector {
    fn name(&self) -> &str { "Internet Gateways" }
    fn filename_prefix(&self) -> &str { "Network_InternetGateways" }
    fn headers(&self) -> &'static [&'static str] {
        &["Gateway ID", "Attached VPC ID", "Attachment State", "Name Tag", "Region"]
    }

    async fn collect_rows(&self, _account_id: &str, region: &str) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut next_token: Option<String> = None;

        loop {
            let mut req = self.client.describe_internet_gateways();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = req.send().await.context("EC2 describe_internet_gateways")?;

            for igw in resp.internet_gateways() {
                let igw_id = igw.internet_gateway_id().unwrap_or("").to_string();
                let name_tag = igw.tags().iter()
                    .find(|t| t.key() == Some("Name"))
                    .and_then(|t| t.value())
                    .unwrap_or("")
                    .to_string();

                let attachments = igw.attachments();
                if attachments.is_empty() {
                    rows.push(vec![
                        igw_id,
                        "Not Attached".to_string(),
                        String::new(),
                        name_tag,
                        region.to_string(),
                    ]);
                } else {
                    for attachment in attachments {
                        let vpc_id = attachment.vpc_id().unwrap_or("").to_string();
                        let state = attachment.state()
                            .map(|s| s.as_str().to_string())
                            .unwrap_or_default();
                        rows.push(vec![
                            igw_id.clone(),
                            vpc_id,
                            state,
                            name_tag.clone(),
                            region.to_string(),
                        ]);
                    }
                }
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() { break; }
        }

        Ok(rows)
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// 2. NAT Gateway Collector
// ══════════════════════════════════════════════════════════════════════════════

pub struct NatGatewayCollector {
    client: Ec2Client,
}

impl NatGatewayCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: Ec2Client::new(config) }
    }
}

#[async_trait]
impl CsvCollector for NatGatewayCollector {
    fn name(&self) -> &str { "NAT Gateways" }
    fn filename_prefix(&self) -> &str { "Network_NatGateways" }
    fn headers(&self) -> &'static [&'static str] {
        &["NAT Gateway ID", "Subnet ID", "VPC ID", "Public IP", "Private IP", "Connectivity Type", "State"]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut next_token: Option<String> = None;

        let state_filter = Filter::builder()
            .name("state")
            .values("available")
            .values("pending")
            .values("failed")
            .build();

        loop {
            let mut req = self.client
                .describe_nat_gateways()
                .filter(state_filter.clone());
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = req.send().await.context("EC2 describe_nat_gateways")?;

            for nat in resp.nat_gateways() {
                let nat_id = nat.nat_gateway_id().unwrap_or("").to_string();
                let subnet_id = nat.subnet_id().unwrap_or("").to_string();
                let vpc_id = nat.vpc_id().unwrap_or("").to_string();

                let first_addr = nat.nat_gateway_addresses().first();
                let public_ip = first_addr.and_then(|a| a.public_ip()).unwrap_or("").to_string();
                let private_ip = first_addr.and_then(|a| a.private_ip()).unwrap_or("").to_string();

                let connectivity = nat.connectivity_type()
                    .map(|c| c.as_str().to_string())
                    .unwrap_or_default();

                let state = nat.state()
                    .map(|s| s.as_str().to_string())
                    .unwrap_or_default();

                rows.push(vec![
                    nat_id,
                    subnet_id,
                    vpc_id,
                    public_ip,
                    private_ip,
                    connectivity,
                    state,
                ]);
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() { break; }
        }

        Ok(rows)
    }
}
