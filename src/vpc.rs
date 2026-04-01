use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_ec2::Client as Ec2Client;

use crate::evidence::CsvCollector;

// ---------------------------------------------------------------------------
// VPC Collector
// ---------------------------------------------------------------------------

pub struct VpcCollector {
    client: Ec2Client,
}

impl VpcCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: Ec2Client::new(config) }
    }
}

#[async_trait]
impl CsvCollector for VpcCollector {
    fn name(&self) -> &str { "VPCs" }
    fn filename_prefix(&self) -> &str { "VPCs" }
    fn headers(&self) -> &'static [&'static str] {
        &["ID", "Name", "CIDR Block", "Owner", "Region"]
    }

    async fn collect_rows(&self, _account_id: &str, region: &str) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut next_token: Option<String> = None;

        loop {
            let mut req = self.client.describe_vpcs();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = req.send().await?;

            for vpc in resp.vpcs() {
                let id   = vpc.vpc_id().unwrap_or("").to_string();
                let name = vpc.tags().iter()
                    .find(|t| t.key() == Some("Name"))
                    .and_then(|t| t.value())
                    .unwrap_or("")
                    .to_string();
                let cidr  = vpc.cidr_block().unwrap_or("").to_string();
                let owner = vpc.owner_id().unwrap_or("").to_string();
                rows.push(vec![id, name, cidr, owner, region.to_string()]);
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() { break; }
        }

        Ok(rows)
    }
}

// ---------------------------------------------------------------------------
// Network ACL Collector
// ---------------------------------------------------------------------------

pub struct NetworkAclCollector {
    client: Ec2Client,
}

impl NetworkAclCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: Ec2Client::new(config) }
    }
}

#[async_trait]
impl CsvCollector for NetworkAclCollector {
    fn name(&self) -> &str { "Network ACLs" }
    fn filename_prefix(&self) -> &str { "Network-ACL" }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Network ACL ID", "Rule Count", "Subnet Associations",
            "Default", "VPC", "Ingress Rules", "Egress Rules",
            "Owner", "ARN", "Region",
        ]
    }

    async fn collect_rows(&self, account_id: &str, region: &str) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut next_token: Option<String> = None;

        loop {
            let mut req = self.client.describe_network_acls();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = req.send().await?;

            for nacl in resp.network_acls() {
                let nacl_id = nacl.network_acl_id().unwrap_or("").to_string();
                let owner   = nacl.owner_id().unwrap_or("").to_string();
                let vpc     = nacl.vpc_id().unwrap_or("").to_string();
                let default = if nacl.is_default() == Some(true) { "Yes" } else { "No" }.to_string();

                let subnets: Vec<&str> = nacl.associations()
                    .iter()
                    .filter_map(|a| a.subnet_id())
                    .collect();
                let subnet_associations = subnets.join(", ");

                let arn = format!(
                    "arn:aws:ec2:{region}:{account_id}:network-acl/{nacl_id}"
                );

                let (ingress, egress) = format_nacl_rules(nacl.entries());
                let rule_count = nacl.entries().len().to_string();

                rows.push(vec![
                    nacl_id, rule_count, subnet_associations,
                    default, vpc, ingress, egress,
                    owner, arn, region.to_string(),
                ]);
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() { break; }
        }

        Ok(rows)
    }
}

fn format_nacl_rules(entries: &[aws_sdk_ec2::types::NetworkAclEntry]) -> (String, String) {
    let mut ingress_parts = Vec::new();
    let mut egress_parts  = Vec::new();

    let mut sorted: Vec<_> = entries.iter().collect();
    sorted.sort_by_key(|e| e.rule_number().unwrap_or(i32::MAX));

    for entry in sorted {
        let num    = entry.rule_number().map(|n| n.to_string()).unwrap_or_default();
        let action = entry.rule_action()
            .map(|a| a.as_str().to_uppercase())
            .unwrap_or_else(|| "?".to_string());
        let proto  = match entry.protocol().unwrap_or("-1") {
            "-1" => "ALL".to_string(),
            "6"  => "tcp".to_string(),
            "17" => "udp".to_string(),
            "1"  => "icmp".to_string(),
            p    => p.to_string(),
        };
        let cidr = entry.cidr_block()
            .or_else(|| entry.ipv6_cidr_block())
            .unwrap_or("*");
        let ports = entry.port_range()
            .map(|pr| {
                let from = pr.from().map(|n| n.to_string()).unwrap_or_default();
                let to   = pr.to().map(|n| n.to_string()).unwrap_or_default();
                if from == to { format!(":{from}") } else { format!(":{from}-{to}") }
            })
            .unwrap_or_default();

        let rule_str = format!("{num}:{action}:{proto}{ports}:{cidr}");
        if entry.egress() == Some(true) {
            egress_parts.push(rule_str);
        } else {
            ingress_parts.push(rule_str);
        }
    }

    (ingress_parts.join(" | "), egress_parts.join(" | "))
}
