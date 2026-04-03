use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_ec2::Client as Ec2Client;

use crate::evidence::CsvCollector;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn format_ip_perms(perms: &[aws_sdk_ec2::types::IpPermission]) -> String {
    let mut parts = Vec::new();
    for perm in perms.iter().take(10) {
        let proto = match perm.ip_protocol().unwrap_or("-1") {
            "-1"  => "ALL".to_string(),
            "6"   => "TCP".to_string(),
            "17"  => "UDP".to_string(),
            "1"   => "ICMP".to_string(),
            other => other.to_string(),
        };
        let ports = match (perm.from_port(), perm.to_port()) {
            (Some(f), Some(t)) if f == t => format!(":{f}"),
            (Some(f), Some(t)) => format!(":{f}-{t}"),
            _ => "".to_string(),
        };
        let sources: Vec<String> = perm.ip_ranges().iter()
            .filter_map(|r| r.cidr_ip())
            .map(|s| s.to_string())
            .chain(
                perm.ipv6_ranges().iter()
                    .filter_map(|r| r.cidr_ipv6())
                    .map(|s| s.to_string())
            )
            .chain(
                perm.user_id_group_pairs().iter()
                    .filter_map(|g| g.group_id())
                    .map(|s| s.to_string())
            )
            .collect();
        let src = if sources.is_empty() { "*".to_string() } else { sources.join(",") };
        parts.push(format!("{proto}{ports}:{src}"));
    }
    if perms.len() > 10 { parts.push(format!("..+{}", perms.len() - 10)); }
    parts.join(" | ")
}

// ---------------------------------------------------------------------------
// Security Groups
// ---------------------------------------------------------------------------

pub struct SecurityGroupCollector {
    client: Ec2Client,
}

impl SecurityGroupCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: Ec2Client::new(config) }
    }
}

#[async_trait]
impl CsvCollector for SecurityGroupCollector {
    fn name(&self) -> &str { "Security Groups" }
    fn filename_prefix(&self) -> &str { "Security_Groups" }
    fn headers(&self) -> &'static [&'static str] {
        &["Group ID", "Group Name", "Inbound Rules", "Outbound Rules", "VPC ID", "Region"]
    }

    async fn collect_rows(&self, _account_id: &str, region: &str, _dates: Option<(i64, i64)>) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut next_token: Option<String> = None;

        loop {
            let mut req = self.client.describe_security_groups();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = req.send().await.context("EC2 describe_security_groups")?;

            for sg in resp.security_groups() {
                let id      = sg.group_id().unwrap_or("").to_string();
                let name    = sg.group_name().unwrap_or("").to_string();
                let inbound = format_ip_perms(sg.ip_permissions());
                let outbound = format_ip_perms(sg.ip_permissions_egress());
                let vpc     = sg.vpc_id().unwrap_or("").to_string();
                rows.push(vec![id, name, inbound, outbound, vpc, region.to_string()]);
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() { break; }
        }

        Ok(rows)
    }
}

// ---------------------------------------------------------------------------
// Route Tables
// ---------------------------------------------------------------------------

pub struct RouteTableCollector {
    client: Ec2Client,
}

impl RouteTableCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: Ec2Client::new(config) }
    }
}

#[async_trait]
impl CsvCollector for RouteTableCollector {
    fn name(&self) -> &str { "Route Tables" }
    fn filename_prefix(&self) -> &str { "Route_Tables" }
    fn headers(&self) -> &'static [&'static str] {
        &["Route Table ID", "Routes", "Subnet Associations", "VPC ID", "Region"]
    }

    async fn collect_rows(&self, _account_id: &str, region: &str, _dates: Option<(i64, i64)>) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut next_token: Option<String> = None;

        loop {
            let mut req = self.client.describe_route_tables();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = req.send().await.context("EC2 describe_route_tables")?;

            for rt in resp.route_tables() {
                let rt_id = rt.route_table_id().unwrap_or("").to_string();
                let vpc   = rt.vpc_id().unwrap_or("").to_string();

                let routes: Vec<String> = rt.routes().iter().map(|r| {
                    let dest = r.destination_cidr_block()
                        .or(r.destination_ipv6_cidr_block())
                        .or(r.destination_prefix_list_id())
                        .unwrap_or("*");
                    let target = r.gateway_id()
                        .or(r.nat_gateway_id())
                        .or(r.transit_gateway_id())
                        .or(r.instance_id())
                        .or(r.vpc_peering_connection_id())
                        .unwrap_or("local");
                    format!("{dest}→{target}")
                }).collect();

                let subnets: Vec<&str> = rt.associations()
                    .iter()
                    .filter_map(|a| a.subnet_id())
                    .collect();

                rows.push(vec![
                    rt_id,
                    routes.join(" | "),
                    subnets.join(", "),
                    vpc,
                    region.to_string(),
                ]);
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() { break; }
        }

        Ok(rows)
    }
}

// ---------------------------------------------------------------------------
// EC2 Instances
// ---------------------------------------------------------------------------

pub struct Ec2InstanceCollector {
    client: Ec2Client,
}

impl Ec2InstanceCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: Ec2Client::new(config) }
    }
}

#[async_trait]
impl CsvCollector for Ec2InstanceCollector {
    fn name(&self) -> &str { "EC2 Instances" }
    fn filename_prefix(&self) -> &str { "EC2_Instances" }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Instance ID", "Instance Type", "AMI ID", "State",
            "VPC ID", "Subnet ID", "IAM Role", "Encryption", "Region",
        ]
    }

    async fn collect_rows(&self, _account_id: &str, region: &str, _dates: Option<(i64, i64)>) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut next_token: Option<String> = None;

        loop {
            let mut req = self.client.describe_instances();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = req.send().await.context("EC2 describe_instances")?;

            for reservation in resp.reservations() {
                for inst in reservation.instances() {
                    let id         = inst.instance_id().unwrap_or("").to_string();
                    let inst_type  = inst.instance_type()
                        .map(|t| t.as_str().to_string())
                        .unwrap_or_default();
                    let ami        = inst.image_id().unwrap_or("").to_string();
                    let state      = inst.state()
                        .and_then(|s| s.name())
                        .map(|n| n.as_str().to_string())
                        .unwrap_or_default();
                    let vpc        = inst.vpc_id().unwrap_or("").to_string();
                    let subnet     = inst.subnet_id().unwrap_or("").to_string();
                    let iam_role   = inst.iam_instance_profile()
                        .and_then(|p| p.arn())
                        .and_then(|arn| arn.split('/').last())
                        .unwrap_or("")
                        .to_string();

                    // EbsInstanceBlockDevice doesn't expose encryption directly.
                    // Full encryption status is available via the EBS Volumes collector.
                    let encrypted = "See EBS Report";

                    rows.push(vec![
                        id, inst_type, ami, state,
                        vpc, subnet, iam_role, encrypted.to_string(), region.to_string(),
                    ]);
                }
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() { break; }
        }

        Ok(rows)
    }
}
