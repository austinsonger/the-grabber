use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_ec2::Client as Ec2Client;
use aws_sdk_ec2::types::VpcAttributeName;

use crate::evidence::CsvCollector;

fn fmt_ip_perm(perms: &[aws_sdk_ec2::types::IpPermission]) -> String {
    perms.iter().map(|p| {
        let proto = p.ip_protocol().unwrap_or("-1");
        let from  = p.from_port().map(|n| n.to_string()).unwrap_or_else(|| "All".to_string());
        let to    = p.to_port().map(|n| n.to_string()).unwrap_or_else(|| "All".to_string());
        let cidrs: Vec<&str> = p.ip_ranges().iter()
            .filter_map(|r| r.cidr_ip())
            .collect();
        let ipv6: Vec<&str> = p.ipv6_ranges().iter()
            .filter_map(|r| r.cidr_ipv6())
            .collect();
        let sgs: Vec<String> = p.user_id_group_pairs().iter()
            .filter_map(|g| g.group_id().map(|s| s.to_string()))
            .collect();
        let mut sources = cidrs;
        sources.extend(ipv6.iter().copied());
        let mut combined: Vec<String> = sources.iter().map(|s| s.to_string()).collect();
        combined.extend(sgs);
        format!("{proto}:{from}-{to}:[{}]", combined.join(","))
    }).collect::<Vec<_>>().join("; ")
}

// ══════════════════════════════════════════════════════════════════════════════
// 1. Security Group Configuration (full rules)
// ══════════════════════════════════════════════════════════════════════════════

pub struct SecurityGroupConfigCollector {
    client: Ec2Client,
}

impl SecurityGroupConfigCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: Ec2Client::new(config) }
    }
}

#[async_trait]
impl CsvCollector for SecurityGroupConfigCollector {
    fn name(&self) -> &str { "Security Group Configuration" }
    fn filename_prefix(&self) -> &str { "Security_Group_Config" }
    fn headers(&self) -> &'static [&'static str] {
        &["Group ID", "Name", "Description", "VPC ID", "Ingress Rules", "Egress Rules"]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut next_token: Option<String> = None;

        loop {
            let mut req = self.client.describe_security_groups();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = req.send().await.context("EC2 describe_security_groups")?;

            for sg in resp.security_groups() {
                let group_id  = sg.group_id().unwrap_or("").to_string();
                let name      = sg.group_name().unwrap_or("").to_string();
                let desc      = sg.description().unwrap_or("").to_string();
                let vpc_id    = sg.vpc_id().unwrap_or("").to_string();
                let ingress   = fmt_ip_perm(sg.ip_permissions());
                let egress    = fmt_ip_perm(sg.ip_permissions_egress());

                rows.push(vec![group_id, name, desc, vpc_id, ingress, egress]);
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() { break; }
        }

        Ok(rows)
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// 2. VPC Configuration (with DNS attributes)
// ══════════════════════════════════════════════════════════════════════════════

pub struct VpcConfigCollector {
    client: Ec2Client,
}

impl VpcConfigCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: Ec2Client::new(config) }
    }
}

#[async_trait]
impl CsvCollector for VpcConfigCollector {
    fn name(&self) -> &str { "VPC Configuration" }
    fn filename_prefix(&self) -> &str { "VPC_Config" }
    fn headers(&self) -> &'static [&'static str] {
        &["VPC ID", "CIDR Block", "State", "Instance Tenancy",
          "Enable DNS Support", "Enable DNS Hostnames", "Is Default"]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut next_token: Option<String> = None;

        loop {
            let mut req = self.client.describe_vpcs();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = req.send().await.context("EC2 describe_vpcs")?;

            for vpc in resp.vpcs() {
                let vpc_id   = vpc.vpc_id().unwrap_or("").to_string();
                let cidr     = vpc.cidr_block().unwrap_or("").to_string();
                let state    = vpc.state().map(|s| s.as_str().to_string()).unwrap_or_default();
                let tenancy  = vpc.instance_tenancy()
                    .map(|t| t.as_str().to_string())
                    .unwrap_or_default();
                let is_default = vpc.is_default().unwrap_or(false).to_string();

                // DNS attributes require separate API calls
                let dns_support = match self.client
                    .describe_vpc_attribute()
                    .vpc_id(&vpc_id)
                    .attribute(VpcAttributeName::EnableDnsSupport)
                    .send()
                    .await
                {
                    Ok(r) => r.enable_dns_support()
                        .and_then(|a| a.value())
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "Unknown".to_string()),
                    Err(_) => "Unknown".to_string(),
                };

                let dns_hostnames = match self.client
                    .describe_vpc_attribute()
                    .vpc_id(&vpc_id)
                    .attribute(VpcAttributeName::EnableDnsHostnames)
                    .send()
                    .await
                {
                    Ok(r) => r.enable_dns_hostnames()
                        .and_then(|a| a.value())
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "Unknown".to_string()),
                    Err(_) => "Unknown".to_string(),
                };

                rows.push(vec![vpc_id, cidr, state, tenancy, dns_support, dns_hostnames, is_default]);
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() { break; }
        }

        Ok(rows)
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// 3. Route Table Configuration
// ══════════════════════════════════════════════════════════════════════════════

pub struct RouteTableConfigCollector {
    client: Ec2Client,
}

impl RouteTableConfigCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: Ec2Client::new(config) }
    }
}

#[async_trait]
impl CsvCollector for RouteTableConfigCollector {
    fn name(&self) -> &str { "Route Table Configuration" }
    fn filename_prefix(&self) -> &str { "Route_Table_Config" }
    fn headers(&self) -> &'static [&'static str] {
        &["Route Table ID", "VPC ID", "Routes", "Associations", "Propagating VGWs"]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut next_token: Option<String> = None;

        loop {
            let mut req = self.client.describe_route_tables();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = req.send().await.context("EC2 describe_route_tables")?;

            for rt in resp.route_tables() {
                let rt_id  = rt.route_table_id().unwrap_or("").to_string();
                let vpc_id = rt.vpc_id().unwrap_or("").to_string();

                let routes: Vec<String> = rt.routes().iter().map(|r| {
                    let dest = r.destination_cidr_block()
                        .or(r.destination_ipv6_cidr_block())
                        .or(r.destination_prefix_list_id())
                        .unwrap_or("?");
                    let target = r.gateway_id()
                        .or(r.nat_gateway_id())
                        .or(r.transit_gateway_id())
                        .or(r.vpc_peering_connection_id())
                        .or(r.instance_id())
                        .or(r.network_interface_id())
                        .unwrap_or("local");
                    let state = r.state().map(|s| s.as_str()).unwrap_or("active");
                    format!("{dest}→{target}({state})")
                }).collect();

                let assocs: Vec<String> = rt.associations().iter().map(|a| {
                    if a.main().unwrap_or(false) {
                        "main".to_string()
                    } else {
                        a.subnet_id().unwrap_or("").to_string()
                    }
                }).collect();

                let vgws: Vec<String> = rt.propagating_vgws().iter()
                    .filter_map(|v| v.gateway_id().map(|s| s.to_string()))
                    .collect();

                rows.push(vec![
                    rt_id,
                    vpc_id,
                    routes.join("; "),
                    assocs.join(", "),
                    vgws.join(", "),
                ]);
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() { break; }
        }

        Ok(rows)
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// 4. EC2 Instance Configuration
// ══════════════════════════════════════════════════════════════════════════════

pub struct Ec2InstanceConfigCollector {
    client: Ec2Client,
}

impl Ec2InstanceConfigCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: Ec2Client::new(config) }
    }
}

#[async_trait]
impl CsvCollector for Ec2InstanceConfigCollector {
    fn name(&self) -> &str { "EC2 Instance Configuration" }
    fn filename_prefix(&self) -> &str { "EC2_Config" }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Instance ID", "Image ID", "Instance Type", "State",
            "IMDS Version", "IAM Instance Profile", "Block Devices", "Monitoring",
        ]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str) -> Result<Vec<Vec<String>>> {
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
                    let instance_id = inst.instance_id().unwrap_or("").to_string();
                    let image_id    = inst.image_id().unwrap_or("").to_string();
                    let inst_type   = inst.instance_type()
                        .map(|t| t.as_str().to_string())
                        .unwrap_or_default();
                    let state = inst.state()
                        .and_then(|s| s.name())
                        .map(|s| s.as_str().to_string())
                        .unwrap_or_default();

                    // IMDSv2 enforcement
                    let imds = inst.metadata_options()
                        .and_then(|m| m.http_tokens())
                        .map(|t| t.as_str().to_string())
                        .unwrap_or_else(|| "optional".to_string());

                    // IAM instance profile
                    let iam_profile = inst.iam_instance_profile()
                        .and_then(|p| p.arn())
                        .unwrap_or("")
                        .to_string();

                    // Block device mappings summary
                    let block_devs: Vec<String> = inst.block_device_mappings().iter()
                        .map(|bd| {
                            let dev  = bd.device_name().unwrap_or("");
                            let vol  = bd.ebs()
                                .and_then(|e| e.volume_id())
                                .unwrap_or("");
                            let del  = bd.ebs()
                                .and_then(|e| e.delete_on_termination())
                                .unwrap_or(true);
                            format!("{dev}:{vol}(delete={del})")
                        })
                        .collect();

                    let monitoring = inst.monitoring()
                        .and_then(|m| m.state())
                        .map(|s| s.as_str().to_string())
                        .unwrap_or_default();

                    rows.push(vec![
                        instance_id,
                        image_id,
                        inst_type,
                        state,
                        imds,
                        iam_profile,
                        block_devs.join("; "),
                        monitoring,
                    ]);
                }
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() { break; }
        }

        Ok(rows)
    }
}
