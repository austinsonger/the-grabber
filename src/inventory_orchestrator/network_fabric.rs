use std::collections::{HashMap, HashSet};

use anyhow::{Context, Result};
use aws_sdk_ec2::Client as Ec2Client;

use crate::inventory_core::RowBuilder;

// ---------------------------------------------------------------------------
// VPC Network Fabric — mapping doc §15-19
//
// Single "vpc-network" flag emits five row kinds: VPC, Subnet, Internet
// Gateway, NAT Gateway, Transit Gateway Attachment. Each sub-collector is
// independent — a failure in one must not lose the other four's rows, so the
// entry point below `unwrap_or_default()`s each call and each sub-collector
// logs its own error via `eprintln!` before propagating it upward.
// ---------------------------------------------------------------------------

pub(super) async fn collect_vpc_network(
    ec2: &Ec2Client,
    account_id: &str,
    region: &str,
) -> Result<Vec<Vec<String>>> {
    let mut rows = Vec::new();

    rows.extend(
        collect_vpcs(ec2, account_id, region)
            .await
            .unwrap_or_else(|e| {
                eprintln!("network_fabric: collect_vpcs failed: {e}");
                Vec::new()
            }),
    );
    rows.extend(
        collect_subnets(ec2, account_id, region)
            .await
            .unwrap_or_else(|e| {
                eprintln!("network_fabric: collect_subnets failed: {e}");
                Vec::new()
            }),
    );
    rows.extend(
        collect_internet_gateways(ec2, account_id, region)
            .await
            .unwrap_or_else(|e| {
                eprintln!("network_fabric: collect_internet_gateways failed: {e}");
                Vec::new()
            }),
    );
    rows.extend(
        collect_nat_gateways(ec2, account_id, region)
            .await
            .unwrap_or_else(|e| {
                eprintln!("network_fabric: collect_nat_gateways failed: {e}");
                Vec::new()
            }),
    );
    rows.extend(
        collect_transit_gateway_attachments(ec2, account_id, region)
            .await
            .unwrap_or_else(|e| {
                eprintln!("network_fabric: collect_transit_gateway_attachments failed: {e}");
                Vec::new()
            }),
    );

    Ok(rows)
}

// ---------------------------------------------------------------------------
// VPC — §15
// ---------------------------------------------------------------------------

/// Builds a resource-id → "has a flow log" set via a single, unfiltered
/// `describe_flow_logs` call for the whole region. Soft-fails to an empty
/// set (FlowLogsEnabled reads "false" for every VPC) rather than aborting
/// the VPC collector.
async fn flow_log_resource_ids(ec2: &Ec2Client) -> HashSet<String> {
    let mut ids = HashSet::new();
    let mut next_token: Option<String> = None;

    loop {
        let mut req = ec2.describe_flow_logs();
        if let Some(ref t) = next_token {
            req = req.next_token(t);
        }
        let resp = match req.send().await {
            Ok(r) => r,
            Err(e) => {
                eprintln!("network_fabric: describe_flow_logs failed: {e}");
                return ids;
            }
        };

        for fl in resp.flow_logs() {
            if let Some(rid) = fl.resource_id() {
                ids.insert(rid.to_string());
            }
        }

        next_token = resp.next_token().map(|s| s.to_string());
        if next_token.is_none() {
            break;
        }
    }

    ids
}

async fn collect_vpcs(ec2: &Ec2Client, account_id: &str, region: &str) -> Result<Vec<Vec<String>>> {
    let flow_log_ids = flow_log_resource_ids(ec2).await;

    let mut rows = Vec::new();
    let mut next_token: Option<String> = None;

    loop {
        let mut req = ec2.describe_vpcs();
        if let Some(ref t) = next_token {
            req = req.next_token(t);
        }
        let resp = req.send().await.context("EC2 describe_vpcs")?;

        for vpc in resp.vpcs() {
            let Some(vpc_id) = vpc.vpc_id() else {
                continue;
            };

            let cidr_block = vpc.cidr_block().unwrap_or("").to_string();
            let ipv6_cidr_block = vpc
                .ipv6_cidr_block_association_set()
                .first()
                .and_then(|a| a.ipv6_cidr_block())
                .unwrap_or("")
                .to_string();
            let is_default = vpc.is_default().map(|b| b.to_string()).unwrap_or_default();
            let state = vpc.state().map(|s| s.as_str()).unwrap_or("").to_string();
            let instance_tenancy = vpc
                .instance_tenancy()
                .map(|t| t.as_str())
                .unwrap_or("")
                .to_string();
            let dhcp_options_id = vpc.dhcp_options_id().unwrap_or("").to_string();

            let enable_dns_hostnames = vpc_attribute_bool(
                ec2,
                vpc_id,
                aws_sdk_ec2::types::VpcAttributeName::EnableDnsHostnames,
            )
            .await;
            let enable_dns_support = vpc_attribute_bool(
                ec2,
                vpc_id,
                aws_sdk_ec2::types::VpcAttributeName::EnableDnsSupport,
            )
            .await;

            let flow_logs_enabled = flow_log_ids.contains(vpc_id).to_string();

            let comments = format!(
                "CidrBlock: {cidr_block} | Ipv6CidrBlock: {ipv6_cidr_block} | \
                 IsDefault: {is_default} | State: {state} | \
                 InstanceTenancy: {instance_tenancy} | DhcpOptionsId: {dhcp_options_id} | \
                 EnableDnsHostnames: {enable_dns_hostnames} | \
                 EnableDnsSupport: {enable_dns_support} | \
                 FlowLogsEnabled: {flow_logs_enabled}"
            );

            rows.push(
                RowBuilder::new()
                    .unique_id(ec2_arn(account_id, region, "vpc", vpc_id))
                    .virtual_flag("Yes")
                    .public("No")
                    .location(region)
                    .asset_type("VPC")
                    .sw_vendor("Amazon Web Services")
                    .sw_name_ver("Amazon VPC")
                    .vlan_network_id(format!("VPC: {vpc_id}"))
                    .function(fabric_function(vpc.tags()))
                    .comments(comments)
                    .build(),
            );
        }

        next_token = resp.next_token().map(|s| s.to_string());
        if next_token.is_none() {
            break;
        }
    }

    Ok(rows)
}

/// Soft-failing per-VPC `describe_vpc_attribute` call. Returns "" on error
/// or when the attribute is absent, "true"/"false" otherwise.
async fn vpc_attribute_bool(
    ec2: &Ec2Client,
    vpc_id: &str,
    attribute: aws_sdk_ec2::types::VpcAttributeName,
) -> String {
    let resp = match ec2
        .describe_vpc_attribute()
        .vpc_id(vpc_id)
        .attribute(attribute.clone())
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!(
                "network_fabric: describe_vpc_attribute({attribute:?}) failed for {vpc_id}: {e}"
            );
            return String::new();
        }
    };

    let value = match attribute {
        aws_sdk_ec2::types::VpcAttributeName::EnableDnsHostnames => {
            resp.enable_dns_hostnames().and_then(|v| v.value())
        }
        aws_sdk_ec2::types::VpcAttributeName::EnableDnsSupport => {
            resp.enable_dns_support().and_then(|v| v.value())
        }
        _ => None,
    };

    value.map(|b| b.to_string()).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Subnet — §16
// ---------------------------------------------------------------------------

/// Per-subnet route-table facts: the route table id and whether it has a
/// default route to an Internet Gateway (`gateway_id` starting "igw-").
#[derive(Clone)]
struct RouteInfo {
    route_table_id: String,
    has_igw_route: bool,
}

/// Builds two maps from a single, region-wide `describe_route_tables` call:
/// explicit subnet associations, and each VPC's main (implicit) route table.
/// Soft-fails to empty maps — subnets then report empty RouteTableId /
/// HasIgwRoute: false rather than aborting the subnet collector.
async fn route_table_maps(
    ec2: &Ec2Client,
) -> (HashMap<String, RouteInfo>, HashMap<String, RouteInfo>) {
    let mut by_subnet: HashMap<String, RouteInfo> = HashMap::new();
    let mut main_by_vpc: HashMap<String, RouteInfo> = HashMap::new();
    let mut next_token: Option<String> = None;

    loop {
        let mut req = ec2.describe_route_tables();
        if let Some(ref t) = next_token {
            req = req.next_token(t);
        }
        let resp = match req.send().await {
            Ok(r) => r,
            Err(e) => {
                eprintln!("network_fabric: describe_route_tables failed: {e}");
                return (by_subnet, main_by_vpc);
            }
        };

        for rt in resp.route_tables() {
            let Some(route_table_id) = rt.route_table_id() else {
                continue;
            };
            let has_igw_route = rt
                .routes()
                .iter()
                .any(|r| r.gateway_id().is_some_and(|g| g.starts_with("igw-")));
            let info = RouteInfo {
                route_table_id: route_table_id.to_string(),
                has_igw_route,
            };

            for assoc in rt.associations() {
                if let Some(subnet_id) = assoc.subnet_id() {
                    by_subnet.insert(subnet_id.to_string(), info.clone());
                }
                if assoc.main() == Some(true) {
                    if let Some(vpc_id) = rt.vpc_id() {
                        main_by_vpc.insert(vpc_id.to_string(), info.clone());
                    }
                }
            }
        }

        next_token = resp.next_token().map(|s| s.to_string());
        if next_token.is_none() {
            break;
        }
    }

    (by_subnet, main_by_vpc)
}

/// Builds a subnet_id → network_acl_id map from a single, region-wide
/// `describe_network_acls` call. Soft-fails to an empty map.
async fn nacl_map(ec2: &Ec2Client) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let mut next_token: Option<String> = None;

    loop {
        let mut req = ec2.describe_network_acls();
        if let Some(ref t) = next_token {
            req = req.next_token(t);
        }
        let resp = match req.send().await {
            Ok(r) => r,
            Err(e) => {
                eprintln!("network_fabric: describe_network_acls failed: {e}");
                return map;
            }
        };

        for nacl in resp.network_acls() {
            let Some(nacl_id) = nacl.network_acl_id() else {
                continue;
            };
            for assoc in nacl.associations() {
                if let Some(subnet_id) = assoc.subnet_id() {
                    map.insert(subnet_id.to_string(), nacl_id.to_string());
                }
            }
        }

        next_token = resp.next_token().map(|s| s.to_string());
        if next_token.is_none() {
            break;
        }
    }

    map
}

async fn collect_subnets(
    ec2: &Ec2Client,
    account_id: &str,
    region: &str,
) -> Result<Vec<Vec<String>>> {
    let (route_by_subnet, main_route_by_vpc) = route_table_maps(ec2).await;
    let nacl_by_subnet = nacl_map(ec2).await;

    let mut rows = Vec::new();
    let mut next_token: Option<String> = None;

    loop {
        let mut req = ec2.describe_subnets();
        if let Some(ref t) = next_token {
            req = req.next_token(t);
        }
        let resp = req.send().await.context("EC2 describe_subnets")?;

        for subnet in resp.subnets() {
            let Some(subnet_id) = subnet.subnet_id() else {
                continue;
            };
            let Some(vpc_id) = subnet.vpc_id() else {
                continue;
            };
            let az = subnet.availability_zone().unwrap_or("");

            let unique_id = subnet
                .subnet_arn()
                .map(|s| s.to_string())
                .unwrap_or_else(|| ec2_arn(account_id, region, "subnet", subnet_id));

            let cidr_block = subnet.cidr_block().unwrap_or("").to_string();
            let ipv6_cidr_block = subnet
                .ipv6_cidr_block_association_set()
                .first()
                .and_then(|a| a.ipv6_cidr_block())
                .unwrap_or("")
                .to_string();
            let available_ip_count = subnet
                .available_ip_address_count()
                .map(|n| n.to_string())
                .unwrap_or_default();
            let state = subnet
                .state()
                .map(|s| s.as_str())
                .unwrap_or("")
                .to_string();
            let map_public_ip = subnet.map_public_ip_on_launch().unwrap_or(false);
            let assign_ipv6_on_create = subnet
                .assign_ipv6_address_on_creation()
                .map(|b| b.to_string())
                .unwrap_or_default();

            let route_info = route_by_subnet
                .get(subnet_id)
                .or_else(|| main_route_by_vpc.get(vpc_id));
            let route_table_id = route_info
                .map(|r| r.route_table_id.clone())
                .unwrap_or_default();
            let has_igw_route = route_info.is_some_and(|r| r.has_igw_route);

            let nacl_id = nacl_by_subnet.get(subnet_id).cloned().unwrap_or_default();

            let public = if map_public_ip || has_igw_route {
                "Yes"
            } else {
                "No"
            };

            let comments = format!(
                "CidrBlock: {cidr_block} | Ipv6CidrBlock: {ipv6_cidr_block} | \
                 AvailableIpAddressCount: {available_ip_count} | State: {state} | \
                 MapPublicIpOnLaunch: {map_public_ip} | \
                 AssignIpv6AddressOnCreation: {assign_ipv6_on_create} | \
                 RouteTableId: {route_table_id} | HasIgwRoute: {has_igw_route} | \
                 NaclId: {nacl_id}"
            );

            rows.push(
                RowBuilder::new()
                    .unique_id(unique_id)
                    .virtual_flag("Yes")
                    .public(public)
                    .location(format!("{region} / AZ: {az}"))
                    .asset_type("Subnet")
                    .sw_vendor("Amazon Web Services")
                    .sw_name_ver("Amazon VPC Subnet")
                    .vlan_network_id(format!("VPC: {vpc_id}, Subnet: {subnet_id}"))
                    .function(fabric_function(subnet.tags()))
                    .comments(comments)
                    .build(),
            );
        }

        next_token = resp.next_token().map(|s| s.to_string());
        if next_token.is_none() {
            break;
        }
    }

    Ok(rows)
}

// ---------------------------------------------------------------------------
// Internet Gateway — §18
// ---------------------------------------------------------------------------

async fn collect_internet_gateways(
    ec2: &Ec2Client,
    account_id: &str,
    region: &str,
) -> Result<Vec<Vec<String>>> {
    let mut rows = Vec::new();
    let mut next_token: Option<String> = None;

    loop {
        let mut req = ec2.describe_internet_gateways();
        if let Some(ref t) = next_token {
            req = req.next_token(t);
        }
        let resp = req.send().await.context("EC2 describe_internet_gateways")?;

        for igw in resp.internet_gateways() {
            let Some(igw_id) = igw.internet_gateway_id() else {
                continue;
            };

            let attachments = igw.attachments();
            let attachment_count = attachments.len();
            let attached_vpc_ids = attachments
                .iter()
                .filter_map(|a| a.vpc_id())
                .collect::<Vec<_>>()
                .join(", ");
            let state = attachments
                .first()
                .and_then(|a| a.state())
                .map(|s| s.as_str())
                .unwrap_or("detached")
                .to_string();
            let name_tag = igw
                .tags()
                .iter()
                .find(|t| t.key() == Some("Name"))
                .and_then(|t| t.value())
                .unwrap_or("")
                .to_string();

            let vlan_network_id = attachments
                .first()
                .and_then(|a| a.vpc_id())
                .map(|vpc_id| format!("VPC: {vpc_id}"))
                .unwrap_or_default();

            let comments = format!(
                "AttachmentCount: {attachment_count} | AttachedVpcIds: {attached_vpc_ids} | \
                 State: {state} | Tags.Name: {name_tag}"
            );

            rows.push(
                RowBuilder::new()
                    .unique_id(ec2_arn(account_id, region, "internet-gateway", igw_id))
                    .virtual_flag("Yes")
                    .public("Yes")
                    .location(region)
                    .asset_type("Internet Gateway")
                    .sw_vendor("Amazon Web Services")
                    .sw_name_ver("Amazon VPC Internet Gateway")
                    .vlan_network_id(vlan_network_id)
                    .function(fabric_function(igw.tags()))
                    .comments(comments)
                    .build(),
            );
        }

        next_token = resp.next_token().map(|s| s.to_string());
        if next_token.is_none() {
            break;
        }
    }

    Ok(rows)
}

// ---------------------------------------------------------------------------
// NAT Gateway — §17
// ---------------------------------------------------------------------------

async fn collect_nat_gateways(
    ec2: &Ec2Client,
    account_id: &str,
    region: &str,
) -> Result<Vec<Vec<String>>> {
    let mut rows = Vec::new();
    let mut next_token: Option<String> = None;

    loop {
        let mut req = ec2.describe_nat_gateways();
        if let Some(ref t) = next_token {
            req = req.next_token(t);
        }
        let resp = req.send().await.context("EC2 describe_nat_gateways")?;

        for nat in resp.nat_gateways() {
            let Some(nat_id) = nat.nat_gateway_id() else {
                continue;
            };
            let vpc_id = nat.vpc_id().unwrap_or("").to_string();
            let subnet_id = nat.subnet_id().unwrap_or("").to_string();

            let addresses = nat.nat_gateway_addresses();
            let public_ips = addresses
                .iter()
                .filter_map(|a| a.public_ip())
                .collect::<Vec<_>>()
                .join(", ");
            let allocation_ids = addresses
                .iter()
                .filter_map(|a| a.allocation_id())
                .collect::<Vec<_>>()
                .join(", ");
            let network_interface_ids = addresses
                .iter()
                .filter_map(|a| a.network_interface_id())
                .collect::<Vec<_>>()
                .join(", ");
            let private_ips = addresses
                .iter()
                .filter_map(|a| a.private_ip())
                .collect::<Vec<_>>()
                .join(", ");

            let state = nat.state().map(|s| s.as_str()).unwrap_or("").to_string();
            let connectivity_type = nat
                .connectivity_type()
                .map(|c| c.as_str())
                .unwrap_or("public")
                .to_string();
            let failure_code = nat.failure_code().unwrap_or("").to_string();
            let failure_message = nat.failure_message().unwrap_or("").to_string();

            let public = if connectivity_type == "private" {
                "No"
            } else {
                "Yes"
            };

            let comments = format!(
                "State: {state} | ConnectivityType: {connectivity_type} | \
                 SubnetId: {subnet_id} | AllocationIds: {allocation_ids} | \
                 NetworkInterfaceIds: {network_interface_ids} | PrivateIps: {private_ips} | \
                 FailureCode: {failure_code} | FailureMessage: {failure_message}"
            );

            rows.push(
                RowBuilder::new()
                    .unique_id(ec2_arn(account_id, region, "natgateway", nat_id))
                    .ipv4_ipv6(public_ips)
                    .virtual_flag("Yes")
                    .public(public)
                    .location(region)
                    .asset_type("NAT Gateway")
                    .sw_vendor("Amazon Web Services")
                    .sw_name_ver("Amazon VPC NAT Gateway")
                    .vlan_network_id(format!("VPC: {vpc_id}, Subnet: {subnet_id}"))
                    .function(fabric_function(nat.tags()))
                    .comments(comments)
                    .build(),
            );
        }

        next_token = resp.next_token().map(|s| s.to_string());
        if next_token.is_none() {
            break;
        }
    }

    Ok(rows)
}

// ---------------------------------------------------------------------------
// Transit Gateway Attachment — §19
// ---------------------------------------------------------------------------

async fn collect_transit_gateway_attachments(
    ec2: &Ec2Client,
    account_id: &str,
    region: &str,
) -> Result<Vec<Vec<String>>> {
    let mut rows = Vec::new();
    let mut next_token: Option<String> = None;

    loop {
        let mut req = ec2.describe_transit_gateway_attachments();
        if let Some(ref t) = next_token {
            req = req.next_token(t);
        }
        let resp = req
            .send()
            .await
            .context("EC2 describe_transit_gateway_attachments")?;

        for att in resp.transit_gateway_attachments() {
            let Some(attachment_id) = att.transit_gateway_attachment_id() else {
                continue;
            };
            let tgw_id = att.transit_gateway_id().unwrap_or("").to_string();
            let resource_id = att.resource_id().unwrap_or("").to_string();
            let resource_type = att
                .resource_type()
                .map(|r| r.as_str())
                .unwrap_or("")
                .to_string();
            let transit_gateway_owner_id =
                att.transit_gateway_owner_id().unwrap_or("").to_string();
            let resource_owner_id = att.resource_owner_id().unwrap_or("").to_string();
            let state = att.state().map(|s| s.as_str()).unwrap_or("").to_string();
            let assoc_route_table_id = att
                .association()
                .and_then(|a| a.transit_gateway_route_table_id())
                .unwrap_or("")
                .to_string();
            let assoc_state = att
                .association()
                .and_then(|a| a.state())
                .map(|s| s.as_str())
                .unwrap_or("")
                .to_string();
            let creation_time = att
                .creation_time()
                .and_then(|d| chrono::DateTime::<chrono::Utc>::from_timestamp(d.secs(), 0))
                .map(|c| c.to_rfc3339())
                .unwrap_or_default();

            let comments = format!(
                "TransitGatewayOwnerId: {transit_gateway_owner_id} | \
                 ResourceOwnerId: {resource_owner_id} | State: {state} | \
                 Association.TransitGatewayRouteTableId: {assoc_route_table_id} | \
                 Association.State: {assoc_state} | CreationTime: {creation_time}"
            );

            rows.push(
                RowBuilder::new()
                    .unique_id(ec2_arn(
                        account_id,
                        region,
                        "transit-gateway-attachment",
                        attachment_id,
                    ))
                    .virtual_flag("Yes")
                    .public("No")
                    .location(region)
                    .asset_type(format!("Transit Gateway Attachment ({resource_type})"))
                    .sw_vendor("Amazon Web Services")
                    .sw_name_ver("AWS Transit Gateway")
                    .vlan_network_id(format!("TGW: {tgw_id}, ResourceId: {resource_id}"))
                    .function(fabric_function(att.tags()))
                    .comments(comments)
                    .build(),
            );
        }

        next_token = resp.next_token().map(|s| s.to_string());
        if next_token.is_none() {
            break;
        }
    }

    Ok(rows)
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Synthesised ARN for EC2 sub-resources that don't return one.
fn ec2_arn(account_id: &str, region: &str, resource_type: &str, id: &str) -> String {
    format!("arn:aws:ec2:{region}:{account_id}:{resource_type}/{id}")
}

/// Network-fabric Function fallback: Purpose/App/Role/Function tag (any case)
/// → Tags.Name → empty. Fabric resources rarely carry purpose tags but
/// operators consistently set Name.
fn fabric_function(tags: &[aws_sdk_ec2::types::Tag]) -> String {
    let purpose = tags
        .iter()
        .find(|t| {
            matches!(
                t.key(),
                Some("Purpose")
                    | Some("App")
                    | Some("Role")
                    | Some("Function")
                    | Some("purpose")
                    | Some("app")
                    | Some("role")
            )
        })
        .and_then(|t| t.value())
        .unwrap_or("");
    if !purpose.is_empty() {
        return purpose.to_string();
    }
    tags.iter()
        .find(|t| t.key() == Some("Name"))
        .and_then(|t| t.value())
        .unwrap_or("")
        .to_string()
}
