use anyhow::{Context, Result};

use aws_sdk_elasticache::Client as ElastiCacheClient;
use aws_sdk_elasticloadbalancingv2::Client as ElbClient;
use aws_sdk_rds::Client as RdsClient;

use crate::inventory_core::RowBuilder;

// ---------------------------------------------------------------------------
// Application Load Balancers
// ---------------------------------------------------------------------------

pub(super) async fn collect_albs(client: &ElbClient, region: &str) -> Result<Vec<Vec<String>>> {
    let mut rows = Vec::new();
    let mut marker: Option<String> = None;

    loop {
        let mut req = client.describe_load_balancers();
        if let Some(ref m) = marker {
            req = req.marker(m);
        }
        let resp = req.send().await.context("ELBv2 describe_load_balancers")?;

        for lb in resp.load_balancers() {
            // Only application load balancers
            if lb.r#type()
                != Some(&aws_sdk_elasticloadbalancingv2::types::LoadBalancerTypeEnum::Application)
            {
                continue;
            }

            let arn = lb.load_balancer_arn().unwrap_or("").to_string();
            let dns_name = lb.dns_name().unwrap_or("").to_string();
            let scheme = lb.scheme().map(|s| s.as_str()).unwrap_or("").to_string();
            let vpc_id = lb.vpc_id().unwrap_or("").to_string();
            let is_public = lb.scheme()
                == Some(
                    &aws_sdk_elasticloadbalancingv2::types::LoadBalancerSchemeEnum::InternetFacing,
                );
            let ip_type = lb
                .ip_address_type()
                .map(|t| t.as_str())
                .unwrap_or("")
                .to_string();
            let sgs = lb.security_groups().join(", ");

            let subnet_ids: Vec<String> = lb
                .availability_zones()
                .iter()
                .filter_map(|az| az.subnet_id())
                .map(|s| s.to_string())
                .collect();
            let az_names: Vec<String> = lb
                .availability_zones()
                .iter()
                .filter_map(|az| az.zone_name())
                .map(|s| s.to_string())
                .collect();

            let location = format!("{region} / AZs: {}", az_names.join(", "));
            let vlan_net = format!("VPC: {vpc_id}, Subnets: {}", subnet_ids.join(", "));

            // Fetch listeners for comments
            let listeners_summary = match client
                .describe_listeners()
                .load_balancer_arn(&arn)
                .send()
                .await
            {
                Ok(r) => r
                    .listeners()
                    .iter()
                    .map(|l| {
                        let port = l.port().unwrap_or(0);
                        let proto = l.protocol().map(|p| p.as_str()).unwrap_or("");
                        format!("{proto}:{port}")
                    })
                    .collect::<Vec<_>>()
                    .join(", "),
                Err(_) => String::new(),
            };

            let comments = format!(
                "VPC: {vpc_id} | SecurityGroups: {sgs} | IpAddressType: {ip_type} | \
                 Scheme: {scheme} | Listeners: {listeners_summary}"
            );

            rows.push(
                RowBuilder::new()
                    .unique_id(&arn)
                    .virtual_flag("Yes")
                    .public(if is_public { "Yes" } else { "No" })
                    .dns_url(&dns_name)
                    .location(location)
                    .asset_type("Application Load Balancer")
                    .hw_make_model("AWS ALB")
                    .sw_vendor("Amazon Web Services")
                    .sw_name_ver("AWS ELBv2 (application)")
                    .vlan_network_id(vlan_net)
                    .comments(comments)
                    .build(),
            );
        }

        marker = resp.next_marker().map(|s| s.to_string());
        if marker.is_none() {
            break;
        }
    }

    Ok(rows)
}

// ---------------------------------------------------------------------------
// RDS DB Instances
// ---------------------------------------------------------------------------

pub(super) async fn collect_rds_instances(
    client: &RdsClient,
    region: &str,
) -> Result<Vec<Vec<String>>> {
    let mut rows = Vec::new();
    let mut marker: Option<String> = None;

    loop {
        let mut req = client.describe_db_instances();
        if let Some(ref m) = marker {
            req = req.marker(m);
        }
        let resp = req.send().await.context("RDS describe_db_instances")?;

        for db in resp.db_instances() {
            let arn = db.db_instance_arn().unwrap_or("").to_string();
            let engine = db.engine().unwrap_or("").to_string();
            let engine_ver = db.engine_version().unwrap_or("").to_string();
            let class = db.db_instance_class().unwrap_or("").to_string();
            let publicly_accessible = db.publicly_accessible().unwrap_or(false);
            let endpoint = db
                .endpoint()
                .and_then(|e| e.address())
                .unwrap_or("")
                .to_string();

            let (subnet_group_name, vpc_id, subnet_ids) = if let Some(sg) = db.db_subnet_group() {
                let sgn = sg.db_subnet_group_name().unwrap_or("").to_string();
                let vid = sg.vpc_id().unwrap_or("").to_string();
                let sids: Vec<String> = sg
                    .subnets()
                    .iter()
                    .filter_map(|s| s.subnet_identifier())
                    .map(|s| s.to_string())
                    .collect();
                (sgn, vid, sids.join(", "))
            } else {
                (String::new(), String::new(), String::new())
            };

            let sw_vendor = match engine.to_lowercase().as_str() {
                e if e.starts_with("aurora") => "Amazon Web Services",
                "postgres" | "postgresql" => "PostgreSQL",
                "mysql" | "mariadb" => "MySQL",
                "oracle-ee" | "oracle-se2" | "oracle-se1" => "Oracle",
                "sqlserver-ee" | "sqlserver-se" | "sqlserver-ex" | "sqlserver-web" => "Microsoft",
                _ => "Amazon Web Services",
            };

            let location = format!("{region} / Subnet group: {subnet_group_name}, VPC: {vpc_id}");
            let vlan_net = if vpc_id.is_empty() {
                String::new()
            } else {
                format!("VPC: {vpc_id}, Subnets: {subnet_ids}")
            };

            rows.push(
                RowBuilder::new()
                    .unique_id(&arn)
                    .virtual_flag("Yes")
                    .public(if publicly_accessible { "Yes" } else { "No" })
                    .dns_url(&endpoint)
                    .location(location)
                    .asset_type("RDS DB Instance")
                    .hw_make_model(format!("AWS RDS {class}"))
                    .sw_vendor(sw_vendor)
                    .sw_name_ver(format!("{engine} {engine_ver}"))
                    .vlan_network_id(vlan_net)
                    .build(),
            );
        }

        marker = resp.marker().map(|s| s.to_string());
        if marker.is_none() {
            break;
        }
    }

    Ok(rows)
}

// ---------------------------------------------------------------------------
// ElastiCache Clusters (via Replication Groups for Redis/Valkey)
// ---------------------------------------------------------------------------

pub(super) async fn collect_elasticache_clusters(
    client: &ElastiCacheClient,
    region: &str,
) -> Result<Vec<Vec<String>>> {
    let mut rows = Vec::new();
    let mut marker: Option<String> = None;

    // Replication groups (Redis / Valkey)
    loop {
        let mut req = client.describe_replication_groups();
        if let Some(ref m) = marker {
            req = req.marker(m);
        }
        let resp = req
            .send()
            .await
            .context("ElastiCache describe_replication_groups")?;

        for rg in resp.replication_groups() {
            let id = rg.replication_group_id().unwrap_or("").to_string();
            let arn = rg.arn().unwrap_or("").to_string();

            // Primary endpoint
            let endpoint = rg
                .configuration_endpoint()
                .and_then(|e| e.address())
                .or_else(|| {
                    rg.node_groups()
                        .first()
                        .and_then(|ng| ng.primary_endpoint())
                        .and_then(|e| e.address())
                })
                .unwrap_or("")
                .to_string();

            // Get CacheNodeType from first member cluster
            let (cache_node_type, engine, engine_ver, subnet_group_name) = {
                let member_id = rg
                    .member_clusters()
                    .first()
                    .map(|s| s.as_str())
                    .unwrap_or("");
                if member_id.is_empty() {
                    (String::new(), String::new(), String::new(), String::new())
                } else {
                    match client
                        .describe_cache_clusters()
                        .cache_cluster_id(member_id)
                        .send()
                        .await
                    {
                        Ok(r) => {
                            let cc = r.cache_clusters().first();
                            (
                                cc.and_then(|c| c.cache_node_type())
                                    .unwrap_or("")
                                    .to_string(),
                                cc.and_then(|c| c.engine()).unwrap_or("").to_string(),
                                cc.and_then(|c| c.engine_version())
                                    .unwrap_or("")
                                    .to_string(),
                                cc.and_then(|c| c.cache_subnet_group_name())
                                    .unwrap_or("")
                                    .to_string(),
                            )
                        }
                        Err(_) => (String::new(), String::new(), String::new(), String::new()),
                    }
                }
            };

            // Subnet group → VPC/subnets
            let (vpc_id, subnet_ids) = if !subnet_group_name.is_empty() {
                match client
                    .describe_cache_subnet_groups()
                    .cache_subnet_group_name(&subnet_group_name)
                    .send()
                    .await
                {
                    Ok(r) => {
                        let sg = r.cache_subnet_groups().first();
                        let vid = sg.and_then(|g| g.vpc_id()).unwrap_or("").to_string();
                        let sids: Vec<String> = sg
                            .map(|g| {
                                g.subnets()
                                    .iter()
                                    .filter_map(|s| s.subnet_identifier())
                                    .map(|s| s.to_string())
                                    .collect()
                            })
                            .unwrap_or_default();
                        (vid, sids.join(", "))
                    }
                    Err(_) => (String::new(), String::new()),
                }
            } else {
                (String::new(), String::new())
            };

            let sw_vendor = match engine.to_lowercase().as_str() {
                "redis" => "Redis",
                "valkey" => "Amazon Web Services",
                "memcached" => "Memcached",
                _ => "Amazon Web Services",
            };

            let location = if subnet_group_name.is_empty() {
                region.to_string()
            } else {
                format!("{region} / Subnet group: {subnet_group_name}, VPC: {vpc_id}")
            };
            let vlan_net = if vpc_id.is_empty() {
                String::new()
            } else {
                format!("VPC: {vpc_id}, Subnets: {subnet_ids}")
            };

            rows.push(
                RowBuilder::new()
                    .unique_id(if arn.is_empty() { &id } else { &arn })
                    .virtual_flag("Yes")
                    .public("No")
                    .dns_url(&endpoint)
                    .location(location)
                    .asset_type("ElastiCache Cluster")
                    .hw_make_model(format!("AWS ElastiCache {cache_node_type}"))
                    .sw_vendor(sw_vendor)
                    .sw_name_ver(format!("{engine} {engine_ver}"))
                    .vlan_network_id(vlan_net)
                    .build(),
            );
        }

        marker = resp.marker().map(|s| s.to_string());
        if marker.is_none() {
            break;
        }
    }

    Ok(rows)
}

use aws_sdk_dynamodb::Client as DynamoDbClient;
use aws_sdk_redshift::Client as RedshiftClient;

// ---------------------------------------------------------------------------
// Network Load Balancers
// ---------------------------------------------------------------------------

pub(super) async fn collect_nlbs(client: &ElbClient, region: &str) -> Result<Vec<Vec<String>>> {
    let mut rows = Vec::new();
    let mut marker: Option<String> = None;

    loop {
        let mut req = client.describe_load_balancers();
        if let Some(ref m) = marker {
            req = req.marker(m);
        }
        let resp = req.send().await.context("ELBv2 describe_load_balancers")?;

        for lb in resp.load_balancers() {
            // Only network load balancers
            if lb.r#type()
                != Some(&aws_sdk_elasticloadbalancingv2::types::LoadBalancerTypeEnum::Network)
            {
                continue;
            }

            let arn = lb.load_balancer_arn().unwrap_or("").to_string();
            let dns_name = lb.dns_name().unwrap_or("").to_string();
            let scheme = lb.scheme().map(|s| s.as_str()).unwrap_or("").to_string();
            let vpc_id = lb.vpc_id().unwrap_or("").to_string();
            let is_public = lb.scheme()
                == Some(
                    &aws_sdk_elasticloadbalancingv2::types::LoadBalancerSchemeEnum::InternetFacing,
                );
            let ip_type = lb
                .ip_address_type()
                .map(|t| t.as_str())
                .unwrap_or("")
                .to_string();

            let subnet_ids: Vec<String> = lb
                .availability_zones()
                .iter()
                .filter_map(|az| az.subnet_id())
                .map(|s| s.to_string())
                .collect();
            let az_names: Vec<String> = lb
                .availability_zones()
                .iter()
                .filter_map(|az| az.zone_name())
                .map(|s| s.to_string())
                .collect();

            let location = format!("{region} / AZs: {}", az_names.join(", "));
            let vlan_net = format!("VPC: {vpc_id}, Subnets: {}", subnet_ids.join(", "));

            // Fetch listeners for comments
            let listeners_summary = match client
                .describe_listeners()
                .load_balancer_arn(&arn)
                .send()
                .await
            {
                Ok(r) => r
                    .listeners()
                    .iter()
                    .map(|l| {
                        let port = l.port().unwrap_or(0);
                        let proto = l.protocol().map(|p| p.as_str()).unwrap_or("");
                        format!("{proto}:{port}")
                    })
                    .collect::<Vec<_>>()
                    .join(", "),
                Err(_) => String::new(),
            };

            // Fetch cross-zone + deletion protection attributes
            let (mut cross_zone_enabled, mut deletion_protection) =
                (String::new(), String::new());
            if let Ok(attrs_resp) = client
                .describe_load_balancer_attributes()
                .load_balancer_arn(&arn)
                .send()
                .await
            {
                for attr in attrs_resp.attributes() {
                    match attr.key() {
                        Some("load_balancing.cross_zone.enabled") => {
                            cross_zone_enabled = attr.value().unwrap_or("").to_string();
                        }
                        Some("deletion_protection.enabled") => {
                            deletion_protection = attr.value().unwrap_or("").to_string();
                        }
                        _ => {}
                    }
                }
            }

            let comments = format!(
                "Scheme: {scheme} | IpAddressType: {ip_type} | Listeners: {listeners_summary} | \
                 CrossZoneEnabled: {cross_zone_enabled} | DeletionProtection: {deletion_protection}"
            );

            rows.push(
                RowBuilder::new()
                    .unique_id(&arn)
                    .virtual_flag("Yes")
                    .public(if is_public { "Yes" } else { "No" })
                    .dns_url(&dns_name)
                    .location(location)
                    .asset_type("Network Load Balancer")
                    .hw_make_model("AWS NLB")
                    .sw_vendor("Amazon Web Services")
                    .sw_name_ver("AWS ELBv2 (network)")
                    .vlan_network_id(vlan_net)
                    .comments(comments)
                    .build(),
            );
        }

        marker = resp.next_marker().map(|s| s.to_string());
        if marker.is_none() {
            break;
        }
    }

    Ok(rows)
}
pub(super) async fn collect_redshift_clusters(_c: &RedshiftClient, _region: &str) -> Result<Vec<Vec<String>>> {
    Ok(Vec::new())
}
pub(super) async fn collect_dynamodb_tables(_c: &DynamoDbClient, _region: &str) -> Result<Vec<Vec<String>>> {
    Ok(Vec::new())
}
