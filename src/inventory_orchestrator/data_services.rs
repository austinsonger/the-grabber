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
            let (mut cross_zone_enabled, mut deletion_protection) = (String::new(), String::new());
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
// ---------------------------------------------------------------------------
// Redshift Clusters
// ---------------------------------------------------------------------------

/// Tag-first Function-column derivation for Redshift clusters. Same
/// convention as `storage::function_from_ec2_tags`; Redshift's `Tag::key()`/
/// `value()` both return `Option<&str>`.
fn function_from_redshift_tags(tags: &[aws_sdk_redshift::types::Tag]) -> String {
    tags.iter()
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
        .unwrap_or("")
        .to_string()
}

pub(super) async fn collect_redshift_clusters(
    client: &RedshiftClient,
    region: &str,
) -> Result<Vec<Vec<String>>> {
    let mut rows = Vec::new();
    let mut marker: Option<String> = None;

    loop {
        let mut req = client.describe_clusters();
        if let Some(ref m) = marker {
            req = req.marker(m);
        }
        let resp = req.send().await.context("Redshift describe_clusters")?;

        for cluster in resp.clusters() {
            let cluster_identifier = cluster.cluster_identifier().unwrap_or("").to_string();
            let unique_id = cluster
                .cluster_namespace_arn()
                .unwrap_or(cluster_identifier.as_str())
                .to_string();

            let publicly_accessible = cluster.publicly_accessible().unwrap_or(false);
            let node_type = cluster.node_type().unwrap_or("").to_string();
            let cluster_version = cluster.cluster_version().unwrap_or("").to_string();
            let availability_zone = cluster.availability_zone().unwrap_or("").to_string();
            let vpc_id = cluster.vpc_id().unwrap_or("").to_string();
            let cluster_subnet_group_name = cluster
                .cluster_subnet_group_name()
                .unwrap_or("")
                .to_string();

            let dns_url = match cluster.endpoint() {
                Some(e) => format!("{}:{}", e.address().unwrap_or(""), e.port().unwrap_or(0)),
                None => String::new(),
            };

            // Subnets for the cluster's subnet group — one extra call per
            // cluster; fall back to empty on error, do not propagate.
            let subnets = if cluster_subnet_group_name.is_empty() {
                String::new()
            } else {
                match client
                    .describe_cluster_subnet_groups()
                    .cluster_subnet_group_name(&cluster_subnet_group_name)
                    .send()
                    .await
                {
                    Ok(r) => r
                        .cluster_subnet_groups()
                        .first()
                        .map(|g| {
                            g.subnets()
                                .iter()
                                .filter_map(|s| s.subnet_identifier())
                                .map(|s| s.to_string())
                                .collect::<Vec<_>>()
                                .join(", ")
                        })
                        .unwrap_or_default(),
                    Err(_) => String::new(),
                }
            };

            // Logging status — secondary call, fall back to empty on error.
            let (logging_enabled, logging_s3_bucket) = match client
                .describe_logging_status()
                .cluster_identifier(&cluster_identifier)
                .send()
                .await
            {
                Ok(r) => (
                    r.logging_enabled().unwrap_or(false).to_string(),
                    r.bucket_name().unwrap_or("").to_string(),
                ),
                Err(_) => (String::new(), String::new()),
            };

            let encrypted = cluster.encrypted().unwrap_or(false).to_string();
            let kms_key_id = cluster.kms_key_id().unwrap_or("").to_string();
            let number_of_nodes = cluster
                .number_of_nodes()
                .map(|n| n.to_string())
                .unwrap_or_default();
            let db_name = cluster.db_name().unwrap_or("").to_string();
            let master_username = cluster.master_username().unwrap_or("").to_string();
            let cluster_status = cluster.cluster_status().unwrap_or("").to_string();
            let enhanced_vpc_routing = cluster.enhanced_vpc_routing().unwrap_or(false).to_string();
            let automated_snapshot_retention_period = cluster
                .automated_snapshot_retention_period()
                .map(|n| n.to_string())
                .unwrap_or_default();

            let function = function_from_redshift_tags(cluster.tags());

            let location = format!("{region} / AZ: {availability_zone}");
            let vlan_net = format!("VPC: {vpc_id}, Subnets: {subnets}");

            let comments = format!(
                "Encrypted: {encrypted} | KmsKeyId: {kms_key_id} | NumberOfNodes: {number_of_nodes} | \
                 DBName: {db_name} | MasterUsername: {master_username} | ClusterStatus: {cluster_status} | \
                 LoggingEnabled: {logging_enabled} | LoggingS3Bucket: {logging_s3_bucket} | \
                 EnhancedVpcRouting: {enhanced_vpc_routing} | \
                 AutomatedSnapshotRetentionPeriod: {automated_snapshot_retention_period}"
            );

            rows.push(
                RowBuilder::new()
                    .unique_id(&unique_id)
                    .virtual_flag("Yes")
                    .public(if publicly_accessible { "Yes" } else { "No" })
                    .dns_url(&dns_url)
                    .location(location)
                    .asset_type("Redshift Cluster")
                    .hw_make_model(format!("AWS Redshift {node_type}"))
                    .sw_vendor("Amazon Web Services")
                    .sw_name_ver(format!("Amazon Redshift {cluster_version}"))
                    .function(function)
                    .vlan_network_id(vlan_net)
                    .comments(comments)
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
// DynamoDB Tables
// ---------------------------------------------------------------------------

/// Tag-first Function-column derivation for DynamoDB tables. Same convention
/// as `function_from_redshift_tags`; DynamoDB's `Tag::key()`/`value()` return
/// plain `&str` (not `Option<&str>`) since both fields are required on the
/// wire, matching the EFS accessor shape.
fn function_from_dynamodb_tags(tags: &[aws_sdk_dynamodb::types::Tag]) -> String {
    tags.iter()
        .find(|t| {
            matches!(
                t.key(),
                "Purpose" | "App" | "Role" | "Function" | "purpose" | "app" | "role"
            )
        })
        .map(|t| t.value())
        .unwrap_or("")
        .to_string()
}

pub(super) async fn collect_dynamodb_tables(
    client: &DynamoDbClient,
    region: &str,
) -> Result<Vec<Vec<String>>> {
    let mut rows = Vec::new();
    let mut exclusive_start: Option<String> = None;

    loop {
        let mut req = client.list_tables();
        if let Some(ref s) = exclusive_start {
            req = req.exclusive_start_table_name(s);
        }
        let resp = req.send().await.context("DynamoDB list_tables")?;

        for table_name in resp.table_names() {
            let describe = client
                .describe_table()
                .table_name(table_name)
                .send()
                .await
                .context("DynamoDB describe_table")?;

            let Some(table) = describe.table() else {
                continue;
            };

            let arn = table.table_arn().unwrap_or("").to_string();
            let table_status = table
                .table_status()
                .map(|s| s.as_str())
                .unwrap_or("")
                .to_string();
            let billing_mode = table
                .billing_mode_summary()
                .and_then(|b| b.billing_mode())
                .map(|m| m.as_str())
                .unwrap_or("")
                .to_string();
            let item_count = table
                .item_count()
                .map(|n| n.to_string())
                .unwrap_or_default();
            let table_size_bytes = table
                .table_size_bytes()
                .map(|n| n.to_string())
                .unwrap_or_default();

            let (sse_type, kms_master_key_arn) = match table.sse_description() {
                Some(sse) => (
                    sse.sse_type().map(|t| t.as_str()).unwrap_or("").to_string(),
                    sse.kms_master_key_arn().unwrap_or("").to_string(),
                ),
                None => (String::new(), String::new()),
            };

            let (stream_enabled, stream_view_type) = match table.stream_specification() {
                Some(spec) => (
                    spec.stream_enabled().to_string(),
                    spec.stream_view_type()
                        .map(|t| t.as_str())
                        .unwrap_or("")
                        .to_string(),
                ),
                None => (String::new(), String::new()),
            };

            let is_global = table.global_table_version().is_some() || !table.replicas().is_empty();
            let deletion_protection = table
                .deletion_protection_enabled()
                .unwrap_or(false)
                .to_string();

            let location = if is_global {
                format!("{region} / GlobalTable")
            } else {
                region.to_string()
            };

            // PITR status — secondary call, fall back to "UNKNOWN" on error
            // or a missing description, do not propagate.
            let pitr_status = match client
                .describe_continuous_backups()
                .table_name(table_name)
                .send()
                .await
            {
                Ok(r) => r
                    .continuous_backups_description()
                    .and_then(|d| d.point_in_time_recovery_description())
                    .and_then(|p| p.point_in_time_recovery_status())
                    .map(|s| s.as_str().to_string())
                    .unwrap_or_else(|| "UNKNOWN".to_string()),
                Err(_) => "UNKNOWN".to_string(),
            };

            // Tags aren't returned by describe_table — secondary call, fall
            // back to empty on error, do not propagate.
            let function = match client
                .list_tags_of_resource()
                .resource_arn(&arn)
                .send()
                .await
            {
                Ok(r) => function_from_dynamodb_tags(r.tags()),
                Err(_) => String::new(),
            };

            let comments = format!(
                "TableStatus: {table_status} | BillingMode: {billing_mode} | ItemCount: {item_count} | \
                 TableSizeBytes: {table_size_bytes} | SseType: {sse_type} | KmsMasterKeyArn: {kms_master_key_arn} | \
                 StreamEnabled: {stream_enabled} | StreamViewType: {stream_view_type} | \
                 PointInTimeRecovery: {pitr_status} | GlobalTable: {is_global} | \
                 DeletionProtection: {deletion_protection}"
            );

            rows.push(
                RowBuilder::new()
                    .unique_id(&arn)
                    .virtual_flag("Yes")
                    .public("No")
                    .location(location)
                    .asset_type("DynamoDB Table")
                    .sw_vendor("Amazon Web Services")
                    .sw_name_ver("Amazon DynamoDB")
                    .function(function)
                    .comments(comments)
                    .build(),
            );
        }

        exclusive_start = resp.last_evaluated_table_name().map(|s| s.to_string());
        if exclusive_start.is_none() {
            break;
        }
    }

    Ok(rows)
}
