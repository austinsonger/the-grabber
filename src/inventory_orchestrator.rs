// ---------------------------------------------------------------------------
// Inventory Orchestrator — Unified AWS asset inventory CSV collector
// ---------------------------------------------------------------------------
//
// Implements CsvCollector.  Given a list of selected asset-type keys, it
// queries each service in parallel via tokio::spawn and merges all rows into
// a single CSV that uses the canonical 14-column schema from inventory_core.

use anyhow::{Context, Result};
use async_trait::async_trait;

use aws_sdk_ec2::Client as Ec2Client;
use aws_sdk_ecr::Client as EcrClient;
use aws_sdk_ecs::Client as EcsClient;
use aws_sdk_eks::Client as EksClient;
use aws_sdk_elasticache::Client as ElastiCacheClient;
use aws_sdk_elasticloadbalancingv2::Client as ElbClient;
use aws_sdk_kms::Client as KmsClient;
use aws_sdk_lambda::Client as LambdaClient;
use aws_sdk_rds::Client as RdsClient;
use aws_sdk_s3::Client as S3Client;

use crate::evidence::CsvCollector;
use crate::inventory_core::{
    normalize_s3_region, RowBuilder, ASSET_KEY_ALB, ASSET_KEY_CONTAINER,
    ASSET_KEY_EC2_INSTANCE, ASSET_KEY_ELASTICACHE_CLUSTER, ASSET_KEY_KMS_KEY,
    ASSET_KEY_LAMBDA_FUNCTION, ASSET_KEY_RDS_DB_INSTANCE, ASSET_KEY_S3_BUCKET,
    INVENTORY_CSV_HEADERS,
};

// ---------------------------------------------------------------------------
// Struct
// ---------------------------------------------------------------------------

pub struct InventoryCollector {
    pub selected_types: Vec<String>,
    kms: KmsClient,
    s3: S3Client,
    lambda: LambdaClient,
    ec2: Ec2Client,
    elb: ElbClient,
    rds: RdsClient,
    elasticache: ElastiCacheClient,
    ecr: EcrClient,
    ecs: EcsClient,
    eks: EksClient,
}

impl InventoryCollector {
    pub fn new(config: &aws_config::SdkConfig, selected_types: Vec<String>) -> Self {
        Self {
            selected_types,
            kms: KmsClient::new(config),
            s3: S3Client::new(config),
            lambda: LambdaClient::new(config),
            ec2: Ec2Client::new(config),
            elb: ElbClient::new(config),
            rds: RdsClient::new(config),
            elasticache: ElastiCacheClient::new(config),
            ecr: EcrClient::new(config),
            ecs: EcsClient::new(config),
            eks: EksClient::new(config),
        }
    }
}

// ---------------------------------------------------------------------------
// CsvCollector impl
// ---------------------------------------------------------------------------

#[async_trait]
impl CsvCollector for InventoryCollector {
    fn name(&self) -> &str { "AWS Inventory" }
    fn filename_prefix(&self) -> &str { "AWS_Inventory" }
    fn headers(&self) -> &'static [&'static str] { INVENTORY_CSV_HEADERS }

    async fn collect_rows(
        &self,
        _account_id: &str,
        region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        use tokio::task::JoinSet;

        let mut set: JoinSet<Result<Vec<Vec<String>>>> = JoinSet::new();
        let region = region.to_string();

        for type_key in &self.selected_types {
            match type_key.as_str() {
                ASSET_KEY_KMS_KEY => {
                    let c = self.kms.clone();
                    let r = region.clone();
                    set.spawn(async move { collect_kms_keys(&c, &r).await });
                }
                ASSET_KEY_S3_BUCKET => {
                    let c = self.s3.clone();
                    let r = region.clone();
                    set.spawn(async move { collect_s3_buckets(&c, &r).await });
                }
                ASSET_KEY_LAMBDA_FUNCTION => {
                    let c = self.lambda.clone();
                    let r = region.clone();
                    set.spawn(async move { collect_lambda_functions(&c, &r).await });
                }
                ASSET_KEY_EC2_INSTANCE => {
                    let c = self.ec2.clone();
                    let r = region.clone();
                    set.spawn(async move { collect_ec2_instances(&c, &r).await });
                }
                ASSET_KEY_ALB => {
                    let c = self.elb.clone();
                    let r = region.clone();
                    set.spawn(async move { collect_albs(&c, &r).await });
                }
                ASSET_KEY_RDS_DB_INSTANCE => {
                    let c = self.rds.clone();
                    let r = region.clone();
                    set.spawn(async move { collect_rds_instances(&c, &r).await });
                }
                ASSET_KEY_ELASTICACHE_CLUSTER => {
                    let c = self.elasticache.clone();
                    let r = region.clone();
                    set.spawn(async move { collect_elasticache_clusters(&c, &r).await });
                }
                ASSET_KEY_CONTAINER => {
                    let ecr = self.ecr.clone();
                    let ecs = self.ecs.clone();
                    let eks = self.eks.clone();
                    let r = region.clone();
                    set.spawn(async move { collect_containers(&ecr, &ecs, &eks, &r).await });
                }
                other => {
                    eprintln!("WARN: inventory: unknown asset type key '{other}' — skipped");
                }
            }
        }

        let mut all_rows: Vec<Vec<String>> = Vec::new();
        while let Some(result) = set.join_next().await {
            match result {
                Ok(Ok(rows)) => all_rows.extend(rows),
                Ok(Err(e)) => eprintln!("WARN: inventory collection error: {e:#}"),
                Err(e) => eprintln!("WARN: inventory task panicked: {e}"),
            }
        }

        Ok(all_rows)
    }
}

// ---------------------------------------------------------------------------
// KMS Keys
// ---------------------------------------------------------------------------

async fn collect_kms_keys(client: &KmsClient, region: &str) -> Result<Vec<Vec<String>>> {
    let mut rows = Vec::new();
    let mut next_marker: Option<String> = None;

    loop {
        let mut req = client.list_keys();
        if let Some(ref m) = next_marker {
            req = req.marker(m);
        }
        let resp = req.send().await.context("KMS list_keys")?;

        for entry in resp.keys() {
            let key_id = entry.key_id().unwrap_or("").to_string();

            let meta = match client.describe_key().key_id(&key_id).send().await {
                Ok(r) => r.key_metadata().cloned(),
                Err(_) => None,
            };
            let Some(meta) = meta else { continue };

            // Skip AWS-managed keys.
            if meta.key_manager() == Some(&aws_sdk_kms::types::KeyManagerType::Aws) {
                continue;
            }

            let rotation = match client.get_key_rotation_status().key_id(&key_id).send().await {
                Ok(r) => if r.key_rotation_enabled() { "Yes" } else { "No" }.to_string(),
                Err(_) => String::new(),
            };

            let description = meta.description().unwrap_or("").to_string();
            let arn = meta.arn().unwrap_or("").to_string();
            let key_manager = meta.key_manager().map(|m| m.as_str()).unwrap_or("").to_string();
            let key_usage = meta.key_usage().map(|u| u.as_str()).unwrap_or("").to_string();
            let key_spec = meta.key_spec().map(|s| s.as_str()).unwrap_or("").to_string();
            let key_state = meta.key_state().map(|s| s.as_str()).unwrap_or("").to_string();
            let origin = meta.origin().map(|o| o.as_str()).unwrap_or("").to_string();
            let multi_region = meta.multi_region().map(|v| v.to_string()).unwrap_or_default();

            let comments = format!(
                "Arn: {arn} | KeyManager: {key_manager} | KeyUsage: {key_usage} | \
                 KeySpec: {key_spec} | KeyState: {key_state} | Origin: {origin} | \
                 MultiRegion: {multi_region} | RotationEnabled: {rotation}"
            );

            rows.push(
                RowBuilder::new()
                    .unique_id(&key_id)
                    .virtual_flag("Yes")
                    .public("No")
                    .location(region)
                    .asset_type("KMS Key")
                    .sw_vendor("Amazon Web Services")
                    .sw_name_ver("AWS Key Management Service (KMS)")
                    .function(description)
                    .comments(comments)
                    .build(),
            );
        }

        next_marker = if resp.truncated() {
            resp.next_marker().map(|s| s.to_string())
        } else {
            None
        };
        if next_marker.is_none() {
            break;
        }
    }

    Ok(rows)
}

// ---------------------------------------------------------------------------
// S3 Buckets
// ---------------------------------------------------------------------------

async fn collect_s3_buckets(client: &S3Client, _region: &str) -> Result<Vec<Vec<String>>> {
    let resp = client.list_buckets().send().await.context("S3 list_buckets")?;
    let mut rows = Vec::new();

    for bucket in resp.buckets() {
        let name = bucket.name().unwrap_or("").to_string();

        let bucket_region = match client.get_bucket_location().bucket(&name).send().await {
            Ok(r) => normalize_s3_region(r.location_constraint().map(|c| c.as_str())).to_string(),
            Err(_) => "us-east-1".to_string(),
        };

        let is_public = match client.get_bucket_policy_status().bucket(&name).send().await {
            Ok(r) => r.policy_status().and_then(|s| s.is_public()).unwrap_or(false),
            Err(_) => false,
        };

        let (block_public_acls, ignore_public_acls, block_public_policy, restrict_public_buckets) =
            match client.get_public_access_block().bucket(&name).send().await {
                Ok(r) => {
                    let cfg = r.public_access_block_configuration();
                    (
                        cfg.and_then(|c| c.block_public_acls()).unwrap_or(false),
                        cfg.and_then(|c| c.ignore_public_acls()).unwrap_or(false),
                        cfg.and_then(|c| c.block_public_policy()).unwrap_or(false),
                        cfg.and_then(|c| c.restrict_public_buckets()).unwrap_or(false),
                    )
                }
                Err(_) => (false, false, false, false),
            };

        let (sse_algo, kms_key_id) =
            match client.get_bucket_encryption().bucket(&name).send().await {
                Ok(r) => {
                    let rule = r
                        .server_side_encryption_configuration()
                        .and_then(|c| c.rules().first())
                        .and_then(|rule| rule.apply_server_side_encryption_by_default());
                    (
                        rule.map(|d| d.sse_algorithm().as_str().to_string())
                            .unwrap_or_default(),
                        rule.and_then(|d| d.kms_master_key_id())
                            .unwrap_or("")
                            .to_string(),
                    )
                }
                Err(_) => (String::new(), String::new()),
            };

        let versioning = match client.get_bucket_versioning().bucket(&name).send().await {
            Ok(r) => r
                .status()
                .map(|s| s.as_str().to_string())
                .unwrap_or_else(|| "Disabled".to_string()),
            Err(_) => String::new(),
        };

        let logging_target = match client.get_bucket_logging().bucket(&name).send().await {
            Ok(r) => r
                .logging_enabled()
                .map(|l| format!("{}/{}", l.target_bucket(), l.target_prefix()))
                .unwrap_or_default(),
            Err(_) => String::new(),
        };

        let function = match client.get_bucket_tagging().bucket(&name).send().await {
            Ok(r) => r
                .tag_set()
                .iter()
                .find(|t| {
                    matches!(t.key(), "Purpose" | "App" | "Role" | "Function" | "purpose" | "app" | "role")
                })
                .map(|t| t.value().to_string())
                .unwrap_or_default(),
            Err(_) => String::new(),
        };

        let dns_url = format!("https://{name}.s3.{bucket_region}.amazonaws.com");

        let comments = format!(
            "BlockPublicAcls: {block_public_acls} | IgnorePublicAcls: {ignore_public_acls} | \
             BlockPublicPolicy: {block_public_policy} | RestrictPublicBuckets: {restrict_public_buckets} | \
             SSEAlgorithm: {sse_algo} | KMSMasterKeyID: {kms_key_id} | \
             Versioning: {versioning} | Logging: {logging_target}"
        );

        rows.push(
            RowBuilder::new()
                .unique_id(&name)
                .virtual_flag("Yes")
                .public(if is_public { "Yes" } else { "No" })
                .dns_url(dns_url)
                .location(&bucket_region)
                .asset_type("S3 Bucket")
                .sw_vendor("Amazon Web Services")
                .sw_name_ver("Amazon S3")
                .function(function)
                .comments(comments)
                .build(),
        );
    }

    Ok(rows)
}

// ---------------------------------------------------------------------------
// Lambda Functions
// ---------------------------------------------------------------------------

async fn collect_lambda_functions(client: &LambdaClient, region: &str) -> Result<Vec<Vec<String>>> {
    let mut rows = Vec::new();
    let mut marker: Option<String> = None;

    loop {
        let mut req = client.list_functions();
        if let Some(ref m) = marker {
            req = req.marker(m);
        }
        let resp = req.send().await.context("Lambda list_functions")?;

        for func in resp.functions() {
            let arn = func.function_arn().unwrap_or("").to_string();
            let name = func.function_name().unwrap_or("").to_string();
            let runtime = func.runtime().map(|r| r.as_str()).unwrap_or("").to_string();
            let description = func.description().unwrap_or("").to_string();
            let role = func.role().unwrap_or("").to_string();
            let kms_key = func.kms_key_arn().unwrap_or("").to_string();
            let timeout = func.timeout().unwrap_or(0);
            let memory = func.memory_size().unwrap_or(0);

            let (vpc_id, subnets, sgs) = if let Some(vpc) = func.vpc_config() {
                let vid = vpc.vpc_id().unwrap_or("").to_string();
                let subs = vpc.subnet_ids().join(", ");
                let sg_list = vpc.security_group_ids().join(", ");
                (vid, subs, sg_list)
            } else {
                (String::new(), String::new(), String::new())
            };

            let vlan_net = if vpc_id.is_empty() {
                String::new()
            } else {
                format!("VPC: {vpc_id}, Subnets: {subnets}")
            };

            let env_var_count = func.environment()
                .and_then(|e| e.variables())
                .map(|m| m.len())
                .unwrap_or(0);

            let dl_arn = func.dead_letter_config()
                .and_then(|d| d.target_arn())
                .unwrap_or("")
                .to_string();

            let comments = format!(
                "Role: {role} | KMSKeyArn: {kms_key} | VPC: {vpc_id} | \
                 Subnets: {subnets} | SecurityGroups: {sgs} | \
                 Timeout: {timeout}s | MemorySize: {memory}MB | \
                 EnvVarCount: {env_var_count} | DeadLetterTarget: {dl_arn}"
            );

            rows.push(
                RowBuilder::new()
                    .unique_id(&arn)
                    .virtual_flag("Yes")
                    .public("No")
                    .location(region)
                    .asset_type("Lambda Function")
                    .sw_vendor("Amazon Web Services")
                    .sw_name_ver(format!("AWS Lambda | Runtime: {runtime}"))
                    .function(if description.is_empty() { name } else { description })
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
// EC2 Instances
// ---------------------------------------------------------------------------

async fn collect_ec2_instances(client: &Ec2Client, region: &str) -> Result<Vec<Vec<String>>> {
    let mut rows = Vec::new();
    let mut next_token: Option<String> = None;

    loop {
        let mut req = client.describe_instances();
        if let Some(ref t) = next_token {
            req = req.next_token(t);
        }
        let resp = req.send().await.context("EC2 describe_instances")?;

        for reservation in resp.reservations() {
            for instance in reservation.instances() {
                let instance_id = instance.instance_id().unwrap_or("").to_string();
                let private_ip = instance.private_ip_address().unwrap_or("").to_string();
                let public_ip = instance.public_ip_address().unwrap_or("").to_string();
                let public_dns = instance.public_dns_name().unwrap_or("").to_string();
                let private_dns = instance.private_dns_name().unwrap_or("").to_string();
                let instance_type = instance.instance_type().map(|t| t.as_str()).unwrap_or("").to_string();
                let vpc_id = instance.vpc_id().unwrap_or("").to_string();
                let subnet_id = instance.subnet_id().unwrap_or("").to_string();
                let az = instance.placement()
                    .and_then(|p| p.availability_zone())
                    .unwrap_or("")
                    .to_string();

                let mac_address = instance.network_interfaces()
                    .first()
                    .and_then(|ni| ni.mac_address())
                    .unwrap_or("")
                    .to_string();

                let is_public = !public_ip.is_empty();
                let dns_name = if !public_dns.is_empty() { public_dns.clone() } else { private_dns.clone() };
                let location = format!("{region} / AZ: {az}");
                let vlan_net = if vpc_id.is_empty() {
                    String::new()
                } else {
                    format!("VPC: {vpc_id}, Subnet: {subnet_id}")
                };

                rows.push(
                    RowBuilder::new()
                        .unique_id(&instance_id)
                        .ipv4_ipv6(&private_ip)
                        .virtual_flag("Yes")
                        .public(if is_public { "Yes" } else { "No" })
                        .dns_url(dns_name)
                        .mac_address(mac_address)
                        .location(location)
                        .asset_type("EC2 Instance")
                        .hw_make_model(format!("AWS EC2 {instance_type}"))
                        .sw_vendor("Amazon Web Services")
                        .sw_name_ver("Amazon EC2")
                        .vlan_network_id(vlan_net)
                        .build(),
                );
            }
        }

        next_token = resp.next_token().map(|s| s.to_string());
        if next_token.is_none() {
            break;
        }
    }

    Ok(rows)
}

// ---------------------------------------------------------------------------
// Application Load Balancers
// ---------------------------------------------------------------------------

async fn collect_albs(client: &ElbClient, region: &str) -> Result<Vec<Vec<String>>> {
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
            if lb.r#type() != Some(&aws_sdk_elasticloadbalancingv2::types::LoadBalancerTypeEnum::Application) {
                continue;
            }

            let arn = lb.load_balancer_arn().unwrap_or("").to_string();
            let dns_name = lb.dns_name().unwrap_or("").to_string();
            let scheme = lb.scheme().map(|s| s.as_str()).unwrap_or("").to_string();
            let vpc_id = lb.vpc_id().unwrap_or("").to_string();
            let is_public = lb.scheme()
                == Some(&aws_sdk_elasticloadbalancingv2::types::LoadBalancerSchemeEnum::InternetFacing);
            let ip_type = lb.ip_address_type().map(|t| t.as_str()).unwrap_or("").to_string();
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

async fn collect_rds_instances(client: &RdsClient, region: &str) -> Result<Vec<Vec<String>>> {
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
            let endpoint = db.endpoint().and_then(|e| e.address()).unwrap_or("").to_string();

            let (subnet_group_name, vpc_id, subnet_ids) =
                if let Some(sg) = db.db_subnet_group() {
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

            let location = format!(
                "{region} / Subnet group: {subnet_group_name}, VPC: {vpc_id}"
            );
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

async fn collect_elasticache_clusters(
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
        let resp = req.send().await.context("ElastiCache describe_replication_groups")?;

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
                let member_id = rg.member_clusters().first().map(|s| s.as_str()).unwrap_or("");
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
                                cc.and_then(|c| c.cache_node_type()).unwrap_or("").to_string(),
                                cc.and_then(|c| c.engine()).unwrap_or("").to_string(),
                                cc.and_then(|c| c.engine_version()).unwrap_or("").to_string(),
                                cc.and_then(|c| c.cache_subnet_group_name()).unwrap_or("").to_string(),
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

// ---------------------------------------------------------------------------
// Containers (ECR images, with ECS / EKS context)
// ---------------------------------------------------------------------------

async fn collect_containers(
    ecr: &EcrClient,
    ecs: &EcsClient,
    eks: &EksClient,
    region: &str,
) -> Result<Vec<Vec<String>>> {
    // Collect ECS cluster names for cross-referencing
    let ecs_cluster_names = collect_ecs_cluster_names(ecs).await;
    let eks_cluster_names = collect_eks_cluster_names(eks).await;

    let mut rows = Vec::new();
    let mut next_token: Option<String> = None;

    loop {
        let mut req = ecr.describe_repositories();
        if let Some(ref t) = next_token {
            req = req.next_token(t);
        }
        let resp = req.send().await.context("ECR describe_repositories")?;

        for repo in resp.repositories() {
            let repo_uri = repo.repository_uri().unwrap_or("").to_string();
            let repo_name = repo.repository_name().unwrap_or("").to_string();
            let repo_arn = repo.repository_arn().unwrap_or("").to_string();
            let registry_id = repo.registry_id().unwrap_or("").to_string();
            let mutability = repo.image_tag_mutability().map(|m| m.as_str()).unwrap_or("").to_string();
            let scan_on_push = repo.image_scanning_configuration()
                .map(|c| c.scan_on_push())
                .unwrap_or(false);
            let enc_type = repo.encryption_configuration()
                .and_then(|e| Some(e.encryption_type().as_str().to_string()))
                .unwrap_or_default();
            let enc_kms = repo.encryption_configuration()
                .and_then(|e| e.kms_key())
                .unwrap_or("")
                .to_string();

            // Fetch images for this repository
            let images = match ecr
                .describe_images()
                .repository_name(&repo_name)
                .send()
                .await
            {
                Ok(r) => r.image_details().to_vec(),
                Err(_) => vec![],
            };

            for img in &images {
                let digest = img.image_digest().unwrap_or("").to_string();
                let tags = img.image_tags().join(", ");
                let unique_id = format!("{repo_uri}@{digest}");

                let repo_comments = format!(
                    "RepositoryArn: {repo_arn} | RegistryId: {registry_id} | \
                     ImageTagMutability: {mutability} | ScanOnPush: {scan_on_push} | \
                     EncryptionType: {enc_type} | EncryptionKMS: {enc_kms} | \
                     ImageDigest: {digest} | ImageTags: {tags} | \
                     ECSClusters: {} | EKSClusters: {}",
                    ecs_cluster_names.join(", "),
                    eks_cluster_names.join(", "),
                );

                let location = format!("{region} / ECR Repo: {repo_name}");

                rows.push(
                    RowBuilder::new()
                        .unique_id(unique_id)
                        .virtual_flag("Yes")
                        .public("No")
                        .location(location)
                        .asset_type("Container Image")
                        .sw_vendor(&repo_name)
                        .sw_name_ver(format!(
                            "{} | Tags: {}",
                            repo_name,
                            if tags.is_empty() { "none".to_string() } else { tags }
                        ))
                        .comments(repo_comments)
                        .build(),
                );
            }

            // If a repo has no images, still emit one row for the repo itself
            if images.is_empty() {
                let repo_comments = format!(
                    "RepositoryArn: {repo_arn} | RegistryId: {registry_id} | \
                     ImageTagMutability: {mutability} | ScanOnPush: {scan_on_push} | \
                     EncryptionType: {enc_type} | EncryptionKMS: {enc_kms} | \
                     (No images)"
                );
                rows.push(
                    RowBuilder::new()
                        .unique_id(&repo_uri)
                        .virtual_flag("Yes")
                        .public("No")
                        .location(format!("{region} / ECR Repo: {repo_name}"))
                        .asset_type("Container Image")
                        .sw_vendor(&repo_name)
                        .sw_name_ver(repo_name.clone())
                        .comments(repo_comments)
                        .build(),
                );
            }
        }

        next_token = resp.next_token().map(|s| s.to_string());
        if next_token.is_none() {
            break;
        }
    }

    Ok(rows)
}

async fn collect_ecs_cluster_names(client: &EcsClient) -> Vec<String> {
    let mut names = Vec::new();
    let mut next_token: Option<String> = None;
    loop {
        let mut req = client.list_clusters();
        if let Some(ref t) = next_token {
            req = req.next_token(t);
        }
        match req.send().await {
            Ok(r) => {
                for arn in r.cluster_arns() {
                    let short = arn.rsplit('/').next().unwrap_or(arn).to_string();
                    names.push(short);
                }
                next_token = r.next_token().map(|s| s.to_string());
            }
            Err(_) => break,
        }
        if next_token.is_none() {
            break;
        }
    }
    names
}

async fn collect_eks_cluster_names(client: &EksClient) -> Vec<String> {
    let mut names = Vec::new();
    let mut next_token: Option<String> = None;
    loop {
        let mut req = client.list_clusters();
        if let Some(ref t) = next_token {
            req = req.next_token(t);
        }
        match req.send().await {
            Ok(r) => {
                names.extend(r.clusters().iter().map(|s| s.to_string()));
                next_token = r.next_token().map(|s| s.to_string());
            }
            Err(_) => break,
        }
        if next_token.is_none() {
            break;
        }
    }
    names
}
