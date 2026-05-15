use anyhow::{Context, Result};

use aws_sdk_ec2::Client as Ec2Client;
use aws_sdk_ecr::Client as EcrClient;
use aws_sdk_ecs::Client as EcsClient;
use aws_sdk_eks::Client as EksClient;
use aws_sdk_lambda::Client as LambdaClient;

use crate::inventory_core::RowBuilder;

// ---------------------------------------------------------------------------
// Lambda Functions
// ---------------------------------------------------------------------------

pub(super) async fn collect_lambda_functions(
    client: &LambdaClient,
    region: &str,
) -> Result<Vec<Vec<String>>> {
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

            let env_var_count = func
                .environment()
                .and_then(|e| e.variables())
                .map(|m| m.len())
                .unwrap_or(0);

            let dl_arn = func
                .dead_letter_config()
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
                    .function(if description.is_empty() {
                        name
                    } else {
                        description
                    })
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

pub(super) async fn collect_ec2_instances(
    client: &Ec2Client,
    region: &str,
) -> Result<Vec<Vec<String>>> {
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
                let instance_type = instance
                    .instance_type()
                    .map(|t| t.as_str())
                    .unwrap_or("")
                    .to_string();
                let vpc_id = instance.vpc_id().unwrap_or("").to_string();
                let subnet_id = instance.subnet_id().unwrap_or("").to_string();
                let az = instance
                    .placement()
                    .and_then(|p| p.availability_zone())
                    .unwrap_or("")
                    .to_string();

                let mac_address = instance
                    .network_interfaces()
                    .first()
                    .and_then(|ni| ni.mac_address())
                    .unwrap_or("")
                    .to_string();

                let is_public = !public_ip.is_empty();
                let dns_name = if !public_dns.is_empty() {
                    public_dns.clone()
                } else {
                    private_dns.clone()
                };
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
// Containers (ECR images, with ECS / EKS context)
// ---------------------------------------------------------------------------

pub(super) async fn collect_containers(
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
            let mutability = repo
                .image_tag_mutability()
                .map(|m| m.as_str())
                .unwrap_or("")
                .to_string();
            let scan_on_push = repo
                .image_scanning_configuration()
                .map(|c| c.scan_on_push())
                .unwrap_or(false);
            let enc_type = repo
                .encryption_configuration()
                .map(|e| e.encryption_type().as_str().to_string())
                .unwrap_or_default();
            let enc_kms = repo
                .encryption_configuration()
                .and_then(|e| e.kms_key())
                .unwrap_or("")
                .to_string();

            // Fetch images for this repository
            let mut images = match ecr
                .describe_images()
                .repository_name(&repo_name)
                .send()
                .await
            {
                Ok(r) => r.image_details().to_vec(),
                Err(_) => vec![],
            };

            let secs_to_rfc3339 = |secs: i64| -> String {
                chrono::DateTime::<chrono::Utc>::from_timestamp(secs, 0)
                    .map(|c| c.to_rfc3339())
                    .unwrap_or_default()
            };

            if images.is_empty() {
                // No images — emit one row for the repo itself
                let repo_comments = format!(
                    "RepositoryArn: {repo_arn} | RegistryId: {registry_id} | \
                     ImageTagMutability: {mutability} | ScanOnPush: {scan_on_push} | \
                     EncryptionType: {enc_type} | EncryptionKMS: {enc_kms} | \
                     ImageCount: 0"
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
            } else {
                // Sort descending by pushed_at so index 0 is the newest image
                images.sort_by(|a, b| {
                    let pa = a.image_pushed_at().map(|d| d.secs()).unwrap_or(0);
                    let pb = b.image_pushed_at().map(|d| d.secs()).unwrap_or(0);
                    pb.cmp(&pa)
                });

                let image_count = images.len();
                let newest_push = images
                    .first()
                    .and_then(|i| i.image_pushed_at())
                    .map(|d| secs_to_rfc3339(d.secs()))
                    .unwrap_or_default();
                let oldest_push = images
                    .last()
                    .and_then(|i| i.image_pushed_at())
                    .map(|d| secs_to_rfc3339(d.secs()))
                    .unwrap_or_default();

                // Representative row uses the newest image's digest and tags
                let img = &images[0];
                let digest = img.image_digest().unwrap_or("").to_string();
                let tags = img.image_tags().join(", ");

                let repo_comments = format!(
                    "RepositoryArn: {repo_arn} | RegistryId: {registry_id} | \
                     ImageTagMutability: {mutability} | ScanOnPush: {scan_on_push} | \
                     EncryptionType: {enc_type} | EncryptionKMS: {enc_kms} | \
                     ImageDigest: {digest} | ImageTags: {tags} | \
                     ECSClusters: {} | EKSClusters: {} | \
                     ImageCount: {image_count} | NewestPush: {newest_push} | OldestPush: {oldest_push}",
                    ecs_cluster_names.join(", "),
                    eks_cluster_names.join(", "),
                );

                rows.push(
                    RowBuilder::new()
                        .unique_id(&repo_uri)
                        .virtual_flag("Yes")
                        .public("No")
                        .location(format!("{region} / ECR Repo: {repo_name}"))
                        .asset_type("Container Image")
                        .sw_vendor(&repo_name)
                        .sw_name_ver(format!(
                            "{} | Tags: {}",
                            repo_name,
                            if tags.is_empty() {
                                "none".to_string()
                            } else {
                                tags
                            }
                        ))
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
