use anyhow::{Context, Result};

use aws_sdk_kms::Client as KmsClient;
use aws_sdk_s3::Client as S3Client;

use crate::inventory_core::{normalize_s3_region, RowBuilder};

/// Tag-first Function-column derivation shared by EBS / other EC2-tagged
/// storage collectors. Matches the S3 convention: check Purpose / App / Role
/// / Function tag keys (any case), then fall through to empty. Description
/// fallback is per-collector and lives at the call site.
fn function_from_ec2_tags(tags: &[aws_sdk_ec2::types::Tag]) -> String {
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

/// Tag-first Function-column derivation for EFS file systems. Same
/// convention as `function_from_ec2_tags`; EFS's `Tag::key()`/`value()`
/// return `&str` rather than `Option<&str>`, so the matching differs slightly.
fn function_from_efs_tags(tags: &[aws_sdk_efs::types::Tag]) -> String {
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

/// Tag-first Function-column derivation for FSx file systems. Same
/// convention as `function_from_ec2_tags`.
fn function_from_fsx_tags(tags: &[aws_sdk_fsx::types::Tag]) -> String {
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

// ---------------------------------------------------------------------------
// KMS Keys
// ---------------------------------------------------------------------------

pub(super) async fn collect_kms_keys(client: &KmsClient, region: &str) -> Result<Vec<Vec<String>>> {
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

            let rotation = match client
                .get_key_rotation_status()
                .key_id(&key_id)
                .send()
                .await
            {
                Ok(r) => if r.key_rotation_enabled() {
                    "Yes"
                } else {
                    "No"
                }
                .to_string(),
                Err(_) => String::new(),
            };

            let description = meta.description().unwrap_or("").to_string();
            let arn = meta.arn().unwrap_or("").to_string();
            let key_manager = meta
                .key_manager()
                .map(|m| m.as_str())
                .unwrap_or("")
                .to_string();
            let key_usage = meta
                .key_usage()
                .map(|u| u.as_str())
                .unwrap_or("")
                .to_string();
            let key_spec = meta
                .key_spec()
                .map(|s| s.as_str())
                .unwrap_or("")
                .to_string();
            let key_state = meta
                .key_state()
                .map(|s| s.as_str())
                .unwrap_or("")
                .to_string();
            let origin = meta.origin().map(|o| o.as_str()).unwrap_or("").to_string();
            let multi_region = meta
                .multi_region()
                .map(|v| v.to_string())
                .unwrap_or_default();

            let comments = format!(
                "Arn: {arn} | KeyManager: {key_manager} | KeyUsage: {key_usage} | \
                 KeySpec: {key_spec} | KeyState: {key_state} | Origin: {origin} | \
                 MultiRegion: {multi_region} | RotationEnabled: {rotation}"
            );

            rows.push(
                RowBuilder::new()
                    .unique_id(&arn)
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

pub(super) async fn collect_s3_buckets(
    client: &S3Client,
    _region: &str,
) -> Result<Vec<Vec<String>>> {
    let resp = client
        .list_buckets()
        .send()
        .await
        .context("S3 list_buckets")?;
    let mut rows = Vec::new();

    for bucket in resp.buckets() {
        let name = bucket.name().unwrap_or("").to_string();

        let bucket_region = match client.get_bucket_location().bucket(&name).send().await {
            Ok(r) => normalize_s3_region(r.location_constraint().map(|c| c.as_str())).to_string(),
            Err(_) => "us-east-1".to_string(),
        };

        let is_public = match client.get_bucket_policy_status().bucket(&name).send().await {
            Ok(r) => r
                .policy_status()
                .and_then(|s| s.is_public())
                .unwrap_or(false),
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
                        cfg.and_then(|c| c.restrict_public_buckets())
                            .unwrap_or(false),
                    )
                }
                Err(_) => (false, false, false, false),
            };

        let (sse_algo, kms_key_id) = match client.get_bucket_encryption().bucket(&name).send().await
        {
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
                    matches!(
                        t.key(),
                        "Purpose" | "App" | "Role" | "Function" | "purpose" | "app" | "role"
                    )
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

use aws_sdk_ec2::Client as Ec2Client;
use aws_sdk_efs::Client as EfsClient;
use aws_sdk_fsx::Client as FsxClient;

fn secs_to_rfc3339(secs: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(secs, 0)
        .map(|c| c.to_rfc3339())
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// EBS Volumes
// ---------------------------------------------------------------------------

pub(super) async fn collect_ebs_volumes(
    client: &Ec2Client,
    region: &str,
) -> Result<Vec<Vec<String>>> {
    let mut rows = Vec::new();
    let mut next_token: Option<String> = None;

    loop {
        let mut req = client.describe_volumes();
        if let Some(ref t) = next_token {
            req = req.next_token(t);
        }
        let resp = req.send().await.context("EC2 describe_volumes")?;

        for vol in resp.volumes() {
            let volume_id = vol.volume_id().unwrap_or("").to_string();
            let az = vol.availability_zone().unwrap_or("").to_string();
            let volume_type = vol.volume_type().map(|t| t.as_str()).unwrap_or("");
            let size = vol.size().unwrap_or(0);
            let iops = vol.iops().unwrap_or(0);
            let throughput = vol.throughput().unwrap_or(0);
            let encrypted = vol.encrypted().unwrap_or(false);
            let kms_key_id = vol.kms_key_id().unwrap_or("").to_string();
            let state = vol.state().map(|s| s.as_str()).unwrap_or("").to_string();
            let multi_attach = vol.multi_attach_enabled().unwrap_or(false);

            let attached_to: Vec<String> = vol
                .attachments()
                .iter()
                .filter_map(|a| a.instance_id())
                .map(|s| s.to_string())
                .collect();
            let attached_to_str = if attached_to.is_empty() {
                "none".to_string()
            } else {
                attached_to.join(", ")
            };

            let create_time = vol
                .create_time()
                .map(|d| secs_to_rfc3339(d.secs()))
                .unwrap_or_default();

            let location = format!("{region} / AZ: {az}");
            let hw_make_model = format!("AWS EBS {volume_type}");
            let function = function_from_ec2_tags(vol.tags());

            let comments = format!(
                "Size: {size}GB | Iops: {iops} | Throughput: {throughput}MBps | \
                 Encrypted: {encrypted} | KmsKeyId: {kms_key_id} | State: {state} | \
                 AttachedTo: {attached_to_str} | CreateTime: {create_time} | \
                 MultiAttach: {multi_attach}"
            );

            rows.push(
                RowBuilder::new()
                    .unique_id(&volume_id)
                    .virtual_flag("Yes")
                    .public("No")
                    .location(location)
                    .asset_type("EBS Volume")
                    .hw_make_model(hw_make_model)
                    .sw_vendor("Amazon Web Services")
                    .sw_name_ver("Amazon Elastic Block Store")
                    .function(function)
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
// EFS File Systems
// ---------------------------------------------------------------------------

pub(super) async fn collect_efs_file_systems(
    client: &EfsClient,
    region: &str,
) -> Result<Vec<Vec<String>>> {
    let mut rows = Vec::new();
    let mut marker: Option<String> = None;

    loop {
        let mut req = client.describe_file_systems();
        if let Some(ref m) = marker {
            req = req.marker(m);
        }
        let resp = req.send().await.context("EFS describe_file_systems")?;

        for fs in resp.file_systems() {
            let file_system_id = fs.file_system_id().to_string();
            let file_system_arn = fs.file_system_arn().unwrap_or("").to_string();
            let encrypted = fs.encrypted().unwrap_or(false);
            let kms_key_id = fs.kms_key_id().unwrap_or("").to_string();
            let performance_mode = fs.performance_mode().as_str().to_string();
            let throughput_mode = fs
                .throughput_mode()
                .map(|m| m.as_str())
                .unwrap_or("")
                .to_string();
            let mount_target_count = fs.number_of_mount_targets();
            let size_bytes = fs.size_in_bytes().map(|s| s.value()).unwrap_or(0);

            // Mount targets — derive VPC (from first target) and subnet list.
            let mount_targets = match client
                .describe_mount_targets()
                .file_system_id(&file_system_id)
                .send()
                .await
            {
                Ok(r) => r.mount_targets().to_vec(),
                Err(_) => Vec::new(),
            };
            let vpc_id = mount_targets
                .first()
                .and_then(|mt| mt.vpc_id())
                .unwrap_or("")
                .to_string();
            let subnet_ids: Vec<String> = mount_targets
                .iter()
                .map(|mt| mt.subnet_id().to_string())
                .collect();
            let vlan_network_id = format!("VPC: {vpc_id}, Subnets: {}", subnet_ids.join(", "));

            // Backup policy — treat any error (e.g. BackupPolicyNotFound) as DISABLED.
            let backup_policy = match client
                .describe_backup_policy()
                .file_system_id(&file_system_id)
                .send()
                .await
            {
                Ok(r) => r
                    .backup_policy()
                    .map(|p| p.status().as_str().to_string())
                    .unwrap_or_else(|| "DISABLED".to_string()),
                Err(_) => "DISABLED".to_string(),
            };

            // Lifecycle configuration — walk transitions and join as e.g.
            // "AFTER_30_DAYS→IA, AFTER_90_DAYS→ARCHIVE".
            let lifecycle_policy = match client
                .describe_lifecycle_configuration()
                .file_system_id(&file_system_id)
                .send()
                .await
            {
                Ok(r) => {
                    let mut transitions = Vec::new();
                    for policy in r.lifecycle_policies() {
                        if let Some(t) = policy.transition_to_ia() {
                            transitions.push(format!("{}→IA", t.as_str()));
                        }
                        if let Some(t) = policy.transition_to_primary_storage_class() {
                            transitions.push(format!("{}→PRIMARY", t.as_str()));
                        }
                        if let Some(t) = policy.transition_to_archive() {
                            transitions.push(format!("{}→ARCHIVE", t.as_str()));
                        }
                    }
                    transitions.join(", ")
                }
                Err(_) => String::new(),
            };

            let dns_url = format!("{file_system_id}.efs.{region}.amazonaws.com");
            let function = function_from_efs_tags(fs.tags());

            let comments = format!(
                "Encrypted: {encrypted} | KmsKeyId: {kms_key_id} | PerformanceMode: {performance_mode} | \
                 ThroughputMode: {throughput_mode} | LifecyclePolicy: {lifecycle_policy} | \
                 BackupPolicy: {backup_policy} | MountTargetCount: {mount_target_count} | \
                 SizeBytes: {size_bytes}"
            );

            rows.push(
                RowBuilder::new()
                    .unique_id(&file_system_arn)
                    .virtual_flag("Yes")
                    .public("No")
                    .dns_url(dns_url)
                    .location(region)
                    .asset_type("EFS File System")
                    .sw_vendor("Amazon Web Services")
                    .sw_name_ver("Amazon EFS")
                    .vlan_network_id(vlan_network_id)
                    .function(function)
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
// FSx File Systems
// ---------------------------------------------------------------------------

pub(super) async fn collect_fsx_file_systems(
    client: &FsxClient,
    region: &str,
) -> Result<Vec<Vec<String>>> {
    let mut rows = Vec::new();
    let mut next_token: Option<String> = None;

    loop {
        let mut req = client.describe_file_systems();
        if let Some(ref t) = next_token {
            req = req.next_token(t);
        }
        let resp = req.send().await.context("FSx describe_file_systems")?;

        for fs in resp.file_systems() {
            let resource_arn = fs.resource_arn().unwrap_or("").to_string();
            let fs_type = fs.file_system_type().map(|t| t.as_str()).unwrap_or("");
            let dns_name = fs.dns_name().unwrap_or("").to_string();
            let kms_key_id = fs.kms_key_id().unwrap_or("").to_string();
            let storage_capacity = fs.storage_capacity().unwrap_or(0);
            let storage_type = fs
                .storage_type()
                .map(|t| t.as_str())
                .unwrap_or("")
                .to_string();
            let vpc_id = fs.vpc_id().unwrap_or("").to_string();
            let subnet_ids: Vec<String> = fs.subnet_ids().iter().map(|s| s.to_string()).collect();
            let vlan_network_id = format!("VPC: {vpc_id}, Subnets: {}", subnet_ids.join(", "));

            let sw_name_ver = match fs_type {
                "WINDOWS" => "Amazon FSx for Windows".to_string(),
                "LUSTRE" => "Amazon FSx for Lustre".to_string(),
                "OPENZFS" => "Amazon FSx for OpenZFS".to_string(),
                "ONTAP" => "Amazon FSx for NetApp OnTap".to_string(),
                other => format!("Amazon FSx for {other}"),
            };

            // DeploymentType / AutomaticBackupRetentionDays / DailyAutomaticBackupStartTime /
            // PreferredSubnetId live under the per-flavour configuration block — try each in
            // turn (Windows, then Lustre, then OpenZFS, then Ontap).
            let (deployment_type, backup_retention_days, daily_backup_start_time, preferred_subnet_id) =
                if let Some(cfg) = fs.windows_configuration() {
                    (
                        cfg.deployment_type().map(|d| d.as_str()).unwrap_or(""),
                        cfg.automatic_backup_retention_days().unwrap_or(0),
                        cfg.daily_automatic_backup_start_time().unwrap_or(""),
                        cfg.preferred_subnet_id().unwrap_or(""),
                    )
                } else if let Some(cfg) = fs.lustre_configuration() {
                    (
                        cfg.deployment_type().map(|d| d.as_str()).unwrap_or(""),
                        cfg.automatic_backup_retention_days().unwrap_or(0),
                        cfg.daily_automatic_backup_start_time().unwrap_or(""),
                        "",
                    )
                } else if let Some(cfg) = fs.open_zfs_configuration() {
                    (
                        cfg.deployment_type().map(|d| d.as_str()).unwrap_or(""),
                        cfg.automatic_backup_retention_days().unwrap_or(0),
                        cfg.daily_automatic_backup_start_time().unwrap_or(""),
                        cfg.preferred_subnet_id().unwrap_or(""),
                    )
                } else if let Some(cfg) = fs.ontap_configuration() {
                    (
                        cfg.deployment_type().map(|d| d.as_str()).unwrap_or(""),
                        cfg.automatic_backup_retention_days().unwrap_or(0),
                        cfg.daily_automatic_backup_start_time().unwrap_or(""),
                        cfg.preferred_subnet_id().unwrap_or(""),
                    )
                } else {
                    ("", 0, "", "")
                };

            let function = function_from_fsx_tags(fs.tags());

            let comments = format!(
                "StorageCapacityGiB: {storage_capacity} | StorageType: {storage_type} | \
                 KmsKeyId: {kms_key_id} | PreferredSubnetId: {preferred_subnet_id} | \
                 AutomaticBackupRetentionDays: {backup_retention_days} | \
                 DailyAutomaticBackupStartTime: {daily_backup_start_time} | \
                 DeploymentType: {deployment_type}"
            );

            rows.push(
                RowBuilder::new()
                    .unique_id(&resource_arn)
                    .virtual_flag("Yes")
                    .public("No")
                    .dns_url(dns_name)
                    .location(region)
                    .asset_type(format!("FSx File System ({fs_type})"))
                    .sw_vendor("Amazon Web Services")
                    .sw_name_ver(sw_name_ver)
                    .vlan_network_id(vlan_network_id)
                    .function(function)
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
