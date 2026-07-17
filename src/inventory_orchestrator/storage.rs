use anyhow::{Context, Result};

use aws_sdk_kms::Client as KmsClient;
use aws_sdk_s3::Client as S3Client;

use crate::inventory_core::{normalize_s3_region, RowBuilder};

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

pub(super) async fn collect_ebs_volumes(_c: &Ec2Client, _region: &str) -> Result<Vec<Vec<String>>> {
    Ok(Vec::new())
}
pub(super) async fn collect_efs_file_systems(_c: &EfsClient, _region: &str) -> Result<Vec<Vec<String>>> {
    Ok(Vec::new())
}
pub(super) async fn collect_fsx_file_systems(_c: &FsxClient, _region: &str) -> Result<Vec<Vec<String>>> {
    Ok(Vec::new())
}
