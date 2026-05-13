use anyhow::Result;
use aws_config::{BehaviorVersion, Region};

use crate::audit_log;
use crate::cli::Cli;
use crate::providers::aws::cloudtrail_s3::{CloudTrailS3Collector, CloudTrailS3Config};

pub async fn load_cli_config(region: &str, profile: Option<&str>) -> aws_config::SdkConfig {
    let mut loader =
        aws_config::defaults(BehaviorVersion::latest()).region(Region::new(region.to_string()));
    if let Some(profile_name) = profile {
        if !profile_name.is_empty() && profile_name != "default" {
            loader = loader.profile_name(profile_name);
        }
    }
    loader.load().await
}

pub async fn load_cli_probe_and_work_configs(
    region: &str,
    profile: Option<&str>,
) -> (aws_config::SdkConfig, aws_config::SdkConfig, bool) {
    let probe = load_cli_config(region, profile).await;
    let probe_identity = audit_log::resolve_aws_identity(&probe).await;
    if probe_identity.is_some() {
        let work = load_cli_config(region, profile).await;
        return (probe, work, false);
    }

    if let Some(profile_name) = profile {
        if !profile_name.is_empty() && profile_name != "default" {
            eprintln!(
                "WARNING: Could not resolve AWS identity with explicit profile '{}'; \
                 trying ambient AWS credentials from the current shell.",
                profile_name
            );
            let ambient_probe = load_cli_config(region, None).await;
            let ambient_identity = audit_log::resolve_aws_identity(&ambient_probe).await;
            if ambient_identity.is_some() {
                let ambient_work = load_cli_config(region, None).await;
                return (ambient_probe, ambient_work, true);
            }
        }
    }

    let work = load_cli_config(region, profile).await;
    (probe, work, false)
}

pub fn print_cli_identity(identity: &Option<audit_log::AwsIdentity>) -> String {
    let account_id = identity
        .as_ref()
        .map(|id| id.account_id.clone())
        .unwrap_or_else(|| "unknown".to_string());
    eprintln!(
        "Identity: account={} arn={}",
        account_id,
        identity.as_ref().map(|id| id.caller_arn.as_str()).unwrap_or("unknown"),
    );
    account_id
}

pub async fn discover_regions(config: &aws_config::SdkConfig) -> Vec<String> {
    let ec2 = aws_sdk_ec2::Client::new(config);
    let filter = aws_sdk_ec2::types::Filter::builder()
        .name("opt-in-status")
        .values("opt-in-not-required")
        .values("opted-in")
        .build();
    match ec2.describe_regions().filters(filter).send().await {
        Ok(r) => {
            let mut regions: Vec<String> = r
                .regions()
                .iter()
                .filter_map(|r| r.region_name().map(|s| s.to_string()))
                .collect();
            regions.sort();
            eprintln!(
                "Discovered {} enabled regions: {}",
                regions.len(),
                regions.join(", ")
            );
            regions
        }
        Err(e) => {
            eprintln!("WARN: could not discover regions via EC2: {e:#}");
            vec![]
        }
    }
}

pub async fn print_identity(config: &aws_config::SdkConfig) -> String {
    let sts = aws_sdk_sts::Client::new(config);
    match sts.get_caller_identity().send().await {
        Ok(resp) => {
            let account = resp.account().unwrap_or("unknown").to_string();
            eprintln!(
                "Identity: account={account} arn={}",
                resp.arn().unwrap_or("unknown"),
            );
            account
        }
        Err(e) => {
            eprintln!("WARNING: Could not resolve AWS identity: {e}");
            "unknown".to_string()
        }
    }
}

pub fn build_s3_collector_from_cli(
    cli: &Cli,
    s3_config: &aws_config::SdkConfig,
    account_id: &str,
) -> Result<Option<CloudTrailS3Collector>> {
    let bucket = match &cli.s3_bucket {
        Some(b) => b.clone(),
        None => return Ok(None),
    };
    let mut account_ids = vec![account_id.to_string()];
    if let Some(ref extras) = cli.s3_accounts {
        for a in extras {
            if !account_ids.contains(a) {
                account_ids.push(a.clone());
            }
        }
    }
    let mut regions = vec![cli.region.clone()];
    if let Some(ref extras) = cli.s3_regions {
        for r in extras {
            if !regions.contains(r) {
                regions.push(r.clone());
            }
        }
    }
    Ok(Some(CloudTrailS3Collector::new(
        s3_config,
        CloudTrailS3Config {
            bucket,
            prefix: cli.s3_prefix.clone(),
            account_ids,
            regions,
        },
    )))
}
