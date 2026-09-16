use anyhow::Result;
use aws_config::{BehaviorVersion, Region};

use crate::audit_log;
use crate::cli::Cli;
use crate::providers::aws::cloudtrail_s3::{CloudTrailS3Collector, CloudTrailS3Config};

/// Build a config loader for `region`, pinned to `profile` when one is named.
///
/// Returns the loader rather than a loaded `SdkConfig` because callers that make
/// an AWS call through a config must not reuse it for building collectors: the
/// call consumes the credential provider's internal state.
///
/// Pinning matters. `.profile_name()` by itself only tells the DEFAULT credential
/// chain which profile to read, and in that chain environment variables rank
/// ahead of the profile. With AWS_ACCESS_KEY_ID / AWS_SESSION_TOKEN exported
/// (as `assume` and similar tools do), every profile would resolve to whatever
/// the shell already held — so a multi-account run reported one account's assets
/// under all the other accounts' names. Attaching an explicit
/// `ProfileFileCredentialsProvider` takes the environment out of the decision.
pub fn cli_config_loader(region: &str, profile: Option<&str>) -> aws_config::ConfigLoader {
    let mut loader =
        aws_config::defaults(BehaviorVersion::latest()).region(Region::new(region.to_string()));
    if let Some(profile_name) = profile {
        if !profile_name.is_empty() && profile_name != "default" {
            loader = loader.profile_name(profile_name).credentials_provider(
                aws_config::profile::ProfileFileCredentialsProvider::builder()
                    .profile_name(profile_name)
                    .build(),
            );
        }
    }
    loader
}

/// The account ID `profile` is meant to reach: `sso_account_id`,
/// `granted_sso_account_id`, or the account in `role_arn` from the AWS config
/// file, else a 12-digit run in the profile name (`fed:Admin-123456789012`).
pub fn expected_account_id(profile: &str) -> Option<String> {
    let path = std::env::var_os("AWS_CONFIG_FILE")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| std::path::Path::new(&h).join(".aws/config")));
    let from_file = path
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|text| account_id_in_config(&text, profile));
    from_file.or_else(|| {
        profile
            .split(|c: char| !c.is_ascii_digit())
            .find(|run| run.len() == 12)
            .map(str::to_string)
    })
}

fn account_id_in_config(text: &str, profile: &str) -> Option<String> {
    let wanted = [format!("[profile {profile}]"), format!("[{profile}]")];
    let mut in_section = false;
    for line in text.lines().map(str::trim) {
        if line.starts_with('[') {
            in_section = wanted.iter().any(|w| w == line);
            continue;
        }
        if !in_section {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        match key.trim() {
            "sso_account_id" | "granted_sso_account_id" => return Some(value.to_string()),
            // arn:aws:iam::123456789012:role/Name
            "role_arn" => return value.split(':').nth(4).map(str::to_string),
            _ => {}
        }
    }
    None
}

/// Decide whether `profile` or the shell's ambient credentials (e.g. exported by
/// `assume`) should back a run. Ambient credentials are used only when the
/// profile itself cannot authenticate AND the ambient identity is the account
/// the profile targets, so evidence is never filed under the wrong account.
/// Returns `(use_ambient, identity)`, or a human-readable reason on failure.
pub async fn resolve_credential_source(
    region: &str,
    profile: &str,
) -> std::result::Result<(bool, audit_log::AwsIdentity), String> {
    let profile_err = match audit_log::resolve_aws_identity_detailed(
        &load_cli_config(region, Some(profile)).await,
    )
    .await
    {
        Ok(id) => return Ok((false, id)),
        Err(e) => e,
    };
    let Ok(ambient) =
        audit_log::resolve_aws_identity_detailed(&load_cli_config(region, None).await).await
    else {
        return Err(format!(
            "profile failed ({profile_err}); no usable shell credentials either"
        ));
    };
    match expected_account_id(profile) {
        Some(want) if want == ambient.account_id => Ok((true, ambient)),
        Some(want) => Err(format!(
            "profile failed ({profile_err}); shell credentials are for account {} but this \
             profile targets {want}, refusing to mix accounts",
            ambient.account_id
        )),
        None => Err(format!(
            "profile failed ({profile_err}); can't tell which account the profile targets, \
             so shell credentials for {} were not used",
            ambient.account_id
        )),
    }
}

pub async fn load_cli_config(region: &str, profile: Option<&str>) -> aws_config::SdkConfig {
    cli_config_loader(region, profile).load().await
}

pub async fn load_cli_probe_and_work_configs(
    region: &str,
    profile: Option<&str>,
) -> (aws_config::SdkConfig, aws_config::SdkConfig, bool) {
    load_cli_probe_and_work_configs_opts(region, profile, true).await
}

/// As `load_cli_probe_and_work_configs`, but `allow_ambient_fallback` controls
/// whether an unusable profile may fall back to the shell's own credentials.
///
/// Multi-account callers must pass `false`. Falling back there would attribute
/// the shell account's assets to whichever profile happened to fail, producing
/// evidence that names the wrong account — worse than collecting nothing.
/// Even with `false`, the fallback still happens when the shell credentials
/// reach the exact account the profile targets (see `expected_account_id`).
pub async fn load_cli_probe_and_work_configs_opts(
    region: &str,
    profile: Option<&str>,
    allow_ambient_fallback: bool,
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
            let same_account = matches!(
                (&ambient_identity, expected_account_id(profile_name)),
                (Some(id), Some(want)) if id.account_id == want
            );
            if ambient_identity.is_some() && (allow_ambient_fallback || same_account) {
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
        identity
            .as_ref()
            .map(|id| id.caller_arn.as_str())
            .unwrap_or("unknown"),
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

#[cfg(test)]
mod expected_account_tests {
    use super::account_id_in_config;

    #[test]
    fn reads_sso_and_role_arn_for_exact_profile() {
        let cfg = "[profile a]\nsso_account_id = 111111111111\n\n[profile b]\nrole_arn = arn:aws:iam::222222222222:role/X\n[profile ab]\nsso_account_id = 333333333333\n";
        assert_eq!(
            account_id_in_config(cfg, "a").as_deref(),
            Some("111111111111")
        );
        assert_eq!(
            account_id_in_config(cfg, "b").as_deref(),
            Some("222222222222")
        );
        assert_eq!(account_id_in_config(cfg, "c"), None);
    }
}
