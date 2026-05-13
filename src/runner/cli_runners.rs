use std::path::PathBuf;

use anyhow::{Context, Result};
use aws_config::{BehaviorVersion, Region};
use chrono::{NaiveDate, Utc};

use crate::audit_log;
use crate::cli::Cli;
use crate::evidence::{
    CollectParams, CsvCollector, EvidenceCollector, EvidenceReport, JsonCollector,
    JsonInventoryReport, ReportMetadata,
};
use crate::inventory_orchestrator::InventoryCollector;
use crate::providers::aws::access_analyzer::AccessAnalyzerCollector;
use crate::providers::aws::account_config::{
    AccountContactsCollector, IamAccountSummaryCollector, SamlProviderCollector,
};
use crate::providers::aws::acm::AcmCertCollector;
use crate::providers::aws::alb_logs::AlbLogsCollector;
use crate::providers::aws::apigateway::ApiGatewayCollector;
use crate::providers::aws::autoscaling::AutoScalingCollector;
use crate::providers::aws::backup::BackupCollector;
use crate::providers::aws::backup_config::{
    BackupPlanConfigCollector, BackupVaultConfigCollector, RdsBackupConfigCollector,
};
use crate::providers::aws::cloudformation_drift::CloudFormationDriftCollector;
use crate::providers::aws::cloudfront::CloudFrontCollector;
use crate::providers::aws::cloudtrail::CloudTrailCollector;
use crate::providers::aws::cloudtrail_config::CloudTrailFullConfigCollector;
use crate::providers::aws::cloudtrail_details::{
    CloudTrailChangeEventsCollector, CloudTrailEventSelectorsCollector,
    CloudTrailLogValidationCollector, CloudTrailS3PolicyCollector, S3DataEventsCollector,
};
use crate::providers::aws::cloudtrail_iam::{
    CloudTrailConfigChangesCollector, CloudTrailIamChangesCollector,
};
use crate::providers::aws::cloudtrail_inventory::CloudTrailInventoryCollector;
use crate::providers::aws::cloudwatch::MetricFilterAlarmCollector;
use crate::providers::aws::cloudwatch_alarms::CloudWatchConfigAlarmsCollector;
use crate::providers::aws::cloudwatch_config::{
    CwLogGroupConfigCollector, MetricFilterConfigCollector,
};
use crate::providers::aws::cloudwatch_resources::{
    CloudWatchAlarmCollector, CloudWatchLogGroupCollector,
};
use crate::providers::aws::config_history::ConfigHistoryCollector;
use crate::providers::aws::config_rules::ConfigRulesCollector;
use crate::providers::aws::config_timeline::{
    ConfigComplianceHistoryCollector, ConfigResourceTimelineCollector, ConfigSnapshotCollector,
};
use crate::providers::aws::dynamodb::DynamoDbCollector;
use crate::providers::aws::ebs::EbsCollector;
use crate::providers::aws::ec2_config::{
    Ec2InstanceConfigCollector, RouteTableConfigCollector, SecurityGroupConfigCollector,
    VpcConfigCollector,
};
use crate::providers::aws::ec2_detailed::Ec2DetailedCollector;
use crate::providers::aws::ec2_inventory::{
    Ec2InstanceCollector, RouteTableCollector, SecurityGroupCollector,
};
use crate::providers::aws::ecr::EcrScanCollector;
use crate::providers::aws::ecr_config::EcrRepoConfigCollector;
use crate::providers::aws::ecs::EcsClusterCollector;
use crate::providers::aws::efs::EfsCollector;
use crate::providers::aws::eks::EksClusterCollector;
use crate::providers::aws::elasticache::{ElastiCacheCollector, ElastiCacheGlobalCollector};
use crate::providers::aws::elb::{LoadBalancerCollector, LoadBalancerListenerCollector};
use crate::providers::aws::elb_config::ElbFullConfigCollector;
use crate::providers::aws::guardduty::GuardDutyCollector;
use crate::providers::aws::guardduty_config::{
    GuardDutyConfigCollector, GuardDutySuppressionCollector,
};
use crate::providers::aws::iam_certs::IamCertCollector;
use crate::providers::aws::iam_inventory::{
    IamAccessKeyCollector, IamPolicyCollector, IamRoleCollector, IamUserCollector,
};
use crate::providers::aws::iam_policies::{
    IamPasswordPolicyCollector, IamRolePoliciesCollector, IamUserPoliciesCollector,
};
use crate::providers::aws::iam_trusts::IamTrustsCollector;
use crate::providers::aws::inspector::InspectorCollector;
use crate::providers::aws::inspector_config::InspectorConfigCollector;
use crate::providers::aws::inspector_ecr::InspectorEcrImagesCollector;
use crate::providers::aws::inspector_history::InspectorFindingsHistoryCollector;
use crate::providers::aws::kms::KmsKeyCollector;
use crate::providers::aws::kms_config::{EbsEncryptionConfigCollector, KmsKeyConfigCollector};
use crate::providers::aws::kms_policies::{EbsDefaultEncryptionCollector, KmsKeyPolicyCollector};
use crate::providers::aws::lambda_config::{LambdaConfigCollector, LambdaPermissionsCollector};
use crate::providers::aws::launch_templates::LaunchTemplateCollector;
use crate::providers::aws::macie::MacieCollector;
use crate::providers::aws::network_gateways::{InternetGatewayCollector, NatGatewayCollector};
use crate::providers::aws::org_config::OrgConfigCollector;
use crate::providers::aws::organizations::OrganizationsSCPCollector;
use crate::providers::aws::public_resources::PublicResourceCollector;
use crate::providers::aws::rds::RdsCollector;
use crate::providers::aws::rds_inventory::RdsInventoryCollector;
use crate::providers::aws::rds_snapshots::RdsSnapshotCollector;
use crate::providers::aws::route53_config::{Route53ResolverRulesCollector, Route53ZonesCollector};
use crate::providers::aws::s3_config::S3BucketConfigCollector;
use crate::providers::aws::s3_detail::{
    S3BucketPolicyDetailCollector, S3EncryptionConfigCollector, S3LoggingConfigCollector,
    S3PublicAccessBlockCollector,
};
use crate::providers::aws::s3_inventory::S3BucketLoggingCollector;
use crate::providers::aws::s3_policies::S3PoliciesCollector;
use crate::providers::aws::secrets_extended::SecretsManagerPoliciesCollector;
use crate::providers::aws::secretsmanager::SecretsManagerCollector;
use crate::providers::aws::security_svc_config::{
    AwsConfigRecorderCollector, GuardDutyFullConfigCollector, SecurityHubConfigCollector,
};
use crate::providers::aws::securityhub::SecurityHubCollector;
use crate::providers::aws::securityhub_standards::SecurityHubStandardsCollector;
use crate::providers::aws::sns::SnsSubscriptionCollector;
use crate::providers::aws::sns_eventbridge::ChangeEventRulesCollector;
use crate::providers::aws::sns_eventbridge::{
    EventBridgeRulesCollector, SnsTopicPoliciesCollector,
};
use crate::providers::aws::ssm::{SsmManagedInstanceCollector, SsmPatchComplianceCollector};
use crate::providers::aws::ssm_extended::{
    SsmParameterConfigCollector, SsmPatchBaselineCollector, TimeSyncConfigCollector,
};
use crate::providers::aws::ssm_patch_detail::{
    SsmMaintenanceWindowCollector, SsmPatchDetailCollector, SsmPatchExecutionCollector,
    SsmPatchSummaryCollector,
};
use crate::providers::aws::tagging_config::ResourceTaggingCollector;
use crate::providers::aws::vpc::{NetworkAclCollector, VpcCollector};
use crate::providers::aws::vpc_endpoints::VpcEndpointCollector;
use crate::providers::aws::vpcflowlogs::VpcFlowLogCollector;
use crate::providers::aws::waf::WafCollector;
use crate::providers::aws::waf_full_config::WafFullConfigCollector;
use crate::providers::aws::waf_logging::WafLoggingCollector;
use crate::runner::multi_account::GLOBAL_COLLECTOR_KEYS;
use crate::runner::output::{format_path_with_osc8, write_csv_bytes, write_inventory_outputs};

pub async fn run_inventory_cli(cli: &Cli) -> Result<()> {
    if cli.collectors.is_some() {
        anyhow::bail!("--collectors cannot be used with --inventory");
    }
    if cli.start_date.is_some() || cli.end_date.is_some() {
        anyhow::bail!(
            "--start-date and --end-date are not used with --inventory; \
             use --lookback to set the collection window (e.g. --lookback 90d)"
        );
    }
    if cli.filter.is_some() {
        anyhow::bail!("--filter is not supported with --inventory");
    }
    if cli.include_raw {
        anyhow::bail!("--include-raw is not supported with --inventory");
    }
    if cli.s3_bucket.is_some()
        || !cli.s3_prefix.is_empty()
        || cli.s3_profile.is_some()
        || cli.s3_accounts.is_some()
        || cli.s3_regions.is_some()
    {
        anyhow::bail!("S3 CloudTrail flags are not supported with --inventory");
    }

    let inventory_types = crate::cli::resolve_inventory_types(cli);
    let output_dir = cli.output.clone().unwrap_or_else(|| PathBuf::from("."));
    let (probe_config, work_config, using_ambient_credentials) =
        crate::aws_loader::load_cli_probe_and_work_configs(&cli.region, cli.profile.as_deref())
            .await;
    let cli_identity = audit_log::resolve_aws_identity(&probe_config).await;
    if cli_identity.is_none() {
        anyhow::bail!(
            "Failed to resolve AWS identity for profile '{}'. Re-authenticate and verify the profile before running inventory CLI.",
            crate::cli::cli_profile_label(cli.profile.as_deref())
        );
    }
    let account_id = crate::aws_loader::print_cli_identity(&cli_identity);

    let inventory_dates: Option<(i64, i64)> = if let Some(ref lb) = cli.lookback {
        let today = chrono::Utc::now().date_naive();
        let start = crate::cli::parse_lookback(lb)?;
        let start_ts = start
            .and_hms_opt(0, 0, 0)
            .expect("valid midnight time")
            .and_utc()
            .timestamp();
        let end_ts = today
            .and_hms_opt(23, 59, 59)
            .expect("valid end-of-day time")
            .and_utc()
            .timestamp();
        eprintln!("Lookback window: {} → {} ({})", start, today, lb);
        Some((start_ts, end_ts))
    } else {
        None
    };

    eprintln!("Inventory asset types: {}", inventory_types.join(", "));

    let target_regions = if let Some(explicit) = cli.regions.as_ref() {
        explicit.clone()
    } else if cli.all_regions {
        let regions = crate::aws_loader::discover_regions(&probe_config).await;
        if regions.is_empty() {
            anyhow::bail!("--all-regions: could not discover any enabled regions");
        }
        regions
    } else {
        vec![cli.region.clone()]
    };

    let mut inventory_rows: Vec<Vec<String>> = Vec::new();
    for region_name in &target_regions {
        let region_work_config = if region_name == &cli.region {
            work_config.clone()
        } else {
            let region_profile = if using_ambient_credentials {
                None
            } else {
                cli.profile.as_deref()
            };
            crate::aws_loader::load_cli_config(region_name, region_profile).await
        };
        let collector = InventoryCollector::new(&region_work_config, inventory_types.clone());
        eprintln!("Collecting inventory from {}...", region_name);
        let rows = collector
            .collect_rows(&account_id, region_name, inventory_dates)
            .await?;
        eprintln!("  {} returned {} rows", region_name, rows.len());
        inventory_rows.extend(rows);
    }

    let timestamp = Utc::now().format("%Y-%m-%d-%H%M%S").to_string();
    let written_files = write_inventory_outputs(
        &output_dir,
        &timestamp,
        &inventory_rows,
        cli.skip_inventory_csv,
    )?;

    if cli.zip && !written_files.is_empty() {
        let zip_name = format!("Evidence-{}.zip", timestamp);
        let zip_path = PathBuf::from(&zip_name);
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        match crate::zip_bundle::bundle_files(&written_files, &cwd, &zip_path) {
            Ok(()) => eprintln!("Zip bundle written: {}", zip_name),
            Err(e) => eprintln!("Zip bundle failed: {e}"),
        }
    }

    if cli.sign && !written_files.is_empty() {
        let key = match &cli.signing_key {
            Some(hex) => crate::signing::SigningKey::from_hex(hex)?,
            None => crate::signing::SigningKey::generate()?,
        };
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        match crate::signing::sign_files(&written_files, &timestamp, &key, &cwd) {
            Ok((manifest_path, key_path)) => {
                eprintln!("Signing manifest: {}", manifest_path.display());
                eprintln!(
                    "Signing key file: {} (move to secure storage)",
                    key_path.display()
                );
                eprintln!("Signing key (hex): {}", key.to_hex());
            }
            Err(e) => eprintln!("Signing failed: {e}"),
        }
    }

    Ok(())
}

pub async fn run_poam_cli(cli: &Cli) -> Result<()> {
    let year = cli
        .poam_year
        .as_deref()
        .context("--poam-year <YYYY> is required with --poam")?;
    let month = cli
        .poam_month
        .as_deref()
        .context("--poam-month <Month> is required with --poam (e.g. January)")?;

    if year.len() != 4 || year.parse::<u32>().is_err() {
        anyhow::bail!("--poam-year must be a 4-digit year (e.g. 2026)");
    }

    let evidence_path =
        crate::poam::resolve_evidence_path(&cli.poam_evidence_base, &cli.region, year, month)?;
    eprintln!("POA&M evidence path: {}", evidence_path.display());

    match crate::poam::run_poam(&cli.poam_evidence_base, &cli.region, year, month)? {
        result => {
            eprintln!("POA&M reconciliation complete.");
            eprintln!(
                "  Region: {}  Year: {}  Month: {}",
                result.region, result.year, result.month_name
            );
            eprintln!("  Evidence path: {}", result.evidence_path.display());
            if let Some(csv) = &result.selected_csv {
                eprintln!("  CSV used: {csv}");
            }
            eprintln!("  Findings opened:  {}", result.added_open_count);
            eprintln!("  Findings closed:  {}", result.moved_closed_count);
            for w in &result.warnings {
                eprintln!("  WARN: {w}");
            }
        }
    }

    Ok(())
}

pub async fn run_json_collectors(
    collectors: &[Box<dyn EvidenceCollector>],
    params: &CollectParams,
    region: &str,
    output_dir: &PathBuf,
    timestamp: &str,
) -> Result<Vec<audit_log::CollectorOutcome>> {
    std::fs::create_dir_all(output_dir)
        .with_context(|| format!("Failed to create output directory {}", output_dir.display()))?;
    let mut outcomes = Vec::new();
    for collector in collectors {
        eprintln!("Collecting from {}...", collector.name());
        match collector.collect(params).await {
            Ok(records) => {
                let count = records.len();
                eprintln!("  {} returned {} records", collector.name(), count);
                if count == 0 {
                    outcomes.push(audit_log::CollectorOutcome::empty(collector.name()));
                    continue;
                }

                let report = EvidenceReport {
                    metadata: ReportMetadata {
                        collected_at: Utc::now().to_rfc3339(),
                        region: region.to_string(),
                        start_date: params.start_time.format("%Y-%m-%d").to_string(),
                        end_date: params.end_time.format("%Y-%m-%d").to_string(),
                        filter: params.filter.clone(),
                    },
                    collector: collector.name().to_string(),
                    record_count: count,
                    records,
                };

                let filename = format!("{}-{}.json", collector.filename_prefix(), timestamp);
                let path = output_dir.join(&filename);
                let json =
                    serde_json::to_string_pretty(&report).context("JSON serialization failed")?;
                std::fs::write(&path, json)
                    .with_context(|| format!("Failed to write {}", path.display()))?;
                eprintln!("  Written: {}", format_path_with_osc8(&path));
                outcomes.push(audit_log::CollectorOutcome::success(
                    collector.name(),
                    count,
                    &path,
                ));
            }
            Err(e) => {
                eprintln!("  ERROR from {}: {e:#}", collector.name());
                outcomes.push(audit_log::CollectorOutcome::error(
                    collector.name(),
                    format!("{e:#}"),
                ));
            }
        }
    }
    Ok(outcomes)
}

pub async fn run_csv_collectors(
    collectors: &[Box<dyn CsvCollector>],
    account_id: &str,
    region: &str,
    output_dir: &PathBuf,
    dates: Option<(i64, i64)>,
    timestamp: &str,
) -> Result<Vec<audit_log::CollectorOutcome>> {
    std::fs::create_dir_all(output_dir)
        .with_context(|| format!("Failed to create output directory {}", output_dir.display()))?;
    let mut outcomes = Vec::new();
    for collector in collectors {
        eprintln!("Collecting from {}...", collector.name());
        match collector.collect_rows(account_id, region, dates).await {
            Ok(rows) => {
                let count = rows.len();
                eprintln!("  {} returned {} rows", collector.name(), count);
                if rows.is_empty() {
                    outcomes.push(audit_log::CollectorOutcome::empty(collector.name()));
                    continue;
                }
                let filename = format!(
                    "{}_{}-{}.csv",
                    account_id,
                    collector.filename_prefix(),
                    timestamp
                );
                let path = output_dir.join(&filename);
                let bytes = write_csv_bytes(collector.headers(), &rows)?;
                std::fs::write(&path, bytes)
                    .with_context(|| format!("Failed to write {}", path.display()))?;
                eprintln!("  Written: {}", format_path_with_osc8(&path));
                outcomes.push(audit_log::CollectorOutcome::success(
                    collector.name(),
                    count,
                    &path,
                ));
            }
            Err(e) => {
                eprintln!("  ERROR from {}: {e:#}", collector.name());
                outcomes.push(audit_log::CollectorOutcome::error(
                    collector.name(),
                    format!("{e:#}"),
                ));
            }
        }
    }
    Ok(outcomes)
}

pub async fn run_json_inv_collectors(
    collectors: &[Box<dyn JsonCollector>],
    account_id: &str,
    region: &str,
    output_dir: &PathBuf,
    timestamp: &str,
) -> Result<Vec<audit_log::CollectorOutcome>> {
    std::fs::create_dir_all(output_dir)
        .with_context(|| format!("Failed to create output directory {}", output_dir.display()))?;
    let mut outcomes = Vec::new();
    for collector in collectors {
        eprintln!("Collecting from {}...", collector.name());
        match collector.collect_records(account_id, region).await {
            Ok(records) => {
                let count = records.len();
                eprintln!("  {} returned {} records", collector.name(), count);
                if records.is_empty() {
                    outcomes.push(audit_log::CollectorOutcome::empty(collector.name()));
                    continue;
                }
                let report = JsonInventoryReport {
                    collected_at: Utc::now().to_rfc3339(),
                    account_id: account_id.to_string(),
                    region: region.to_string(),
                    collector: collector.name().to_string(),
                    record_count: count,
                    records,
                };
                let filename = format!(
                    "{}_{}-{}.json",
                    account_id,
                    collector.filename_prefix(),
                    timestamp
                );
                let path = output_dir.join(&filename);
                let json = serde_json::to_string_pretty(&report).context("JSON serialise")?;
                std::fs::write(&path, json)
                    .with_context(|| format!("Failed to write {}", path.display()))?;
                eprintln!("  Written: {}", format_path_with_osc8(&path));
                outcomes.push(audit_log::CollectorOutcome::success(
                    collector.name(),
                    count,
                    &path,
                ));
            }
            Err(e) => {
                eprintln!("  ERROR from {}: {e:#}", collector.name());
                outcomes.push(audit_log::CollectorOutcome::error(
                    collector.name(),
                    format!("{e:#}"),
                ));
            }
        }
    }
    Ok(outcomes)
}

pub async fn run_standard_cli(cli: &Cli) -> Result<()> {
    let (start, end) = if let Some(ref lb) = cli.lookback {
        if cli.start_date.is_some() || cli.end_date.is_some() {
            anyhow::bail!("--lookback cannot be combined with --start-date or --end-date");
        }
        let today = chrono::Utc::now().date_naive();
        let start_date = crate::cli::parse_lookback(lb)?;
        (
            start_date
                .and_hms_opt(0, 0, 0)
                .expect("valid midnight time")
                .and_utc(),
            today
                .and_hms_opt(23, 59, 59)
                .expect("valid end-of-day time")
                .and_utc(),
        )
    } else {
        let start_str = cli
            .start_date
            .as_deref()
            .expect("start_date is Some — guarded by caller");
        let end_str = cli
            .end_date
            .as_deref()
            .context("--end-date is required when --start-date is provided")?;
        (
            NaiveDate::parse_from_str(start_str, "%Y-%m-%d")
                .context("Invalid --start-date")?
                .and_hms_opt(0, 0, 0)
                .expect("valid midnight time")
                .and_utc(),
            NaiveDate::parse_from_str(end_str, "%Y-%m-%d")
                .context("Invalid --end-date")?
                .and_hms_opt(23, 59, 59)
                .expect("valid end-of-day time")
                .and_utc(),
        )
    };

    let mut loader =
        aws_config::defaults(BehaviorVersion::latest()).region(Region::new(cli.region.clone()));
    if let Some(ref p) = cli.profile {
        loader = loader.profile_name(p);
    }
    let config = loader.load().await;

    let s3_config = if let Some(ref p) = cli.s3_profile {
        aws_config::defaults(BehaviorVersion::latest())
            .region(Region::new(cli.region.clone()))
            .profile_name(p)
            .load()
            .await
    } else {
        config.clone()
    };

    let cli_started_at = Utc::now().to_rfc3339();
    let cli_identity = audit_log::resolve_aws_identity(&config).await;
    let account_id = cli_identity
        .as_ref()
        .map(|id| id.account_id.clone())
        .unwrap_or_else(|| "unknown".to_string());
    eprintln!(
        "Identity: account={} arn={}",
        account_id,
        cli_identity
            .as_ref()
            .map(|id| id.caller_arn.as_str())
            .unwrap_or("unknown"),
    );

    let params = CollectParams {
        start_time: start,
        end_time: end,
        filter: cli.filter.clone(),
        include_raw: cli.include_raw,
    };

    let run_all = cli.collectors.is_none();
    let wants = |name: &str| -> bool {
        cli.collectors
            .as_deref()
            .map(|v| v.iter().any(|n| n.eq_ignore_ascii_case(name)))
            .unwrap_or(true)
    };

    // --- JSON evidence collectors (time-windowed) ---------------------------
    let mut json_collectors: Vec<Box<dyn EvidenceCollector>> = Vec::new();
    if wants("cloudtrail") {
        json_collectors.push(Box::new(CloudTrailCollector::new(&config)));
    }
    if wants("backup") {
        json_collectors.push(Box::new(BackupCollector::new(&config)));
    }
    if wants("rds") {
        json_collectors.push(Box::new(RdsCollector::new(&config)));
    }
    if wants("s3") && !run_all {
        match crate::aws_loader::build_s3_collector_from_cli(cli, &s3_config, &account_id) {
            Ok(Some(c)) => json_collectors.push(Box::new(c)),
            Ok(None) => anyhow::bail!("--s3-bucket is required for the s3 collector"),
            Err(e) => eprintln!("WARN: {e:#}"),
        }
    }

    // --- JSON inventory collectors (current-state, structured JSON output) ---
    let mut json_inv_collectors: Vec<Box<dyn JsonCollector>> = Vec::new();
    if wants("iam-roles") {
        json_inv_collectors.push(Box::new(IamRoleCollector::new(&config)));
    }
    if wants("iam-role-policies") {
        json_inv_collectors.push(Box::new(IamRolePoliciesCollector::new(&config)));
    }
    if wants("iam-user-policies") {
        json_inv_collectors.push(Box::new(IamUserPoliciesCollector::new(&config)));
    }
    if wants("eventbridge-rules") {
        json_inv_collectors.push(Box::new(EventBridgeRulesCollector::new(&config)));
    }
    if wants("ct-config-changes") {
        json_inv_collectors.push(Box::new(CloudTrailConfigChangesCollector::new(&config)));
    }
    if wants("kms-config") {
        json_inv_collectors.push(Box::new(KmsKeyConfigCollector::new(&config)));
    }

    // --- CSV inventory collectors (current-state snapshots) -----------------
    let mut csv_collectors: Vec<Box<dyn CsvCollector>> = Vec::new();
    if wants("vpc") {
        csv_collectors.push(Box::new(VpcCollector::new(&config)));
    }
    if wants("nacl") {
        csv_collectors.push(Box::new(NetworkAclCollector::new(&config)));
    }
    if wants("waf") {
        csv_collectors.push(Box::new(WafCollector::new(&config)));
    }
    if wants("elasticache") {
        csv_collectors.push(Box::new(ElastiCacheCollector::new(&config)));
    }
    if wants("elasticache-global") {
        csv_collectors.push(Box::new(ElastiCacheGlobalCollector::new(&config)));
    }
    if wants("efs") {
        csv_collectors.push(Box::new(EfsCollector::new(&config)));
    }
    if wants("dynamodb") {
        csv_collectors.push(Box::new(DynamoDbCollector::new(&config)));
    }
    if wants("ebs") {
        csv_collectors.push(Box::new(EbsCollector::new(&config)));
    }
    if wants("rds-inventory") {
        csv_collectors.push(Box::new(RdsInventoryCollector::new(&config)));
    }
    if wants("cloudtrail-config") {
        csv_collectors.push(Box::new(CloudTrailInventoryCollector::new(&config)));
    }
    if wants("sns") {
        csv_collectors.push(Box::new(SnsSubscriptionCollector::new(&config)));
    }
    if wants("vpc-flow-logs") {
        csv_collectors.push(Box::new(VpcFlowLogCollector::new(&config)));
    }
    if wants("metric-filters") {
        csv_collectors.push(Box::new(MetricFilterAlarmCollector::new(&config)));
    }
    if wants("s3-logging") {
        csv_collectors.push(Box::new(S3BucketLoggingCollector::new(&config)));
    }
    if wants("iam-certs") {
        csv_collectors.push(Box::new(IamCertCollector::new(&config)));
    }
    if wants("elb") {
        csv_collectors.push(Box::new(LoadBalancerCollector::new(&config)));
    }
    if wants("elb-listeners") {
        csv_collectors.push(Box::new(LoadBalancerListenerCollector::new(&config)));
    }
    if wants("acm") {
        csv_collectors.push(Box::new(AcmCertCollector::new(&config)));
    }
    if wants("iam-users") {
        csv_collectors.push(Box::new(IamUserCollector::new(&config)));
    }
    // iam-roles → json_inv_collectors (see above)
    if wants("iam-policies") {
        csv_collectors.push(Box::new(IamPolicyCollector::new(&config)));
    }
    if wants("iam-access-keys") {
        csv_collectors.push(Box::new(IamAccessKeyCollector::new(&config)));
    }
    if wants("guardduty") {
        csv_collectors.push(Box::new(GuardDutyCollector::new(&config)));
    }
    if wants("securityhub") {
        csv_collectors.push(Box::new(SecurityHubCollector::new(&config)));
    }
    if wants("config-rules") {
        csv_collectors.push(Box::new(ConfigRulesCollector::new(&config)));
    }
    if wants("security-groups") {
        csv_collectors.push(Box::new(SecurityGroupCollector::new(&config)));
    }
    if wants("route-tables") {
        csv_collectors.push(Box::new(RouteTableCollector::new(&config)));
    }
    if wants("ec2-instances") {
        csv_collectors.push(Box::new(Ec2InstanceCollector::new(&config)));
    }
    if wants("asg") {
        csv_collectors.push(Box::new(AutoScalingCollector::new(&config)));
    }
    if wants("kms") {
        csv_collectors.push(Box::new(KmsKeyCollector::new(&config)));
    }
    if wants("secrets") {
        csv_collectors.push(Box::new(SecretsManagerCollector::new(&config)));
    }
    if wants("s3-config") {
        csv_collectors.push(Box::new(S3BucketConfigCollector::new(&config)));
    }
    if wants("cw-alarms") {
        csv_collectors.push(Box::new(CloudWatchAlarmCollector::new(&config)));
    }
    if wants("cw-log-groups") {
        csv_collectors.push(Box::new(CloudWatchLogGroupCollector::new(&config)));
    }
    if wants("api-gateway") {
        csv_collectors.push(Box::new(ApiGatewayCollector::new(&config)));
    }
    if wants("cloudfront") {
        csv_collectors.push(Box::new(CloudFrontCollector::new(&config)));
    }
    if wants("ecs") {
        csv_collectors.push(Box::new(EcsClusterCollector::new(&config)));
    }
    if wants("eks") {
        csv_collectors.push(Box::new(EksClusterCollector::new(&config)));
    }
    // IAM extended
    if wants("iam-trusts") {
        csv_collectors.push(Box::new(IamTrustsCollector::new(&config)));
    }
    if wants("access-analyzer") {
        csv_collectors.push(Box::new(AccessAnalyzerCollector::new(&config)));
    }
    if wants("scp") {
        csv_collectors.push(Box::new(OrganizationsSCPCollector::new(&config)));
    }
    // CloudTrail extended
    if wants("ct-selectors") {
        csv_collectors.push(Box::new(CloudTrailEventSelectorsCollector::new(&config)));
    }
    if wants("ct-validation") {
        csv_collectors.push(Box::new(CloudTrailLogValidationCollector::new(&config)));
    }
    if wants("ct-s3-policy") {
        csv_collectors.push(Box::new(CloudTrailS3PolicyCollector::new(&config)));
    }
    if wants("ct-changes") {
        csv_collectors.push(Box::new(CloudTrailChangeEventsCollector::new(&config)));
    }
    if wants("s3-data-events") {
        csv_collectors.push(Box::new(S3DataEventsCollector::new(&config)));
    }
    // GuardDuty extended
    if wants("guardduty-config") {
        csv_collectors.push(Box::new(GuardDutyConfigCollector::new(&config)));
    }
    if wants("guardduty-rules") {
        csv_collectors.push(Box::new(GuardDutySuppressionCollector::new(&config)));
    }
    // Security Hub extended
    if wants("sh-standards") {
        csv_collectors.push(Box::new(SecurityHubStandardsCollector::new(&config)));
    }
    // Network
    if wants("igw") {
        csv_collectors.push(Box::new(InternetGatewayCollector::new(&config)));
    }
    if wants("nat-gateways") {
        csv_collectors.push(Box::new(NatGatewayCollector::new(&config)));
    }
    if wants("public-resources") {
        csv_collectors.push(Box::new(PublicResourceCollector::new(&config)));
    }
    // EC2/SSM extended
    if wants("ec2-detailed") {
        csv_collectors.push(Box::new(Ec2DetailedCollector::new(&config)));
    }
    if wants("ssm-instances") {
        csv_collectors.push(Box::new(SsmManagedInstanceCollector::new(&config)));
    }
    if wants("ssm-patches") {
        csv_collectors.push(Box::new(SsmPatchComplianceCollector::new(&config)));
    }
    // Encryption extended
    if wants("kms-policies") {
        csv_collectors.push(Box::new(KmsKeyPolicyCollector::new(&config)));
    }
    if wants("ebs-encryption") {
        csv_collectors.push(Box::new(EbsDefaultEncryptionCollector::new(&config)));
    }
    if wants("rds-snapshots") {
        csv_collectors.push(Box::new(RdsSnapshotCollector::new(&config)));
    }
    if wants("s3-policies") {
        csv_collectors.push(Box::new(S3PoliciesCollector::new(&config)));
    }
    // Other
    if wants("macie") {
        csv_collectors.push(Box::new(MacieCollector::new(&config)));
    }
    if wants("config-history") {
        csv_collectors.push(Box::new(ConfigHistoryCollector::new(&config)));
    }
    if wants("inspector") {
        csv_collectors.push(Box::new(InspectorCollector::new(&config)));
    }
    if wants("ecr-scan") {
        csv_collectors.push(Box::new(EcrScanCollector::new(&config)));
    }
    if wants("waf-logging") {
        csv_collectors.push(Box::new(WafLoggingCollector::new(&config)));
    }
    if wants("alb-logs") {
        csv_collectors.push(Box::new(AlbLogsCollector::new(&config)));
    }
    // IAM config
    // iam-role-policies, iam-user-policies → json_inv_collectors (see above)
    if wants("iam-password-policy") {
        csv_collectors.push(Box::new(IamPasswordPolicyCollector::new(&config)));
    }
    // KMS / EBS config
    // kms-config → json_inv_collectors (see above)
    if wants("ebs-config") {
        csv_collectors.push(Box::new(EbsEncryptionConfigCollector::new(&config)));
    }
    // S3 detail
    if wants("s3-encryption") {
        csv_collectors.push(Box::new(S3EncryptionConfigCollector::new(&config)));
    }
    if wants("s3-bucket-policy") {
        csv_collectors.push(Box::new(S3BucketPolicyDetailCollector::new(&config)));
    }
    if wants("s3-public-access") {
        csv_collectors.push(Box::new(S3PublicAccessBlockCollector::new(&config)));
    }
    if wants("s3-logging-config") {
        csv_collectors.push(Box::new(S3LoggingConfigCollector::new(&config)));
    }
    // EC2 config
    if wants("sg-config") {
        csv_collectors.push(Box::new(SecurityGroupConfigCollector::new(&config)));
    }
    if wants("vpc-config") {
        csv_collectors.push(Box::new(VpcConfigCollector::new(&config)));
    }
    if wants("rt-config") {
        csv_collectors.push(Box::new(RouteTableConfigCollector::new(&config)));
    }
    if wants("ec2-config") {
        csv_collectors.push(Box::new(Ec2InstanceConfigCollector::new(&config)));
    }
    // CloudTrail config
    if wants("ct-full-config") {
        csv_collectors.push(Box::new(CloudTrailFullConfigCollector::new(&config)));
    }
    // CloudWatch config
    if wants("cw-log-config") {
        csv_collectors.push(Box::new(CwLogGroupConfigCollector::new(&config)));
    }
    if wants("metric-filter-config") {
        csv_collectors.push(Box::new(MetricFilterConfigCollector::new(&config)));
    }
    // Security service config
    if wants("gd-full-config") {
        csv_collectors.push(Box::new(GuardDutyFullConfigCollector::new(&config)));
    }
    if wants("sh-config") {
        csv_collectors.push(Box::new(SecurityHubConfigCollector::new(&config)));
    }
    if wants("config-recorder") {
        csv_collectors.push(Box::new(AwsConfigRecorderCollector::new(&config)));
    }
    // EC2 extended
    if wants("launch-templates") {
        csv_collectors.push(Box::new(LaunchTemplateCollector::new(&config)));
    }
    if wants("vpc-endpoints") {
        csv_collectors.push(Box::new(VpcEndpointCollector::new(&config)));
    }
    // SSM extended
    if wants("ssm-baselines") {
        csv_collectors.push(Box::new(SsmPatchBaselineCollector::new(&config)));
    }
    if wants("ssm-params") {
        csv_collectors.push(Box::new(SsmParameterConfigCollector::new(&config)));
    }
    if wants("time-sync") {
        csv_collectors.push(Box::new(TimeSyncConfigCollector::new(&config)));
    }
    // Inspector ECR
    if wants("inspector-ecr-images") {
        csv_collectors.push(Box::new(InspectorEcrImagesCollector::new(&config)));
    }
    // Inspector config
    if wants("inspector-config") {
        csv_collectors.push(Box::new(InspectorConfigCollector::new(&config)));
    }
    // WAF full config
    if wants("waf-config") {
        csv_collectors.push(Box::new(WafFullConfigCollector::new(&config)));
    }
    // ELB full config
    if wants("elb-full-config") {
        csv_collectors.push(Box::new(ElbFullConfigCollector::new(&config)));
    }
    // Org + account
    if wants("org-config") {
        csv_collectors.push(Box::new(OrgConfigCollector::new(&config)));
    }
    if wants("account-contacts") {
        csv_collectors.push(Box::new(AccountContactsCollector::new(&config)));
    }
    if wants("saml-providers") {
        csv_collectors.push(Box::new(SamlProviderCollector::new(&config)));
    }
    if wants("iam-account-summary") {
        csv_collectors.push(Box::new(IamAccountSummaryCollector::new(&config)));
    }
    // SNS / EventBridge
    if wants("sns-policies") {
        csv_collectors.push(Box::new(SnsTopicPoliciesCollector::new(&config)));
    }
    // eventbridge-rules → json_inv_collectors (see above)
    // Backup
    if wants("backup-plans") {
        csv_collectors.push(Box::new(BackupPlanConfigCollector::new(&config)));
    }
    if wants("backup-vaults") {
        csv_collectors.push(Box::new(BackupVaultConfigCollector::new(&config)));
    }
    if wants("rds-backup-config") {
        csv_collectors.push(Box::new(RdsBackupConfigCollector::new(&config)));
    }
    // Lambda
    if wants("lambda-config") {
        csv_collectors.push(Box::new(LambdaConfigCollector::new(&config)));
    }
    if wants("lambda-permissions") {
        csv_collectors.push(Box::new(LambdaPermissionsCollector::new(&config)));
    }
    // ECR config
    if wants("ecr-config") {
        csv_collectors.push(Box::new(EcrRepoConfigCollector::new(&config)));
    }
    // Route53
    if wants("route53-zones") {
        csv_collectors.push(Box::new(Route53ZonesCollector::new(&config)));
    }
    if wants("route53-resolver") {
        csv_collectors.push(Box::new(Route53ResolverRulesCollector::new(&config)));
    }
    // Tagging
    if wants("resource-tags") {
        csv_collectors.push(Box::new(ResourceTaggingCollector::new(&config)));
    }
    // Secrets extended
    if wants("secrets-policies") {
        csv_collectors.push(Box::new(SecretsManagerPoliciesCollector::new(&config)));
    }
    // Config timeline / compliance
    if wants("config-timeline") {
        csv_collectors.push(Box::new(ConfigResourceTimelineCollector::new(&config)));
    }
    if wants("config-compliance") {
        csv_collectors.push(Box::new(ConfigComplianceHistoryCollector::new(&config)));
    }
    if wants("config-snapshot") {
        csv_collectors.push(Box::new(ConfigSnapshotCollector::new(&config)));
    }
    // CloudTrail IAM / config changes
    // ct-config-changes → json_inv_collectors (see above)
    if wants("ct-iam-changes") {
        csv_collectors.push(Box::new(CloudTrailIamChangesCollector::new(&config)));
    }
    // CloudFormation drift
    if wants("cfn-drift") {
        csv_collectors.push(Box::new(CloudFormationDriftCollector::new(&config)));
    }
    // SSM patch detail
    if wants("ssm-patch-detail") {
        csv_collectors.push(Box::new(SsmPatchDetailCollector::new(&config)));
    }
    if wants("ssm-patch-summary") {
        csv_collectors.push(Box::new(SsmPatchSummaryCollector::new(&config)));
    }
    if wants("ssm-patch-exec") {
        csv_collectors.push(Box::new(SsmPatchExecutionCollector::new(&config)));
    }
    if wants("ssm-maint-windows") {
        csv_collectors.push(Box::new(SsmMaintenanceWindowCollector::new(&config)));
    }
    // Inspector findings history
    if wants("inspector-history") {
        csv_collectors.push(Box::new(InspectorFindingsHistoryCollector::new(&config)));
    }
    // CloudWatch alarms
    if wants("cw-config-alarms") {
        csv_collectors.push(Box::new(CloudWatchConfigAlarmsCollector::new(&config)));
    }
    // EventBridge change rules
    if wants("change-event-rules") {
        csv_collectors.push(Box::new(ChangeEventRulesCollector::new(&config)));
    }

    if json_collectors.is_empty()
        && csv_collectors.is_empty()
        && !cli.all_regions
        && cli.regions.is_none()
    {
        anyhow::bail!("No collectors selected.");
    }

    let output_dir = cli.output.clone().unwrap_or_else(|| PathBuf::from("."));

    // ── Multi-region round-robin mode ────────────────────────────────────────
    if cli.all_regions || cli.regions.is_some() {
        // Determine the target region list.
        let target_regions: Vec<String> = if let Some(explicit) = cli.regions.as_ref() {
            explicit.clone()
        } else {
            let regions = crate::aws_loader::discover_regions(&config).await;
            if regions.is_empty() {
                anyhow::bail!("--all-regions: could not discover any enabled regions");
            }
            regions
        };

        // Build the wanted name lists, honouring any --collectors filter.
        let wanted_csv: Vec<&str> = {
            // All keys that appear in both the full key space AND the wants() filter.
            let full: &[&str] = &[
                "vpc",
                "nacl",
                "waf",
                "elasticache",
                "elasticache-global",
                "efs",
                "dynamodb",
                "ebs",
                "rds-inventory",
                "cloudtrail-config",
                "sns",
                "vpc-flow-logs",
                "metric-filters",
                "s3-logging",
                "iam-certs",
                "elb",
                "elb-listeners",
                "acm",
                "iam-users",
                "iam-policies",
                "iam-access-keys",
                "guardduty",
                "securityhub",
                "config-rules",
                "security-groups",
                "route-tables",
                "ec2-instances",
                "asg",
                "kms",
                "secrets",
                "s3-config",
                "cw-alarms",
                "cw-log-groups",
                "api-gateway",
                "cloudfront",
                "ecs",
                "eks",
                "iam-trusts",
                "access-analyzer",
                "scp",
                "ct-selectors",
                "ct-validation",
                "ct-s3-policy",
                "ct-changes",
                "s3-data-events",
                "guardduty-config",
                "guardduty-rules",
                "sh-standards",
                "igw",
                "nat-gateways",
                "public-resources",
                "ec2-detailed",
                "ssm-instances",
                "ssm-patches",
                "kms-policies",
                "ebs-encryption",
                "rds-snapshots",
                "s3-policies",
                "macie",
                "config-history",
                "inspector",
                "inspector-ecr-images",
                "inspector-history",
                "ecr-scan",
                "waf-logging",
                "alb-logs",
                "iam-password-policy",
                "ebs-config",
                "s3-encryption",
                "s3-bucket-policy",
                "s3-public-access",
                "s3-logging-config",
                "sg-config",
                "vpc-config",
                "rt-config",
                "ec2-config",
                "ct-full-config",
                "cw-log-config",
                "metric-filter-config",
                "gd-full-config",
                "sh-config",
                "config-recorder",
                "launch-templates",
                "vpc-endpoints",
                "ssm-baselines",
                "ssm-params",
                "time-sync",
                "inspector-config",
                "waf-config",
                "elb-full-config",
                "org-config",
                "account-contacts",
                "saml-providers",
                "iam-account-summary",
                "sns-policies",
                "backup-plans",
                "backup-vaults",
                "rds-backup-config",
                "lambda-config",
                "lambda-permissions",
                "ecr-config",
                "route53-zones",
                "route53-resolver",
                "resource-tags",
                "secrets-policies",
                "config-timeline",
                "config-compliance",
                "config-snapshot",
                "ct-iam-changes",
                "cfn-drift",
                "ssm-patch-detail",
                "ssm-patch-summary",
                "ssm-patch-exec",
                "ssm-maint-windows",
                "cw-config-alarms",
                "change-event-rules",
            ];
            full.iter().copied().filter(|k| wants(k)).collect()
        };
        let wanted_json_inv: Vec<&str> = [
            "iam-roles",
            "iam-role-policies",
            "iam-user-policies",
            "eventbridge-rules",
            "ct-config-changes",
            "kms-config",
        ]
        .iter()
        .copied()
        .filter(|k| wants(k))
        .collect();
        let wanted_json: Vec<&str> = ["cloudtrail", "backup", "rds"]
            .iter()
            .copied()
            .filter(|k| wants(k))
            .collect();

        // Split into global (run once) and regional (run per region).
        let global_csv: Vec<&str> = wanted_csv
            .iter()
            .copied()
            .filter(|k| GLOBAL_COLLECTOR_KEYS.contains(k))
            .collect();
        let regional_csv: Vec<&str> = wanted_csv
            .iter()
            .copied()
            .filter(|k| !GLOBAL_COLLECTOR_KEYS.contains(k))
            .collect();
        let global_json_inv: Vec<&str> = wanted_json_inv
            .iter()
            .copied()
            .filter(|k| GLOBAL_COLLECTOR_KEYS.contains(k))
            .collect();
        let regional_json_inv: Vec<&str> = wanted_json_inv
            .iter()
            .copied()
            .filter(|k| !GLOBAL_COLLECTOR_KEYS.contains(k))
            .collect();
        // JSON time-windowed collectors are all regional.

        let mr_run_id = Utc::now().format("%Y-%m-%d-%H%M%S").to_string();
        let mr_dates = Some((params.start_time.timestamp(), params.end_time.timestamp()));
        let mr_coll_start = params.start_time.format("%Y-%m-%d").to_string();
        let mr_coll_end = params.end_time.format("%Y-%m-%d").to_string();
        let mut mr_outcomes: Vec<audit_log::CollectorOutcome> = Vec::new();

        // ── Run global collectors once (into base output dir) ─────────────────
        if !global_csv.is_empty() || !global_json_inv.is_empty() {
            eprintln!("\n=== Global collectors (running once) ===");
            let global_csv_v =
                crate::runner::collector_registry::build_csv_collectors(&global_csv, &config);
            let global_inv_v = crate::runner::collector_registry::build_json_inv_collectors(
                &global_json_inv,
                &config,
            );
            mr_outcomes.extend(
                run_csv_collectors(
                    &global_csv_v,
                    &account_id,
                    &cli.region,
                    &output_dir,
                    mr_dates,
                    &mr_run_id,
                )
                .await?,
            );
            mr_outcomes.extend(
                run_json_inv_collectors(
                    &global_inv_v,
                    &account_id,
                    &cli.region,
                    &output_dir,
                    &mr_run_id,
                )
                .await?,
            );
        }

        // ── Loop through each region ──────────────────────────────────────────
        for region_name in &target_regions {
            eprintln!("\n=== Region: {} ===", region_name);

            let region_config = {
                let mut loader = aws_config::defaults(BehaviorVersion::latest())
                    .region(Region::new(region_name.clone()));
                if let Some(ref p) = cli.profile {
                    loader = loader.profile_name(p);
                }
                loader.load().await
            };

            let region_dir = output_dir.join(region_name);

            if !regional_csv.is_empty() {
                let csv_v = crate::runner::collector_registry::build_csv_collectors(
                    &regional_csv,
                    &region_config,
                );
                mr_outcomes.extend(
                    run_csv_collectors(
                        &csv_v,
                        &account_id,
                        region_name,
                        &region_dir,
                        mr_dates,
                        &mr_run_id,
                    )
                    .await?,
                );
            }
            if !regional_json_inv.is_empty() {
                let inv_v = crate::runner::collector_registry::build_json_inv_collectors(
                    &regional_json_inv,
                    &region_config,
                );
                mr_outcomes.extend(
                    run_json_inv_collectors(
                        &inv_v,
                        &account_id,
                        region_name,
                        &region_dir,
                        &mr_run_id,
                    )
                    .await?,
                );
            }
            if !wanted_json.is_empty() {
                let json_v = crate::runner::collector_registry::build_json_collectors(
                    &wanted_json,
                    &region_config,
                );
                mr_outcomes.extend(
                    run_json_collectors(&json_v, &params, region_name, &region_dir, &mr_run_id)
                        .await?,
                );
            }
        }

        // ── Write run manifest (multi-region) ─────────────────────────────────
        let mr_manifest = audit_log::RunManifest::build(
            &mr_run_id,
            &account_id,
            &cli.region,
            &mr_coll_start,
            &mr_coll_end,
            mr_outcomes,
        );
        if !cli.skip_run_manifest {
            match audit_log::write_run_manifest(&output_dir, &mr_manifest) {
                Ok(p) => eprintln!("Run manifest written: {}", p.display()),
                Err(e) => eprintln!("WARN: could not write run manifest: {e}"),
            }
        }

        // ── Write chain-of-custody (multi-region) ─────────────────────────────
        if !cli.skip_chain_of_custody {
            let identity = cli_identity.unwrap_or(audit_log::AwsIdentity {
                account_id: account_id.clone(),
                caller_arn: "unknown".to_string(),
                user_id: "unknown".to_string(),
            });
            let profile = cli.profile.as_deref().unwrap_or("default");
            let entry = audit_log::CustodyEntry::new(
                &mr_run_id,
                &cli_started_at,
                identity,
                profile,
                &cli.region,
                &mr_coll_start,
                &mr_coll_end,
                mr_manifest.summary.total_collectors,
            );
            match audit_log::write_chain_of_custody(&output_dir, &entry) {
                Ok(p) => eprintln!("Chain of custody written: {}", p.display()),
                Err(e) => eprintln!("WARN: could not write chain of custody: {e}"),
            }
        }

        let mr_timestamp = mr_run_id.clone();

        if cli.zip {
            let zip_name = format!("Evidence-{}.zip", mr_timestamp);
            let zip_path = std::path::Path::new(&zip_name);
            match crate::zip_bundle::bundle_dir(&output_dir, zip_path) {
                Ok(()) => eprintln!("Zip bundle written: {}", zip_name),
                Err(e) => eprintln!("Zip bundle failed: {e}"),
            }
        }

        if cli.sign {
            let key = match &cli.signing_key {
                Some(hex) => crate::signing::SigningKey::from_hex(hex)?,
                None => crate::signing::SigningKey::generate()?,
            };
            let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
            let files = crate::signing::collect_dir_files(&output_dir);
            match crate::signing::sign_files(&files, &mr_timestamp, &key, &cwd) {
                Ok((manifest_path, key_path)) => {
                    eprintln!("Signing manifest: {}", manifest_path.display());
                    eprintln!(
                        "Signing key file: {} (move to secure storage)",
                        key_path.display()
                    );
                    eprintln!("Signing key (hex): {}", key.to_hex());
                }
                Err(e) => eprintln!("Signing failed: {e}"),
            }
        }

        return Ok(());
    }

    // ── Single-region path (existing behaviour) ──────────────────────────────
    let timestamp = Utc::now().format("%Y-%m-%d-%H%M%S").to_string();
    let sr_dates = Some((params.start_time.timestamp(), params.end_time.timestamp()));
    let sr_coll_start = params.start_time.format("%Y-%m-%d").to_string();
    let sr_coll_end = params.end_time.format("%Y-%m-%d").to_string();
    let mut sr_outcomes: Vec<audit_log::CollectorOutcome> = Vec::new();

    sr_outcomes.extend(
        run_json_collectors(
            &json_collectors,
            &params,
            &cli.region,
            &output_dir,
            &timestamp,
        )
        .await?,
    );
    sr_outcomes.extend(
        run_json_inv_collectors(
            &json_inv_collectors,
            &account_id,
            &cli.region,
            &output_dir,
            &timestamp,
        )
        .await?,
    );
    sr_outcomes.extend(
        run_csv_collectors(
            &csv_collectors,
            &account_id,
            &cli.region,
            &output_dir,
            sr_dates,
            &timestamp,
        )
        .await?,
    );

    // ── Write run manifest (single-region) ───────────────────────────────────
    let sr_manifest = audit_log::RunManifest::build(
        &timestamp,
        &account_id,
        &cli.region,
        &sr_coll_start,
        &sr_coll_end,
        sr_outcomes,
    );
    if !cli.skip_run_manifest {
        match audit_log::write_run_manifest(&output_dir, &sr_manifest) {
            Ok(p) => eprintln!("Run manifest written: {}", p.display()),
            Err(e) => eprintln!("WARN: could not write run manifest: {e}"),
        }
    }

    // ── Write chain-of-custody (single-region) ───────────────────────────────
    if !cli.skip_chain_of_custody {
        let identity = cli_identity.unwrap_or(audit_log::AwsIdentity {
            account_id: account_id.clone(),
            caller_arn: "unknown".to_string(),
            user_id: "unknown".to_string(),
        });
        let profile = cli.profile.as_deref().unwrap_or("default");
        let entry = audit_log::CustodyEntry::new(
            &timestamp,
            &cli_started_at,
            identity,
            profile,
            &cli.region,
            &sr_coll_start,
            &sr_coll_end,
            sr_manifest.summary.total_collectors,
        );
        match audit_log::write_chain_of_custody(&output_dir, &entry) {
            Ok(p) => eprintln!("Chain of custody written: {}", p.display()),
            Err(e) => eprintln!("WARN: could not write chain of custody: {e}"),
        }
    }

    if cli.zip {
        let zip_name = format!("Evidence-{}.zip", timestamp);
        let zip_path = std::path::Path::new(&zip_name);
        match crate::zip_bundle::bundle_dir(&output_dir, zip_path) {
            Ok(()) => eprintln!("Zip bundle written: {}", zip_name),
            Err(e) => eprintln!("Zip bundle failed: {e}"),
        }
    }

    if cli.sign {
        let key = match &cli.signing_key {
            Some(hex) => crate::signing::SigningKey::from_hex(hex)?,
            None => crate::signing::SigningKey::generate()?,
        };
        let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
        let files = crate::signing::collect_dir_files(&output_dir);
        match crate::signing::sign_files(&files, &timestamp, &key, &cwd) {
            Ok((manifest_path, key_path)) => {
                eprintln!("Signing manifest: {}", manifest_path.display());
                eprintln!(
                    "Signing key file: {} (move to secure storage)",
                    key_path.display()
                );
                eprintln!("Signing key (hex): {}", key.to_hex());
            }
            Err(e) => eprintln!("Signing failed: {e}"),
        }
    }
    Ok(())
}
