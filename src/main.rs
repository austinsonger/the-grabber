mod access_analyzer;
mod acm;
mod alb_logs;
mod apigateway;
mod autoscaling;
mod backup;
mod cloudfront;
mod cloudtrail;
mod cloudtrail_config;
mod cloudtrail_details;
mod cloudtrail_inventory;
mod cloudtrail_s3;
mod cloudwatch;
mod cloudwatch_config;
mod cloudwatch_resources;
mod config_history;
mod config_rules;
mod dynamodb;
mod ebs;
mod ec2_config;
mod ec2_detailed;
mod ec2_inventory;
mod ecr;
mod ecs;
mod eks;
mod elasticache;
mod efs;
mod elb;
mod evidence;
mod guardduty;
mod guardduty_config;
mod iam_certs;
mod iam_inventory;
mod iam_policies;
mod iam_trusts;
mod inspector;
mod kms;
mod kms_config;
mod kms_policies;
mod macie;
mod network_gateways;
mod organizations;
mod public_resources;
mod rds;
mod rds_inventory;
mod rds_snapshots;
mod s3_config;
mod s3_detail;
mod s3_inventory;
mod s3_policies;
mod secretsmanager;
mod securityhub;
mod securityhub_standards;
mod security_svc_config;
mod sns;
mod ssm;
mod tui;
mod vpc;
mod vpcflowlogs;
mod waf;
mod waf_logging;
mod account_config;
mod backup_config;
mod ecr_config;
mod elb_config;
mod inspector_config;
mod lambda_config;
mod launch_templates;
mod org_config;
mod route53_config;
mod secrets_extended;
mod sns_eventbridge;
mod ssm_extended;
mod tagging_config;
mod vpc_endpoints;
mod waf_full_config;
mod cloudformation_drift;
mod cloudtrail_iam;
mod cloudwatch_alarms;
mod config_timeline;
mod inspector_history;
mod ssm_patch_detail;

use std::path::PathBuf;

use anyhow::{Context, Result};
use aws_config::BehaviorVersion;
use aws_config::Region;
use chrono::{NaiveDate, Utc};
use clap::Parser;
use tokio::sync::mpsc;

use crate::access_analyzer::AccessAnalyzerCollector;
use crate::acm::AcmCertCollector;
use crate::alb_logs::AlbLogsCollector;
use crate::apigateway::ApiGatewayCollector;
use crate::autoscaling::AutoScalingCollector;
use crate::backup::BackupCollector;
use crate::cloudfront::CloudFrontCollector;
use crate::cloudtrail::CloudTrailCollector;
use crate::cloudtrail_details::{
    CloudTrailChangeEventsCollector, CloudTrailEventSelectorsCollector,
    CloudTrailLogValidationCollector, CloudTrailS3PolicyCollector, S3DataEventsCollector,
};
use crate::cloudtrail_inventory::CloudTrailInventoryCollector;
use crate::cloudtrail_s3::{CloudTrailS3Collector, CloudTrailS3Config};
use crate::cloudwatch::MetricFilterAlarmCollector;
use crate::cloudwatch_resources::{CloudWatchAlarmCollector, CloudWatchLogGroupCollector};
use crate::config_history::ConfigHistoryCollector;
use crate::config_rules::ConfigRulesCollector;
use crate::dynamodb::DynamoDbCollector;
use crate::ebs::EbsCollector;
use crate::ec2_detailed::Ec2DetailedCollector;
use crate::ec2_inventory::{Ec2InstanceCollector, RouteTableCollector, SecurityGroupCollector};
use crate::ecr::EcrScanCollector;
use crate::ecs::EcsClusterCollector;
use crate::eks::EksClusterCollector;
use crate::elasticache::{ElastiCacheCollector, ElastiCacheGlobalCollector};
use crate::efs::EfsCollector;
use crate::elb::{LoadBalancerCollector, LoadBalancerListenerCollector};
use crate::guardduty::GuardDutyCollector;
use crate::guardduty_config::{GuardDutyConfigCollector, GuardDutySuppressionCollector};
use crate::iam_certs::IamCertCollector;
use crate::iam_inventory::{IamAccessKeyCollector, IamPolicyCollector, IamRoleCollector, IamUserCollector};
use crate::iam_trusts::IamTrustsCollector;
use crate::inspector::InspectorCollector;
use crate::kms::KmsKeyCollector;
use crate::kms_policies::{EbsDefaultEncryptionCollector, KmsKeyPolicyCollector};
use crate::macie::MacieCollector;
use crate::network_gateways::{InternetGatewayCollector, NatGatewayCollector};
use crate::organizations::OrganizationsSCPCollector;
use crate::public_resources::PublicResourceCollector;
use crate::rds::RdsCollector;
use crate::rds_inventory::RdsInventoryCollector;
use crate::rds_snapshots::RdsSnapshotCollector;
use crate::s3_config::S3BucketConfigCollector;
use crate::s3_inventory::S3BucketLoggingCollector;
use crate::s3_policies::S3PoliciesCollector;
use crate::secretsmanager::SecretsManagerCollector;
use crate::securityhub::SecurityHubCollector;
use crate::securityhub_standards::SecurityHubStandardsCollector;
use crate::sns::SnsSubscriptionCollector;
use crate::ssm::{SsmManagedInstanceCollector, SsmPatchComplianceCollector};
use crate::vpcflowlogs::VpcFlowLogCollector;
use crate::waf_logging::WafLoggingCollector;
use crate::cloudtrail_config::CloudTrailFullConfigCollector;
use crate::cloudwatch_config::{CwLogGroupConfigCollector, MetricFilterConfigCollector};
use crate::ec2_config::{Ec2InstanceConfigCollector, RouteTableConfigCollector, SecurityGroupConfigCollector, VpcConfigCollector};
use crate::iam_policies::{IamPasswordPolicyCollector, IamRolePoliciesCollector, IamUserPoliciesCollector};
use crate::kms_config::{EbsEncryptionConfigCollector, KmsKeyConfigCollector};
use crate::s3_detail::{S3BucketPolicyDetailCollector, S3EncryptionConfigCollector, S3LoggingConfigCollector, S3PublicAccessBlockCollector};
use crate::security_svc_config::{AwsConfigRecorderCollector, GuardDutyFullConfigCollector, SecurityHubConfigCollector};
use crate::account_config::{AccountContactsCollector, IamAccountSummaryCollector, SamlProviderCollector};
use crate::backup_config::{BackupPlanConfigCollector, BackupVaultConfigCollector, RdsBackupConfigCollector};
use crate::ecr_config::EcrRepoConfigCollector;
use crate::elb_config::ElbFullConfigCollector;
use crate::inspector_config::InspectorConfigCollector;
use crate::lambda_config::{LambdaConfigCollector, LambdaPermissionsCollector};
use crate::launch_templates::LaunchTemplateCollector;
use crate::org_config::OrgConfigCollector;
use crate::route53_config::{Route53ResolverRulesCollector, Route53ZonesCollector};
use crate::secrets_extended::SecretsManagerPoliciesCollector;
use crate::sns_eventbridge::{EventBridgeRulesCollector, SnsTopicPoliciesCollector};
use crate::ssm_extended::{SsmParameterConfigCollector, SsmPatchBaselineCollector, TimeSyncConfigCollector};
use crate::tagging_config::ResourceTaggingCollector;
use crate::vpc_endpoints::VpcEndpointCollector;
use crate::waf_full_config::WafFullConfigCollector;
use crate::cloudformation_drift::CloudFormationDriftCollector;
use crate::cloudtrail_iam::{CloudTrailConfigChangesCollector, CloudTrailIamChangesCollector};
use crate::cloudwatch_alarms::CloudWatchConfigAlarmsCollector;
use crate::config_timeline::{ConfigComplianceHistoryCollector, ConfigResourceTimelineCollector, ConfigSnapshotCollector};
use crate::inspector_history::InspectorFindingsHistoryCollector;
use crate::sns_eventbridge::ChangeEventRulesCollector;
use crate::ssm_patch_detail::{SsmMaintenanceWindowCollector, SsmPatchDetailCollector, SsmPatchExecutionCollector, SsmPatchSummaryCollector};
use crate::evidence::{
    CollectParams, CsvCollector, EvidenceCollector, EvidenceReport, ReportMetadata,
};
use crate::tui::{
    App, CollectorState, CollectorStatus, Progress,
    read_aws_profiles, restore_terminal, run as run_tui, setup_terminal,
};
use crate::vpc::{NetworkAclCollector, VpcCollector};
use crate::waf::WafCollector;

// ---------------------------------------------------------------------------
// CLI  (all fields optional — omitting --start-date launches the TUI)
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(
    name = "evidence",
    about = "Collect AWS compliance evidence — run with no args for interactive TUI"
)]
struct Cli {
    /// Start date (inclusive), YYYY-MM-DD.  Omit to launch the interactive TUI.
    #[arg(long)]
    start_date: Option<String>,

    /// End date (inclusive), YYYY-MM-DD
    #[arg(long)]
    end_date: Option<String>,

    /// AWS region
    #[arg(long, default_value = "us-east-1")]
    region: String,

    /// AWS named profile (overrides AWS_PROFILE)
    #[arg(long)]
    profile: Option<String>,

    /// Output file path (default: stdout)
    #[arg(long, short)]
    output: Option<PathBuf>,

    /// Optional filter
    #[arg(long)]
    filter: Option<String>,

    /// Include raw event JSON in each record
    #[arg(long, default_value_t = false)]
    include_raw: bool,

    /// Collectors to run (default: cloudtrail,backup,rds). Comma-separated.
    /// Available: cloudtrail, backup, rds, s3
    #[arg(long, value_delimiter = ',')]
    collectors: Option<Vec<String>>,

    // ------- S3 collector options -------

    /// S3 bucket containing CloudTrail logs (required for the s3 collector)
    #[arg(long)]
    s3_bucket: Option<String>,

    /// Key prefix before "AWSLogs/" (e.g. "management")
    #[arg(long, default_value = "")]
    s3_prefix: String,

    /// AWS profile for S3 access (cross-account bucket)
    #[arg(long)]
    s3_profile: Option<String>,

    /// Additional account IDs to scan in S3 logs (comma-separated)
    #[arg(long, value_delimiter = ',')]
    s3_accounts: Option<Vec<String>>,

    /// Additional regions to scan in S3 logs (comma-separated)
    #[arg(long, value_delimiter = ',')]
    s3_regions: Option<Vec<String>>,
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() -> Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .thread_stack_size(8 * 1024 * 1024) // 8 MB — prevents stack overflow with 120+ collectors
        .enable_all()
        .build()?
        .block_on(async_main())
}

async fn async_main() -> Result<()> {
    let cli = Cli::parse();

    if cli.start_date.is_none() {
        // ── Interactive TUI mode ─────────────────────────────────────────
        let profiles = read_aws_profiles();
        let app = App::new(profiles);

        match run_tui(app)? {
            None => {
                // User quit before confirming
                println!("No collection started.");
                return Ok(());
            }
            Some(mut app) => {
                // Build params from what the user configured in the TUI.
                let start = NaiveDate::parse_from_str(&app.start_date.value, "%Y-%m-%d")
                    .context("invalid start date from TUI")?
                    .and_hms_opt(0, 0, 0).unwrap().and_utc();
                let end = NaiveDate::parse_from_str(&app.end_date.value, "%Y-%m-%d")
                    .context("invalid end date from TUI")?
                    .and_hms_opt(23, 59, 59).unwrap().and_utc();

                let mut loader = aws_config::defaults(BehaviorVersion::latest())
                    .region(Region::new(app.selected_region()));
                let profile = app.selected_profile().to_string();
                if !profile.is_empty() && profile != "default" {
                    loader = loader.profile_name(&profile);
                }
                let config = loader.load().await;

                let account_id = print_identity(&config).await;

                let params = CollectParams {
                    start_time: start,
                    end_time: end,
                    filter: if app.filter_input.value.is_empty() {
                        None
                    } else {
                        Some(app.filter_input.value.clone())
                    },
                    include_raw: app.include_raw,
                };

                let collectors = app.selected_collectors();
                let output_path = if app.output_dir.value.is_empty() {
                    None
                } else {
                    Some(PathBuf::from(&app.output_dir.value))
                };

                // Set up progress channel so the TUI running screen gets live updates.
                let (tx, rx) = mpsc::unbounded_channel::<Progress>();
                app.progress_rx = Some(rx);

                // Initialise status entries.
                app.collector_statuses = collectors
                    .iter()
                    .map(|name| CollectorStatus {
                        name: name.clone(),
                        state: CollectorState::Waiting,
                    })
                    .collect();

                // Restart the TUI to show the Running screen.
                let mut terminal = setup_terminal()?;
                let run_result = run_tui_running(
                    &mut terminal,
                    &mut app,
                    &config,
                    &params,
                    &collectors,
                    output_path.clone(),
                    account_id,
                    tx,
                )
                .await;
                restore_terminal(&mut terminal)?;
                return run_result;
            }
        }
    }

    // ── Non-interactive (CLI flags) mode ─────────────────────────────────
    let start_str = cli.start_date.as_deref().unwrap();
    let end_str   = cli.end_date.as_deref()
        .context("--end-date is required when --start-date is provided")?;

    let start = NaiveDate::parse_from_str(start_str, "%Y-%m-%d")
        .context("Invalid --start-date")?
        .and_hms_opt(0, 0, 0).unwrap().and_utc();
    let end = NaiveDate::parse_from_str(end_str, "%Y-%m-%d")
        .context("Invalid --end-date")?
        .and_hms_opt(23, 59, 59).unwrap().and_utc();

    let mut loader = aws_config::defaults(BehaviorVersion::latest())
        .region(Region::new(cli.region.clone()));
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

    let account_id = print_identity(&config).await;

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
    if wants("cloudtrail") { json_collectors.push(Box::new(CloudTrailCollector::new(&config))); }
    if wants("backup")     { json_collectors.push(Box::new(BackupCollector::new(&config))); }
    if wants("rds")        { json_collectors.push(Box::new(RdsCollector::new(&config))); }
    if wants("s3") && !run_all {
        match build_s3_collector_from_cli(&cli, &s3_config, &account_id) {
            Ok(Some(c)) => json_collectors.push(Box::new(c)),
            Ok(None) => anyhow::bail!("--s3-bucket is required for the s3 collector"),
            Err(e) => eprintln!("WARN: {e:#}"),
        }
    }

    // --- CSV inventory collectors (current-state snapshots) -----------------
    let mut csv_collectors: Vec<Box<dyn CsvCollector>> = Vec::new();
    if wants("vpc")               { csv_collectors.push(Box::new(VpcCollector::new(&config))); }
    if wants("nacl")              { csv_collectors.push(Box::new(NetworkAclCollector::new(&config))); }
    if wants("waf")               { csv_collectors.push(Box::new(WafCollector::new(&config))); }
    if wants("elasticache")       { csv_collectors.push(Box::new(ElastiCacheCollector::new(&config))); }
    if wants("elasticache-global") { csv_collectors.push(Box::new(ElastiCacheGlobalCollector::new(&config))); }
    if wants("efs")               { csv_collectors.push(Box::new(EfsCollector::new(&config))); }
    if wants("dynamodb")          { csv_collectors.push(Box::new(DynamoDbCollector::new(&config))); }
    if wants("ebs")               { csv_collectors.push(Box::new(EbsCollector::new(&config))); }
    if wants("rds-inventory")     { csv_collectors.push(Box::new(RdsInventoryCollector::new(&config))); }
    if wants("cloudtrail-config") { csv_collectors.push(Box::new(CloudTrailInventoryCollector::new(&config))); }
    if wants("sns")               { csv_collectors.push(Box::new(SnsSubscriptionCollector::new(&config))); }
    if wants("vpc-flow-logs")     { csv_collectors.push(Box::new(VpcFlowLogCollector::new(&config))); }
    if wants("metric-filters")    { csv_collectors.push(Box::new(MetricFilterAlarmCollector::new(&config))); }
    if wants("s3-logging")        { csv_collectors.push(Box::new(S3BucketLoggingCollector::new(&config))); }
    if wants("iam-certs")         { csv_collectors.push(Box::new(IamCertCollector::new(&config))); }
    if wants("elb")               { csv_collectors.push(Box::new(LoadBalancerCollector::new(&config))); }
    if wants("elb-listeners")     { csv_collectors.push(Box::new(LoadBalancerListenerCollector::new(&config))); }
    if wants("acm")               { csv_collectors.push(Box::new(AcmCertCollector::new(&config))); }
    if wants("iam-users")         { csv_collectors.push(Box::new(IamUserCollector::new(&config))); }
    if wants("iam-roles")         { csv_collectors.push(Box::new(IamRoleCollector::new(&config))); }
    if wants("iam-policies")      { csv_collectors.push(Box::new(IamPolicyCollector::new(&config))); }
    if wants("iam-access-keys")   { csv_collectors.push(Box::new(IamAccessKeyCollector::new(&config))); }
    if wants("guardduty")         { csv_collectors.push(Box::new(GuardDutyCollector::new(&config))); }
    if wants("securityhub")       { csv_collectors.push(Box::new(SecurityHubCollector::new(&config))); }
    if wants("config-rules")      { csv_collectors.push(Box::new(ConfigRulesCollector::new(&config))); }
    if wants("security-groups")   { csv_collectors.push(Box::new(SecurityGroupCollector::new(&config))); }
    if wants("route-tables")      { csv_collectors.push(Box::new(RouteTableCollector::new(&config))); }
    if wants("ec2-instances")     { csv_collectors.push(Box::new(Ec2InstanceCollector::new(&config))); }
    if wants("asg")               { csv_collectors.push(Box::new(AutoScalingCollector::new(&config))); }
    if wants("kms")               { csv_collectors.push(Box::new(KmsKeyCollector::new(&config))); }
    if wants("secrets")           { csv_collectors.push(Box::new(SecretsManagerCollector::new(&config))); }
    if wants("s3-config")         { csv_collectors.push(Box::new(S3BucketConfigCollector::new(&config))); }
    if wants("cw-alarms")         { csv_collectors.push(Box::new(CloudWatchAlarmCollector::new(&config))); }
    if wants("cw-log-groups")     { csv_collectors.push(Box::new(CloudWatchLogGroupCollector::new(&config))); }
    if wants("api-gateway")       { csv_collectors.push(Box::new(ApiGatewayCollector::new(&config))); }
    if wants("cloudfront")        { csv_collectors.push(Box::new(CloudFrontCollector::new(&config))); }
    if wants("ecs")               { csv_collectors.push(Box::new(EcsClusterCollector::new(&config))); }
    if wants("eks")               { csv_collectors.push(Box::new(EksClusterCollector::new(&config))); }
    // IAM extended
    if wants("iam-trusts")        { csv_collectors.push(Box::new(IamTrustsCollector::new(&config))); }
    if wants("access-analyzer")   { csv_collectors.push(Box::new(AccessAnalyzerCollector::new(&config))); }
    if wants("scp")               { csv_collectors.push(Box::new(OrganizationsSCPCollector::new(&config))); }
    // CloudTrail extended
    if wants("ct-selectors")      { csv_collectors.push(Box::new(CloudTrailEventSelectorsCollector::new(&config))); }
    if wants("ct-validation")     { csv_collectors.push(Box::new(CloudTrailLogValidationCollector::new(&config))); }
    if wants("ct-s3-policy")      { csv_collectors.push(Box::new(CloudTrailS3PolicyCollector::new(&config))); }
    if wants("ct-changes")        { csv_collectors.push(Box::new(CloudTrailChangeEventsCollector::new(&config))); }
    if wants("s3-data-events")    { csv_collectors.push(Box::new(S3DataEventsCollector::new(&config))); }
    // GuardDuty extended
    if wants("guardduty-config")  { csv_collectors.push(Box::new(GuardDutyConfigCollector::new(&config))); }
    if wants("guardduty-rules")   { csv_collectors.push(Box::new(GuardDutySuppressionCollector::new(&config))); }
    // Security Hub extended
    if wants("sh-standards")      { csv_collectors.push(Box::new(SecurityHubStandardsCollector::new(&config))); }
    // Network
    if wants("igw")               { csv_collectors.push(Box::new(InternetGatewayCollector::new(&config))); }
    if wants("nat-gateways")      { csv_collectors.push(Box::new(NatGatewayCollector::new(&config))); }
    if wants("public-resources")  { csv_collectors.push(Box::new(PublicResourceCollector::new(&config))); }
    // EC2/SSM extended
    if wants("ec2-detailed")      { csv_collectors.push(Box::new(Ec2DetailedCollector::new(&config))); }
    if wants("ssm-instances")     { csv_collectors.push(Box::new(SsmManagedInstanceCollector::new(&config))); }
    if wants("ssm-patches")       { csv_collectors.push(Box::new(SsmPatchComplianceCollector::new(&config))); }
    // Encryption extended
    if wants("kms-policies")      { csv_collectors.push(Box::new(KmsKeyPolicyCollector::new(&config))); }
    if wants("ebs-encryption")    { csv_collectors.push(Box::new(EbsDefaultEncryptionCollector::new(&config))); }
    if wants("rds-snapshots")     { csv_collectors.push(Box::new(RdsSnapshotCollector::new(&config))); }
    if wants("s3-policies")       { csv_collectors.push(Box::new(S3PoliciesCollector::new(&config))); }
    // Other
    if wants("macie")             { csv_collectors.push(Box::new(MacieCollector::new(&config))); }
    if wants("config-history")    { csv_collectors.push(Box::new(ConfigHistoryCollector::new(&config))); }
    if wants("inspector")         { csv_collectors.push(Box::new(InspectorCollector::new(&config))); }
    if wants("ecr-scan")          { csv_collectors.push(Box::new(EcrScanCollector::new(&config))); }
    if wants("waf-logging")       { csv_collectors.push(Box::new(WafLoggingCollector::new(&config))); }
    if wants("alb-logs")          { csv_collectors.push(Box::new(AlbLogsCollector::new(&config))); }
    // IAM config
    if wants("iam-role-policies")  { csv_collectors.push(Box::new(IamRolePoliciesCollector::new(&config))); }
    if wants("iam-user-policies")  { csv_collectors.push(Box::new(IamUserPoliciesCollector::new(&config))); }
    if wants("iam-password-policy"){ csv_collectors.push(Box::new(IamPasswordPolicyCollector::new(&config))); }
    // KMS / EBS config
    if wants("kms-config")         { csv_collectors.push(Box::new(KmsKeyConfigCollector::new(&config))); }
    if wants("ebs-config")         { csv_collectors.push(Box::new(EbsEncryptionConfigCollector::new(&config))); }
    // S3 detail
    if wants("s3-encryption")      { csv_collectors.push(Box::new(S3EncryptionConfigCollector::new(&config))); }
    if wants("s3-bucket-policy")   { csv_collectors.push(Box::new(S3BucketPolicyDetailCollector::new(&config))); }
    if wants("s3-public-access")   { csv_collectors.push(Box::new(S3PublicAccessBlockCollector::new(&config))); }
    if wants("s3-logging-config")  { csv_collectors.push(Box::new(S3LoggingConfigCollector::new(&config))); }
    // EC2 config
    if wants("sg-config")          { csv_collectors.push(Box::new(SecurityGroupConfigCollector::new(&config))); }
    if wants("vpc-config")         { csv_collectors.push(Box::new(VpcConfigCollector::new(&config))); }
    if wants("rt-config")          { csv_collectors.push(Box::new(RouteTableConfigCollector::new(&config))); }
    if wants("ec2-config")         { csv_collectors.push(Box::new(Ec2InstanceConfigCollector::new(&config))); }
    // CloudTrail config
    if wants("ct-full-config")     { csv_collectors.push(Box::new(CloudTrailFullConfigCollector::new(&config))); }
    // CloudWatch config
    if wants("cw-log-config")      { csv_collectors.push(Box::new(CwLogGroupConfigCollector::new(&config))); }
    if wants("metric-filter-config"){ csv_collectors.push(Box::new(MetricFilterConfigCollector::new(&config))); }
    // Security service config
    if wants("gd-full-config")     { csv_collectors.push(Box::new(GuardDutyFullConfigCollector::new(&config))); }
    if wants("sh-config")          { csv_collectors.push(Box::new(SecurityHubConfigCollector::new(&config))); }
    if wants("config-recorder")    { csv_collectors.push(Box::new(AwsConfigRecorderCollector::new(&config))); }
    // EC2 extended
    if wants("launch-templates")   { csv_collectors.push(Box::new(LaunchTemplateCollector::new(&config))); }
    if wants("vpc-endpoints")      { csv_collectors.push(Box::new(VpcEndpointCollector::new(&config))); }
    // SSM extended
    if wants("ssm-baselines")      { csv_collectors.push(Box::new(SsmPatchBaselineCollector::new(&config))); }
    if wants("ssm-params")         { csv_collectors.push(Box::new(SsmParameterConfigCollector::new(&config))); }
    if wants("time-sync")          { csv_collectors.push(Box::new(TimeSyncConfigCollector::new(&config))); }
    // Inspector config
    if wants("inspector-config")   { csv_collectors.push(Box::new(InspectorConfigCollector::new(&config))); }
    // WAF full config
    if wants("waf-config")         { csv_collectors.push(Box::new(WafFullConfigCollector::new(&config))); }
    // ELB full config
    if wants("elb-full-config")    { csv_collectors.push(Box::new(ElbFullConfigCollector::new(&config))); }
    // Org + account
    if wants("org-config")         { csv_collectors.push(Box::new(OrgConfigCollector::new(&config))); }
    if wants("account-contacts")   { csv_collectors.push(Box::new(AccountContactsCollector::new(&config))); }
    if wants("saml-providers")     { csv_collectors.push(Box::new(SamlProviderCollector::new(&config))); }
    if wants("iam-account-summary"){ csv_collectors.push(Box::new(IamAccountSummaryCollector::new(&config))); }
    // SNS / EventBridge
    if wants("sns-policies")       { csv_collectors.push(Box::new(SnsTopicPoliciesCollector::new(&config))); }
    if wants("eventbridge-rules")  { csv_collectors.push(Box::new(EventBridgeRulesCollector::new(&config))); }
    // Backup
    if wants("backup-plans")       { csv_collectors.push(Box::new(BackupPlanConfigCollector::new(&config))); }
    if wants("backup-vaults")      { csv_collectors.push(Box::new(BackupVaultConfigCollector::new(&config))); }
    if wants("rds-backup-config")  { csv_collectors.push(Box::new(RdsBackupConfigCollector::new(&config))); }
    // Lambda
    if wants("lambda-config")      { csv_collectors.push(Box::new(LambdaConfigCollector::new(&config))); }
    if wants("lambda-permissions") { csv_collectors.push(Box::new(LambdaPermissionsCollector::new(&config))); }
    // ECR config
    if wants("ecr-config")         { csv_collectors.push(Box::new(EcrRepoConfigCollector::new(&config))); }
    // Route53
    if wants("route53-zones")      { csv_collectors.push(Box::new(Route53ZonesCollector::new(&config))); }
    if wants("route53-resolver")   { csv_collectors.push(Box::new(Route53ResolverRulesCollector::new(&config))); }
    // Tagging
    if wants("resource-tags")      { csv_collectors.push(Box::new(ResourceTaggingCollector::new(&config))); }
    // Secrets extended
    if wants("secrets-policies")   { csv_collectors.push(Box::new(SecretsManagerPoliciesCollector::new(&config))); }
    // Config timeline / compliance
    if wants("config-timeline")    { csv_collectors.push(Box::new(ConfigResourceTimelineCollector::new(&config))); }
    if wants("config-compliance")  { csv_collectors.push(Box::new(ConfigComplianceHistoryCollector::new(&config))); }
    if wants("config-snapshot")    { csv_collectors.push(Box::new(ConfigSnapshotCollector::new(&config))); }
    // CloudTrail IAM / config changes
    if wants("ct-config-changes")  { csv_collectors.push(Box::new(CloudTrailConfigChangesCollector::new(&config))); }
    if wants("ct-iam-changes")     { csv_collectors.push(Box::new(CloudTrailIamChangesCollector::new(&config))); }
    // CloudFormation drift
    if wants("cfn-drift")          { csv_collectors.push(Box::new(CloudFormationDriftCollector::new(&config))); }
    // SSM patch detail
    if wants("ssm-patch-detail")   { csv_collectors.push(Box::new(SsmPatchDetailCollector::new(&config))); }
    if wants("ssm-patch-summary")  { csv_collectors.push(Box::new(SsmPatchSummaryCollector::new(&config))); }
    if wants("ssm-patch-exec")     { csv_collectors.push(Box::new(SsmPatchExecutionCollector::new(&config))); }
    if wants("ssm-maint-windows")  { csv_collectors.push(Box::new(SsmMaintenanceWindowCollector::new(&config))); }
    // Inspector findings history
    if wants("inspector-history")  { csv_collectors.push(Box::new(InspectorFindingsHistoryCollector::new(&config))); }
    // CloudWatch alarms
    if wants("cw-config-alarms")   { csv_collectors.push(Box::new(CloudWatchConfigAlarmsCollector::new(&config))); }
    // EventBridge change rules
    if wants("change-event-rules") { csv_collectors.push(Box::new(ChangeEventRulesCollector::new(&config))); }

    if json_collectors.is_empty() && csv_collectors.is_empty() {
        anyhow::bail!("No collectors selected.");
    }

    let output_dir = cli.output.clone().unwrap_or_else(|| PathBuf::from("."));
    run_json_collectors(&json_collectors, &params, &cli.region, &output_dir).await?;
    run_csv_collectors(&csv_collectors, &account_id, &cli.region, &output_dir).await
}

// ---------------------------------------------------------------------------
// TUI running screen + async collection
// ---------------------------------------------------------------------------

async fn run_tui_running(
    terminal: &mut ratatui::Terminal<ratatui::backend::CrosstermBackend<std::io::Stdout>>,
    app: &mut App,
    config: &aws_config::SdkConfig,
    params: &CollectParams,
    collector_names: &[String],
    output_path: Option<PathBuf>,
    account_id: String,
    tx: mpsc::UnboundedSender<Progress>,
) -> Result<()> {
    use crossterm::event::{self, Event, KeyCode, KeyEventKind};

    // Build the actual collectors (JSON + CSV).
    let mut json_collectors: Vec<Box<dyn EvidenceCollector>> = Vec::new();
    let mut csv_collectors:  Vec<Box<dyn CsvCollector>>      = Vec::new();
    for name in collector_names {
        match name.as_str() {
            "cloudtrail"       => json_collectors.push(Box::new(CloudTrailCollector::new(config))),
            "backup"           => json_collectors.push(Box::new(BackupCollector::new(config))),
            "rds"              => json_collectors.push(Box::new(RdsCollector::new(config))),
            "vpc"              => csv_collectors.push(Box::new(VpcCollector::new(config))),
            "nacl"             => csv_collectors.push(Box::new(NetworkAclCollector::new(config))),
            "waf"              => csv_collectors.push(Box::new(WafCollector::new(config))),
            "elasticache"      => csv_collectors.push(Box::new(ElastiCacheCollector::new(config))),
            "elasticache-global" => csv_collectors.push(Box::new(ElastiCacheGlobalCollector::new(config))),
            "efs"              => csv_collectors.push(Box::new(EfsCollector::new(config))),
            "dynamodb"         => csv_collectors.push(Box::new(DynamoDbCollector::new(config))),
            "ebs"              => csv_collectors.push(Box::new(EbsCollector::new(config))),
            "rds-inventory"    => csv_collectors.push(Box::new(RdsInventoryCollector::new(config))),
            "cloudtrail-config" => csv_collectors.push(Box::new(CloudTrailInventoryCollector::new(config))),
            "sns"              => csv_collectors.push(Box::new(SnsSubscriptionCollector::new(config))),
            "vpc-flow-logs"    => csv_collectors.push(Box::new(VpcFlowLogCollector::new(config))),
            "metric-filters"   => csv_collectors.push(Box::new(MetricFilterAlarmCollector::new(config))),
            "s3-logging"       => csv_collectors.push(Box::new(S3BucketLoggingCollector::new(config))),
            "iam-certs"        => csv_collectors.push(Box::new(IamCertCollector::new(config))),
            "elb"              => csv_collectors.push(Box::new(LoadBalancerCollector::new(config))),
            "elb-listeners"    => csv_collectors.push(Box::new(LoadBalancerListenerCollector::new(config))),
            "acm"              => csv_collectors.push(Box::new(AcmCertCollector::new(config))),
            "iam-users"        => csv_collectors.push(Box::new(IamUserCollector::new(config))),
            "iam-roles"        => csv_collectors.push(Box::new(IamRoleCollector::new(config))),
            "iam-policies"     => csv_collectors.push(Box::new(IamPolicyCollector::new(config))),
            "iam-access-keys"  => csv_collectors.push(Box::new(IamAccessKeyCollector::new(config))),
            "guardduty"        => csv_collectors.push(Box::new(GuardDutyCollector::new(config))),
            "securityhub"      => csv_collectors.push(Box::new(SecurityHubCollector::new(config))),
            "config-rules"     => csv_collectors.push(Box::new(ConfigRulesCollector::new(config))),
            "security-groups"  => csv_collectors.push(Box::new(SecurityGroupCollector::new(config))),
            "route-tables"     => csv_collectors.push(Box::new(RouteTableCollector::new(config))),
            "ec2-instances"    => csv_collectors.push(Box::new(Ec2InstanceCollector::new(config))),
            "asg"              => csv_collectors.push(Box::new(AutoScalingCollector::new(config))),
            "kms"              => csv_collectors.push(Box::new(KmsKeyCollector::new(config))),
            "secrets"          => csv_collectors.push(Box::new(SecretsManagerCollector::new(config))),
            "s3-config"        => csv_collectors.push(Box::new(S3BucketConfigCollector::new(config))),
            "cw-alarms"        => csv_collectors.push(Box::new(CloudWatchAlarmCollector::new(config))),
            "cw-log-groups"    => csv_collectors.push(Box::new(CloudWatchLogGroupCollector::new(config))),
            "api-gateway"      => csv_collectors.push(Box::new(ApiGatewayCollector::new(config))),
            "cloudfront"       => csv_collectors.push(Box::new(CloudFrontCollector::new(config))),
            "ecs"              => csv_collectors.push(Box::new(EcsClusterCollector::new(config))),
            "eks"              => csv_collectors.push(Box::new(EksClusterCollector::new(config))),
            // IAM extended
            "iam-trusts"       => csv_collectors.push(Box::new(IamTrustsCollector::new(config))),
            "access-analyzer"  => csv_collectors.push(Box::new(AccessAnalyzerCollector::new(config))),
            "scp"              => csv_collectors.push(Box::new(OrganizationsSCPCollector::new(config))),
            // CloudTrail extended
            "ct-selectors"     => csv_collectors.push(Box::new(CloudTrailEventSelectorsCollector::new(config))),
            "ct-validation"    => csv_collectors.push(Box::new(CloudTrailLogValidationCollector::new(config))),
            "ct-s3-policy"     => csv_collectors.push(Box::new(CloudTrailS3PolicyCollector::new(config))),
            "ct-changes"       => csv_collectors.push(Box::new(CloudTrailChangeEventsCollector::new(config))),
            "s3-data-events"   => csv_collectors.push(Box::new(S3DataEventsCollector::new(config))),
            // GuardDuty extended
            "guardduty-config" => csv_collectors.push(Box::new(GuardDutyConfigCollector::new(config))),
            "guardduty-rules"  => csv_collectors.push(Box::new(GuardDutySuppressionCollector::new(config))),
            // Security Hub extended
            "sh-standards"     => csv_collectors.push(Box::new(SecurityHubStandardsCollector::new(config))),
            // Network
            "igw"              => csv_collectors.push(Box::new(InternetGatewayCollector::new(config))),
            "nat-gateways"     => csv_collectors.push(Box::new(NatGatewayCollector::new(config))),
            "public-resources" => csv_collectors.push(Box::new(PublicResourceCollector::new(config))),
            // EC2/SSM extended
            "ec2-detailed"     => csv_collectors.push(Box::new(Ec2DetailedCollector::new(config))),
            "ssm-instances"    => csv_collectors.push(Box::new(SsmManagedInstanceCollector::new(config))),
            "ssm-patches"      => csv_collectors.push(Box::new(SsmPatchComplianceCollector::new(config))),
            // Encryption extended
            "kms-policies"     => csv_collectors.push(Box::new(KmsKeyPolicyCollector::new(config))),
            "ebs-encryption"   => csv_collectors.push(Box::new(EbsDefaultEncryptionCollector::new(config))),
            "rds-snapshots"    => csv_collectors.push(Box::new(RdsSnapshotCollector::new(config))),
            "s3-policies"      => csv_collectors.push(Box::new(S3PoliciesCollector::new(config))),
            // Other
            "macie"            => csv_collectors.push(Box::new(MacieCollector::new(config))),
            "config-history"   => csv_collectors.push(Box::new(ConfigHistoryCollector::new(config))),
            "inspector"        => csv_collectors.push(Box::new(InspectorCollector::new(config))),
            "ecr-scan"         => csv_collectors.push(Box::new(EcrScanCollector::new(config))),
            "waf-logging"      => csv_collectors.push(Box::new(WafLoggingCollector::new(config))),
            "alb-logs"          => csv_collectors.push(Box::new(AlbLogsCollector::new(config))),
            // IAM config
            "iam-role-policies"  => csv_collectors.push(Box::new(IamRolePoliciesCollector::new(config))),
            "iam-user-policies"  => csv_collectors.push(Box::new(IamUserPoliciesCollector::new(config))),
            "iam-password-policy"=> csv_collectors.push(Box::new(IamPasswordPolicyCollector::new(config))),
            // KMS / EBS config
            "kms-config"         => csv_collectors.push(Box::new(KmsKeyConfigCollector::new(config))),
            "ebs-config"         => csv_collectors.push(Box::new(EbsEncryptionConfigCollector::new(config))),
            // S3 detail
            "s3-encryption"      => csv_collectors.push(Box::new(S3EncryptionConfigCollector::new(config))),
            "s3-bucket-policy"   => csv_collectors.push(Box::new(S3BucketPolicyDetailCollector::new(config))),
            "s3-public-access"   => csv_collectors.push(Box::new(S3PublicAccessBlockCollector::new(config))),
            "s3-logging-config"  => csv_collectors.push(Box::new(S3LoggingConfigCollector::new(config))),
            // EC2 config
            "sg-config"          => csv_collectors.push(Box::new(SecurityGroupConfigCollector::new(config))),
            "vpc-config"         => csv_collectors.push(Box::new(VpcConfigCollector::new(config))),
            "rt-config"          => csv_collectors.push(Box::new(RouteTableConfigCollector::new(config))),
            "ec2-config"         => csv_collectors.push(Box::new(Ec2InstanceConfigCollector::new(config))),
            // CloudTrail config
            "ct-full-config"     => csv_collectors.push(Box::new(CloudTrailFullConfigCollector::new(config))),
            // CloudWatch config
            "cw-log-config"      => csv_collectors.push(Box::new(CwLogGroupConfigCollector::new(config))),
            "metric-filter-config"=> csv_collectors.push(Box::new(MetricFilterConfigCollector::new(config))),
            // Security service config
            "gd-full-config"     => csv_collectors.push(Box::new(GuardDutyFullConfigCollector::new(config))),
            "sh-config"          => csv_collectors.push(Box::new(SecurityHubConfigCollector::new(config))),
            "config-recorder"    => csv_collectors.push(Box::new(AwsConfigRecorderCollector::new(config))),
            // EC2 extended
            "launch-templates"   => csv_collectors.push(Box::new(LaunchTemplateCollector::new(config))),
            "vpc-endpoints"      => csv_collectors.push(Box::new(VpcEndpointCollector::new(config))),
            // SSM extended
            "ssm-baselines"      => csv_collectors.push(Box::new(SsmPatchBaselineCollector::new(config))),
            "ssm-params"         => csv_collectors.push(Box::new(SsmParameterConfigCollector::new(config))),
            "time-sync"          => csv_collectors.push(Box::new(TimeSyncConfigCollector::new(config))),
            // Inspector config
            "inspector-config"   => csv_collectors.push(Box::new(InspectorConfigCollector::new(config))),
            // WAF / ELB full config
            "waf-config"         => csv_collectors.push(Box::new(WafFullConfigCollector::new(config))),
            "elb-full-config"    => csv_collectors.push(Box::new(ElbFullConfigCollector::new(config))),
            // Org + account
            "org-config"         => csv_collectors.push(Box::new(OrgConfigCollector::new(config))),
            "account-contacts"   => csv_collectors.push(Box::new(AccountContactsCollector::new(config))),
            "saml-providers"     => csv_collectors.push(Box::new(SamlProviderCollector::new(config))),
            "iam-account-summary"=> csv_collectors.push(Box::new(IamAccountSummaryCollector::new(config))),
            // SNS / EventBridge
            "sns-policies"       => csv_collectors.push(Box::new(SnsTopicPoliciesCollector::new(config))),
            "eventbridge-rules"  => csv_collectors.push(Box::new(EventBridgeRulesCollector::new(config))),
            // Backup
            "backup-plans"       => csv_collectors.push(Box::new(BackupPlanConfigCollector::new(config))),
            "backup-vaults"      => csv_collectors.push(Box::new(BackupVaultConfigCollector::new(config))),
            "rds-backup-config"  => csv_collectors.push(Box::new(RdsBackupConfigCollector::new(config))),
            // Lambda
            "lambda-config"      => csv_collectors.push(Box::new(LambdaConfigCollector::new(config))),
            "lambda-permissions" => csv_collectors.push(Box::new(LambdaPermissionsCollector::new(config))),
            // ECR config
            "ecr-config"         => csv_collectors.push(Box::new(EcrRepoConfigCollector::new(config))),
            // Route53
            "route53-zones"      => csv_collectors.push(Box::new(Route53ZonesCollector::new(config))),
            "route53-resolver"   => csv_collectors.push(Box::new(Route53ResolverRulesCollector::new(config))),
            // Tagging
            "resource-tags"      => csv_collectors.push(Box::new(ResourceTaggingCollector::new(config))),
            // Secrets extended
            "secrets-policies"   => csv_collectors.push(Box::new(SecretsManagerPoliciesCollector::new(config))),
            // Config timeline / compliance
            "config-timeline"    => csv_collectors.push(Box::new(ConfigResourceTimelineCollector::new(config))),
            "config-compliance"  => csv_collectors.push(Box::new(ConfigComplianceHistoryCollector::new(config))),
            "config-snapshot"    => csv_collectors.push(Box::new(ConfigSnapshotCollector::new(config))),
            // CloudTrail IAM / config changes
            "ct-config-changes"  => csv_collectors.push(Box::new(CloudTrailConfigChangesCollector::new(config))),
            "ct-iam-changes"     => csv_collectors.push(Box::new(CloudTrailIamChangesCollector::new(config))),
            // CloudFormation drift
            "cfn-drift"          => csv_collectors.push(Box::new(CloudFormationDriftCollector::new(config))),
            // SSM patch detail
            "ssm-patch-detail"   => csv_collectors.push(Box::new(SsmPatchDetailCollector::new(config))),
            "ssm-patch-summary"  => csv_collectors.push(Box::new(SsmPatchSummaryCollector::new(config))),
            "ssm-patch-exec"     => csv_collectors.push(Box::new(SsmPatchExecutionCollector::new(config))),
            "ssm-maint-windows"  => csv_collectors.push(Box::new(SsmMaintenanceWindowCollector::new(config))),
            // Inspector findings history
            "inspector-history"  => csv_collectors.push(Box::new(InspectorFindingsHistoryCollector::new(config))),
            // CloudWatch alarms
            "cw-config-alarms"   => csv_collectors.push(Box::new(CloudWatchConfigAlarmsCollector::new(config))),
            // EventBridge change rules
            "change-event-rules" => csv_collectors.push(Box::new(ChangeEventRulesCollector::new(config))),
            _ => {}
        }
    }

    // Re-key collector_statuses using display names so Progress messages match.
    app.collector_statuses = json_collectors
        .iter()
        .map(|c| CollectorStatus { name: c.name().to_string(), state: CollectorState::Waiting })
        .chain(
            csv_collectors
                .iter()
                .map(|c| CollectorStatus { name: c.name().to_string(), state: CollectorState::Waiting })
        )
        .collect();

    let params_clone = params.clone();
    let output_dir_clone = output_path.clone();
    let tx_clone = tx.clone();
    let timestamp = Utc::now().format("%Y-%m-%d-%H%M%S").to_string();
    let account_id_clone = account_id.clone();
    let region_clone = {
        // Extract region string from config.
        config.region().map(|r| r.to_string()).unwrap_or_else(|| "us-east-1".to_string())
    };

    // Spawn collection in background.
    tokio::spawn(async move {
        let mut written_files: Vec<String> = Vec::new();
        let out_dir = output_dir_clone.unwrap_or_else(|| PathBuf::from("."));

        // --- JSON collectors ------------------------------------------------
        for collector in &json_collectors {
            let _ = tx_clone.send(Progress::Started { collector: collector.name().to_string() });

            match collector.collect(&params_clone).await {
                Ok(records) => {
                    let count = records.len();
                    let _ = tx_clone.send(Progress::Done { collector: collector.name().to_string(), count });

                    let report = EvidenceReport {
                        metadata: ReportMetadata {
                            collected_at: Utc::now().to_rfc3339(),
                            region: region_clone.clone(),
                            start_date: params_clone.start_time.format("%Y-%m-%d").to_string(),
                            end_date:   params_clone.end_time.format("%Y-%m-%d").to_string(),
                            filter: params_clone.filter.clone(),
                        },
                        collector: collector.name().to_string(),
                        record_count: count,
                        records,
                    };

                    let filename = format!("{}-{}.json", collector.filename_prefix(), timestamp);
                    let path = out_dir.join(&filename);

                    if let Ok(json) = serde_json::to_string_pretty(&report) {
                        if std::fs::write(&path, json).is_ok() {
                            written_files.push(path.display().to_string());
                        }
                    }
                }
                Err(e) => {
                    let _ = tx_clone.send(Progress::Error {
                        collector: collector.name().to_string(),
                        message: e.to_string(),
                    });
                }
            }
        }

        // --- CSV collectors -------------------------------------------------
        for collector in &csv_collectors {
            let _ = tx_clone.send(Progress::Started { collector: collector.name().to_string() });

            match collector.collect_rows(&account_id_clone, &region_clone).await {
                Ok(rows) => {
                    let count = rows.len();
                    let _ = tx_clone.send(Progress::Done { collector: collector.name().to_string(), count });

                    let filename = format!(
                        "{}_{}-{}.csv",
                        account_id_clone,
                        collector.filename_prefix(),
                        timestamp
                    );
                    let path = out_dir.join(&filename);

                    match write_csv_bytes(collector.headers(), &rows) {
                        Ok(bytes) => {
                            if std::fs::write(&path, bytes).is_ok() {
                                written_files.push(path.display().to_string());
                            }
                        }
                        Err(e) => eprintln!("  WARN: CSV write failed for {}: {e:#}", collector.name()),
                    }
                }
                Err(e) => {
                    let _ = tx_clone.send(Progress::Error {
                        collector: collector.name().to_string(),
                        message: e.to_string(),
                    });
                }
            }
        }

        let _ = tx_clone.send(Progress::Finished { files: written_files });
    });

    // Drive the TUI until Results screen.
    loop {
        app.tick = app.tick.wrapping_add(1);
        app.poll_progress();

        terminal.draw(|f| tui::ui::draw(f, app))?;

        if app.screen == tui::Screen::Results {
            // Give user time to read, wait for q/Esc
            if event::poll(std::time::Duration::from_millis(100))? {
                if let Event::Key(key) = event::read()? {
                    if key.kind == KeyEventKind::Press
                        && matches!(key.code, KeyCode::Char('q') | KeyCode::Esc)
                    {
                        break;
                    }
                }
            }
        } else if event::poll(std::time::Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press && key.code == KeyCode::Char('q') {
                    break;
                }
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Shared collection + report writing (CLI path)
// ---------------------------------------------------------------------------

async fn run_json_collectors(
    collectors: &[Box<dyn EvidenceCollector>],
    params: &CollectParams,
    region: &str,
    output_dir: &PathBuf,
) -> Result<()> {
    let timestamp = Utc::now().format("%Y-%m-%d-%H%M%S").to_string();
    for collector in collectors {
        eprintln!("Collecting from {}...", collector.name());
        match collector.collect(params).await {
            Ok(records) => {
                let count = records.len();
                eprintln!("  {} returned {} records", collector.name(), count);

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
                let json = serde_json::to_string_pretty(&report)
                    .context("JSON serialization failed")?;
                std::fs::write(&path, json)
                    .with_context(|| format!("Failed to write {}", path.display()))?;
                eprintln!("  Written: {}", path.display());
            }
            Err(e) => eprintln!("  ERROR from {}: {e:#}", collector.name()),
        }
    }
    Ok(())
}

async fn run_csv_collectors(
    collectors: &[Box<dyn CsvCollector>],
    account_id: &str,
    region: &str,
    output_dir: &PathBuf,
) -> Result<()> {
    let timestamp = Utc::now().format("%Y-%m-%d-%H%M%S").to_string();
    for collector in collectors {
        eprintln!("Collecting from {}...", collector.name());
        match collector.collect_rows(account_id, region).await {
            Ok(rows) => {
                eprintln!("  {} returned {} rows", collector.name(), rows.len());
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
                eprintln!("  Written: {}", path.display());
            }
            Err(e) => eprintln!("  ERROR from {}: {e:#}", collector.name()),
        }
    }
    Ok(())
}

fn write_csv_bytes(headers: &[&str], rows: &[Vec<String>]) -> Result<Vec<u8>> {
    let mut writer = csv::Writer::from_writer(Vec::new());
    writer.write_record(headers).context("CSV write headers")?;
    for row in rows {
        writer.write_record(row).context("CSV write row")?;
    }
    writer.flush().context("CSV flush")?;
    writer.into_inner().map_err(|e| anyhow::anyhow!("CSV into_inner: {e}"))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn build_s3_collector_from_cli(
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
            if !account_ids.contains(a) { account_ids.push(a.clone()); }
        }
    }
    let mut regions = vec![cli.region.clone()];
    if let Some(ref extras) = cli.s3_regions {
        for r in extras {
            if !regions.contains(r) { regions.push(r.clone()); }
        }
    }
    Ok(Some(CloudTrailS3Collector::new(s3_config, CloudTrailS3Config {
        bucket,
        prefix: cli.s3_prefix.clone(),
        account_ids,
        regions,
    })))
}

async fn print_identity(config: &aws_config::SdkConfig) -> String {
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
