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
mod inventory_core;
mod inventory_orchestrator;
mod inventory_xlsx;
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
mod signing;
mod tui;
mod vpc;
mod vpcflowlogs;
mod zip_bundle;
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
mod poam;
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
mod inspector_ecr;
mod inspector_history;
mod ssm_patch_detail;
mod app_config;
mod audit_log;

use std::path::PathBuf;
#[cfg(unix)]
use std::os::unix::io::IntoRawFd;

use anyhow::{Context, Result};
use aws_config::BehaviorVersion;
use aws_config::Region;
use chrono::{Local, NaiveDate, Utc};
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
use crate::inspector_ecr::InspectorEcrCollector;
use crate::inspector_history::InspectorFindingsHistoryCollector;
use crate::sns_eventbridge::ChangeEventRulesCollector;
use crate::ssm_patch_detail::{SsmMaintenanceWindowCollector, SsmPatchDetailCollector, SsmPatchExecutionCollector, SsmPatchSummaryCollector};
use crate::evidence::{
    CollectParams, CsvCollector, EvidenceCollector, EvidenceReport, JsonCollector,
    JsonInventoryReport, ReportMetadata,
};
use crate::inventory_orchestrator::InventoryCollector;
use crate::tui::{
    App, CollectorState, CollectorStatus, Feature, Progress,
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

    // ------- Multi-region options -------

    /// Collect evidence from every enabled region (round-robin).
    /// Global services (IAM, S3, Route53, CloudFront, etc.) run once;
    /// regional services run once per region.
    /// Output is written to <output>/<region>/ subdirectories.
    #[arg(long, default_value_t = false)]
    all_regions: bool,

    /// Explicit list of regions to collect from (comma-separated).
    /// Implies round-robin mode.  If omitted with --all-regions, regions
    /// are auto-discovered via EC2 DescribeRegions.
    #[arg(long, value_delimiter = ',')]
    regions: Option<Vec<String>>,

    /// Bundle all output files into a dated Evidence-<timestamp>.zip after collection.
    /// The zip is placed in the current working directory.
    #[arg(long, default_value_t = false)]
    zip: bool,

    // ------- Signing options -------

    /// HMAC-SHA256-sign all output files after collection.
    /// Writes SIGNING-MANIFEST-<ts>.json and SIGNING-<ts>.key to the current directory.
    /// Move the .key file to secure storage (separate from the evidence) before sharing.
    #[arg(long, default_value_t = false)]
    sign: bool,

    /// Provide a 64-char hex signing key instead of auto-generating one.
    /// Used with --sign (CLI mode) or --verify-manifest.
    #[arg(long)]
    signing_key: Option<String>,

    /// Verify a SIGNING-MANIFEST-*.json without collecting new evidence.
    /// Requires --signing-key.
    #[arg(long)]
    verify_manifest: Option<String>,
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() -> Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .thread_stack_size(16 * 1024 * 1024)
        .enable_all()
        .build()?
        .block_on(async_main())
}

async fn async_main() -> Result<()> {
    let cli = Cli::parse();

    // ── Verify-only mode (no collection) ─────────────────────────────────────
    if let Some(ref manifest_path) = cli.verify_manifest {
        let key_hex = cli.signing_key.as_deref()
            .context("--signing-key <hex> is required with --verify-manifest")?;
        let key = signing::SigningKey::from_hex(key_hex)?;
        let report = signing::verify_manifest(std::path::Path::new(manifest_path), &key)?;
        report.print();
        return Ok(());
    }

    if cli.start_date.is_none() {
        // ── Interactive TUI mode ─────────────────────────────────────────
        let profiles = read_aws_profiles();
        let mut app = App::new(profiles);

        loop {
        app = match run_tui(app)? {
            None => {
                // User quit before confirming
                println!("No collection started.");
                return Ok(());
            }
            Some(a) => a,
        };

        if matches!(app.selected_feature, Feature::Poam) {
            let region = app.poam_selected_region();
            let year = app.poam_year_value();
            let month_name = app.poam_month_name().to_string();

            let (tx, rx) = mpsc::unbounded_channel::<Progress>();
            app.progress_rx = Some(rx);
            app.collector_statuses = vec![CollectorStatus {
                name: "POA&M Reconciliation".to_string(),
                state: CollectorState::Waiting,
            }];
            app.error_messages.clear();
            app.result_files.clear();
            app.result_zip = None;
            app.result_signing_manifest = None;
            app.result_signing_key_path = None;
            app.poam_summary = None;
            app.finished_tick = None;
            app.screen = tui::Screen::Running;

            let mut terminal = setup_terminal()?;
            terminal.draw(|f| tui::ui::draw(f, &app))?;
            let restart =
                run_tui_poam(&mut terminal, &mut app, tx, region, year, month_name).await?;
            restore_terminal(&mut terminal)?;

            if !restart {
                return Ok(());
            }
            continue;
        }
        {
                // Build params from what the user configured in the TUI.
                let start = NaiveDate::parse_from_str(&app.start_date.value, "%Y-%m-%d")
                    .context("invalid start date from TUI")?
                    .and_hms_opt(0, 0, 0).unwrap().and_utc();
                let end = NaiveDate::parse_from_str(&app.end_date.value, "%Y-%m-%d")
                    .context("invalid end date from TUI")?
                    .and_hms_opt(23, 59, 59).unwrap().and_utc();

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

                let base_output_path = if app.output_dir.value.is_empty() {
                    None
                } else {
                    Some(PathBuf::from(&app.output_dir.value))
                };

                // Build the list of accounts to iterate over.
                // Each entry: (profile, region, account_id, output_path, collector_keys)
                let mut account_runs: Vec<(String, String, String, Option<PathBuf>, Vec<String>)> = Vec::new();

                // For Inventory mode we use a sentinel key; the actual types are stored on app.
                let inventory_collector_keys = vec!["inventory".to_string()];
                let is_inventory = matches!(app.selected_feature, Feature::Inventory);

                if app.selected_accounts.is_empty() {
                    // Legacy single-account path (no TOML accounts or "Other" chosen).
                    let profile = app.selected_profile().to_string();
                    let region = app.selected_region();
                    let mut loader = aws_config::defaults(BehaviorVersion::latest())
                        .region(Region::new(region.clone()));
                    if !profile.is_empty() && profile != "default" {
                        loader = loader.profile_name(&profile);
                    }
                    let cfg = loader.load().await;
                    let account_id = print_identity(&cfg).await;
                    let collectors = if is_inventory {
                        inventory_collector_keys.clone()
                    } else {
                        app.selected_collectors()
                    };
                    account_runs.push((profile, region, account_id, base_output_path.clone(), collectors));
                } else {
                    let mut sorted: Vec<usize> = app.selected_accounts.iter().copied().collect();
                    sorted.sort();
                    let multi = sorted.len() > 1;
                    for &idx in &sorted {
                        let (profile, region, acct_output_dir, collector_keys_from_toml) =
                            app.resolve_account_settings(idx);
                        let collector_keys = if is_inventory {
                            inventory_collector_keys.clone()
                        } else {
                            collector_keys_from_toml
                        };
                        let raw_name = app.accounts[idx].name.clone();
                        let sanitized: String = raw_name.chars()
                            .map(|c| if c.is_alphanumeric() || c == '-' { c } else { '_' })
                            .collect();
                        let output_path = if let Some(dir) = acct_output_dir {
                            Some(PathBuf::from(dir))
                        } else if multi {
                            // Multi-account: isolate into subdirectory per account.
                            Some(base_output_path.clone()
                                .unwrap_or_else(|| PathBuf::from("."))
                                .join(&sanitized))
                        } else {
                            base_output_path.clone()
                        };
                        account_runs.push((profile, region, sanitized, output_path, collector_keys));
                    }
                }

                // Build AWS configs, SDK clients, and collectors BEFORE starting
                // collection.  SSO credential resolution is lazy (reads cached token
                // from ~/.aws/sso/cache), so we can safely be in TUI mode already.
                let use_all_regions = app.all_regions;
                let explicit_regions = app.explicit_regions(); // empty = use account default
                let total_accounts = account_runs.len();
                // Capture inventory asset type selection before entering the prep loop.
                let inventory_types = app.selected_inventory_types();

                // Redirect stderr to a log file BEFORE entering TUI so that any
                // AWS SDK warnings don't corrupt the alternate screen.
                let log_path = {
                    let dir = base_output_path.clone().unwrap_or_else(|| PathBuf::from("."));
                    let _ = std::fs::create_dir_all(&dir);
                    dir.join("evidence-collection.log")
                };
                let stderr_backup = redirect_stderr_to_file(&log_path);

                // Enter the TUI immediately — show Preparing screen while we build.
                app.screen = tui::Screen::Preparing;
                app.prep_total = total_accounts;
                app.prep_log.push(format!(
                    "Building AWS SDK clients for {} account(s){}…",
                    total_accounts,
                    if use_all_regions { " across all enabled regions" } else { "" },
                ));
                let mut terminal = setup_terminal()?;
                terminal.draw(|f| tui::ui::draw(f, &app))?;

                let mut prepared: Vec<AccountCollectors> = Vec::with_capacity(account_runs.len());
                for (acct_idx, (profile, region, account_id, output_path, collector_keys)) in account_runs.into_iter().enumerate() {
                    app.prep_current = acct_idx + 1;
                    app.prep_log.push(format!(
                        "  [{}/{}] {}  (profile: {})",
                        acct_idx + 1, total_accounts, account_id, profile,
                    ));
                    terminal.draw(|f| tui::ui::draw(f, &app))?;
                    // Helper closure to build a fresh config loader for this account.
                    // CRITICAL: Never reuse a config that has already been used for an
                    // AWS API call (canary, region discovery, etc.) for building
                    // collectors.  Calling an AWS API through a config "takes" the
                    // credential provider's internal state, leaving it broken when the
                    // collectors try to initialise credentials inside tokio::spawn.
                    let make_cfg = || {
                        let mut l = aws_config::defaults(BehaviorVersion::latest())
                            .region(Region::new(region.clone()));
                        if !profile.is_empty() && profile != "default" {
                            l = l.profile_name(&profile);
                        }
                        l
                    };

                    // ── Probe config (disposable) ────────────────────────────────────
                    // Used only for the canary STS check and region discovery.
                    // Explicitly NOT used for building collectors.
                    let probe_config = make_cfg().load().await;

                    // Canary: verify credentials are valid.  If the canary fails
                    // we skip this account entirely — its profile is not configured
                    // (or SSO session is not logged in) and every collector would
                    // fail anyway.
                    let sts = aws_sdk_sts::Client::new(&probe_config);
                    let (canary_ok, aws_caller_arn, aws_user_id) = match sts.get_caller_identity().send().await {
                        Ok(resp) => {
                            let arn = resp.arn().unwrap_or("unknown").to_string();
                            let uid = resp.user_id().unwrap_or("unknown").to_string();
                            app.prep_log.push(format!(
                                "  ✓ Credentials OK  account={}",
                                resp.account().unwrap_or("?"),
                            ));
                            (true, arn, uid)
                        }
                        Err(e) => {
                            app.prep_log.push(format!(
                                "  ✗ Credentials FAILED — skipping. Run: aws sso login --profile {}",
                                profile,
                            ));
                            app.prep_log.push(format!("    ({})", e));
                            (false, String::new(), String::new())
                        }
                    };
                    terminal.draw(|f| tui::ui::draw(f, &app))?;

                    if !canary_ok {
                        // Don't build any collectors for this account — it has no
                        // working credentials and every AWS API call would fail.
                        app.prep_log.push("    ↷ Account skipped.".to_string());
                        terminal.draw(|f| tui::ui::draw(f, &app))?;
                        continue;
                    }

                    let names_ref: Vec<&str> = collector_keys.iter().map(|s| s.as_str()).collect();

                    // Pre-discover or explicitly set the region list.
                    let mut discovered_regions: Vec<String> = Vec::new();
                    let mut regional_collectors = Vec::new();
                    let mut inventory_multi_region: Vec<(String, Box<dyn CsvCollector>)> = Vec::new();
                    if use_all_regions {
                        app.prep_log.push("    Discovering enabled regions…".to_string());
                        terminal.draw(|f| tui::ui::draw(f, &app))?;
                        discovered_regions = discover_regions(&probe_config).await;
                        if discovered_regions.is_empty() {
                            app.prep_log.push(format!(
                                "  ✗ Could not discover regions for {}, falling back to {}",
                                account_id, region,
                            ));
                            terminal.draw(|f| tui::ui::draw(f, &app))?;
                        }
                    } else if !explicit_regions.is_empty() {
                        // User selected specific regions — no discovery needed.
                        discovered_regions = explicit_regions.clone();
                        app.prep_log.push(format!(
                            "    Using {} explicitly selected region(s): {}",
                            discovered_regions.len(),
                            discovered_regions.join(", "),
                        ));
                        terminal.draw(|f| tui::ui::draw(f, &app))?;
                    }
                    // ── Build regional collectors from whatever list we now have ─────────
                    if !discovered_regions.is_empty() {
                        app.prep_log.push(format!(
                            "    Building collectors for {} region(s)…", discovered_regions.len()
                        ));
                        terminal.draw(|f| tui::ui::draw(f, &app))?;
                        let out_base = output_path.clone().unwrap_or_else(|| PathBuf::from("."));

                        if is_inventory {
                            // Inventory mode: one InventoryCollector per region, all rows merged
                            // into a single CSV at the end — no region subdirectories.
                            let region_total = discovered_regions.len();
                            for (ridx, region_name) in discovered_regions.iter().enumerate() {
                                if let Some(last) = app.prep_log.last_mut() {
                                    *last = format!(
                                        "    Region {:>2}/{}: {}",
                                        ridx + 1, region_total, region_name,
                                    );
                                }
                                terminal.draw(|f| tui::ui::draw(f, &app))?;
                                let rcfg = aws_config::defaults(BehaviorVersion::latest())
                                    .region(Region::new(region_name.clone()))
                                    .profile_name(if profile.is_empty() || profile == "default" { "default" } else { &profile })
                                    .load().await;
                                inventory_multi_region.push((
                                    region_name.clone(),
                                    Box::new(InventoryCollector::new(&rcfg, inventory_types.clone())) as Box<dyn CsvCollector>,
                                ));
                            }
                            if let Some(last) = app.prep_log.last_mut() {
                                *last = format!("    All {} regions ready.", region_total);
                            }
                        } else {
                            let global_csv_keys: Vec<&str> = names_ref.iter().copied().filter(|k| GLOBAL_COLLECTOR_KEYS.contains(k)).collect();
                            let regional_csv_keys: Vec<&str> = names_ref.iter().copied().filter(|k| !GLOBAL_COLLECTOR_KEYS.contains(k)).collect();
                            let global_inv_keys: Vec<&str> = ["iam-roles","iam-role-policies","iam-user-policies"].iter().copied()
                                .filter(|k| names_ref.contains(k) && GLOBAL_COLLECTOR_KEYS.contains(k)).collect();
                            let regional_inv_keys: Vec<&str> = ["eventbridge-rules","ct-config-changes","kms-config"].iter().copied()
                                .filter(|k| names_ref.contains(k)).collect();
                            let json_keys: Vec<&str> = ["cloudtrail","backup","rds"].iter().copied()
                                .filter(|k| names_ref.contains(k)).collect();
                            // Global collectors: run once from the account's base region.
                            // Route into <out_base>/<base_region>/YYYY/##-MMM so the output
                            // sits alongside per-region evidence in the date-based hierarchy.
                            if !global_csv_keys.is_empty() || !global_inv_keys.is_empty() {
                                let gcfg = make_cfg().load().await;
                                let gdir = out_base.join(&region).join(date_path_suffix());
                                regional_collectors.push((
                                    region.clone(),
                                    gdir,
                                    build_csv_collectors(&global_csv_keys, &gcfg),
                                    build_json_inv_collectors(&global_inv_keys, &gcfg),
                                    Vec::new(),
                                ));
                            }
                            // Per-region collectors: each gets a fresh config.
                            // Route into <out_base>/<region>/YYYY/##-MMM.
                            let region_total = discovered_regions.len();
                            for (ridx, region_name) in discovered_regions.iter().enumerate() {
                                if let Some(last) = app.prep_log.last_mut() {
                                    *last = format!(
                                        "    Region {:>2}/{}: {}",
                                        ridx + 1, region_total, region_name,
                                    );
                                }
                                terminal.draw(|f| tui::ui::draw(f, &app))?;
                                let rcfg = aws_config::defaults(BehaviorVersion::latest())
                                    .region(Region::new(region_name.clone()))
                                    .profile_name(if profile.is_empty() || profile == "default" { "default" } else { &profile })
                                    .load().await;
                                let rdir = out_base.join(region_name).join(date_path_suffix());
                                regional_collectors.push((
                                    region_name.clone(),
                                    rdir,
                                    build_csv_collectors(&regional_csv_keys, &rcfg),
                                    build_json_inv_collectors(&regional_inv_keys, &rcfg),
                                    build_json_collectors(&json_keys, &rcfg),
                                ));
                            }
                            if let Some(last) = app.prep_log.last_mut() {
                                *last = format!("    All {} regions ready.", region_total);
                            }
                        }
                        terminal.draw(|f| tui::ui::draw(f, &app))?;
                    }

                    // ── Work config (fresh, never used for API calls) ─────────────────
                    // Build a brand-new config so its credential provider has never been
                    // touched.  It will initialise correctly the first time it is used
                    // inside tokio::spawn.
                    let work_config = make_cfg().load().await;

                    // Build single-region collectors from the fresh work config.
                    // For inventory mode with multi-region, all collection is in regional_collectors;
                    // only build a base InventoryCollector when no regions were discovered (single-region path).
                    let json_collectors     = build_json_collectors(&names_ref, &work_config);
                    let json_inv_collectors = build_json_inv_collectors(&names_ref, &work_config);
                    let csv_collectors = if is_inventory {
                        if discovered_regions.is_empty() {
                            // Single-region fallback (SetOptions left all-regions and explicit-regions blank).
                            vec![Box::new(InventoryCollector::new(&work_config, inventory_types.clone())) as Box<dyn CsvCollector>]
                        } else {
                            // Regional collectors were built above; nothing needed here.
                            Vec::new()
                        }
                    } else {
                        build_csv_collectors(&names_ref, &work_config)
                    };

                    let mut display_names: Vec<String> = json_collectors.iter().map(|c| c.name().to_string())
                        .chain(json_inv_collectors.iter().map(|c| c.name().to_string()))
                        .chain(csv_collectors.iter().map(|c| c.name().to_string()))
                        .collect();

                    // If all-regions, add regional collector names to the display list.
                    for (rname, _, rcsv, rinv, rjson) in &regional_collectors {
                        for c in rcsv { if !display_names.contains(&c.name().to_string()) { display_names.push(format!("{} ({})", c.name(), rname)); } }
                        for c in rinv { if !display_names.contains(&c.name().to_string()) { display_names.push(format!("{} ({})", c.name(), rname)); } }
                        for c in rjson { if !display_names.contains(&c.name().to_string()) { display_names.push(format!("{} ({})", c.name(), rname)); } }
                    }
                    // Inventory multi-region: show one entry in the display list (not one per region).
                    if !inventory_multi_region.is_empty() {
                        let inv_name = inventory_multi_region[0].1.name().to_string();
                        let canonical = format!("{} ({} regions)", inv_name, inventory_multi_region.len());
                        if !display_names.contains(&canonical) {
                            display_names.push(canonical);
                        }
                    }

                    prepared.push(AccountCollectors {
                        account_id, aws_caller_arn, aws_user_id,
                        profile, region, output_path, collector_keys,
                        json_collectors, json_inv_collectors, csv_collectors, display_names,
                        discovered_regions, regional_collectors, inventory_multi_region,
                    });
                }

                // Guard: if every account failed the canary check, prepared is empty.
                // Show an error on the Preparing screen and return cleanly instead of
                // panicking at prepared[0].
                if prepared.is_empty() {
                    app.prep_log.push(String::new());
                    app.prep_log.push("⚠  No accounts are ready to collect from.".to_string());
                    app.prep_log.push("   All credential checks failed — check your AWS profile or SSO login.".to_string());
                    app.prep_log.push(String::new());
                    app.prep_log.push("   Press any key to return to the setup wizard.".to_string());
                    terminal.draw(|f| tui::ui::draw(f, &app))?;
                    // Wait for a keypress, then restart the wizard.
                    use crossterm::event as cxevent;
                    loop {
                        if cxevent::poll(std::time::Duration::from_millis(200))? {
                            let _ = cxevent::read()?;
                            break;
                        }
                    }
                    restore_terminal(&mut terminal)?;
                    restore_stderr(stderr_backup);
                    app.reset();
                    // Fall through to outer loop — restart the wizard.
                    continue;
                }

                // Set up progress channel so the TUI running screen gets live updates.
                let (tx, rx) = mpsc::unbounded_channel::<Progress>();
                app.progress_rx = Some(rx);

                // Initialise status entries from the first account's collectors.
                app.collector_statuses = prepared[0].display_names
                    .iter()
                    .map(|name| CollectorStatus {
                        name: name.clone(),
                        state: CollectorState::Waiting,
                    })
                    .collect();
                app.total_account_count = prepared.len();
                if prepared.len() > 1 {
                    app.current_account_index = 1;
                    app.current_account_label = Some(prepared[0].account_id.clone());
                }

                app.prep_log.push("All accounts prepared — starting collection…".to_string());
                app.screen = tui::Screen::Running;
                terminal.draw(|f| tui::ui::draw(f, &app))?;

                // Transition directly to Running screen (terminal is already set up).
                let do_zip = app.zip;
                let do_sign = app.sign;
                let skip_inventory_csv = app.skip_inventory_csv;
                let skip_run_manifest = app.skip_run_manifest;
                let skip_chain_of_custody = app.skip_chain_of_custody;
                let restart = run_tui_multi_account(
                    &mut terminal,
                    &mut app,
                    &params,
                    prepared,
                    tx,
                    do_zip,
                    do_sign,
                    skip_inventory_csv,
                    skip_run_manifest,
                    skip_chain_of_custody,
                )
                .await?;
                restore_terminal(&mut terminal)?;

                // Restore stderr after TUI exits.
                restore_stderr(stderr_backup);

                if !restart {
                    return Ok(());
                }
                // User pressed 'n' — app.reset() was called inside the collection
                // loop, so app.screen == Welcome.  Fall through to the top of the
                // outer loop to re-run the wizard.
            }
        } // end restart loop
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

    let cli_started_at = Utc::now().to_rfc3339();
    let cli_identity = audit_log::resolve_aws_identity(&config).await;
    let account_id = cli_identity.as_ref()
        .map(|id| id.account_id.clone())
        .unwrap_or_else(|| "unknown".to_string());
    eprintln!(
        "Identity: account={} arn={}",
        account_id,
        cli_identity.as_ref().map(|id| id.caller_arn.as_str()).unwrap_or("unknown"),
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

    // --- JSON inventory collectors (current-state, structured JSON output) ---
    let mut json_inv_collectors: Vec<Box<dyn JsonCollector>> = Vec::new();
    if wants("iam-roles")        { json_inv_collectors.push(Box::new(IamRoleCollector::new(&config))); }
    if wants("iam-role-policies"){ json_inv_collectors.push(Box::new(IamRolePoliciesCollector::new(&config))); }
    if wants("iam-user-policies"){ json_inv_collectors.push(Box::new(IamUserPoliciesCollector::new(&config))); }
    if wants("eventbridge-rules"){ json_inv_collectors.push(Box::new(EventBridgeRulesCollector::new(&config))); }
    if wants("ct-config-changes"){ json_inv_collectors.push(Box::new(CloudTrailConfigChangesCollector::new(&config))); }
    if wants("kms-config")       { json_inv_collectors.push(Box::new(KmsKeyConfigCollector::new(&config))); }

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
    // iam-roles → json_inv_collectors (see above)
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
    // iam-role-policies, iam-user-policies → json_inv_collectors (see above)
    if wants("iam-password-policy"){ csv_collectors.push(Box::new(IamPasswordPolicyCollector::new(&config))); }
    // KMS / EBS config
    // kms-config → json_inv_collectors (see above)
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
    // Inspector ECR
    if wants("inspector-ecr")      { csv_collectors.push(Box::new(InspectorEcrCollector::new(&config))); }
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
    // eventbridge-rules → json_inv_collectors (see above)
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
    // ct-config-changes → json_inv_collectors (see above)
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

    if json_collectors.is_empty() && csv_collectors.is_empty() && !cli.all_regions && cli.regions.is_none() {
        anyhow::bail!("No collectors selected.");
    }

    let output_dir = cli.output.clone().unwrap_or_else(|| PathBuf::from("."));

    // ── Multi-region round-robin mode ────────────────────────────────────────
    if cli.all_regions || cli.regions.is_some() {
        // Determine the target region list.
        let target_regions: Vec<String> = if let Some(explicit) = cli.regions.as_ref() {
            explicit.clone()
        } else {
            let regions = discover_regions(&config).await;
            if regions.is_empty() {
                anyhow::bail!("--all-regions: could not discover any enabled regions");
            }
            regions
        };

        // Build the wanted name lists, honouring any --collectors filter.
        let wanted_csv: Vec<&str> = {
            // All keys that appear in both the full key space AND the wants() filter.
            let full: &[&str] = &[
                "vpc","nacl","waf","elasticache","elasticache-global","efs","dynamodb",
                "ebs","rds-inventory","cloudtrail-config","sns","vpc-flow-logs",
                "metric-filters","s3-logging","iam-certs","elb","elb-listeners","acm",
                "iam-users","iam-policies","iam-access-keys","guardduty","securityhub",
                "config-rules","security-groups","route-tables","ec2-instances","asg",
                "kms","secrets","s3-config","cw-alarms","cw-log-groups","api-gateway",
                "cloudfront","ecs","eks","iam-trusts","access-analyzer","scp",
                "ct-selectors","ct-validation","ct-s3-policy","ct-changes","s3-data-events",
                "guardduty-config","guardduty-rules","sh-standards","igw","nat-gateways",
                "public-resources","ec2-detailed","ssm-instances","ssm-patches",
                "kms-policies","ebs-encryption","rds-snapshots","s3-policies","macie",
                "config-history","inspector","inspector-ecr","inspector-history","ecr-scan",
                "waf-logging","alb-logs","iam-password-policy","ebs-config","s3-encryption",
                "s3-bucket-policy","s3-public-access","s3-logging-config","sg-config",
                "vpc-config","rt-config","ec2-config","ct-full-config","cw-log-config",
                "metric-filter-config","gd-full-config","sh-config","config-recorder",
                "launch-templates","vpc-endpoints","ssm-baselines","ssm-params","time-sync",
                "inspector-config","waf-config","elb-full-config","org-config",
                "account-contacts","saml-providers","iam-account-summary","sns-policies",
                "backup-plans","backup-vaults","rds-backup-config","lambda-config",
                "lambda-permissions","ecr-config","route53-zones","route53-resolver",
                "resource-tags","secrets-policies","config-timeline","config-compliance",
                "config-snapshot","ct-iam-changes","cfn-drift","ssm-patch-detail",
                "ssm-patch-summary","ssm-patch-exec","ssm-maint-windows","cw-config-alarms",
                "change-event-rules",
            ];
            full.iter().copied()
                .filter(|k| wants(k))
                .collect()
        };
        let wanted_json_inv: Vec<&str> = ["iam-roles","iam-role-policies","iam-user-policies",
            "eventbridge-rules","ct-config-changes","kms-config"]
            .iter().copied().filter(|k| wants(k)).collect();
        let wanted_json: Vec<&str> = ["cloudtrail","backup","rds"]
            .iter().copied().filter(|k| wants(k)).collect();

        // Split into global (run once) and regional (run per region).
        let global_csv: Vec<&str>      = wanted_csv.iter().copied().filter(|k| GLOBAL_COLLECTOR_KEYS.contains(k)).collect();
        let regional_csv: Vec<&str>    = wanted_csv.iter().copied().filter(|k| !GLOBAL_COLLECTOR_KEYS.contains(k)).collect();
        let global_json_inv: Vec<&str> = wanted_json_inv.iter().copied()
            .filter(|k| GLOBAL_COLLECTOR_KEYS.contains(k)).collect();
        let regional_json_inv: Vec<&str> = wanted_json_inv.iter().copied()
            .filter(|k| !GLOBAL_COLLECTOR_KEYS.contains(k)).collect();
        // JSON time-windowed collectors are all regional.

        let mr_run_id = Utc::now().format("%Y-%m-%d-%H%M%S").to_string();
        let mr_dates = Some((params.start_time.timestamp(), params.end_time.timestamp()));
        let mr_coll_start = params.start_time.format("%Y-%m-%d").to_string();
        let mr_coll_end   = params.end_time.format("%Y-%m-%d").to_string();
        let mut mr_outcomes: Vec<audit_log::CollectorOutcome> = Vec::new();

        // ── Run global collectors once (into base output dir) ─────────────────
        if !global_csv.is_empty() || !global_json_inv.is_empty() {
            eprintln!("\n=== Global collectors (running once) ===");
            let global_csv_v  = build_csv_collectors(&global_csv, &config);
            let global_inv_v  = build_json_inv_collectors(&global_json_inv, &config);
            mr_outcomes.extend(run_csv_collectors(&global_csv_v, &account_id, &cli.region, &output_dir, mr_dates, &mr_run_id).await?);
            mr_outcomes.extend(run_json_inv_collectors(&global_inv_v, &account_id, &cli.region, &output_dir, &mr_run_id).await?);
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
                let csv_v = build_csv_collectors(&regional_csv, &region_config);
                mr_outcomes.extend(run_csv_collectors(&csv_v, &account_id, region_name, &region_dir, mr_dates, &mr_run_id).await?);
            }
            if !regional_json_inv.is_empty() {
                let inv_v = build_json_inv_collectors(&regional_json_inv, &region_config);
                mr_outcomes.extend(run_json_inv_collectors(&inv_v, &account_id, region_name, &region_dir, &mr_run_id).await?);
            }
            if !wanted_json.is_empty() {
                let json_v = build_json_collectors(&wanted_json, &region_config);
                mr_outcomes.extend(run_json_collectors(&json_v, &params, region_name, &region_dir, &mr_run_id).await?);
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
        match audit_log::write_run_manifest(&output_dir, &mr_manifest) {
            Ok(p) => eprintln!("Run manifest written: {}", p.display()),
            Err(e) => eprintln!("WARN: could not write run manifest: {e}"),
        }

        // ── Write chain-of-custody (multi-region) ─────────────────────────────
        {
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
            match zip_bundle::bundle_dir(&output_dir, zip_path) {
                Ok(()) => eprintln!("Zip bundle written: {}", zip_name),
                Err(e) => eprintln!("Zip bundle failed: {e}"),
            }
        }

        if cli.sign {
            let key = match &cli.signing_key {
                Some(hex) => signing::SigningKey::from_hex(hex)?,
                None => signing::SigningKey::generate()?,
            };
            let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
            let files = signing::collect_dir_files(&output_dir);
            match signing::sign_files(&files, &mr_timestamp, &key, &cwd) {
                Ok((manifest_path, key_path)) => {
                    eprintln!("Signing manifest: {}", manifest_path.display());
                    eprintln!("Signing key file: {} (move to secure storage)", key_path.display());
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
    let sr_coll_end   = params.end_time.format("%Y-%m-%d").to_string();
    let mut sr_outcomes: Vec<audit_log::CollectorOutcome> = Vec::new();

    sr_outcomes.extend(run_json_collectors(&json_collectors, &params, &cli.region, &output_dir, &timestamp).await?);
    sr_outcomes.extend(run_json_inv_collectors(&json_inv_collectors, &account_id, &cli.region, &output_dir, &timestamp).await?);
    sr_outcomes.extend(run_csv_collectors(&csv_collectors, &account_id, &cli.region, &output_dir, sr_dates, &timestamp).await?);

    // ── Write run manifest (single-region) ───────────────────────────────────
    let sr_manifest = audit_log::RunManifest::build(
        &timestamp,
        &account_id,
        &cli.region,
        &sr_coll_start,
        &sr_coll_end,
        sr_outcomes,
    );
    match audit_log::write_run_manifest(&output_dir, &sr_manifest) {
        Ok(p) => eprintln!("Run manifest written: {}", p.display()),
        Err(e) => eprintln!("WARN: could not write run manifest: {e}"),
    }

    // ── Write chain-of-custody (single-region) ───────────────────────────────
    {
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
        match zip_bundle::bundle_dir(&output_dir, zip_path) {
            Ok(()) => eprintln!("Zip bundle written: {}", zip_name),
            Err(e) => eprintln!("Zip bundle failed: {e}"),
        }
    }

    if cli.sign {
        let key = match &cli.signing_key {
            Some(hex) => signing::SigningKey::from_hex(hex)?,
            None => signing::SigningKey::generate()?,
        };
        let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
        let files = signing::collect_dir_files(&output_dir);
        match signing::sign_files(&files, &timestamp, &key, &cwd) {
            Ok((manifest_path, key_path)) => {
                eprintln!("Signing manifest: {}", manifest_path.display());
                eprintln!("Signing key file: {} (move to secure storage)", key_path.display());
                eprintln!("Signing key (hex): {}", key.to_hex());
            }
            Err(e) => eprintln!("Signing failed: {e}"),
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// TUI running screen + async collection
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Per-collector helpers used by the TUI background task
// ---------------------------------------------------------------------------

async fn run_tui_csv_collector(
    collector: &Box<dyn CsvCollector>,
    account_id: &str,
    region: &str,
    out_dir: &PathBuf,
    timestamp: &str,
    tx: &mpsc::UnboundedSender<Progress>,
    timeout: std::time::Duration,
    written: &mut Vec<String>,
    outcomes: &mut Vec<audit_log::CollectorOutcome>,
    dates: Option<(i64, i64)>,
) {
    let name = collector.name().to_string();
    let _ = tx.send(Progress::Started { collector: name.clone() });
    match tokio::time::timeout(timeout, collector.collect_rows(account_id, region, dates)).await {
        Ok(Ok(rows)) => {
            let count = rows.len();
            let _ = tx.send(Progress::Done { collector: name.clone(), count });
            if count == 0 {
                outcomes.push(audit_log::CollectorOutcome::empty(&name));
                return;
            }
            let filename = format!("{}_{}-{}.csv", account_id, collector.filename_prefix(), timestamp);
            let path = out_dir.join(&filename);
            if let Ok(bytes) = write_csv_bytes(collector.headers(), &rows) {
                if std::fs::write(&path, bytes).is_ok() {
                    outcomes.push(audit_log::CollectorOutcome::success(&name, count, &path));
                    written.push(path.display().to_string());
                } else {
                    outcomes.push(audit_log::CollectorOutcome::error(&name, "write failed".to_string()));
                }
            } else {
                outcomes.push(audit_log::CollectorOutcome::error(&name, "CSV serialisation failed".to_string()));
            }
        }
        Ok(Err(e)) => {
            let msg = format!("{:#}", e);
            eprintln!("  ERROR [csv] {}: {}", name, msg);
            let _ = tx.send(Progress::Error { collector: name.clone(), message: msg.clone() });
            outcomes.push(audit_log::CollectorOutcome::error(&name, msg));
        }
        Err(_) => {
            eprintln!("  ERROR [csv] {}: timed out after 3 minutes", name);
            let _ = tx.send(Progress::Error { collector: name.clone(), message: "timed out after 3 minutes".to_string() });
            outcomes.push(audit_log::CollectorOutcome::timeout(&name));
        }
    }
}

async fn run_tui_inv_collector(
    collector: &Box<dyn JsonCollector>,
    account_id: &str,
    region: &str,
    out_dir: &PathBuf,
    timestamp: &str,
    tx: &mpsc::UnboundedSender<Progress>,
    timeout: std::time::Duration,
    written: &mut Vec<String>,
    outcomes: &mut Vec<audit_log::CollectorOutcome>,
) {
    let name = collector.name().to_string();
    let _ = tx.send(Progress::Started { collector: name.clone() });
    match tokio::time::timeout(timeout, collector.collect_records(account_id, region)).await {
        Ok(Ok(records)) => {
            let count = records.len();
            let _ = tx.send(Progress::Done { collector: name.clone(), count });
            if count == 0 {
                outcomes.push(audit_log::CollectorOutcome::empty(&name));
                return;
            }
            let report = JsonInventoryReport {
                collected_at: Utc::now().to_rfc3339(),
                account_id: account_id.to_string(),
                region: region.to_string(),
                collector: name.clone(),
                record_count: count,
                records,
            };
            let filename = format!("{}_{}-{}.json", account_id, collector.filename_prefix(), timestamp);
            let path = out_dir.join(&filename);
            if let Ok(json) = serde_json::to_string_pretty(&report) {
                if std::fs::write(&path, json).is_ok() {
                    outcomes.push(audit_log::CollectorOutcome::success(&name, count, &path));
                    written.push(path.display().to_string());
                } else {
                    outcomes.push(audit_log::CollectorOutcome::error(&name, "write failed".to_string()));
                }
            } else {
                outcomes.push(audit_log::CollectorOutcome::error(&name, "JSON serialisation failed".to_string()));
            }
        }
        Ok(Err(e)) => {
            let msg = format!("{:#}", e);
            eprintln!("  ERROR [inv] {}: {}", name, msg);
            let _ = tx.send(Progress::Error { collector: name.clone(), message: msg.clone() });
            outcomes.push(audit_log::CollectorOutcome::error(&name, msg));
        }
        Err(_) => {
            eprintln!("  ERROR [inv] {}: timed out after 3 minutes", name);
            let _ = tx.send(Progress::Error { collector: name.clone(), message: "timed out after 3 minutes".to_string() });
            outcomes.push(audit_log::CollectorOutcome::timeout(&name));
        }
    }
}

async fn run_tui_json_collector(
    collector: &Box<dyn EvidenceCollector>,
    params: &CollectParams,
    region: &str,
    account_id: &str,
    out_dir: &PathBuf,
    timestamp: &str,
    tx: &mpsc::UnboundedSender<Progress>,
    timeout: std::time::Duration,
    written: &mut Vec<String>,
    outcomes: &mut Vec<audit_log::CollectorOutcome>,
) {
    let name = collector.name().to_string();
    let _ = tx.send(Progress::Started { collector: name.clone() });
    match tokio::time::timeout(timeout, collector.collect(params)).await {
        Ok(Ok(records)) => {
            let count = records.len();
            let _ = tx.send(Progress::Done { collector: name.clone(), count });
            if count == 0 {
                outcomes.push(audit_log::CollectorOutcome::empty(&name));
                return;
            }
            let report = EvidenceReport {
                metadata: ReportMetadata {
                    collected_at: Utc::now().to_rfc3339(),
                    region: region.to_string(),
                    start_date: params.start_time.format("%Y-%m-%d").to_string(),
                    end_date: params.end_time.format("%Y-%m-%d").to_string(),
                    filter: params.filter.clone(),
                },
                collector: name.clone(),
                record_count: count,
                records,
            };
            let filename = format!("{}_{}-{}.json", account_id, collector.filename_prefix(), timestamp);
            let path = out_dir.join(&filename);
            if let Ok(json) = serde_json::to_string_pretty(&report) {
                if std::fs::write(&path, json).is_ok() {
                    outcomes.push(audit_log::CollectorOutcome::success(&name, count, &path));
                    written.push(path.display().to_string());
                } else {
                    outcomes.push(audit_log::CollectorOutcome::error(&name, "write failed".to_string()));
                }
            } else {
                outcomes.push(audit_log::CollectorOutcome::error(&name, "JSON serialisation failed".to_string()));
            }
        }
        Ok(Err(e)) => {
            let msg = format!("{:#}", e);
            eprintln!("  ERROR [json] {}: {}", name, msg);
            let _ = tx.send(Progress::Error { collector: name.clone(), message: msg.clone() });
            outcomes.push(audit_log::CollectorOutcome::error(&name, msg));
        }
        Err(_) => {
            eprintln!("  ERROR [json] {}: timed out after 3 minutes", name);
            let _ = tx.send(Progress::Error { collector: name.clone(), message: "timed out after 3 minutes".to_string() });
            outcomes.push(audit_log::CollectorOutcome::timeout(&name));
        }
    }
}

/// Pre-built account data ready for the background collection task.
/// AWS configs and SDK clients must be created on the main async task (not inside
/// tokio::spawn) so that the HTTP/TLS connector initializes correctly.
struct AccountCollectors {
    account_id: String,
    aws_caller_arn: String,
    aws_user_id: String,
    profile: String,
    region: String,
    output_path: Option<PathBuf>,
    #[allow(dead_code)]
    collector_keys: Vec<String>,
    json_collectors: Vec<Box<dyn EvidenceCollector>>,
    json_inv_collectors: Vec<Box<dyn JsonCollector>>,
    csv_collectors: Vec<Box<dyn CsvCollector>>,
    display_names: Vec<String>,
    /// Pre-discovered regions (if all-regions was requested). Empty = use single-region path.
    discovered_regions: Vec<String>,
    /// Pre-built regional collectors for each discovered region.
    /// Each entry: (region_name, csv_collectors, inv_collectors, json_collectors)
    regional_collectors: Vec<(
        String,
        PathBuf,
        Vec<Box<dyn CsvCollector>>,
        Vec<Box<dyn JsonCollector>>,
        Vec<Box<dyn EvidenceCollector>>,
    )>,
    /// Inventory-mode multi-region collectors: one per region, all rows merged
    /// into a single output CSV. Each entry: (region_name, collector).
    inventory_multi_region: Vec<(String, Box<dyn CsvCollector>)>,
}

/// Returns a `PathBuf` representing the date-based sub-path `YYYY/##-MMM`
/// (e.g. `2026/04-APR`) computed from the current local system time.
fn date_path_suffix() -> PathBuf {
    let now = Local::now();
    let year = now.format("%Y").to_string();
    let month_num = now.format("%m").to_string();
    let month_abbr = match month_num.as_str() {
        "01" => "JAN", "02" => "FEB", "03" => "MAR", "04" => "APR",
        "05" => "MAY", "06" => "JUN", "07" => "JUL", "08" => "AUG",
        "09" => "SEP", "10" => "OCT", "11" => "NOV", "12" => "DEC",
        _ => "UNK",
    };
    PathBuf::from(&year).join(format!("{month_num}-{month_abbr}"))
}

/// Multi-account wrapper: iterates over all pre-built accounts, running the
/// full collector set for each. Sends AccountStarted / AccountFinished progress
/// events so the TUI shows which account is active.
///
/// IMPORTANT: `prepared` must be built BEFORE the terminal enters raw mode,
/// because `aws_config::load()` needs a normal terminal for SSO credential
/// resolution.
/// Returns `Ok(true)` if the user pressed 'n' (new collection) on the Results
/// screen, or `Ok(false)` if they pressed 'q'/Esc (exit).
async fn run_tui_multi_account(
    terminal: &mut ratatui::Terminal<ratatui::backend::CrosstermBackend<std::io::Stdout>>,
    app: &mut App,
    params: &CollectParams,
    prepared: Vec<AccountCollectors>,
    tx: mpsc::UnboundedSender<Progress>,
    do_zip: bool,
    do_sign: bool,
    skip_inventory_csv: bool,
    skip_run_manifest: bool,
    skip_chain_of_custody: bool,
) -> Result<bool> {
    use crossterm::event::{self, Event, KeyCode, KeyEventKind};

    let params_clone = params.clone();
    let total_accounts = prepared.len();

    // Spawn background task that loops through all pre-built accounts.
    // IMPORTANT: No AWS configs or SDK clients are created inside this spawn.
    // All collectors and configs were built on the main async task before
    // entering raw terminal mode.
    tokio::spawn(async move {
        let mut all_written_files: Vec<String> = Vec::new();
        let collector_timeout = std::time::Duration::from_secs(600); // 10 minutes
        let run_id = Utc::now().format("%Y-%m-%d-%H%M%S").to_string();
        let timestamp = run_id.clone();
        let started_at = Utc::now().to_rfc3339();
        let dates = Some((params_clone.start_time.timestamp(), params_clone.end_time.timestamp()));
        let coll_start = params_clone.start_time.format("%Y-%m-%d").to_string();
        let coll_end   = params_clone.end_time.format("%Y-%m-%d").to_string();

        // For inventory mode: accumulate all rows across every account + region into one buffer.
        // The file is written once after all accounts complete.
        let is_inventory_mode = prepared.iter().any(|a| !a.inventory_multi_region.is_empty());
        let mut inventory_global_rows: Vec<Vec<String>> = Vec::new();
        // Capture headers/prefix/output_dir from the first account that has inventory data.
        let inventory_out_dir = prepared.iter().find(|a| !a.inventory_multi_region.is_empty())
            .and_then(|a| a.output_path.clone())
            .unwrap_or_else(|| PathBuf::from("."));
        let inventory_headers: &'static [&'static str] = if is_inventory_mode {
            crate::inventory_core::INVENTORY_CSV_HEADERS
        } else {
            &[]
        };

        for (acct_idx, acct) in prepared.into_iter().enumerate() {
            // For collectors mode (non-inventory) with a single region, route evidence
            // into <account>/<region>/YYYY/##-MMM.  Multi-region evidence files already
            // have the date suffix baked into their pre-built `rdir`.
            let out_dir = {
                let base = acct.output_path.clone().unwrap_or_else(|| PathBuf::from("."));
                if !is_inventory_mode && acct.discovered_regions.is_empty() {
                    base.join(&acct.region).join(date_path_suffix())
                } else {
                    base
                }
            };
            if let Err(e) = std::fs::create_dir_all(&out_dir) {
                let _ = tx.send(Progress::Error {
                    collector: format!("output dir ({})", acct.account_id),
                    message: format!("could not create {}: {e}", out_dir.display()),
                });
                let _ = tx.send(Progress::AccountFinished { name: acct.account_id.clone() });
                continue;
            }

            eprintln!("=== Account {}/{}: {} (profile={}, region={}, out={}) ===",
                acct_idx + 1, total_accounts, acct.account_id, acct.profile, acct.region, out_dir.display());
            eprintln!("  collectors: json={}, inv={}, csv={}",
                acct.json_collectors.len(), acct.json_inv_collectors.len(), acct.csv_collectors.len());

            // Notify TUI of new account.
            let _ = tx.send(Progress::AccountStarted {
                name: acct.account_id.clone(),
                index: acct_idx + 1,
                total: total_accounts,
                region: acct.region.clone(),
                collectors: acct.display_names,
            });

            let mut acct_outcomes: Vec<audit_log::CollectorOutcome> = Vec::new();
            let has_inventory_multi_region = !acct.inventory_multi_region.is_empty();

            // ── Inventory multi-region path: collect all regions in parallel; rows go to global buffer ──
            if has_inventory_multi_region {
                let collector_name = format!(
                    "{} ({} regions)",
                    acct.inventory_multi_region[0].1.name(),
                    acct.inventory_multi_region.len(),
                );
                let total_regions = acct.inventory_multi_region.len();
                let _ = tx.send(Progress::Started { collector: collector_name.clone() });

                // Spawn all regions concurrently.
                let mut join_set: tokio::task::JoinSet<(String, std::result::Result<Vec<Vec<String>>, anyhow::Error>)> =
                    tokio::task::JoinSet::new();
                let region_timeout = std::time::Duration::from_secs(300); // 5 min per region
                for (region_name, collector) in acct.inventory_multi_region {
                    let acct_id = acct.account_id.clone();
                    let rname = region_name.clone();
                    join_set.spawn(async move {
                        let result = tokio::time::timeout(
                            region_timeout,
                            collector.collect_rows(&acct_id, &rname, dates),
                        )
                        .await
                        .map_err(|_| anyhow::anyhow!("region timed out after 5 minutes"))
                        .and_then(|r| r);
                        (region_name, result)
                    });
                }

                let mut acct_rows: Vec<Vec<String>> = Vec::new();
                let mut completed = 0usize;
                while let Some(task_result) = join_set.join_next().await {
                    completed += 1;
                    match task_result {
                        Ok((region_name, Ok(rows))) => {
                            let row_count = rows.len();
                            eprintln!("  [inventory] region {}/{}: {} — {} rows", completed, total_regions, region_name, row_count);
                            acct_rows.extend(rows);
                            let _ = tx.send(Progress::Done {
                                collector: format!("{} [{}/{}]", collector_name, completed, total_regions),
                                count: acct_rows.len(),
                            });
                        }
                        Ok((region_name, Err(e))) => {
                            eprintln!("  ERROR [inventory] {}: {:#}", region_name, e);
                            let _ = tx.send(Progress::Error {
                                collector: format!("{} ({})", collector_name, region_name),
                                message: format!("{:#}", e),
                            });
                        }
                        Err(e) => {
                            eprintln!("  ERROR [inventory] task panicked: {e}");
                            let _ = tx.send(Progress::Error {
                                collector: collector_name.clone(),
                                message: format!("task panicked: {e}"),
                            });
                        }
                    }
                }

                eprintln!("  [inventory] account {} done: {} rows this account", acct.account_id, acct_rows.len());
                inventory_global_rows.extend(acct_rows);
                // No per-account file write — the unified file is written after all accounts finish.
            }

            // ── All-regions path: use pre-built regional collectors ──
            if !acct.discovered_regions.is_empty() && !has_inventory_multi_region {
                eprintln!("  all-regions: {} regions pre-built", acct.discovered_regions.len());
                for (region_name, rdir, rcsv, rinv, rjson) in &acct.regional_collectors {
                    let _ = tx.send(Progress::RegionStarted { region: region_name.clone() });
                    let _ = std::fs::create_dir_all(rdir);
                    for collector in rcsv {
                        run_tui_csv_collector(collector, &acct.account_id, region_name, rdir, &timestamp, &tx, collector_timeout, &mut all_written_files, &mut acct_outcomes, dates).await;
                    }
                    for collector in rinv {
                        run_tui_inv_collector(collector, &acct.account_id, region_name, rdir, &timestamp, &tx, collector_timeout, &mut all_written_files, &mut acct_outcomes).await;
                    }
                    for collector in rjson {
                        run_tui_json_collector(collector, &params_clone, region_name, &acct.account_id, rdir, &timestamp, &tx, collector_timeout, &mut all_written_files, &mut acct_outcomes).await;
                    }
                }
            } else if acct.discovered_regions.is_empty() && !has_inventory_multi_region {
                // ── Single-region path (default) ──
                for collector in &acct.json_collectors {
                    run_tui_json_collector(collector, &params_clone, &acct.region, &acct.account_id, &out_dir, &timestamp, &tx, collector_timeout, &mut all_written_files, &mut acct_outcomes).await;
                }
                for collector in &acct.json_inv_collectors {
                    run_tui_inv_collector(collector, &acct.account_id, &acct.region, &out_dir, &timestamp, &tx, collector_timeout, &mut all_written_files, &mut acct_outcomes).await;
                }
                if is_inventory_mode {
                    // Route inventory rows into the global buffer (written as one file after all accounts).
                    for collector in &acct.csv_collectors {
                        let name = collector.name().to_string();
                        let _ = tx.send(Progress::Started { collector: name.clone() });
                        match tokio::time::timeout(collector_timeout, collector.collect_rows(&acct.account_id, &acct.region, dates)).await {
                            Ok(Ok(rows)) => {
                                let count = rows.len();
                                inventory_global_rows.extend(rows);
                                let _ = tx.send(Progress::Done { collector: name, count });
                            }
                            Ok(Err(e)) => { let _ = tx.send(Progress::Error { collector: name, message: format!("{e:#}") }); }
                            Err(_)     => { let _ = tx.send(Progress::Error { collector: name, message: "timed out".to_string() }); }
                        }
                    }
                } else {
                    for collector in &acct.csv_collectors {
                        run_tui_csv_collector(collector, &acct.account_id, &acct.region, &out_dir, &timestamp, &tx, collector_timeout, &mut all_written_files, &mut acct_outcomes, dates).await;
                    }
                }
            }

            // ── Write run manifest ────────────────────────────────────────────
            if !is_inventory_mode && !skip_run_manifest {
                let manifest = audit_log::RunManifest::build(
                    &run_id,
                    &acct.account_id,
                    &acct.region,
                    &coll_start,
                    &coll_end,
                    acct_outcomes.clone(),
                );
                match audit_log::write_run_manifest(&out_dir, &manifest) {
                    Ok(p) => eprintln!("  Run manifest: {}", p.display()),
                    Err(e) => eprintln!("  WARN: could not write run manifest: {e}"),
                }
            }

            // ── Write chain-of-custody log ────────────────────────────────────
            if !is_inventory_mode && !skip_chain_of_custody {
                let identity = audit_log::AwsIdentity {
                    account_id: acct.account_id.clone(),
                    caller_arn: acct.aws_caller_arn.clone(),
                    user_id: acct.aws_user_id.clone(),
                };
                let entry = audit_log::CustodyEntry::new(
                    &run_id,
                    &started_at,
                    identity,
                    &acct.profile,
                    &acct.region,
                    &coll_start,
                    &coll_end,
                    acct_outcomes.len(),
                );
                match audit_log::write_chain_of_custody(&out_dir, &entry) {
                    Ok(p) => eprintln!("  Chain of custody: {}", p.display()),
                    Err(e) => eprintln!("  WARN: could not write chain of custody: {e}"),
                }
            }

            let _ = tx.send(Progress::AccountFinished { name: acct.account_id });
        }

        eprintln!("=== All accounts done. {} files written. ===", all_written_files.len());

        // ── Write single unified inventory CSV (all accounts + all regions) ──
        if !inventory_global_rows.is_empty() {
            if !skip_inventory_csv {
                let _ = std::fs::create_dir_all(&inventory_out_dir);
                let filename = format!("AWS_Inventory-{}.csv", timestamp);
                let path = inventory_out_dir.join(&filename);
                match write_csv_bytes(inventory_headers, &inventory_global_rows) {
                    Ok(bytes) => {
                        if std::fs::write(&path, bytes).is_ok() {
                            eprintln!("=== Inventory CSV: {} ({} rows) ===", path.display(), inventory_global_rows.len());
                            all_written_files.push(path.display().to_string());
                        } else {
                            eprintln!("=== ERROR: could not write inventory CSV to {} ===", path.display());
                        }
                    }
                    Err(e) => eprintln!("=== ERROR: inventory CSV serialisation failed: {e:#} ==="),
                }
            }

            // ── Write inventory Excel workbook from template ──────────────────
            // Use local system time for the date-based directory hierarchy so
            // the folder reflects the user's calendar date, not UTC.
            let now_local   = Local::now();
            let year        = now_local.format("%Y").to_string();
            let month_num   = now_local.format("%m").to_string(); // "04"
            let month_abbr  = match month_num.as_str() {
                "01" => "JAN", "02" => "FEB", "03" => "MAR", "04" => "APR",
                "05" => "MAY", "06" => "JUN", "07" => "JUL", "08" => "AUG",
                "09" => "SEP", "10" => "OCT", "11" => "NOV", "12" => "DEC",
                other => {
                    eprintln!("=== WARN: unexpected month '{other}', using 'UNK' in path ===");
                    "UNK"
                }
            };
            let xlsx_filename = now_local.format("%Y-%m-%d_Inventory_%H-%M-%S.xlsx").to_string();
            let xlsx_path = std::path::PathBuf::from("inventory")
                .join(&year)
                .join(format!("{month_num}-{month_abbr}"))
                .join(&xlsx_filename);
            let template_path = std::path::Path::new("assets/Inventory.xlsx");
            if template_path.exists() {
                match crate::inventory_xlsx::write_inventory_xlsx(
                    &inventory_global_rows,
                    template_path,
                    &xlsx_path,
                ) {
                    Ok(()) => {
                        eprintln!(
                            "=== Inventory XLSX: {} ({} rows) ===",
                            xlsx_path.display(),
                            inventory_global_rows.len()
                        );
                        all_written_files.push(xlsx_path.display().to_string());
                    }
                    Err(e) => eprintln!("=== ERROR: inventory XLSX generation failed: {e:#} ==="),
                }
            } else {
                eprintln!(
                    "=== WARN: inventory XLSX skipped — template not found at '{}' ===",
                    template_path.display()
                );
            }
        } else if is_inventory_mode {
            eprintln!("=== Inventory: no rows collected (all asset types empty) ===");
        }

        let zip_path = if do_zip && !all_written_files.is_empty() {
            let zip_name = format!("Evidence-{}.zip", timestamp);
            let zip_path = std::path::PathBuf::from(&zip_name);
            let base = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
            match zip_bundle::bundle_files(&all_written_files, &base, &zip_path) {
                Ok(()) => {
                    eprintln!("=== Zip bundle written: {} ===", zip_name);
                    Some(zip_name)
                }
                Err(e) => {
                    eprintln!("=== Zip bundle failed: {e} ===");
                    None
                }
            }
        } else {
            None
        };

        let (signing_manifest, signing_key_path) = if do_sign && !all_written_files.is_empty() {
            let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
            match signing::SigningKey::generate() {
                Ok(key) => {
                    eprintln!("=== Signing {} files with HMAC-SHA256 ===", all_written_files.len());
                    match signing::sign_files(&all_written_files, &timestamp, &key, &cwd) {
                        Ok((manifest_path, key_path)) => {
                            let key_hex = key.to_hex();
                            eprintln!("=== Signing manifest: {} ===", manifest_path.display());
                            eprintln!("=== Signing key (store securely): {} ===", key_hex);
                            (
                                Some(manifest_path.to_string_lossy().into_owned()),
                                Some(key_path.to_string_lossy().into_owned()),
                            )
                        }
                        Err(e) => {
                            eprintln!("=== Signing failed: {e} ===");
                            (None, None)
                        }
                    }
                }
                Err(e) => {
                    eprintln!("=== Key generation failed: {e} ===");
                    (None, None)
                }
            }
        } else {
            (None, None)
        };

        let _ = tx.send(Progress::Finished {
            files: all_written_files,
            zip_path,
            signing_manifest,
            signing_key_path,
            poam_summary: None,
        });
    });

    // Drive the TUI until the user exits or requests a new collection.
    let restart = loop {
        app.tick = app.tick.wrapping_add(1);
        app.poll_progress();

        terminal.draw(|f| tui::ui::draw(f, app))?;

        if app.screen == tui::Screen::Results {
            if event::poll(std::time::Duration::from_millis(100))? {
                if let Event::Key(key) = event::read()? {
                    if key.kind == KeyEventKind::Press {
                        match key.code {
                            KeyCode::Char('n') => {
                                app.reset();
                                break true;
                            }
                            KeyCode::Char('q') | KeyCode::Esc => break false,
                            _ => {}
                        }
                    }
                }
            }
        } else if event::poll(std::time::Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press && key.code == KeyCode::Char('q') {
                    break false;
                }
            }
        }
    };

    Ok(restart)
}

async fn run_tui_poam(
    terminal: &mut ratatui::Terminal<ratatui::backend::CrosstermBackend<std::io::Stdout>>,
    app: &mut App,
    tx: mpsc::UnboundedSender<Progress>,
    region: String,
    year: String,
    month_name: String,
) -> Result<bool> {
    use crossterm::event::{self, Event, KeyCode, KeyEventKind};

    tokio::spawn(async move {
        let collector_name = "POA&M Reconciliation".to_string();
        let _ = tx.send(Progress::Started {
            collector: collector_name.clone(),
        });

        let evidence_path = poam::resolve_evidence_path(&region, &year, &month_name)
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| String::new());

        match poam::run_poam(&region, &year, &month_name) {
            Ok(result) => {
                let mut files: Vec<String> = vec![result.workbook_path.display().to_string()];
                if let Some(csv) = &result.selected_csv {
                    files.push(result.evidence_path.join(csv).display().to_string());
                }
                let _ = tx.send(Progress::Done {
                    collector: collector_name,
                    count: result.added_open_count + result.moved_closed_count,
                });
                let summary = tui::PoamSummary {
                    region: result.region,
                    year: result.year,
                    month: result.month_name,
                    evidence_path: result.evidence_path.display().to_string(),
                    csv_used: result.selected_csv,
                    added_open_count: result.added_open_count,
                    moved_closed_count: result.moved_closed_count,
                    warnings: result.warnings,
                };
                let _ = tx.send(Progress::Finished {
                    files,
                    zip_path: None,
                    signing_manifest: None,
                    signing_key_path: None,
                    poam_summary: Some(summary),
                });
            }
            Err(e) => {
                let _ = tx.send(Progress::Error {
                    collector: collector_name.clone(),
                    message: format!("{e:#}"),
                });
                let summary = tui::PoamSummary {
                    region,
                    year,
                    month: month_name,
                    evidence_path,
                    csv_used: None,
                    added_open_count: 0,
                    moved_closed_count: 0,
                    warnings: Vec::new(),
                };
                let _ = tx.send(Progress::Finished {
                    files: Vec::new(),
                    zip_path: None,
                    signing_manifest: None,
                    signing_key_path: None,
                    poam_summary: Some(summary),
                });
            }
        }
    });

    let restart = loop {
        app.tick = app.tick.wrapping_add(1);
        app.poll_progress();

        terminal.draw(|f| tui::ui::draw(f, app))?;

        if app.screen == tui::Screen::Results {
            if event::poll(std::time::Duration::from_millis(100))? {
                if let Event::Key(key) = event::read()? {
                    if key.kind == KeyEventKind::Press {
                        match key.code {
                            KeyCode::Char('n') => {
                                app.reset();
                                break true;
                            }
                            KeyCode::Char('q') | KeyCode::Esc => break false,
                            _ => {}
                        }
                    }
                }
            }
        } else if event::poll(std::time::Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press && key.code == KeyCode::Char('q') {
                    break false;
                }
            }
        }
    };

    Ok(restart)
}

// ---------------------------------------------------------------------------
// Shared collection + report writing (CLI path)
// ---------------------------------------------------------------------------

async fn run_json_collectors(
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
                let json = serde_json::to_string_pretty(&report)
                    .context("JSON serialization failed")?;
                std::fs::write(&path, json)
                    .with_context(|| format!("Failed to write {}", path.display()))?;
                eprintln!("  Written: {}", format_path_with_osc8(&path));
                outcomes.push(audit_log::CollectorOutcome::success(collector.name(), count, &path));
            }
            Err(e) => {
                eprintln!("  ERROR from {}: {e:#}", collector.name());
                outcomes.push(audit_log::CollectorOutcome::error(collector.name(), format!("{e:#}")));
            }
        }
    }
    Ok(outcomes)
}

async fn run_csv_collectors(
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
                outcomes.push(audit_log::CollectorOutcome::success(collector.name(), count, &path));
            }
            Err(e) => {
                eprintln!("  ERROR from {}: {e:#}", collector.name());
                outcomes.push(audit_log::CollectorOutcome::error(collector.name(), format!("{e:#}")));
            }
        }
    }
    Ok(outcomes)
}

async fn run_json_inv_collectors(
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
                let json = serde_json::to_string_pretty(&report)
                    .context("JSON serialise")?;
                std::fs::write(&path, json)
                    .with_context(|| format!("Failed to write {}", path.display()))?;
                eprintln!("  Written: {}", format_path_with_osc8(&path));
                outcomes.push(audit_log::CollectorOutcome::success(collector.name(), count, &path));
            }
            Err(e) => {
                eprintln!("  ERROR from {}: {e:#}", collector.name());
                outcomes.push(audit_log::CollectorOutcome::error(collector.name(), format!("{e:#}")));
            }
        }
    }
    Ok(outcomes)
}

// ---------------------------------------------------------------------------
// Multi-region helpers
// ---------------------------------------------------------------------------

/// Collectors that query account-global AWS services.  In all-regions mode
/// these run once against the primary region rather than once per region.
const GLOBAL_COLLECTOR_KEYS: &[&str] = &[
    // IAM (global)
    "iam-users", "iam-roles", "iam-policies", "iam-access-keys", "iam-certs",
    "iam-trusts", "iam-role-policies", "iam-user-policies",
    "iam-password-policy", "iam-account-summary",
    // S3 (bucket list is global)
    "s3-config", "s3-logging", "s3-policies", "s3-encryption",
    "s3-bucket-policy", "s3-public-access", "s3-logging-config", "s3-data-events",
    // CloudFront (global)
    "cloudfront",
    // Route53 (global)
    "route53-zones", "route53-resolver",
    // Organizations / account (global)
    "scp", "org-config", "account-contacts", "saml-providers",
];

/// Discover all opt-in and standard enabled regions via EC2 DescribeRegions.
async fn discover_regions(config: &aws_config::SdkConfig) -> Vec<String> {
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
            eprintln!("Discovered {} enabled regions: {}", regions.len(), regions.join(", "));
            regions
        }
        Err(e) => {
            eprintln!("WARN: could not discover regions via EC2: {e:#}");
            vec![]
        }
    }
}

/// Build CSV collectors for the given set of collector keys and AWS config.
/// This is the single source of truth — both CLI and TUI call this.
fn build_csv_collectors(names: &[&str], config: &aws_config::SdkConfig) -> Vec<Box<dyn CsvCollector>> {
    let mut v: Vec<Box<dyn CsvCollector>> = Vec::new();
    let has = |n: &str| names.contains(&n);
    if has("vpc")               { v.push(Box::new(VpcCollector::new(config))); }
    if has("nacl")              { v.push(Box::new(NetworkAclCollector::new(config))); }
    if has("waf")               { v.push(Box::new(WafCollector::new(config))); }
    if has("elasticache")       { v.push(Box::new(ElastiCacheCollector::new(config))); }
    if has("elasticache-global"){ v.push(Box::new(ElastiCacheGlobalCollector::new(config))); }
    if has("efs")               { v.push(Box::new(EfsCollector::new(config))); }
    if has("dynamodb")          { v.push(Box::new(DynamoDbCollector::new(config))); }
    if has("ebs")               { v.push(Box::new(EbsCollector::new(config))); }
    if has("rds-inventory")     { v.push(Box::new(RdsInventoryCollector::new(config))); }
    if has("cloudtrail-config") { v.push(Box::new(CloudTrailInventoryCollector::new(config))); }
    if has("sns")               { v.push(Box::new(SnsSubscriptionCollector::new(config))); }
    if has("vpc-flow-logs")     { v.push(Box::new(VpcFlowLogCollector::new(config))); }
    if has("metric-filters")    { v.push(Box::new(MetricFilterAlarmCollector::new(config))); }
    if has("s3-logging")        { v.push(Box::new(S3BucketLoggingCollector::new(config))); }
    if has("iam-certs")         { v.push(Box::new(IamCertCollector::new(config))); }
    if has("elb")               { v.push(Box::new(LoadBalancerCollector::new(config))); }
    if has("elb-listeners")     { v.push(Box::new(LoadBalancerListenerCollector::new(config))); }
    if has("acm")               { v.push(Box::new(AcmCertCollector::new(config))); }
    if has("iam-users")         { v.push(Box::new(IamUserCollector::new(config))); }
    if has("iam-policies")      { v.push(Box::new(IamPolicyCollector::new(config))); }
    if has("iam-access-keys")   { v.push(Box::new(IamAccessKeyCollector::new(config))); }
    if has("guardduty")         { v.push(Box::new(GuardDutyCollector::new(config))); }
    if has("securityhub")       { v.push(Box::new(SecurityHubCollector::new(config))); }
    if has("config-rules")      { v.push(Box::new(ConfigRulesCollector::new(config))); }
    if has("security-groups")   { v.push(Box::new(SecurityGroupCollector::new(config))); }
    if has("route-tables")      { v.push(Box::new(RouteTableCollector::new(config))); }
    if has("ec2-instances")     { v.push(Box::new(Ec2InstanceCollector::new(config))); }
    if has("asg")               { v.push(Box::new(AutoScalingCollector::new(config))); }
    if has("kms")               { v.push(Box::new(KmsKeyCollector::new(config))); }
    if has("secrets")           { v.push(Box::new(SecretsManagerCollector::new(config))); }
    if has("s3-config")         { v.push(Box::new(S3BucketConfigCollector::new(config))); }
    if has("cw-alarms")         { v.push(Box::new(CloudWatchAlarmCollector::new(config))); }
    if has("cw-log-groups")     { v.push(Box::new(CloudWatchLogGroupCollector::new(config))); }
    if has("api-gateway")       { v.push(Box::new(ApiGatewayCollector::new(config))); }
    if has("cloudfront")        { v.push(Box::new(CloudFrontCollector::new(config))); }
    if has("ecs")               { v.push(Box::new(EcsClusterCollector::new(config))); }
    if has("eks")               { v.push(Box::new(EksClusterCollector::new(config))); }
    if has("iam-trusts")        { v.push(Box::new(IamTrustsCollector::new(config))); }
    if has("access-analyzer")   { v.push(Box::new(AccessAnalyzerCollector::new(config))); }
    if has("scp")               { v.push(Box::new(OrganizationsSCPCollector::new(config))); }
    if has("ct-selectors")      { v.push(Box::new(CloudTrailEventSelectorsCollector::new(config))); }
    if has("ct-validation")     { v.push(Box::new(CloudTrailLogValidationCollector::new(config))); }
    if has("ct-s3-policy")      { v.push(Box::new(CloudTrailS3PolicyCollector::new(config))); }
    if has("ct-changes")        { v.push(Box::new(CloudTrailChangeEventsCollector::new(config))); }
    if has("s3-data-events")    { v.push(Box::new(S3DataEventsCollector::new(config))); }
    if has("guardduty-config")  { v.push(Box::new(GuardDutyConfigCollector::new(config))); }
    if has("guardduty-rules")   { v.push(Box::new(GuardDutySuppressionCollector::new(config))); }
    if has("sh-standards")      { v.push(Box::new(SecurityHubStandardsCollector::new(config))); }
    if has("igw")               { v.push(Box::new(InternetGatewayCollector::new(config))); }
    if has("nat-gateways")      { v.push(Box::new(NatGatewayCollector::new(config))); }
    if has("public-resources")  { v.push(Box::new(PublicResourceCollector::new(config))); }
    if has("ec2-detailed")      { v.push(Box::new(Ec2DetailedCollector::new(config))); }
    if has("ssm-instances")     { v.push(Box::new(SsmManagedInstanceCollector::new(config))); }
    if has("ssm-patches")       { v.push(Box::new(SsmPatchComplianceCollector::new(config))); }
    if has("kms-policies")      { v.push(Box::new(KmsKeyPolicyCollector::new(config))); }
    if has("ebs-encryption")    { v.push(Box::new(EbsDefaultEncryptionCollector::new(config))); }
    if has("rds-snapshots")     { v.push(Box::new(RdsSnapshotCollector::new(config))); }
    if has("s3-policies")       { v.push(Box::new(S3PoliciesCollector::new(config))); }
    if has("macie")             { v.push(Box::new(MacieCollector::new(config))); }
    if has("config-history")    { v.push(Box::new(ConfigHistoryCollector::new(config))); }
    if has("inspector")         { v.push(Box::new(InspectorCollector::new(config))); }
    if has("inspector-ecr")     { v.push(Box::new(InspectorEcrCollector::new(config))); }
    if has("inspector-history") { v.push(Box::new(InspectorFindingsHistoryCollector::new(config))); }
    if has("ecr-scan")          { v.push(Box::new(EcrScanCollector::new(config))); }
    if has("waf-logging")       { v.push(Box::new(WafLoggingCollector::new(config))); }
    if has("alb-logs")          { v.push(Box::new(AlbLogsCollector::new(config))); }
    if has("iam-password-policy"){ v.push(Box::new(IamPasswordPolicyCollector::new(config))); }
    if has("ebs-config")        { v.push(Box::new(EbsEncryptionConfigCollector::new(config))); }
    if has("s3-encryption")     { v.push(Box::new(S3EncryptionConfigCollector::new(config))); }
    if has("s3-bucket-policy")  { v.push(Box::new(S3BucketPolicyDetailCollector::new(config))); }
    if has("s3-public-access")  { v.push(Box::new(S3PublicAccessBlockCollector::new(config))); }
    if has("s3-logging-config") { v.push(Box::new(S3LoggingConfigCollector::new(config))); }
    if has("sg-config")         { v.push(Box::new(SecurityGroupConfigCollector::new(config))); }
    if has("vpc-config")        { v.push(Box::new(VpcConfigCollector::new(config))); }
    if has("rt-config")         { v.push(Box::new(RouteTableConfigCollector::new(config))); }
    if has("ec2-config")        { v.push(Box::new(Ec2InstanceConfigCollector::new(config))); }
    if has("ct-full-config")    { v.push(Box::new(CloudTrailFullConfigCollector::new(config))); }
    if has("cw-log-config")     { v.push(Box::new(CwLogGroupConfigCollector::new(config))); }
    if has("metric-filter-config"){ v.push(Box::new(MetricFilterConfigCollector::new(config))); }
    if has("gd-full-config")    { v.push(Box::new(GuardDutyFullConfigCollector::new(config))); }
    if has("sh-config")         { v.push(Box::new(SecurityHubConfigCollector::new(config))); }
    if has("config-recorder")   { v.push(Box::new(AwsConfigRecorderCollector::new(config))); }
    if has("launch-templates")  { v.push(Box::new(LaunchTemplateCollector::new(config))); }
    if has("vpc-endpoints")     { v.push(Box::new(VpcEndpointCollector::new(config))); }
    if has("ssm-baselines")     { v.push(Box::new(SsmPatchBaselineCollector::new(config))); }
    if has("ssm-params")        { v.push(Box::new(SsmParameterConfigCollector::new(config))); }
    if has("time-sync")         { v.push(Box::new(TimeSyncConfigCollector::new(config))); }
    if has("inspector-config")  { v.push(Box::new(InspectorConfigCollector::new(config))); }
    if has("waf-config")        { v.push(Box::new(WafFullConfigCollector::new(config))); }
    if has("elb-full-config")   { v.push(Box::new(ElbFullConfigCollector::new(config))); }
    if has("org-config")        { v.push(Box::new(OrgConfigCollector::new(config))); }
    if has("account-contacts")  { v.push(Box::new(AccountContactsCollector::new(config))); }
    if has("saml-providers")    { v.push(Box::new(SamlProviderCollector::new(config))); }
    if has("iam-account-summary"){ v.push(Box::new(IamAccountSummaryCollector::new(config))); }
    if has("sns-policies")      { v.push(Box::new(SnsTopicPoliciesCollector::new(config))); }
    if has("backup-plans")      { v.push(Box::new(BackupPlanConfigCollector::new(config))); }
    if has("backup-vaults")     { v.push(Box::new(BackupVaultConfigCollector::new(config))); }
    if has("rds-backup-config") { v.push(Box::new(RdsBackupConfigCollector::new(config))); }
    if has("lambda-config")     { v.push(Box::new(LambdaConfigCollector::new(config))); }
    if has("lambda-permissions"){ v.push(Box::new(LambdaPermissionsCollector::new(config))); }
    if has("ecr-config")        { v.push(Box::new(EcrRepoConfigCollector::new(config))); }
    if has("route53-zones")     { v.push(Box::new(Route53ZonesCollector::new(config))); }
    if has("route53-resolver")  { v.push(Box::new(Route53ResolverRulesCollector::new(config))); }
    if has("resource-tags")     { v.push(Box::new(ResourceTaggingCollector::new(config))); }
    if has("secrets-policies")  { v.push(Box::new(SecretsManagerPoliciesCollector::new(config))); }
    if has("config-timeline")   { v.push(Box::new(ConfigResourceTimelineCollector::new(config))); }
    if has("config-compliance") { v.push(Box::new(ConfigComplianceHistoryCollector::new(config))); }
    if has("config-snapshot")   { v.push(Box::new(ConfigSnapshotCollector::new(config))); }
    if has("ct-iam-changes")    { v.push(Box::new(CloudTrailIamChangesCollector::new(config))); }
    if has("cfn-drift")         { v.push(Box::new(CloudFormationDriftCollector::new(config))); }
    if has("ssm-patch-detail")  { v.push(Box::new(SsmPatchDetailCollector::new(config))); }
    if has("ssm-patch-summary") { v.push(Box::new(SsmPatchSummaryCollector::new(config))); }
    if has("ssm-patch-exec")    { v.push(Box::new(SsmPatchExecutionCollector::new(config))); }
    if has("ssm-maint-windows") { v.push(Box::new(SsmMaintenanceWindowCollector::new(config))); }
    if has("cw-config-alarms")  { v.push(Box::new(CloudWatchConfigAlarmsCollector::new(config))); }
    if has("change-event-rules"){ v.push(Box::new(ChangeEventRulesCollector::new(config))); }
    v
}

/// Build JSON-inventory collectors for the given set of keys and AWS config.
fn build_json_inv_collectors(names: &[&str], config: &aws_config::SdkConfig) -> Vec<Box<dyn JsonCollector>> {
    let mut v: Vec<Box<dyn JsonCollector>> = Vec::new();
    let has = |n: &str| names.contains(&n);
    if has("iam-roles")          { v.push(Box::new(IamRoleCollector::new(config))); }
    if has("iam-role-policies")  { v.push(Box::new(IamRolePoliciesCollector::new(config))); }
    if has("iam-user-policies")  { v.push(Box::new(IamUserPoliciesCollector::new(config))); }
    if has("eventbridge-rules")  { v.push(Box::new(EventBridgeRulesCollector::new(config))); }
    if has("ct-config-changes")  { v.push(Box::new(CloudTrailConfigChangesCollector::new(config))); }
    if has("kms-config")         { v.push(Box::new(KmsKeyConfigCollector::new(config))); }
    v
}

/// Build time-windowed JSON collectors for the given set of keys and AWS config.
fn build_json_collectors(names: &[&str], config: &aws_config::SdkConfig) -> Vec<Box<dyn EvidenceCollector>> {
    let mut v: Vec<Box<dyn EvidenceCollector>> = Vec::new();
    let has = |n: &str| names.contains(&n);
    if has("cloudtrail") { v.push(Box::new(CloudTrailCollector::new(config))); }
    if has("backup")     { v.push(Box::new(BackupCollector::new(config))); }
    if has("rds")        { v.push(Box::new(RdsCollector::new(config))); }
    v
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

/// Format a path as an OSC 8 hyperlink when stderr is a TTY.
///
/// Terminals that don't support OSC 8 will simply display the
/// visible text portion, so this is safe to enable by default.
fn format_path_with_osc8(path: &std::path::Path) -> String {
    use std::io::IsTerminal;

    let text = path.display().to_string();

    // Avoid emitting escape sequences when stderr is not a terminal
    // (e.g. when logs are redirected to a file or CI).
    if !std::io::stderr().is_terminal() {
        return text;
    }

    let abs = path
        .canonicalize()
        .unwrap_or_else(|_| path.to_path_buf());
    let url = format!("file://{}", abs.display());

    // OSC 8: ESC ] 8 ;; <url> BEL <text> ESC ] 8 ;; BEL
    format!("\x1b]8;;{url}\x07{text}\x1b]8;;\x07")
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

/// Redirect stderr (fd 2) to `path`, returning a saved copy of the old fd.
/// Returns -1 if anything fails (stderr is left unchanged).
#[cfg(unix)]
fn redirect_stderr_to_file(path: &std::path::Path) -> i32 {
    use std::os::unix::io::IntoRawFd;
    let backup = unsafe { libc::dup(2) };
    if backup < 0 { return -1; }
    match std::fs::OpenOptions::new().create(true).append(true).open(path) {
        Ok(f) => {
            let fd = f.into_raw_fd();
            unsafe { libc::dup2(fd, 2); libc::close(fd); }
            backup
        }
        Err(_) => {
            unsafe { libc::close(backup); }
            -1
        }
    }
}

#[cfg(not(unix))]
fn redirect_stderr_to_file(_path: &std::path::Path) -> i32 { -1 }

/// Restore stderr from a previously saved fd. No-op if `saved` is -1.
#[cfg(unix)]
fn restore_stderr(saved: i32) {
    if saved >= 0 {
        unsafe { libc::dup2(saved, 2); libc::close(saved); }
    }
}

#[cfg(not(unix))]
fn restore_stderr(_saved: i32) {}

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
