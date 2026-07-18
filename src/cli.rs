use std::path::PathBuf;

use anyhow::{Context, Result};
use chrono::NaiveDate;
use clap::Parser;

use crate::inventory_core::INVENTORY_ITEMS;

#[derive(Parser)]
#[command(
    name = "evidence",
    about = "Collect AWS compliance evidence — run with no args for interactive TUI"
)]
pub struct Cli {
    /// Start date (inclusive), YYYY-MM-DD.
    /// Providing this flag (or --lookback) enables non-interactive CLI mode; omit both to launch the TUI.
    #[arg(long)]
    pub start_date: Option<String>,

    /// End date (inclusive), YYYY-MM-DD.
    /// Required when --start-date is provided; ignored with --lookback (end = today).
    #[arg(long)]
    pub end_date: Option<String>,

    /// Lookback window from today, e.g. 30, 30d, 12w, 3m, 1y.
    /// A bare integer is treated as days. Accepted units: d / day / days,
    /// w / week / weeks, m / month / months, y / year / years.
    /// Sets end-date to today and start-date to today minus the window.
    /// Cannot be combined with --start-date or --end-date.
    #[arg(long)]
    pub lookback: Option<String>,

    /// AWS region
    #[arg(long, default_value = "us-east-1")]
    pub region: String,

    /// AWS named profile (overrides AWS_PROFILE)
    #[arg(long)]
    pub profile: Option<String>,

    /// Output directory for collected evidence (default: current working directory)
    #[arg(long, short)]
    pub output: Option<PathBuf>,

    /// Optional collector filter string for supported time-windowed collectors
    #[arg(long)]
    pub filter: Option<String>,

    /// Include raw event JSON in each record
    #[arg(long, default_value_t = false)]
    pub include_raw: bool,

    /// Collectors to run (comma-separated).
    /// Omit to run the tool's full configured collector set; see evidence-list.md for keys.
    #[arg(long, value_delimiter = ',')]
    pub collectors: Option<Vec<String>>,

    // ------- S3 collector options -------
    /// S3 bucket containing CloudTrail logs (required for the s3 collector)
    #[arg(long)]
    pub s3_bucket: Option<String>,

    /// Key prefix before "AWSLogs/" (e.g. "management")
    #[arg(long, default_value = "")]
    pub s3_prefix: String,

    /// AWS profile for S3 access (cross-account bucket)
    #[arg(long)]
    pub s3_profile: Option<String>,

    /// Additional account IDs to scan in S3 logs (comma-separated)
    #[arg(long, value_delimiter = ',')]
    pub s3_accounts: Option<Vec<String>>,

    /// Additional regions to scan in S3 logs (comma-separated)
    #[arg(long, value_delimiter = ',')]
    pub s3_regions: Option<Vec<String>>,

    // ------- Multi-region options -------
    /// Collect evidence from every enabled region (round-robin).
    /// Global services (IAM, S3, Route53, CloudFront, etc.) run once;
    /// regional services run once per region.
    /// Output is written to <output>/<region>/ subdirectories.
    #[arg(long, default_value_t = false)]
    pub all_regions: bool,

    /// Explicit list of regions to collect from (comma-separated).
    /// Implies round-robin mode. If omitted with --all-regions, regions
    /// are auto-discovered via EC2 DescribeRegions.
    #[arg(long, value_delimiter = ',')]
    pub regions: Option<Vec<String>>,

    /// Bundle all output files into a dated Evidence-<timestamp>.zip after collection.
    /// The zip is placed in the current working directory.
    #[arg(long, default_value_t = false)]
    pub zip: bool,

    /// Run the unified Inventory workflow from the CLI.
    /// This current-state asset inventory mode does not use --start-date/--end-date.
    #[arg(long, default_value_t = false)]
    pub inventory: bool,

    /// Merge inventory from every authenticated AWS account listed in config.toml /
    /// tenable-config / okta-config / jira-config into a single unified CSV + XLSX
    /// (matches the TUI multi-account inventory output). Accounts whose profile
    /// cannot resolve an AWS identity (expired SSO, missing creds) are skipped
    /// with a WARN; the run continues against the rest. Requires --inventory.
    /// Cannot be combined with --profile — profiles are read from the account config.
    #[arg(long, default_value_t = false, conflicts_with = "profile", requires = "inventory")]
    pub inventory_all_accounts: bool,

    // ------- Signing options -------
    /// HMAC-SHA256-sign all output files after collection.
    /// Writes SIGNING-MANIFEST-<ts>.json and SIGNING-<ts>.key to the current directory.
    /// Move the .key file to secure storage (separate from the evidence) before sharing.
    #[arg(long, default_value_t = false)]
    pub sign: bool,

    /// Provide a 64-char hex signing key instead of auto-generating one.
    /// Used with --sign (CLI mode) or --verify-manifest.
    #[arg(long)]
    pub signing_key: Option<String>,

    /// Verify a SIGNING-MANIFEST-*.json without collecting new evidence.
    /// Requires --signing-key.
    #[arg(long)]
    pub verify_manifest: Option<String>,

    // ------- Audit artifact opt-ins -------
    /// Opt in to writing the run-manifest JSON after collection (collectors mode only).
    /// Disabled by default; pass this flag to emit RUN-MANIFEST-<run_id>.json.
    #[arg(long, default_value_t = false)]
    pub write_run_manifest: bool,

    /// Opt in to writing the chain-of-custody log after collection (collectors mode only).
    /// Disabled by default; pass this flag to emit CHAIN-OF-CUSTODY-<run_id>.json
    /// and append to CHAIN-OF-CUSTODY.jsonl.
    #[arg(long, default_value_t = false)]
    pub write_chain_of_custody: bool,

    /// Skip writing the inventory CSV after collection (inventory mode only).
    #[arg(long, default_value_t = false)]
    pub skip_inventory_csv: bool,

    /// Limit inventory to specific asset types (comma-separated, inventory mode only).
    /// See INVENTORY_ITEMS in src/inventory_core.rs for the full list of valid keys.
    /// Omit to collect all types (or use individual type flags below).
    #[arg(long, value_delimiter = ',')]
    pub inventory_types: Option<Vec<String>>,

    // ------- Individual inventory asset-type flags -------
    /// Inventory: include KMS Keys.
    #[arg(long = "kms", default_value_t = false)]
    pub inv_kms: bool,

    /// Inventory: include S3 Buckets.
    #[arg(long = "s3", default_value_t = false)]
    pub inv_s3: bool,

    /// Inventory: include Lambda Functions.
    #[arg(long = "lambda", default_value_t = false)]
    pub inv_lambda: bool,

    /// Inventory: include EC2 Instances.
    #[arg(long = "ec2", default_value_t = false)]
    pub inv_ec2: bool,

    /// Inventory: include Application Load Balancers.
    #[arg(long = "alb", default_value_t = false)]
    pub inv_alb: bool,

    /// Inventory: include RDS DB Instances.
    #[arg(long = "rds", default_value_t = false)]
    pub inv_rds: bool,

    /// Inventory: include ElastiCache Clusters.
    #[arg(long = "elasticache", default_value_t = false)]
    pub inv_elasticache: bool,

    /// Inventory: include Containers (ECR/ECS/EKS).
    #[arg(long = "containers", default_value_t = false)]
    pub inv_containers: bool,

    /// Inventory: include Network Load Balancers.
    #[arg(long = "nlb", default_value_t = false)]
    pub inv_nlb: bool,

    /// Inventory: include EBS Volumes.
    #[arg(long = "ebs", default_value_t = false)]
    pub inv_ebs: bool,

    /// Inventory: include EFS File Systems.
    #[arg(long = "efs", default_value_t = false)]
    pub inv_efs: bool,

    /// Inventory: include FSx File Systems.
    #[arg(long = "fsx", default_value_t = false)]
    pub inv_fsx: bool,

    /// Inventory: include Redshift Clusters.
    #[arg(long = "redshift", default_value_t = false)]
    pub inv_redshift: bool,

    /// Inventory: include DynamoDB Tables.
    #[arg(long = "dynamodb", default_value_t = false)]
    pub inv_dynamodb: bool,

    /// Inventory: include API Gateway (REST, HTTP, WebSocket) APIs.
    #[arg(long = "apigw", default_value_t = false)]
    pub inv_apigw: bool,

    /// Inventory: include SNS Topics.
    #[arg(long = "sns", default_value_t = false)]
    pub inv_sns: bool,

    /// Inventory: include SQS Queues.
    #[arg(long = "sqs", default_value_t = false)]
    pub inv_sqs: bool,

    /// Inventory: include Kinesis Data Streams.
    #[arg(long = "kinesis", default_value_t = false)]
    pub inv_kinesis: bool,

    /// Inventory: include Kinesis Firehose Delivery Streams.
    #[arg(long = "firehose", default_value_t = false)]
    pub inv_firehose: bool,

    /// Inventory: include EventBridge Buses and Rules.
    #[arg(long = "eventbridge", default_value_t = false)]
    pub inv_eventbridge: bool,

    /// Inventory: include Secrets Manager Secrets (metadata only — never reads secret values).
    #[arg(long = "secretsmanager", default_value_t = false)]
    pub inv_secretsmanager: bool,

    /// Inventory: include VPC network fabric (VPC + Subnet + IGW + NAT GW + TGW Attachment).
    #[arg(long = "vpc-network", default_value_t = false)]
    pub inv_vpc_network: bool,

    /// Inventory: include CloudTrail Trails.
    #[arg(long = "cloudtrail", default_value_t = false)]
    pub inv_cloudtrail: bool,

    /// Inventory: include Config Recorders.
    #[arg(long = "config-recorder", default_value_t = false)]
    pub inv_config_recorder: bool,

    /// Inventory: include GuardDuty Detectors.
    #[arg(long = "guardduty", default_value_t = false)]
    pub inv_guardduty: bool,

    /// Inventory: include Security Hub Hubs.
    #[arg(long = "securityhub", default_value_t = false)]
    pub inv_securityhub: bool,

    /// Inventory: include WAF WebACLs (Regional + CloudFront scope).
    #[arg(long = "waf", default_value_t = false)]
    pub inv_waf: bool,

    // ------- POA&M mode -------
    /// Run the POA&M reconciliation workflow (non-interactive).
    /// Requires --poam-year and --poam-month; uses --region for the region.
    #[arg(long, default_value_t = false)]
    pub poam: bool,

    /// Base evidence directory for POA&M (e.g. evidence-output/security).
    #[arg(long, default_value = "evidence-output/security")]
    pub poam_evidence_base: String,

    /// 4-digit findings year for POA&M (e.g. 2026).
    #[arg(long)]
    pub poam_year: Option<String>,

    /// Month name for POA&M (e.g. January, February … December). Required with --poam.
    #[arg(long)]
    pub poam_month: Option<String>,

    /// Output format for --poam: xlsx (default), oscal, or both.
    #[arg(long, default_value = "xlsx")]
    pub poam_format: String,

    // ------- Inspector SBOM export options -------
    /// S3 bucket for Inspector SBOM export destination.
    #[arg(long)]
    pub sbom_bucket: Option<String>,

    /// KMS key ARN for Inspector SBOM export encryption.
    #[arg(long)]
    pub sbom_kms_key: Option<String>,

    /// SBOM report format: cyclonedx14 or spdx23.
    #[arg(long, default_value = "cyclonedx14")]
    pub sbom_format: String,
}

/// Parse a lookback string like "30", "30d", "12weeks", "3m", "1year" into a
/// start `NaiveDate` (end date is always today). A bare integer is treated
/// as days, so `--lookback 30` is equivalent to `--lookback 30d`.
pub fn parse_lookback(s: &str) -> Result<NaiveDate> {
    let s = s.trim().to_ascii_lowercase();
    let today = chrono::Utc::now().date_naive();

    // Bare integer → days. `--lookback 30` == `--lookback 30d`.
    if !s.is_empty() && s.chars().all(|c| c.is_ascii_digit()) {
        let amount: i64 = s
            .parse()
            .context("--lookback: expected a positive integer")?;
        if amount <= 0 {
            anyhow::bail!("--lookback: amount must be greater than zero");
        }
        return Ok(today - chrono::Duration::days(amount));
    }

    let split = s
        .find(|c: char| c.is_alphabetic())
        .context("--lookback must start with a number, e.g. 30, 30d, or 3months")?;
    let amount: i64 = s[..split]
        .parse()
        .context("--lookback: expected a positive integer before the unit")?;
    if amount <= 0 {
        anyhow::bail!("--lookback: amount must be greater than zero");
    }
    let unit = s[split..].trim_end_matches('s');
    let start = match unit {
        "d" | "day" => today - chrono::Duration::days(amount),
        "w" | "week" => today - chrono::Duration::weeks(amount),
        "m" | "month" => today - chrono::Months::new(amount as u32),
        "y" | "year" => today - chrono::Months::new(amount as u32 * 12),
        other => anyhow::bail!(
            "--lookback: unknown unit '{other}'. Use d/day, w/week, m/month, or y/year"
        ),
    };
    Ok(start)
}

pub fn cli_profile_label(profile: Option<&str>) -> &str {
    match profile {
        Some(p) if !p.is_empty() => p,
        _ => "default",
    }
}

fn all_inventory_type_keys() -> Vec<String> {
    INVENTORY_ITEMS
        .iter()
        .map(|(key, _)| (*key).to_string())
        .collect()
}

/// Build the inventory type list from the individual type flags and/or
/// --inventory-types. Individual flags and --inventory-types are additive.
/// If nothing is selected the full set is returned (collect everything).
pub fn resolve_inventory_types(cli: &Cli) -> Vec<String> {
    let mut selected: Vec<String> = Vec::new();

    if let Some(ref types) = cli.inventory_types {
        selected.extend(types.iter().cloned());
    }

    if cli.inv_kms {
        selected.push("kms-key".to_string());
    }
    if cli.inv_s3 {
        selected.push("s3-bucket".to_string());
    }
    if cli.inv_lambda {
        selected.push("lambda-function".to_string());
    }
    if cli.inv_ec2 {
        selected.push("ec2-instance".to_string());
    }
    if cli.inv_alb {
        selected.push("alb".to_string());
    }
    if cli.inv_rds {
        selected.push("rds-db-instance".to_string());
    }
    if cli.inv_elasticache {
        selected.push("elasticache-cluster".to_string());
    }
    if cli.inv_containers {
        selected.push("container".to_string());
    }
    if cli.inv_nlb {
        selected.push("nlb".to_string());
    }
    if cli.inv_ebs {
        selected.push("ebs-volume".to_string());
    }
    if cli.inv_efs {
        selected.push("efs-file-system".to_string());
    }
    if cli.inv_fsx {
        selected.push("fsx-file-system".to_string());
    }
    if cli.inv_redshift {
        selected.push("redshift-cluster".to_string());
    }
    if cli.inv_dynamodb {
        selected.push("dynamodb-table".to_string());
    }
    if cli.inv_apigw {
        selected.push("apigw".to_string());
    }
    if cli.inv_sns {
        selected.push("sns-topic".to_string());
    }
    if cli.inv_sqs {
        selected.push("sqs-queue".to_string());
    }
    if cli.inv_kinesis {
        selected.push("kinesis-stream".to_string());
    }
    if cli.inv_firehose {
        selected.push("firehose-stream".to_string());
    }
    if cli.inv_eventbridge {
        selected.push("eventbridge".to_string());
    }
    if cli.inv_secretsmanager {
        selected.push("secretsmanager-secret".to_string());
    }
    if cli.inv_vpc_network {
        selected.push("vpc-network".to_string());
    }
    if cli.inv_cloudtrail {
        selected.push("cloudtrail-trail".to_string());
    }
    if cli.inv_config_recorder {
        selected.push("config-recorder".to_string());
    }
    if cli.inv_guardduty {
        selected.push("guardduty-detector".to_string());
    }
    if cli.inv_securityhub {
        selected.push("securityhub-hub".to_string());
    }
    if cli.inv_waf {
        selected.push("waf-webacl".to_string());
    }

    let mut seen = std::collections::HashSet::new();
    selected.retain(|k| seen.insert(k.clone()));

    if selected.is_empty() {
        all_inventory_type_keys()
    } else {
        selected
    }
}
