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
    /// Valid keys: kms-key, s3-bucket, lambda-function, ec2-instance, alb,
    ///             rds-db-instance, elasticache-cluster, container.
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

    // ------- Provider selection -------
    /// Cloud provider to collect from. Defaults to "aws".
    /// Supported values: aws, gcp (requires --features gcp).
    #[arg(long, default_value = "aws")]
    pub provider: String,

    // ------- GCP-specific options (used when --provider gcp) -------
    /// GCP project ID (e.g. "my-project-123").
    /// Falls back to the active gcloud project if omitted.
    #[arg(long)]
    pub gcp_project: Option<String>,

    /// GCP organization ID (numeric). Required for org-scoped GCP collectors
    /// (Security Command Center, Org Policy, organization structure).
    #[arg(long)]
    pub gcp_org: Option<String>,

    /// GCP location/region (e.g. "us-central1", "us", "global").
    /// Defaults to "us-central1" when omitted.
    #[arg(long, default_value = "us-central1")]
    pub gcp_location: String,
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

    let mut seen = std::collections::HashSet::new();
    selected.retain(|k| seen.insert(k.clone()));

    if selected.is_empty() {
        all_inventory_type_keys()
    } else {
        selected
    }
}
