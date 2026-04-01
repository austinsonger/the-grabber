mod acm;
mod backup;
mod cloudtrail;
mod cloudtrail_inventory;
mod cloudtrail_s3;
mod cloudwatch;
mod dynamodb;
mod ebs;
mod elasticache;
mod efs;
mod elb;
mod evidence;
mod iam_certs;
mod rds;
mod rds_inventory;
mod s3_inventory;
mod sns;
mod tui;
mod vpc;
mod vpcflowlogs;
mod waf;

use std::path::PathBuf;

use anyhow::{Context, Result};
use aws_config::BehaviorVersion;
use aws_config::Region;
use chrono::{NaiveDate, Utc};
use clap::Parser;
use tokio::sync::mpsc;

use crate::backup::BackupCollector;
use crate::cloudtrail::CloudTrailCollector;
use crate::cloudtrail_s3::{CloudTrailS3Collector, CloudTrailS3Config};
use crate::acm::AcmCertCollector;
use crate::cloudtrail_inventory::CloudTrailInventoryCollector;
use crate::cloudwatch::MetricFilterAlarmCollector;
use crate::dynamodb::DynamoDbCollector;
use crate::ebs::EbsCollector;
use crate::elasticache::{ElastiCacheCollector, ElastiCacheGlobalCollector};
use crate::efs::EfsCollector;
use crate::elb::{LoadBalancerCollector, LoadBalancerListenerCollector};
use crate::iam_certs::IamCertCollector;
use crate::s3_inventory::S3BucketLoggingCollector;
use crate::sns::SnsSubscriptionCollector;
use crate::vpcflowlogs::VpcFlowLogCollector;
use crate::evidence::{
    CollectParams, CsvCollector, EvidenceCollector, EvidenceReport, ReportMetadata,
};
use crate::rds::RdsCollector;
use crate::rds_inventory::RdsInventoryCollector;
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

#[tokio::main]
async fn main() -> Result<()> {
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
            _ => {}
        }
    }

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
