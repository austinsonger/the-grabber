use std::path::PathBuf;

use anyhow::{Context, Result};
use chrono::Utc;

use crate::audit_log;
use crate::cli::Cli;
use crate::evidence::{
    CollectParams, CsvCollector, EvidenceCollector, EvidenceReport, JsonCollector,
    JsonInventoryReport, ReportMetadata,
};
use crate::inventory_orchestrator::InventoryCollector;
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
        let start_ts = start.and_hms_opt(0, 0, 0).unwrap().and_utc().timestamp();
        let end_ts = today.and_hms_opt(23, 59, 59).unwrap().and_utc().timestamp();
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
