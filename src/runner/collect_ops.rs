use std::path::PathBuf;

use anyhow::{Context, Result};
use chrono::Utc;

use crate::audit_log;
use crate::evidence::{
    CollectParams, CsvCollector, EvidenceCollector, EvidenceReport, JsonCollector,
    JsonInventoryReport, ReportMetadata,
};
use crate::runner::output::{evidence_basename, format_path_with_osc8, write_csv_bytes_with_manifest};

pub(crate) async fn run_json_collectors(
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

pub(crate) async fn run_csv_collectors(
    collectors: &[Box<dyn CsvCollector>],
    account_id: &str,
    region: &str,
    output_dir: &PathBuf,
    dates: Option<(i64, i64)>,
    _timestamp: &str,
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
                let basename = evidence_basename(account_id, collector.filename_prefix(), "csv");
                let mapping = collector.fedramp_mapping();
                let path = output_dir.join(&basename);
                let bytes = write_csv_bytes_with_manifest(
                    collector.headers(),
                    &rows,
                    &mapping,
                    &basename,
                )?;
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

pub(crate) async fn run_json_inv_collectors(
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
