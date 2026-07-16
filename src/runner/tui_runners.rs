use std::path::PathBuf;

use anyhow::Result;
use chrono::Utc;
use tokio::sync::mpsc;

use crate::audit_log;
use crate::evidence::{
    CollectParams, CsvCollector, EvidenceCollector, EvidenceReport, JsonCollector,
    JsonInventoryReport, ReportMetadata,
};
use crate::runner::failure_classifier;
use crate::runner::output::{evidence_basename, write_csv_bytes_with_manifest};
use crate::tui::{App, PoamSummary, Progress, Screen};

pub async fn run_tui_csv_collector(
    collector: &Box<dyn CsvCollector>,
    account_id: &str,
    region: &str,
    out_dir: &PathBuf,
    _timestamp: &str,
    tx: &mpsc::UnboundedSender<Progress>,
    timeout: std::time::Duration,
    written: &mut Vec<String>,
    outcomes: &mut Vec<audit_log::CollectorOutcome>,
    dates: Option<(i64, i64)>,
) {
    let name = collector.name().to_string();
    let _ = tx.send(Progress::Started {
        collector: name.clone(),
    });
    match tokio::time::timeout(timeout, collector.collect_rows(account_id, region, dates)).await {
        Ok(Ok(rows)) => {
            let count = rows.len();
            let _ = tx.send(Progress::Done {
                collector: name.clone(),
                count,
            });
            if count == 0 {
                eprintln!("  [csv] {} ({}): 0 rows — no file written", name, region);
                outcomes.push(audit_log::CollectorOutcome::empty(&name));
                return;
            }
            eprintln!("  [csv] {} ({}): {} rows", name, region, count);
            let basename = evidence_basename(account_id, collector.filename_prefix(), "csv");
            let mapping = collector.fedramp_mapping();
            let path = out_dir.join(&basename);
            if let Ok(bytes) =
                write_csv_bytes_with_manifest(collector.headers(), &rows, &mapping, &basename)
            {
                if std::fs::write(&path, bytes).is_ok() {
                    outcomes.push(audit_log::CollectorOutcome::success(&name, count, &path));
                    written.push(path.display().to_string());
                } else {
                    outcomes.push(audit_log::CollectorOutcome::error(
                        &name,
                        "write failed".to_string(),
                    ));
                }
            } else {
                outcomes.push(audit_log::CollectorOutcome::error(
                    &name,
                    "CSV serialisation failed".to_string(),
                ));
            }
        }
        Ok(Err(e)) => {
            let msg = format!("{:#}", e);
            eprintln!("  ERROR [csv] {}: {}", name, msg);
            if let Some(reason) = failure_classifier::classify_failure(&name, &msg) {
                let _ = tx.send(Progress::Skipped {
                    collector: name.clone(),
                    reason: reason.to_string(),
                });
                outcomes.push(audit_log::CollectorOutcome::skipped(&name, reason));
            } else {
                let _ = tx.send(Progress::Error {
                    collector: name.clone(),
                    message: msg.clone(),
                });
                outcomes.push(audit_log::CollectorOutcome::error(&name, msg));
            }
        }
        Err(_) => {
            eprintln!("  ERROR [csv] {}: timed out after 3 minutes", name);
            if let Some(reason) = failure_classifier::classify_timeout(&name) {
                let _ = tx.send(Progress::Skipped {
                    collector: name.clone(),
                    reason: reason.to_string(),
                });
                outcomes.push(audit_log::CollectorOutcome::skipped(&name, reason));
            } else {
                let _ = tx.send(Progress::Error {
                    collector: name.clone(),
                    message: "timed out after 3 minutes".to_string(),
                });
                outcomes.push(audit_log::CollectorOutcome::timeout(&name));
            }
        }
    }
}

pub async fn run_tui_inv_collector(
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
    let _ = tx.send(Progress::Started {
        collector: name.clone(),
    });
    match tokio::time::timeout(timeout, collector.collect_records(account_id, region)).await {
        Ok(Ok(records)) => {
            let count = records.len();
            let _ = tx.send(Progress::Done {
                collector: name.clone(),
                count,
            });
            if count == 0 {
                outcomes.push(audit_log::CollectorOutcome::empty(&name));
                return;
            }
            let filename = format!(
                "{}_{}-{}.json",
                account_id,
                collector.filename_prefix(),
                timestamp
            );
            let report = JsonInventoryReport {
                collected_at: Utc::now().to_rfc3339(),
                account_id: account_id.to_string(),
                region: region.to_string(),
                collector: name.clone(),
                record_count: count,
                records,
                fedramp_manifest: crate::fedramp_map::FedRampManifest::new(
                    &collector.fedramp_mapping(),
                    &filename,
                ),
            };
            let path = out_dir.join(&filename);
            if let Ok(json) = serde_json::to_string_pretty(&report) {
                if std::fs::write(&path, json).is_ok() {
                    outcomes.push(audit_log::CollectorOutcome::success(&name, count, &path));
                    written.push(path.display().to_string());
                } else {
                    outcomes.push(audit_log::CollectorOutcome::error(
                        &name,
                        "write failed".to_string(),
                    ));
                }
            } else {
                outcomes.push(audit_log::CollectorOutcome::error(
                    &name,
                    "JSON serialisation failed".to_string(),
                ));
            }
        }
        Ok(Err(e)) => {
            let msg = format!("{:#}", e);
            eprintln!("  ERROR [inv] {}: {}", name, msg);
            if let Some(reason) = failure_classifier::classify_failure(&name, &msg) {
                let _ = tx.send(Progress::Skipped {
                    collector: name.clone(),
                    reason: reason.to_string(),
                });
                outcomes.push(audit_log::CollectorOutcome::skipped(&name, reason));
            } else {
                let _ = tx.send(Progress::Error {
                    collector: name.clone(),
                    message: msg.clone(),
                });
                outcomes.push(audit_log::CollectorOutcome::error(&name, msg));
            }
        }
        Err(_) => {
            eprintln!("  ERROR [inv] {}: timed out after 3 minutes", name);
            if let Some(reason) = failure_classifier::classify_timeout(&name) {
                let _ = tx.send(Progress::Skipped {
                    collector: name.clone(),
                    reason: reason.to_string(),
                });
                outcomes.push(audit_log::CollectorOutcome::skipped(&name, reason));
            } else {
                let _ = tx.send(Progress::Error {
                    collector: name.clone(),
                    message: "timed out after 3 minutes".to_string(),
                });
                outcomes.push(audit_log::CollectorOutcome::timeout(&name));
            }
        }
    }
}

pub async fn run_tui_json_collector(
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
    let _ = tx.send(Progress::Started {
        collector: name.clone(),
    });
    match tokio::time::timeout(timeout, collector.collect(params)).await {
        Ok(Ok(records)) => {
            let count = records.len();
            let _ = tx.send(Progress::Done {
                collector: name.clone(),
                count,
            });
            if count == 0 {
                outcomes.push(audit_log::CollectorOutcome::empty(&name));
                return;
            }
            let filename = format!(
                "{}_{}-{}.json",
                account_id,
                collector.filename_prefix(),
                timestamp
            );
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
                fedramp_manifest: Some(crate::fedramp_map::FedRampManifest::new(
                    &collector.fedramp_mapping(),
                    &filename,
                )),
            };
            let path = out_dir.join(&filename);
            if let Ok(json) = serde_json::to_string_pretty(&report) {
                if std::fs::write(&path, json).is_ok() {
                    outcomes.push(audit_log::CollectorOutcome::success(&name, count, &path));
                    written.push(path.display().to_string());
                } else {
                    outcomes.push(audit_log::CollectorOutcome::error(
                        &name,
                        "write failed".to_string(),
                    ));
                }
            } else {
                outcomes.push(audit_log::CollectorOutcome::error(
                    &name,
                    "JSON serialisation failed".to_string(),
                ));
            }
        }
        Ok(Err(e)) => {
            let msg = format!("{:#}", e);
            eprintln!("  ERROR [json] {}: {}", name, msg);
            if let Some(reason) = failure_classifier::classify_failure(&name, &msg) {
                let _ = tx.send(Progress::Skipped {
                    collector: name.clone(),
                    reason: reason.to_string(),
                });
                outcomes.push(audit_log::CollectorOutcome::skipped(&name, reason));
            } else {
                let _ = tx.send(Progress::Error {
                    collector: name.clone(),
                    message: msg.clone(),
                });
                outcomes.push(audit_log::CollectorOutcome::error(&name, msg));
            }
        }
        Err(_) => {
            eprintln!("  ERROR [json] {}: timed out after 3 minutes", name);
            if let Some(reason) = failure_classifier::classify_timeout(&name) {
                let _ = tx.send(Progress::Skipped {
                    collector: name.clone(),
                    reason: reason.to_string(),
                });
                outcomes.push(audit_log::CollectorOutcome::skipped(&name, reason));
            } else {
                let _ = tx.send(Progress::Error {
                    collector: name.clone(),
                    message: "timed out after 3 minutes".to_string(),
                });
                outcomes.push(audit_log::CollectorOutcome::timeout(&name));
            }
        }
    }
}

pub async fn run_tui_poam(
    terminal: &mut ratatui::Terminal<ratatui::backend::CrosstermBackend<std::io::Stdout>>,
    app: &mut App,
    tx: mpsc::UnboundedSender<Progress>,
    evidence_base: String,
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

        let evidence_path =
            crate::poam::resolve_evidence_path(&evidence_base, &region, &year, &month_name)
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| String::new());

        match crate::poam::run_poam(&evidence_base, &region, &year, &month_name) {
            Ok(result) => {
                let mut files: Vec<String> = vec![result.workbook_path.display().to_string()];
                if let Some(csv) = &result.selected_csv {
                    files.push(result.evidence_path.join(csv).display().to_string());
                }
                let _ = tx.send(Progress::Done {
                    collector: collector_name,
                    count: result.added_open_count + result.moved_closed_count,
                });
                let summary = PoamSummary {
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
                let summary = PoamSummary {
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

        terminal.draw(|f| crate::tui::ui::draw(f, app))?;

        if app.screen == Screen::Results {
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
