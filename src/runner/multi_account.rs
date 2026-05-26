use std::path::PathBuf;

use anyhow::Result;
use chrono::{Local, Utc};
use tokio::sync::mpsc;

use crate::audit_log;
use crate::evidence::{CollectParams, CsvCollector, EvidenceCollector, JsonCollector};
use crate::runner::output::{date_path_suffix, write_csv_bytes};
use crate::runner::tui_runners::{
    run_tui_csv_collector, run_tui_inv_collector, run_tui_json_collector,
};
use crate::tui::{App, Progress, Screen};

/// Collectors that query account-global AWS services. In all-regions mode
/// these run once against the primary region rather than once per region.
pub const GLOBAL_COLLECTOR_KEYS: &[&str] = &[
    // IAM (global)
    "iam-users",
    "iam-roles",
    "iam-policies",
    "iam-access-keys",
    "iam-certs",
    "iam-trusts",
    "iam-role-policies",
    "iam-user-policies",
    "iam-password-policy",
    "iam-account-summary",
    // S3 (bucket list is global)
    "s3-config",
    "s3-logging",
    "s3-policies",
    "s3-encryption",
    "s3-bucket-policy",
    "s3-public-access",
    "s3-logging-config",
    "s3-data-events",
    // CloudFront (global)
    "cloudfront",
    // Route53 (global)
    "route53-zones",
    "route53-resolver",
    // Organizations / account (global)
    "scp",
    "org-config",
    "account-contacts",
    "saml-providers",
];

/// Pre-built account data ready for the background collection task.
/// AWS configs and SDK clients must be created on the main async task (not inside
/// tokio::spawn) so that the HTTP/TLS connector initializes correctly.
pub struct AccountCollectors {
    pub account_id: String,
    pub aws_caller_arn: String,
    pub aws_user_id: String,
    pub profile: String,
    pub region: String,
    pub output_path: Option<PathBuf>,
    #[allow(dead_code)]
    pub collector_keys: Vec<String>,
    pub json_collectors: Vec<Box<dyn EvidenceCollector>>,
    pub json_inv_collectors: Vec<Box<dyn JsonCollector>>,
    pub csv_collectors: Vec<Box<dyn CsvCollector>>,
    pub display_names: Vec<String>,
    /// Optional endpoint label shown in the Running-screen header for providers
    /// that aren't AWS-region-scoped (e.g. Tenable: "Tenable.io (FedRAMP) — https://fedcloud.tenable.com").
    pub endpoint_label: Option<String>,
    /// Pre-discovered regions (if all-regions was requested). Empty = use single-region path.
    pub discovered_regions: Vec<String>,
    /// Pre-built regional collectors for each discovered region.
    /// Each entry: (region_name, out_dir, csv_collectors, inv_collectors, json_collectors)
    pub regional_collectors: Vec<(
        String,
        PathBuf,
        Vec<Box<dyn CsvCollector>>,
        Vec<Box<dyn JsonCollector>>,
        Vec<Box<dyn EvidenceCollector>>,
    )>,
    /// Inventory-mode multi-region collectors: one per region, all rows merged
    /// into a single output CSV. Each entry: (region_name, collector).
    pub inventory_multi_region: Vec<(String, Box<dyn CsvCollector>)>,
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
pub async fn run_tui_multi_account(
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

    tokio::spawn(async move {
        let mut all_written_files: Vec<String> = Vec::new();
        let collector_timeout = std::time::Duration::from_secs(600); // 10 minutes
        let run_id = Utc::now().format("%Y-%m-%d-%H%M%S").to_string();
        let timestamp = run_id.clone();
        let started_at = Utc::now().to_rfc3339();
        let dates = Some((
            params_clone.start_time.timestamp(),
            params_clone.end_time.timestamp(),
        ));
        let coll_start = params_clone.start_time.format("%Y-%m-%d").to_string();
        let coll_end = params_clone.end_time.format("%Y-%m-%d").to_string();

        let is_inventory_mode = prepared
            .iter()
            .any(|a| !a.inventory_multi_region.is_empty());
        let mut inventory_global_rows: Vec<Vec<String>> = Vec::new();
        let inventory_out_dir = prepared
            .iter()
            .find(|a| !a.inventory_multi_region.is_empty())
            .and_then(|a| a.output_path.clone())
            .unwrap_or_else(|| PathBuf::from("."));
        let inventory_headers: &'static [&'static str] = if is_inventory_mode {
            crate::inventory_core::INVENTORY_CSV_HEADERS
        } else {
            &[]
        };

        for (acct_idx, acct) in prepared.into_iter().enumerate() {
            let out_dir = {
                let base = acct
                    .output_path
                    .clone()
                    .unwrap_or_else(|| PathBuf::from("."));
                if !is_inventory_mode && acct.discovered_regions.is_empty() {
                    if acct.region.is_empty() {
                        // Tenable (and any future regionless provider): site_name is already
                        // embedded in `base` via output_path; just append the date hierarchy.
                        base.join(date_path_suffix())
                    } else {
                        base.join(&acct.region).join(date_path_suffix())
                    }
                } else {
                    base
                }
            };
            if let Err(e) = std::fs::create_dir_all(&out_dir) {
                let _ = tx.send(Progress::Error {
                    collector: format!("output dir ({})", acct.account_id),
                    message: format!("could not create {}: {e}", out_dir.display()),
                });
                let _ = tx.send(Progress::AccountFinished {
                    name: acct.account_id.clone(),
                });
                continue;
            }

            eprintln!(
                "=== Account {}/{}: {} (profile={}, region={}, out={}) ===",
                acct_idx + 1,
                total_accounts,
                acct.account_id,
                acct.profile,
                acct.region,
                out_dir.display()
            );
            eprintln!(
                "  collectors: json={}, inv={}, csv={}",
                acct.json_collectors.len(),
                acct.json_inv_collectors.len(),
                acct.csv_collectors.len()
            );

            let _ = tx.send(Progress::AccountStarted {
                name: acct.account_id.clone(),
                index: acct_idx + 1,
                total: total_accounts,
                region: acct.region.clone(),
                collectors: acct.display_names,
                endpoint_label: acct.endpoint_label.clone(),
            });

            let mut acct_outcomes: Vec<audit_log::CollectorOutcome> = Vec::new();
            let has_inventory_multi_region = !acct.inventory_multi_region.is_empty();

            // ── Inventory multi-region path ──────────────────────────────────────
            if has_inventory_multi_region {
                let collector_name = format!(
                    "{} ({} regions)",
                    acct.inventory_multi_region[0].1.name(),
                    acct.inventory_multi_region.len(),
                );
                let total_regions = acct.inventory_multi_region.len();
                let _ = tx.send(Progress::Started {
                    collector: collector_name.clone(),
                });

                let mut join_set: tokio::task::JoinSet<(
                    String,
                    std::result::Result<Vec<Vec<String>>, anyhow::Error>,
                )> = tokio::task::JoinSet::new();
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
                            eprintln!(
                                "  [inventory] region {}/{}: {} — {} rows",
                                completed, total_regions, region_name, row_count
                            );
                            acct_rows.extend(rows);
                            let _ = tx.send(Progress::Done {
                                collector: format!(
                                    "{} [{}/{}]",
                                    collector_name, completed, total_regions
                                ),
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

                eprintln!(
                    "  [inventory] account {} done: {} rows this account",
                    acct.account_id,
                    acct_rows.len()
                );
                inventory_global_rows.extend(acct_rows);
            }

            // ── All-regions path ─────────────────────────────────────────────────
            if !acct.discovered_regions.is_empty() && !has_inventory_multi_region {
                eprintln!(
                    "  all-regions: {} regions pre-built",
                    acct.discovered_regions.len()
                );
                for (region_name, rdir, rcsv, rinv, rjson) in &acct.regional_collectors {
                    let _ = tx.send(Progress::RegionStarted {
                        region: region_name.clone(),
                    });
                    let _ = std::fs::create_dir_all(rdir);
                    for collector in rcsv {
                        run_tui_csv_collector(
                            collector,
                            &acct.account_id,
                            region_name,
                            rdir,
                            &timestamp,
                            &tx,
                            collector_timeout,
                            &mut all_written_files,
                            &mut acct_outcomes,
                            dates,
                        )
                        .await;
                    }
                    for collector in rinv {
                        run_tui_inv_collector(
                            collector,
                            &acct.account_id,
                            region_name,
                            rdir,
                            &timestamp,
                            &tx,
                            collector_timeout,
                            &mut all_written_files,
                            &mut acct_outcomes,
                        )
                        .await;
                    }
                    for collector in rjson {
                        run_tui_json_collector(
                            collector,
                            &params_clone,
                            region_name,
                            &acct.account_id,
                            rdir,
                            &timestamp,
                            &tx,
                            collector_timeout,
                            &mut all_written_files,
                            &mut acct_outcomes,
                        )
                        .await;
                    }
                }
            } else if acct.discovered_regions.is_empty() && !has_inventory_multi_region {
                // ── Single-region path ───────────────────────────────────────────
                for collector in &acct.json_collectors {
                    run_tui_json_collector(
                        collector,
                        &params_clone,
                        &acct.region,
                        &acct.account_id,
                        &out_dir,
                        &timestamp,
                        &tx,
                        collector_timeout,
                        &mut all_written_files,
                        &mut acct_outcomes,
                    )
                    .await;
                }
                for collector in &acct.json_inv_collectors {
                    run_tui_inv_collector(
                        collector,
                        &acct.account_id,
                        &acct.region,
                        &out_dir,
                        &timestamp,
                        &tx,
                        collector_timeout,
                        &mut all_written_files,
                        &mut acct_outcomes,
                    )
                    .await;
                }
                if is_inventory_mode {
                    for collector in &acct.csv_collectors {
                        let name = collector.name().to_string();
                        let _ = tx.send(Progress::Started {
                            collector: name.clone(),
                        });
                        match tokio::time::timeout(
                            collector_timeout,
                            collector.collect_rows(&acct.account_id, &acct.region, dates),
                        )
                        .await
                        {
                            Ok(Ok(rows)) => {
                                let count = rows.len();
                                inventory_global_rows.extend(rows);
                                let _ = tx.send(Progress::Done {
                                    collector: name,
                                    count,
                                });
                            }
                            Ok(Err(e)) => {
                                let _ = tx.send(Progress::Error {
                                    collector: name,
                                    message: format!("{e:#}"),
                                });
                            }
                            Err(_) => {
                                let _ = tx.send(Progress::Error {
                                    collector: name,
                                    message: "timed out".to_string(),
                                });
                            }
                        }
                    }
                } else {
                    for collector in &acct.csv_collectors {
                        run_tui_csv_collector(
                            collector,
                            &acct.account_id,
                            &acct.region,
                            &out_dir,
                            &timestamp,
                            &tx,
                            collector_timeout,
                            &mut all_written_files,
                            &mut acct_outcomes,
                            dates,
                        )
                        .await;
                    }
                }
            }

            // ── Write run manifest ───────────────────────────────────────────────
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

            // ── Write chain-of-custody log ───────────────────────────────────────
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

            let _ = tx.send(Progress::AccountFinished {
                name: acct.account_id,
            });
        }

        eprintln!(
            "=== All accounts done. {} files written. ===",
            all_written_files.len()
        );

        // ── Write single unified inventory CSV (all accounts + all regions) ──────
        if !inventory_global_rows.is_empty() {
            if !skip_inventory_csv {
                let _ = std::fs::create_dir_all(&inventory_out_dir);
                let filename = format!("AWS_Inventory-{}.csv", timestamp);
                let path = inventory_out_dir.join(&filename);
                match write_csv_bytes(inventory_headers, &inventory_global_rows) {
                    Ok(bytes) => {
                        if std::fs::write(&path, bytes).is_ok() {
                            eprintln!(
                                "=== Inventory CSV: {} ({} rows) ===",
                                path.display(),
                                inventory_global_rows.len()
                            );
                            all_written_files.push(path.display().to_string());
                        } else {
                            eprintln!(
                                "=== ERROR: could not write inventory CSV to {} ===",
                                path.display()
                            );
                        }
                    }
                    Err(e) => {
                        eprintln!("=== ERROR: inventory CSV serialisation failed: {e:#} ===")
                    }
                }
            }

            // ── Write inventory Excel workbook from template ──────────────────────
            let now_local = Local::now();
            let year = now_local.format("%Y").to_string();
            let month_num = now_local.format("%m").to_string();
            let month_abbr = match month_num.as_str() {
                "01" => "JAN",
                "02" => "FEB",
                "03" => "MAR",
                "04" => "APR",
                "05" => "MAY",
                "06" => "JUN",
                "07" => "JUL",
                "08" => "AUG",
                "09" => "SEP",
                "10" => "OCT",
                "11" => "NOV",
                "12" => "DEC",
                other => {
                    eprintln!("=== WARN: unexpected month '{other}', using 'UNK' in path ===");
                    "UNK"
                }
            };
            let xlsx_filename = now_local
                .format("%Y-%m-%d_Inventory_%H-%M-%S.xlsx")
                .to_string();
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
            match crate::zip_bundle::bundle_files(&all_written_files, &base, &zip_path) {
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
            match crate::signing::SigningKey::generate() {
                Ok(key) => {
                    eprintln!(
                        "=== Signing {} files with HMAC-SHA256 ===",
                        all_written_files.len()
                    );
                    match crate::signing::sign_files(&all_written_files, &timestamp, &key, &cwd) {
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
