use std::path::PathBuf;

use anyhow::{Context, Result};
use aws_config::{BehaviorVersion, Region};
use chrono::NaiveDate;
use tokio::sync::mpsc;

use crate::cli::Cli;
use crate::evidence::CsvCollector;
use crate::inventory_orchestrator::InventoryCollector;
use crate::runner::collector_registry;
use crate::runner::multi_account::{
    run_tui_multi_account, AccountCollectors, GLOBAL_COLLECTOR_KEYS,
};
use crate::runner::output::date_path_suffix;
use crate::runner::tui_runners::run_tui_poam;
use crate::tui::{
    read_aws_profiles, restore_terminal, run as run_tui, setup_terminal, App, CollectorState,
    CollectorStatus, Feature, Progress,
};

pub async fn run_tui_session(_cli: &Cli) -> Result<()> {
    let profiles = read_aws_profiles();
    let mut app = App::new(profiles);

    // Pre-populate Jira project list so the JiraProjectSelection screen has data ready.
    // Uses the first configured Jira account's credentials.
    #[cfg(feature = "jira")]
    {
        use crate::providers::CloudProvider;
        use crate::tui::state::JiraProjectItem;
        if let Some(acct) = app
            .accounts
            .iter()
            .find(|a| a.provider == CloudProvider::Jira)
        {
            if let (Some(domain), Some(email), Some(token)) = (
                acct.jira_domain_resolved(),
                acct.jira_email_resolved(),
                acct.jira_api_token_resolved(),
            ) {
                if let Ok(client) = jira_rs::JiraClient::new(&domain, &email, &token) {
                    if let Ok(projects) = client.projects().list_all().await {
                        app.jira_project_list = projects
                            .into_iter()
                            .map(|p| JiraProjectItem {
                                key: p.key,
                                name: p.name,
                            })
                            .collect();
                    }
                }
            }
        }
    }

    // Pre-populate scan list so the ScanSelection screen has data ready.
    // Uses the first configured Tenable account's credentials.
    #[cfg(feature = "tenable")]
    {
        use crate::providers::CloudProvider;
        use crate::tui::scan::TuiScan;
        if let Some(acct) = app
            .accounts
            .iter()
            .find(|a| a.provider == CloudProvider::Tenable)
        {
            if let (Some(ak), Some(sk)) = (
                acct.tenable_access_key_resolved(),
                acct.tenable_secret_key_resolved(),
            ) {
                let base_url = acct.tenable_url_resolved();
                let client_result =
                    tenable_rs::TenableClient::from_url(&base_url, &ak, &sk).map(|(c, _)| c);
                if let Ok(client) = client_result {
                    let mut combined: Vec<TuiScan> = Vec::new();
                    if let Ok(vm_scans) = client.scans().list().await {
                        combined.extend(vm_scans.into_iter().map(TuiScan::Vm));
                    }
                    if let Ok(was_scans) = client.was().list_scans().await {
                        combined.extend(was_scans.into_iter().map(TuiScan::Was));
                    }
                    app.scan_list = combined;
                }
            }
        }
    }

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
            let evidence_base = app.poam_evidence_base();
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
            app.screen = crate::tui::Screen::Running;

            let mut terminal = setup_terminal()?;
            terminal.draw(|f| crate::tui::ui::draw(f, &app))?;
            let restart = run_tui_poam(
                &mut terminal,
                &mut app,
                tx,
                evidence_base,
                region,
                year,
                month_name,
            )
            .await?;
            restore_terminal(&mut terminal)?;

            if !restart {
                return Ok(());
            }
            continue;
        }
        {
            // Build params from what the user configured in the TUI.
            #[cfg(feature = "tenable")]
            let is_tenable = app.selected_provider == crate::providers::CloudProvider::Tenable;
            #[cfg(not(feature = "tenable"))]
            let is_tenable = false;

            let params = if is_tenable {
                // Tenable uses scan selection instead of date ranges; provide a sentinel.
                crate::evidence::CollectParams {
                    start_time: chrono::Utc::now(),
                    end_time: chrono::Utc::now(),
                    filter: None,
                    include_raw: false,
                }
            } else {
                let start = NaiveDate::parse_from_str(&app.start_date.value, "%Y-%m-%d")
                    .context("invalid start date from TUI")?
                    .and_hms_opt(0, 0, 0)
                    .expect("valid midnight time")
                    .and_utc();
                let end = NaiveDate::parse_from_str(&app.end_date.value, "%Y-%m-%d")
                    .context("invalid end date from TUI")?
                    .and_hms_opt(23, 59, 59)
                    .expect("valid end-of-day time")
                    .and_utc();
                crate::evidence::CollectParams {
                    start_time: start,
                    end_time: end,
                    filter: if app.filter_input.value.is_empty() {
                        None
                    } else {
                        Some(app.filter_input.value.clone())
                    },
                    include_raw: app.include_raw,
                }
            };

            let base_output_path = if app.output_dir.value.is_empty() {
                None
            } else {
                Some(PathBuf::from(&app.output_dir.value))
            };

            // Build the list of accounts to iterate over.
            // Each entry: (profile, region, account_id, output_path, collector_keys)
            let mut account_runs: Vec<(String, String, String, Option<PathBuf>, Vec<String>)> =
                Vec::new();

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
                let account_id = crate::aws_loader::print_identity(&cfg).await;
                let collectors = if is_inventory {
                    inventory_collector_keys.clone()
                } else {
                    app.selected_collectors()
                };
                account_runs.push((
                    profile,
                    region,
                    account_id,
                    base_output_path.clone(),
                    collectors,
                ));
            } else {
                let mut sorted: Vec<usize> = app.selected_accounts.iter().copied().collect();
                sorted.sort();
                let multi = sorted.len() > 1;
                for &idx in &sorted {
                    // Non-AWS providers are handled after the AWS prep loop.
                    if app.accounts[idx].provider != crate::providers::CloudProvider::Aws {
                        continue;
                    }
                    let (profile, region, acct_output_dir, collector_keys_from_toml) =
                        app.resolve_account_settings(idx);
                    let collector_keys = if is_inventory {
                        inventory_collector_keys.clone()
                    } else {
                        collector_keys_from_toml
                    };
                    let raw_name = app.accounts[idx].name.clone();
                    let sanitized: String = raw_name
                        .chars()
                        .map(|c| {
                            if c.is_alphanumeric() || c == '-' {
                                c
                            } else {
                                '_'
                            }
                        })
                        .collect();
                    let output_path = if let Some(dir) = acct_output_dir {
                        Some(PathBuf::from(dir))
                    } else if multi {
                        // Multi-account: isolate into subdirectory per account.
                        Some(
                            base_output_path
                                .clone()
                                .unwrap_or_else(|| PathBuf::from("."))
                                .join(&sanitized),
                        )
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
                let dir = base_output_path
                    .clone()
                    .unwrap_or_else(|| PathBuf::from("."));
                let _ = std::fs::create_dir_all(&dir);
                dir.join("evidence-collection.log")
            };
            let stderr_backup = crate::platform::redirect_stderr_to_file(&log_path);

            // Enter the TUI immediately — show Preparing screen while we build.
            app.screen = crate::tui::Screen::Preparing;
            app.prep_total = total_accounts;
            app.prep_log.push(format!(
                "Building AWS SDK clients for {} account(s){}…",
                total_accounts,
                if use_all_regions {
                    " across all enabled regions"
                } else {
                    ""
                },
            ));
            let mut terminal = setup_terminal()?;
            terminal.draw(|f| crate::tui::ui::draw(f, &app))?;

            let mut prepared: Vec<AccountCollectors> = Vec::with_capacity(account_runs.len());
            for (acct_idx, (profile, region, account_id, output_path, collector_keys)) in
                account_runs.into_iter().enumerate()
            {
                app.prep_current = acct_idx + 1;
                app.prep_log.push(format!(
                    "  [{}/{}] {}  (profile: {})",
                    acct_idx + 1,
                    total_accounts,
                    account_id,
                    profile,
                ));
                terminal.draw(|f| crate::tui::ui::draw(f, &app))?;
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
                let (canary_ok, aws_caller_arn, aws_user_id, resolved_account_id) =
                    match sts.get_caller_identity().send().await {
                        Ok(resp) => {
                            let arn = resp.arn().unwrap_or("unknown").to_string();
                            let uid = resp.user_id().unwrap_or("unknown").to_string();
                            let resolved = resp.account().unwrap_or("unknown").to_string();
                            app.prep_log
                                .push(format!("  ✓ Credentials OK  account={}", resolved));
                            (true, arn, uid, resolved)
                        }
                        Err(e) => {
                            app.prep_log.push(format!(
                            "  ✗ Credentials FAILED — skipping. Run: aws sso login --profile {}",
                            profile,
                        ));
                            app.prep_log.push(format!("    ({})", e));
                            (false, String::new(), String::new(), String::new())
                        }
                    };
                terminal.draw(|f| crate::tui::ui::draw(f, &app))?;

                if !canary_ok {
                    // Don't build any collectors for this account — it has no
                    // working credentials and every AWS API call would fail.
                    app.prep_log.push("    ↷ Account skipped.".to_string());
                    terminal.draw(|f| crate::tui::ui::draw(f, &app))?;
                    continue;
                }

                // From here on, use the real numeric AWS account ID (not the
                // sanitized display name from config.toml) — this value is
                // embedded directly into hand-built ARNs (VPC, IGW, NAT,
                // TGW attachment, Config recorder, GuardDuty detector) by the
                // inventory orchestrator, so a display name here would
                // produce malformed ARNs.
                let account_id = resolved_account_id;

                let names_ref: Vec<&str> = collector_keys.iter().map(|s| s.as_str()).collect();

                // Pre-discover or explicitly set the region list.
                let mut discovered_regions: Vec<String> = Vec::new();
                let mut regional_collectors = Vec::new();
                let mut inventory_multi_region: Vec<(String, Box<dyn CsvCollector>)> = Vec::new();
                if use_all_regions {
                    app.prep_log
                        .push("    Discovering enabled regions…".to_string());
                    terminal.draw(|f| crate::tui::ui::draw(f, &app))?;
                    discovered_regions = crate::aws_loader::discover_regions(&probe_config).await;
                    if discovered_regions.is_empty() {
                        app.prep_log.push(format!(
                            "  ✗ Could not discover regions for {}, falling back to {}",
                            account_id, region,
                        ));
                        terminal.draw(|f| crate::tui::ui::draw(f, &app))?;
                    }
                } else if !explicit_regions.is_empty() {
                    // User selected specific regions — no discovery needed.
                    discovered_regions = explicit_regions.clone();
                    app.prep_log.push(format!(
                        "    Using {} explicitly selected region(s): {}",
                        discovered_regions.len(),
                        discovered_regions.join(", "),
                    ));
                    terminal.draw(|f| crate::tui::ui::draw(f, &app))?;
                }
                // ── Build regional collectors from whatever list we now have ─────────
                if !discovered_regions.is_empty() {
                    app.prep_log.push(format!(
                        "    Building collectors for {} region(s)…",
                        discovered_regions.len()
                    ));
                    terminal.draw(|f| crate::tui::ui::draw(f, &app))?;
                    let out_base = output_path.clone().unwrap_or_else(|| PathBuf::from("."));

                    if is_inventory {
                        // Inventory mode: one InventoryCollector per region, all rows merged
                        // into a single CSV at the end — no region subdirectories.
                        let region_total = discovered_regions.len();
                        for (ridx, region_name) in discovered_regions.iter().enumerate() {
                            if let Some(last) = app.prep_log.last_mut() {
                                *last = format!(
                                    "    Region {:>2}/{}: {}",
                                    ridx + 1,
                                    region_total,
                                    region_name,
                                );
                            }
                            terminal.draw(|f| crate::tui::ui::draw(f, &app))?;
                            let rcfg = aws_config::defaults(BehaviorVersion::latest())
                                .region(Region::new(region_name.clone()))
                                .profile_name(if profile.is_empty() || profile == "default" {
                                    "default"
                                } else {
                                    &profile
                                })
                                .load()
                                .await;
                            inventory_multi_region.push((
                                region_name.clone(),
                                Box::new(InventoryCollector::new(&rcfg, inventory_types.clone()))
                                    as Box<dyn CsvCollector>,
                            ));
                        }
                        if let Some(last) = app.prep_log.last_mut() {
                            *last = format!("    All {} regions ready.", region_total);
                        }
                    } else {
                        let global_csv_keys: Vec<&str> = names_ref
                            .iter()
                            .copied()
                            .filter(|k| GLOBAL_COLLECTOR_KEYS.contains(k))
                            .collect();
                        let regional_csv_keys: Vec<&str> = names_ref
                            .iter()
                            .copied()
                            .filter(|k| !GLOBAL_COLLECTOR_KEYS.contains(k))
                            .collect();
                        let global_inv_keys: Vec<&str> =
                            ["iam-roles", "iam-role-policies", "iam-user-policies"]
                                .iter()
                                .copied()
                                .filter(|k| {
                                    names_ref.contains(k) && GLOBAL_COLLECTOR_KEYS.contains(k)
                                })
                                .collect();
                        let regional_inv_keys: Vec<&str> =
                            ["eventbridge-rules", "ct-config-changes", "kms-config"]
                                .iter()
                                .copied()
                                .filter(|k| names_ref.contains(k))
                                .collect();
                        let json_keys: Vec<&str> = ["cloudtrail", "backup", "rds"]
                            .iter()
                            .copied()
                            .filter(|k| names_ref.contains(k))
                            .collect();
                        // Global collectors: run once from the account's base region.
                        // Route into <out_base>/<base_region>/YYYY/##-MMM so the output
                        // sits alongside per-region evidence in the date-based hierarchy.
                        if !global_csv_keys.is_empty() || !global_inv_keys.is_empty() {
                            let gcfg = make_cfg().load().await;
                            let gdir = out_base.join(&region).join(date_path_suffix());
                            regional_collectors.push((
                                region.clone(),
                                gdir,
                                collector_registry::build_csv_collectors(&global_csv_keys, &gcfg),
                                collector_registry::build_json_inv_collectors(
                                    &global_inv_keys,
                                    &gcfg,
                                ),
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
                                    ridx + 1,
                                    region_total,
                                    region_name,
                                );
                            }
                            terminal.draw(|f| crate::tui::ui::draw(f, &app))?;
                            let rcfg = aws_config::defaults(BehaviorVersion::latest())
                                .region(Region::new(region_name.clone()))
                                .profile_name(if profile.is_empty() || profile == "default" {
                                    "default"
                                } else {
                                    &profile
                                })
                                .load()
                                .await;
                            let rdir = out_base.join(region_name).join(date_path_suffix());
                            regional_collectors.push((
                                region_name.clone(),
                                rdir,
                                collector_registry::build_csv_collectors(&regional_csv_keys, &rcfg),
                                collector_registry::build_json_inv_collectors(
                                    &regional_inv_keys,
                                    &rcfg,
                                ),
                                collector_registry::build_json_collectors(&json_keys, &rcfg),
                            ));
                        }
                        if let Some(last) = app.prep_log.last_mut() {
                            *last = format!("    All {} regions ready.", region_total);
                        }
                    }
                    terminal.draw(|f| crate::tui::ui::draw(f, &app))?;
                }

                // ── Work config (fresh, never used for API calls) ─────────────────
                // Build a brand-new config so its credential provider has never been
                // touched.  It will initialise correctly the first time it is used
                // inside tokio::spawn.
                let work_config = make_cfg().load().await;

                // Build single-region collectors from the fresh work config.
                // For inventory mode with multi-region, all collection is in regional_collectors;
                // only build a base InventoryCollector when no regions were discovered (single-region path).
                let json_collectors =
                    collector_registry::build_json_collectors(&names_ref, &work_config);
                let json_inv_collectors =
                    collector_registry::build_json_inv_collectors(&names_ref, &work_config);
                let csv_collectors = if is_inventory {
                    if discovered_regions.is_empty() {
                        // Single-region fallback (SetOptions left all-regions and explicit-regions blank).
                        vec![Box::new(InventoryCollector::new(
                            &work_config,
                            inventory_types.clone(),
                        )) as Box<dyn CsvCollector>]
                    } else {
                        // Regional collectors were built above; nothing needed here.
                        Vec::new()
                    }
                } else {
                    collector_registry::build_csv_collectors(&names_ref, &work_config)
                };

                let mut display_names: Vec<String> = json_collectors
                    .iter()
                    .map(|c| c.name().to_string())
                    .chain(json_inv_collectors.iter().map(|c| c.name().to_string()))
                    .chain(csv_collectors.iter().map(|c| c.name().to_string()))
                    .collect();

                // If all-regions, add regional collector names to the display list.
                for (rname, _, rcsv, rinv, rjson) in &regional_collectors {
                    for c in rcsv {
                        if !display_names.contains(&c.name().to_string()) {
                            display_names.push(format!("{} ({})", c.name(), rname));
                        }
                    }
                    for c in rinv {
                        if !display_names.contains(&c.name().to_string()) {
                            display_names.push(format!("{} ({})", c.name(), rname));
                        }
                    }
                    for c in rjson {
                        if !display_names.contains(&c.name().to_string()) {
                            display_names.push(format!("{} ({})", c.name(), rname));
                        }
                    }
                }
                // Inventory multi-region: show one entry in the display list (not one per region).
                if !inventory_multi_region.is_empty() {
                    let inv_name = inventory_multi_region[0].1.name().to_string();
                    let canonical =
                        format!("{} ({} regions)", inv_name, inventory_multi_region.len());
                    if !display_names.contains(&canonical) {
                        display_names.push(canonical);
                    }
                }

                prepared.push(AccountCollectors {
                    account_id,
                    aws_caller_arn,
                    aws_user_id,
                    profile,
                    region,
                    output_path,
                    collector_keys,
                    json_collectors,
                    json_inv_collectors,
                    csv_collectors,
                    display_names,
                    discovered_regions,
                    regional_collectors,
                    inventory_multi_region,
                    endpoint_label: None,
                });
            }

            // ── Tenable accounts ─────────────────────────────────────────────────
            #[cfg(feature = "tenable")]
            if !app.selected_accounts.is_empty() {
                use crate::providers::ProviderFactory as _;

                let sorted_all: Vec<usize> = {
                    let mut v: Vec<usize> = app.selected_accounts.iter().copied().collect();
                    v.sort();
                    v
                };
                for &idx in &sorted_all {
                    if app.accounts[idx].provider != crate::providers::CloudProvider::Tenable {
                        continue;
                    }
                    let acct = &app.accounts[idx];
                    let base_url = acct.tenable_url_resolved();
                    let flavor = tenable_rs::TenableFlavor::for_url(&base_url);
                    let site_name = acct.name.clone();

                    app.prep_log
                        .push(format!("  Tenable '{}' → {}", site_name, flavor.label()));
                    app.prep_log.push(format!("    URL: {}", base_url));
                    terminal.draw(|f| crate::tui::ui::draw(f, &app))?;

                    let access_key_present = acct.tenable_access_key_resolved().is_some();
                    let secret_key_present = acct.tenable_secret_key_resolved().is_some();
                    if !access_key_present || !secret_key_present {
                        let mut missing: Vec<&str> = Vec::new();
                        if !access_key_present {
                            missing
                                .push("access key (TENABLE_ACCESS_KEY env or tenable_access_key)");
                        }
                        if !secret_key_present {
                            missing
                                .push("secret key (TENABLE_SECRET_KEY env or tenable_secret_key)");
                        }
                        app.prep_log.push(format!(
                            "  ✗ Tenable '{}' — missing {} for {}",
                            site_name,
                            missing.join(" and "),
                            flavor.label(),
                        ));
                        app.prep_log.push(format!("    {}", flavor.api_keys_hint()));
                        terminal.draw(|f| crate::tui::ui::draw(f, &app))?;
                        continue;
                    }
                    let access_key = acct
                        .tenable_access_key_resolved()
                        .expect("checked above to be Some");
                    let secret_key = acct
                        .tenable_secret_key_resolved()
                        .expect("checked above to be Some");

                    let selected_keys: Vec<String> = app
                        .selected_collectors()
                        .into_iter()
                        .filter(|k| k.starts_with("tenable-"))
                        .collect();

                    let client = match tenable_rs::TenableClient::from_url(
                        &base_url,
                        &access_key,
                        &secret_key,
                    ) {
                        Ok((c, _)) => c,
                        Err(e) => {
                            app.prep_log.push(format!(
                                "  ✗ Tenable '{}' — client build failed: {e}",
                                site_name,
                            ));
                            terminal.draw(|f| crate::tui::ui::draw(f, &app))?;
                            continue;
                        }
                    };

                    let factory = crate::providers::tenable::factory::TenableProviderFactory::new(
                        client,
                        site_name.clone(),
                        selected_keys.clone(),
                        app.selected_scan_ids.clone(),
                        app.selected_was_scan_ids.clone(),
                    );
                    let csv_cols = factory.csv_collectors();
                    let display_names: Vec<String> =
                        csv_cols.iter().map(|c| c.name().to_string()).collect();

                    // Always include site_name so the final layout is:
                    // {base_output_dir}/{site_name}/{YYYY}/{MM-MMM}/
                    // (date_path_suffix() is appended by run_accounts in multi_account.rs)
                    let output_path = Some(
                        base_output_path
                            .clone()
                            .unwrap_or_else(|| PathBuf::from("."))
                            .join(&site_name),
                    );

                    prepared.push(crate::runner::multi_account::AccountCollectors {
                        account_id: site_name.clone(),
                        aws_caller_arn: String::new(),
                        aws_user_id: String::new(),
                        profile: String::new(),
                        region: String::new(),
                        output_path,
                        collector_keys: selected_keys,
                        json_collectors: Vec::new(),
                        json_inv_collectors: Vec::new(),
                        csv_collectors: csv_cols,
                        display_names,
                        discovered_regions: Vec::new(),
                        regional_collectors: Vec::new(),
                        inventory_multi_region: Vec::new(),
                        endpoint_label: Some(format!("{} — {}", flavor.label(), base_url)),
                    });

                    app.prep_log
                        .push(format!("  ✓ Tenable '{}' ready.", site_name));
                    terminal.draw(|f| crate::tui::ui::draw(f, &app))?;
                }
            }

            // ── Okta accounts ────────────────────────────────────────────────────
            #[cfg(feature = "okta")]
            if !app.selected_accounts.is_empty() {
                use crate::providers::ProviderFactory as _;

                let sorted_all: Vec<usize> = {
                    let mut v: Vec<usize> = app.selected_accounts.iter().copied().collect();
                    v.sort();
                    v
                };
                for &idx in &sorted_all {
                    if app.accounts[idx].provider != crate::providers::CloudProvider::Okta {
                        continue;
                    }
                    let acct = &app.accounts[idx];
                    let tenant_name = acct.name.clone();

                    let domain = match acct.okta_domain_resolved() {
                        Some(d) => d,
                        None => {
                            app.prep_log.push(format!(
                                "  ✗ Okta '{}' — missing okta_domain (or OKTA_DOMAIN env)",
                                tenant_name,
                            ));
                            terminal.draw(|f| crate::tui::ui::draw(f, &app))?;
                            continue;
                        }
                    };
                    let token = match acct.okta_api_token_resolved() {
                        Some(t) => t,
                        None => {
                            app.prep_log.push(format!(
                                "  ✗ Okta '{}' — missing okta_api_token (or OKTA_API_TOKEN env)",
                                tenant_name,
                            ));
                            terminal.draw(|f| crate::tui::ui::draw(f, &app))?;
                            continue;
                        }
                    };

                    app.prep_log
                        .push(format!("  Okta '{}' → {}", tenant_name, domain));
                    terminal.draw(|f| crate::tui::ui::draw(f, &app))?;

                    let client = match okta_rs::OktaClient::new(&domain, &token) {
                        Ok(c) => c,
                        Err(e) => {
                            app.prep_log.push(format!(
                                "  ✗ Okta '{}' — client build failed: {e}",
                                tenant_name,
                            ));
                            terminal.draw(|f| crate::tui::ui::draw(f, &app))?;
                            continue;
                        }
                    };

                    let selected_keys: Vec<String> = app
                        .selected_collectors()
                        .into_iter()
                        .filter(|k| k.starts_with("okta-"))
                        .collect();

                    let factory = crate::providers::okta::factory::OktaProviderFactory::new(
                        client,
                        tenant_name.clone(),
                        selected_keys.clone(),
                    );
                    let csv_cols = factory.csv_collectors();
                    let json_inv_cols = factory.json_collectors();
                    let evidence_cols = factory.evidence_collectors();
                    let display_names: Vec<String> = csv_cols
                        .iter()
                        .map(|c| c.name().to_string())
                        .chain(json_inv_cols.iter().map(|c| c.name().to_string()))
                        .chain(evidence_cols.iter().map(|c| c.name().to_string()))
                        .collect();

                    // Always include tenant_name so the final layout is:
                    // {base_output_dir}/{tenant_name}/{YYYY}/{MM-MMM}/
                    let output_path = Some(
                        base_output_path
                            .clone()
                            .unwrap_or_else(|| PathBuf::from("."))
                            .join(&tenant_name),
                    );

                    prepared.push(crate::runner::multi_account::AccountCollectors {
                        account_id: tenant_name.clone(),
                        aws_caller_arn: String::new(),
                        aws_user_id: String::new(),
                        profile: String::new(),
                        region: String::new(),
                        output_path,
                        collector_keys: selected_keys,
                        json_collectors: evidence_cols,
                        json_inv_collectors: json_inv_cols,
                        csv_collectors: csv_cols,
                        display_names,
                        discovered_regions: Vec::new(),
                        regional_collectors: Vec::new(),
                        inventory_multi_region: Vec::new(),
                        endpoint_label: Some(format!("Okta — {}", domain)),
                    });

                    app.prep_log
                        .push(format!("  ✓ Okta '{}' ready.", tenant_name));
                    terminal.draw(|f| crate::tui::ui::draw(f, &app))?;
                }
            }

            // ── Jira accounts ─────────────────────────────────────────────────────
            #[cfg(feature = "jira")]
            if !app.selected_accounts.is_empty() {
                use crate::providers::ProviderFactory as _;

                let sorted_all: Vec<usize> = {
                    let mut v: Vec<usize> = app.selected_accounts.iter().copied().collect();
                    v.sort();
                    v
                };
                for &idx in &sorted_all {
                    if app.accounts[idx].provider != crate::providers::CloudProvider::Jira {
                        continue;
                    }
                    let acct = &app.accounts[idx];
                    let tenant_name = acct.name.clone();

                    let domain = match acct.jira_domain_resolved() {
                        Some(d) => d,
                        None => {
                            app.prep_log.push(format!(
                                "  ✗ Jira '{}' — missing jira_domain (or JIRA_DOMAIN env)",
                                tenant_name,
                            ));
                            terminal.draw(|f| crate::tui::ui::draw(f, &app))?;
                            continue;
                        }
                    };
                    let email = match acct.jira_email_resolved() {
                        Some(e) => e,
                        None => {
                            app.prep_log.push(format!(
                                "  ✗ Jira '{}' — missing jira_email (or JIRA_EMAIL env)",
                                tenant_name,
                            ));
                            terminal.draw(|f| crate::tui::ui::draw(f, &app))?;
                            continue;
                        }
                    };
                    let token = match acct.jira_api_token_resolved() {
                        Some(t) => t,
                        None => {
                            app.prep_log.push(format!(
                                "  ✗ Jira '{}' — missing jira_api_token (or JIRA_API_TOKEN env)",
                                tenant_name,
                            ));
                            terminal.draw(|f| crate::tui::ui::draw(f, &app))?;
                            continue;
                        }
                    };

                    app.prep_log
                        .push(format!("  Jira '{}' → {}", tenant_name, domain));
                    terminal.draw(|f| crate::tui::ui::draw(f, &app))?;

                    let client = match jira_rs::JiraClient::new(&domain, &email, &token) {
                        Ok(c) => c,
                        Err(e) => {
                            app.prep_log.push(format!(
                                "  ✗ Jira '{}' — client build failed: {e}",
                                tenant_name,
                            ));
                            terminal.draw(|f| crate::tui::ui::draw(f, &app))?;
                            continue;
                        }
                    };

                    let selected_keys: Vec<String> = app
                        .selected_collectors()
                        .into_iter()
                        .filter(|k| k.starts_with("jira-"))
                        .collect();

                    let factory = crate::providers::jira::factory::JiraProviderFactory::new(
                        client,
                        tenant_name.clone(),
                        selected_keys.clone(),
                    )
                    .with_project_keys(app.selected_jira_project_keys.clone());
                    let csv_cols = factory.csv_collectors();
                    let json_inv_cols = factory.json_collectors();
                    let evidence_cols = factory.evidence_collectors();
                    let display_names: Vec<String> = csv_cols
                        .iter()
                        .map(|c| c.name().to_string())
                        .chain(json_inv_cols.iter().map(|c| c.name().to_string()))
                        .chain(evidence_cols.iter().map(|c| c.name().to_string()))
                        .collect();

                    let output_path = Some(
                        base_output_path
                            .clone()
                            .unwrap_or_else(|| PathBuf::from("."))
                            .join(&tenant_name),
                    );

                    prepared.push(crate::runner::multi_account::AccountCollectors {
                        account_id: tenant_name.clone(),
                        aws_caller_arn: String::new(),
                        aws_user_id: String::new(),
                        profile: String::new(),
                        region: String::new(),
                        output_path,
                        collector_keys: selected_keys,
                        json_collectors: evidence_cols,
                        json_inv_collectors: json_inv_cols,
                        csv_collectors: csv_cols,
                        display_names,
                        discovered_regions: Vec::new(),
                        regional_collectors: Vec::new(),
                        inventory_multi_region: Vec::new(),
                        endpoint_label: Some(format!("Jira — {}", domain)),
                    });

                    app.prep_log
                        .push(format!("  ✓ Jira '{}' ready.", tenant_name));
                    terminal.draw(|f| crate::tui::ui::draw(f, &app))?;
                }
            }

            // ── GitHub accounts ──────────────────────────────────────────────────
            #[cfg(feature = "github")]
            if !app.selected_accounts.is_empty() {
                use crate::providers::ProviderFactory as _;

                let sorted_all: Vec<usize> = {
                    let mut v: Vec<usize> = app.selected_accounts.iter().copied().collect();
                    v.sort();
                    v
                };
                for &idx in &sorted_all {
                    if app.accounts[idx].provider != crate::providers::CloudProvider::Github {
                        continue;
                    }
                    let acct = &app.accounts[idx];
                    let account_name = acct.name.clone();

                    let org = match acct.github_org_resolved() {
                        Some(o) => o,
                        None => {
                            app.prep_log.push(format!(
                                "  ✗ GitHub '{}' — missing github_org (or GITHUB_ORG env)",
                                account_name,
                            ));
                            terminal.draw(|f| crate::tui::ui::draw(f, &app))?;
                            continue;
                        }
                    };
                    let token = match acct.github_token_resolved() {
                        Some(t) => t,
                        None => {
                            app.prep_log.push(format!(
                                "  ✗ GitHub '{}' — missing github_token (or GITHUB_TOKEN env)",
                                account_name,
                            ));
                            terminal.draw(|f| crate::tui::ui::draw(f, &app))?;
                            continue;
                        }
                    };
                    let base_url = acct.github_base_url_resolved();

                    app.prep_log.push(format!(
                        "  GitHub '{}' → {} ({})",
                        account_name, org, base_url
                    ));
                    terminal.draw(|f| crate::tui::ui::draw(f, &app))?;

                    let client = match github_rs::GithubClient::new(&base_url, &token, &org) {
                        Ok(c) => c,
                        Err(e) => {
                            app.prep_log.push(format!(
                                "  ✗ GitHub '{}' — client build failed: {e}",
                                account_name,
                            ));
                            terminal.draw(|f| crate::tui::ui::draw(f, &app))?;
                            continue;
                        }
                    };

                    let selected_keys: Vec<String> = app
                        .selected_collectors()
                        .into_iter()
                        .filter(|k| k.starts_with("github-"))
                        .collect();

                    let factory = crate::providers::github::factory::GithubProviderFactory::new(
                        client,
                        org.clone(),
                        selected_keys.clone(),
                    );
                    let csv_cols = factory.csv_collectors();
                    let json_inv_cols = factory.json_collectors();
                    let evidence_cols = factory.evidence_collectors();
                    let display_names: Vec<String> = csv_cols
                        .iter()
                        .map(|c| c.name().to_string())
                        .chain(json_inv_cols.iter().map(|c| c.name().to_string()))
                        .chain(evidence_cols.iter().map(|c| c.name().to_string()))
                        .collect();

                    let output_path = Some(
                        base_output_path
                            .clone()
                            .unwrap_or_else(|| PathBuf::from("."))
                            .join(&account_name),
                    );

                    prepared.push(crate::runner::multi_account::AccountCollectors {
                        account_id: org.clone(),
                        aws_caller_arn: String::new(),
                        aws_user_id: String::new(),
                        profile: String::new(),
                        region: String::new(),
                        output_path,
                        collector_keys: selected_keys,
                        json_collectors: evidence_cols,
                        json_inv_collectors: json_inv_cols,
                        csv_collectors: csv_cols,
                        display_names,
                        discovered_regions: Vec::new(),
                        regional_collectors: Vec::new(),
                        inventory_multi_region: Vec::new(),
                        endpoint_label: Some(format!("GitHub — {}", org)),
                    });

                    app.prep_log
                        .push(format!("  ✓ GitHub '{}' ready.", account_name));
                    terminal.draw(|f| crate::tui::ui::draw(f, &app))?;
                }
            }

            // ── Elastic accounts ────────────────────────────────────────────────────
            #[cfg(feature = "elastic")]
            if !app.selected_accounts.is_empty() {
                use crate::providers::ProviderFactory as _;

                let sorted_all: Vec<usize> = {
                    let mut v: Vec<usize> = app.selected_accounts.iter().copied().collect();
                    v.sort();
                    v
                };
                for &idx in &sorted_all {
                    if app.accounts[idx].provider != crate::providers::CloudProvider::Elastic {
                        continue;
                    }
                    let acct = &app.accounts[idx];
                    let deployment_name = acct.name.clone();

                    let kibana_url = match acct.elastic_kibana_url_resolved() {
                        Some(u) => u,
                        None => {
                            app.prep_log.push(format!(
                                "  ✗ Elastic '{}' — missing elastic_kibana_url (or ELASTIC_KIBANA_URL env)",
                                deployment_name,
                            ));
                            terminal.draw(|f| crate::tui::ui::draw(f, &app))?;
                            continue;
                        }
                    };
                    let es_url = match acct.elastic_es_url_resolved() {
                        Some(u) => u,
                        None => {
                            app.prep_log.push(format!(
                                "  ✗ Elastic '{}' — missing elastic_es_url (or ELASTIC_ES_URL env)",
                                deployment_name,
                            ));
                            terminal.draw(|f| crate::tui::ui::draw(f, &app))?;
                            continue;
                        }
                    };
                    let api_key = match acct.elastic_api_key_resolved() {
                        Some(k) => k,
                        None => {
                            app.prep_log.push(format!(
                                "  ✗ Elastic '{}' — missing elastic_api_key (or ELASTIC_API_KEY env)",
                                deployment_name,
                            ));
                            terminal.draw(|f| crate::tui::ui::draw(f, &app))?;
                            continue;
                        }
                    };

                    app.prep_log
                        .push(format!("  Elastic '{}' → {}", deployment_name, kibana_url));
                    terminal.draw(|f| crate::tui::ui::draw(f, &app))?;

                    let client =
                        match elastic_rs::ElasticClient::new(&kibana_url, &es_url, &api_key) {
                            Ok(c) => c,
                            Err(e) => {
                                app.prep_log.push(format!(
                                    "  ✗ Elastic '{}' — client build failed: {e}",
                                    deployment_name,
                                ));
                                terminal.draw(|f| crate::tui::ui::draw(f, &app))?;
                                continue;
                            }
                        };

                    let selected_keys: Vec<String> = app
                        .selected_collectors()
                        .into_iter()
                        .filter(|k| k.starts_with("elastic-"))
                        .collect();

                    let factory = crate::providers::elastic::factory::ElasticProviderFactory::new(
                        client,
                        deployment_name.clone(),
                        selected_keys.clone(),
                    );
                    let csv_cols = factory.csv_collectors();
                    let json_inv_cols = factory.json_collectors();
                    let evidence_cols = factory.evidence_collectors();
                    let display_names: Vec<String> = csv_cols
                        .iter()
                        .map(|c| c.name().to_string())
                        .chain(json_inv_cols.iter().map(|c| c.name().to_string()))
                        .chain(evidence_cols.iter().map(|c| c.name().to_string()))
                        .collect();

                    let output_path = Some(
                        base_output_path
                            .clone()
                            .unwrap_or_else(|| PathBuf::from("."))
                            .join(&deployment_name),
                    );

                    prepared.push(crate::runner::multi_account::AccountCollectors {
                        account_id: deployment_name.clone(),
                        aws_caller_arn: String::new(),
                        aws_user_id: String::new(),
                        profile: String::new(),
                        region: String::new(),
                        output_path,
                        collector_keys: selected_keys,
                        json_collectors: evidence_cols,
                        json_inv_collectors: json_inv_cols,
                        csv_collectors: csv_cols,
                        display_names,
                        discovered_regions: Vec::new(),
                        regional_collectors: Vec::new(),
                        inventory_multi_region: Vec::new(),
                        endpoint_label: Some(format!("Elastic — {}", kibana_url)),
                    });

                    app.prep_log
                        .push(format!("  ✓ Elastic '{}' ready.", deployment_name));
                    terminal.draw(|f| crate::tui::ui::draw(f, &app))?;
                }
            }

            // Guard: if every account failed the canary check, prepared is empty.
            // Show an error on the Preparing screen and return cleanly instead of
            // panicking at prepared[0].
            if prepared.is_empty() {
                app.prep_log.push(String::new());
                app.prep_log
                    .push("⚠  No accounts are ready to collect from.".to_string());
                app.prep_log.push(
                    "   All credential checks failed — check your AWS profile or SSO login."
                        .to_string(),
                );
                app.prep_log.push(String::new());
                app.prep_log
                    .push("   Press any key to return to the setup wizard.".to_string());
                terminal.draw(|f| crate::tui::ui::draw(f, &app))?;
                // Wait for a keypress, then restart the wizard.
                use crossterm::event as cxevent;
                loop {
                    if cxevent::poll(std::time::Duration::from_millis(200))? {
                        let _ = cxevent::read()?;
                        break;
                    }
                }
                restore_terminal(&mut terminal)?;
                crate::platform::restore_stderr(stderr_backup);
                app.reset();
                // Fall through to outer loop — restart the wizard.
                continue;
            }

            // Set up progress channel so the TUI running screen gets live updates.
            let (tx, rx) = mpsc::unbounded_channel::<Progress>();
            app.progress_rx = Some(rx);

            // Initialise status entries from the first account's collectors.
            app.collector_statuses = prepared[0]
                .display_names
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

            app.prep_log
                .push("All accounts prepared — starting collection…".to_string());
            app.screen = crate::tui::Screen::Running;
            terminal.draw(|f| crate::tui::ui::draw(f, &app))?;

            // Transition directly to Running screen (terminal is already set up).
            let do_zip = app.zip;
            let do_sign = app.sign;
            let skip_inventory_csv = app.skip_inventory_csv;
            let write_run_manifest = app.write_run_manifest;
            let write_chain_of_custody = app.write_chain_of_custody;
            let restart = run_tui_multi_account(
                &mut terminal,
                &mut app,
                &params,
                prepared,
                tx,
                do_zip,
                do_sign,
                skip_inventory_csv,
                write_run_manifest,
                write_chain_of_custody,
            )
            .await?;
            restore_terminal(&mut terminal)?;

            // Restore stderr after TUI exits.
            crate::platform::restore_stderr(stderr_backup);

            if !restart {
                return Ok(());
            }
            // User pressed 'n' — app.reset() was called inside the collection
            // loop, so app.screen == Welcome.  Fall through to the top of the
            // outer loop to re-run the wizard.
        }
    } // end restart loop
}
