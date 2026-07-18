use std::path::PathBuf;

use anyhow::{Context, Result};
use aws_config::{BehaviorVersion, Region};
use chrono::{NaiveDate, Utc};

use crate::audit_log;
use crate::cli::Cli;
use crate::evidence::{CollectParams, CsvCollector, EvidenceCollector, JsonCollector};
use crate::inventory_orchestrator::InventoryCollector;
use crate::providers::aws::factory::AwsProviderFactory;
use crate::providers::ProviderFactory;
use crate::runner::collect_ops::{
    run_csv_collectors, run_json_collectors, run_json_inv_collectors,
};
use crate::runner::multi_account::GLOBAL_COLLECTOR_KEYS;
use crate::runner::multi_region_cli::run_multi_region_standard;
use crate::runner::output::write_inventory_outputs;

pub async fn run_inventory_cli(cli: &Cli) -> Result<()> {
    if cli.inventory_all_accounts {
        return run_inventory_cli_all_accounts(cli).await;
    }
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
        let start_ts = start
            .and_hms_opt(0, 0, 0)
            .expect("valid midnight time")
            .and_utc()
            .timestamp();
        let end_ts = today
            .and_hms_opt(23, 59, 59)
            .expect("valid end-of-day time")
            .and_utc()
            .timestamp();
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
    if let Some(uuid) = &cli.poam_remove_item {
        let found = crate::poam::remove_custom_poam_item(uuid)?;
        if found {
            eprintln!("Closed custom POA&M item {uuid}.");
        } else {
            eprintln!("No POA&M item with uuid {uuid} found.");
        }
        return Ok(());
    }

    if let Some(item_path) = &cli.poam_add_item {
        let contents = std::fs::read_to_string(item_path)
            .with_context(|| format!("cannot read --poam-add-item file {item_path}"))?;
        #[derive(serde::Deserialize)]
        struct ItemFile {
            title: String,
            description: String,
            status: Option<String>,
            deadline: Option<String>,
        }
        let parsed: ItemFile = serde_json::from_str(&contents)
            .with_context(|| format!("cannot parse --poam-add-item file {item_path} as JSON"))?;
        let uuid = crate::poam::add_custom_poam_item(
            parsed.title,
            parsed.description,
            parsed.status,
            parsed.deadline,
        )?;
        eprintln!("Added custom POA&M item {uuid}.");
        return Ok(());
    }

    if let (Some(title), Some(description)) = (&cli.poam_item_title, &cli.poam_item_description) {
        let uuid = crate::poam::add_custom_poam_item(
            title.clone(),
            description.clone(),
            cli.poam_item_status.clone(),
            cli.poam_item_deadline.clone(),
        )?;
        eprintln!("Added custom POA&M item {uuid}.");
        return Ok(());
    }

    if cli.poam_item_title.is_some() != cli.poam_item_description.is_some() {
        anyhow::bail!("--poam-item-title and --poam-item-description must be provided together");
    }

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

    let format: crate::poam::PoamFormat = cli
        .poam_format
        .parse()
        .context("invalid --poam-format value")?;

    let result = crate::poam::run_poam(&cli.poam_evidence_base, &cli.region, year, month, format)?;
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

    Ok(())
}

pub async fn run_standard_cli(cli: &Cli) -> Result<()> {
    let (start, end) = if let Some(ref lb) = cli.lookback {
        if cli.start_date.is_some() || cli.end_date.is_some() {
            anyhow::bail!("--lookback cannot be combined with --start-date or --end-date");
        }
        let today = chrono::Utc::now().date_naive();
        let start_date = crate::cli::parse_lookback(lb)?;
        (
            start_date
                .and_hms_opt(0, 0, 0)
                .expect("valid midnight time")
                .and_utc(),
            today
                .and_hms_opt(23, 59, 59)
                .expect("valid end-of-day time")
                .and_utc(),
        )
    } else {
        let start_str = cli
            .start_date
            .as_deref()
            .expect("start_date is Some — guarded by caller");
        let end_str = cli
            .end_date
            .as_deref()
            .context("--end-date is required when --start-date is provided")?;
        (
            NaiveDate::parse_from_str(start_str, "%Y-%m-%d")
                .context("Invalid --start-date")?
                .and_hms_opt(0, 0, 0)
                .expect("valid midnight time")
                .and_utc(),
            NaiveDate::parse_from_str(end_str, "%Y-%m-%d")
                .context("Invalid --end-date")?
                .and_hms_opt(23, 59, 59)
                .expect("valid end-of-day time")
                .and_utc(),
        )
    };

    let mut loader =
        aws_config::defaults(BehaviorVersion::latest()).region(Region::new(cli.region.clone()));
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
    let account_id = cli_identity
        .as_ref()
        .map(|id| id.account_id.clone())
        .unwrap_or_else(|| "unknown".to_string());
    eprintln!(
        "Identity: account={} arn={}",
        account_id,
        cli_identity
            .as_ref()
            .map(|id| id.caller_arn.as_str())
            .unwrap_or("unknown"),
    );

    let params = CollectParams {
        start_time: start,
        end_time: end,
        filter: cli.filter.clone(),
        include_raw: cli.include_raw,
    };

    // Determine selected collector keys from CLI
    let selected: Vec<String> = if let Some(ref names) = cli.collectors {
        names.iter().map(|n| n.to_lowercase()).collect()
    } else {
        GLOBAL_COLLECTOR_KEYS
            .iter()
            .map(|s| s.to_string())
            .collect()
    };

    // Build all collectors through the factory
    let mut factory = AwsProviderFactory::new(
        config.clone(),
        account_id.clone(),
        cli.region.clone(),
        selected.clone(),
    );
    if selected.iter().any(|n| n == "inspector-sbom") {
        let sbom_cfg = crate::providers::aws::inspector_sbom::InspectorSbomConfig {
            bucket: cli.sbom_bucket.clone().unwrap_or_default(),
            key_prefix: None,
            kms_key_arn: cli.sbom_kms_key.clone().unwrap_or_default(),
            format: cli.sbom_format.as_str().into(),
        };
        let sbom_out = cli.output.clone().unwrap_or_else(|| PathBuf::from("."));
        factory = factory.with_sbom_config(sbom_cfg, Some(sbom_out));
    }
    let mut json_collectors: Vec<Box<dyn EvidenceCollector>> = factory.evidence_collectors();
    let json_inv_collectors: Vec<Box<dyn JsonCollector>> = factory.json_collectors();
    let csv_collectors: Vec<Box<dyn CsvCollector>> = factory.csv_collectors();

    // S3 is a special-case collector requiring CLI flags — add it manually
    if selected.iter().any(|n| n == "s3") && cli.collectors.is_some() {
        match crate::aws_loader::build_s3_collector_from_cli(cli, &s3_config, &account_id) {
            Ok(Some(c)) => json_collectors.push(Box::new(c)),
            Ok(None) => anyhow::bail!("--s3-bucket is required for the s3 collector"),
            Err(e) => eprintln!("WARN: {e:#}"),
        }
    }

    if json_collectors.is_empty()
        && csv_collectors.is_empty()
        && !cli.all_regions
        && cli.regions.is_none()
    {
        anyhow::bail!("No collectors selected.");
    }

    let output_dir = cli.output.clone().unwrap_or_else(|| PathBuf::from("."));

    // ── Multi-region round-robin mode ────────────────────────────────────────
    if cli.all_regions || cli.regions.is_some() {
        return run_multi_region_standard(
            cli,
            &config,
            &account_id,
            cli_identity,
            &cli_started_at,
            &params,
            &selected,
            &output_dir,
        )
        .await;
    }

    // ── Single-region path (existing behaviour) ──────────────────────────────
    let timestamp = Utc::now().format("%Y-%m-%d-%H%M%S").to_string();
    let sr_dates = Some((params.start_time.timestamp(), params.end_time.timestamp()));
    let sr_coll_start = params.start_time.format("%Y-%m-%d").to_string();
    let sr_coll_end = params.end_time.format("%Y-%m-%d").to_string();
    let mut sr_outcomes: Vec<audit_log::CollectorOutcome> = Vec::new();

    sr_outcomes.extend(
        run_json_collectors(
            &json_collectors,
            &params,
            &cli.region,
            &output_dir,
            &timestamp,
        )
        .await?,
    );
    sr_outcomes.extend(
        run_json_inv_collectors(
            &json_inv_collectors,
            &account_id,
            &cli.region,
            &output_dir,
            &timestamp,
        )
        .await?,
    );
    sr_outcomes.extend(
        run_csv_collectors(
            &csv_collectors,
            &account_id,
            &cli.region,
            &output_dir,
            sr_dates,
            &timestamp,
        )
        .await?,
    );

    // ── Write run manifest (single-region) ───────────────────────────────────
    let sr_manifest = audit_log::RunManifest::build(
        &timestamp,
        &account_id,
        &cli.region,
        &sr_coll_start,
        &sr_coll_end,
        sr_outcomes,
    );
    if cli.write_run_manifest {
        match audit_log::write_run_manifest(&output_dir, &sr_manifest) {
            Ok(p) => eprintln!("Run manifest written: {}", p.display()),
            Err(e) => eprintln!("WARN: could not write run manifest: {e}"),
        }
    }

    // ── Write chain-of-custody (single-region) ───────────────────────────────
    if cli.write_chain_of_custody {
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
        match crate::zip_bundle::bundle_dir(&output_dir, zip_path) {
            Ok(()) => eprintln!("Zip bundle written: {}", zip_name),
            Err(e) => eprintln!("Zip bundle failed: {e}"),
        }
    }

    if cli.sign {
        let key = match &cli.signing_key {
            Some(hex) => crate::signing::SigningKey::from_hex(hex)?,
            None => crate::signing::SigningKey::generate()?,
        };
        let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
        let files = crate::signing::collect_dir_files(&output_dir);
        match crate::signing::sign_files(&files, &timestamp, &key, &cwd) {
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

async fn run_inventory_cli_all_accounts(cli: &Cli) -> Result<()> {
    // Reject the same flag combinations run_inventory_cli rejects, since we
    // bypass its guards when we branch early.
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

    let cfg = crate::app_config::load_config().context(
        "--inventory-all-accounts requires a config.toml with [[account]] entries (or tenable-/okta-/jira-config.toml merged in)",
    )?;

    let aws_accounts: Vec<&crate::app_config::Account> = cfg
        .account
        .iter()
        .filter(|a| a.provider == crate::providers::CloudProvider::Aws)
        .filter(|a| a.profile.as_ref().map(|p| !p.trim().is_empty()).unwrap_or(false))
        .collect();

    if aws_accounts.is_empty() {
        anyhow::bail!(
            "--inventory-all-accounts: no AWS accounts with a `profile` were found in config"
        );
    }

    let inventory_types = crate::cli::resolve_inventory_types(cli);
    eprintln!("Inventory asset types: {}", inventory_types.join(", "));

    let inventory_dates: Option<(i64, i64)> = if let Some(ref lb) = cli.lookback {
        let today = chrono::Utc::now().date_naive();
        let start = crate::cli::parse_lookback(lb)?;
        let start_ts = start
            .and_hms_opt(0, 0, 0)
            .expect("valid midnight time")
            .and_utc()
            .timestamp();
        let end_ts = today
            .and_hms_opt(23, 59, 59)
            .expect("valid end-of-day time")
            .and_utc()
            .timestamp();
        eprintln!("Lookback window: {} → {} ({})", start, today, lb);
        Some((start_ts, end_ts))
    } else {
        None
    };

    let output_dir = cli.output.clone().unwrap_or_else(|| PathBuf::from("."));
    let mut inventory_rows: Vec<Vec<String>> = Vec::new();
    let mut authenticated_accounts: Vec<String> = Vec::new();
    let mut skipped_accounts: Vec<String> = Vec::new();

    for (idx, acct) in aws_accounts.iter().enumerate() {
        let profile = acct.profile.as_deref().unwrap_or("");
        let account_region = acct
            .region
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or(&cli.region);
        let display = acct
            .account_id
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or(&acct.name);

        eprintln!(
            "=== Account {}/{}: {} (profile={}, region={}) ===",
            idx + 1,
            aws_accounts.len(),
            display,
            profile,
            account_region,
        );

        let (probe_config, work_config, using_ambient_credentials) =
            crate::aws_loader::load_cli_probe_and_work_configs(
                account_region,
                Some(profile),
            )
            .await;

        let identity = crate::audit_log::resolve_aws_identity(&probe_config).await;
        if identity.is_none() {
            eprintln!(
                "  WARN: could not resolve AWS identity for profile '{}' — skipping account. \
                 Re-authenticate (e.g. `aws sso login --profile {}`) and rerun.",
                profile, profile
            );
            skipped_accounts.push(format!("{} (profile={})", display, profile));
            continue;
        }
        let account_id = crate::aws_loader::print_cli_identity(&identity);
        authenticated_accounts.push(account_id.clone());

        let target_regions: Vec<String> = if let Some(explicit) = cli.regions.as_ref() {
            explicit.clone()
        } else if cli.all_regions {
            let regions = crate::aws_loader::discover_regions(&probe_config).await;
            if regions.is_empty() {
                eprintln!(
                    "  WARN: could not discover regions for {} — falling back to {}",
                    account_id, account_region
                );
                vec![account_region.to_string()]
            } else {
                regions
            }
        } else {
            vec![account_region.to_string()]
        };

        for region_name in &target_regions {
            let region_work_config = if region_name == account_region {
                work_config.clone()
            } else {
                let region_profile = if using_ambient_credentials {
                    None
                } else {
                    Some(profile)
                };
                crate::aws_loader::load_cli_config(region_name, region_profile).await
            };
            let collector = InventoryCollector::new(&region_work_config, inventory_types.clone());
            eprintln!("  Collecting inventory from {}...", region_name);
            match collector
                .collect_rows(&account_id, region_name, inventory_dates)
                .await
            {
                Ok(rows) => {
                    eprintln!("    {} returned {} rows", region_name, rows.len());
                    inventory_rows.extend(rows);
                }
                Err(e) => {
                    eprintln!("    ERROR collecting from {}: {:#}", region_name, e);
                }
            }
        }
    }

    eprintln!(
        "=== All accounts done. {}/{} authenticated, {} skipped. {} total inventory rows. ===",
        authenticated_accounts.len(),
        aws_accounts.len(),
        skipped_accounts.len(),
        inventory_rows.len()
    );
    if !authenticated_accounts.is_empty() {
        eprintln!("    Included: {}", authenticated_accounts.join(", "));
    }
    if !skipped_accounts.is_empty() {
        eprintln!("    Skipped:  {}", skipped_accounts.join(", "));
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
