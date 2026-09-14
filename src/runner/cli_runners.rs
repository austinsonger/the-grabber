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

/// One AWS account to inventory, resolved from either config.toml `[[account]]`
/// entries or `--accounts` profile patterns.
struct InventoryTarget {
    profile: String,
    region: String,
    /// Label used in progress output before STS resolves the real account ID.
    display: String,
}

pub async fn run_inventory_cli(cli: &Cli) -> Result<()> {
    if cli.accounts.is_some() {
        return run_inventory_cli_profiles(cli).await;
    }
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

    finalize_inventory_outputs(cli, &output_dir, &inventory_rows)?;

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
        if cli.sbom_all_repos && cli.sbom_repos.is_some() {
            anyhow::bail!("--sbom-repos and --sbom-all-repos are mutually exclusive");
        }

        let repositories: Vec<String> = if let Some(ref list) = cli.sbom_repos {
            let names = parse_sbom_repos(list);
            if names.is_empty() {
                anyhow::bail!("--sbom-repos was given but contained no repository names");
            }
            names
        } else if cli.sbom_all_repos {
            let discovered = crate::providers::aws::ecr_repos::list_repositories(&config)
                .await
                .context("discovering ECR repositories for --sbom-all-repos")?;
            if discovered.is_empty() {
                anyhow::bail!("--sbom-all-repos found no ECR repositories in this account/region");
            }
            eprintln!(
                "  --sbom-all-repos: exporting SBOMs for {} repositories",
                discovered.len()
            );
            discovered.into_iter().map(|r| r.name).collect()
        } else {
            Vec::new()
        };

        let sbom_cfg = crate::providers::aws::inspector_sbom::InspectorSbomConfig {
            bucket: cli.sbom_bucket.clone().unwrap_or_default(),
            key_prefix: cli.sbom_key_prefix.clone(),
            kms_key_arn: cli.sbom_kms_key.clone().unwrap_or_default(),
            format: parse_sbom_format(&cli.sbom_format)?,
            repositories,
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
        .filter(|a| {
            a.profile
                .as_ref()
                .map(|p| !p.trim().is_empty())
                .unwrap_or(false)
        })
        .collect();

    if aws_accounts.is_empty() {
        anyhow::bail!(
            "--inventory-all-accounts: no AWS accounts with a `profile` were found in config"
        );
    }

    let targets: Vec<InventoryTarget> = aws_accounts
        .iter()
        .map(|acct| InventoryTarget {
            profile: acct.profile.as_deref().unwrap_or("").to_string(),
            region: acct
                .region
                .as_deref()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or(&cli.region)
                .to_string(),
            display: acct
                .account_id
                .as_deref()
                .filter(|s| !s.is_empty())
                .unwrap_or(&acct.name)
                .to_string(),
        })
        .collect();

    let inventory_types = crate::cli::resolve_inventory_types(cli);
    eprintln!("Inventory asset types: {}", inventory_types.join(", "));

    let inventory_dates = resolve_inventory_dates(cli)?;
    let output_dir = cli.output.clone().unwrap_or_else(|| PathBuf::from("."));
    let inventory_rows =
        collect_inventory_across_targets(cli, &targets, &inventory_types, inventory_dates).await;

    finalize_inventory_outputs(cli, &output_dir, &inventory_rows)?;

    Ok(())
}

/// Write the merged inventory rows, then apply the opt-in `--zip` and `--sign`
/// steps. Shared by all three inventory entry points so they cannot drift.
///
/// Bundling and signing report failures without failing the run: the evidence
/// files are already on disk at that point, and losing them to a zip error
/// would be worse than shipping them unbundled.
fn finalize_inventory_outputs(
    cli: &Cli,
    output_dir: &PathBuf,
    inventory_rows: &[Vec<String>],
) -> Result<()> {
    let timestamp = Utc::now().format("%Y-%m-%d-%H%M%S").to_string();
    let written_files = write_inventory_outputs(
        output_dir,
        &timestamp,
        inventory_rows,
        cli.skip_inventory_csv,
    )?;

    if written_files.is_empty() {
        return Ok(());
    }

    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));

    if cli.zip {
        let zip_name = format!("Evidence-{}.zip", timestamp);
        match crate::zip_bundle::bundle_files(&written_files, &cwd, &PathBuf::from(&zip_name)) {
            Ok(()) => eprintln!("Zip bundle written: {}", zip_name),
            Err(e) => eprintln!("Zip bundle failed: {e}"),
        }
    }

    if cli.sign {
        let key = match &cli.signing_key {
            Some(hex) => crate::signing::SigningKey::from_hex(hex)?,
            None => crate::signing::SigningKey::generate()?,
        };
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

/// Translate `--lookback` into the (start, end) unix timestamps the inventory
/// collectors take, or `None` when no window was requested.
fn resolve_inventory_dates(cli: &Cli) -> Result<Option<(i64, i64)>> {
    let Some(ref lb) = cli.lookback else {
        return Ok(None);
    };
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
    Ok(Some((start_ts, end_ts)))
}

/// Inventory every target in turn and merge the rows into one set, the way the
/// TUI's multi-account inventory does.
///
/// A target whose AWS identity will not resolve is reported and skipped rather
/// than failing the run, so one expired SSO session does not cost the whole
/// collection. Targets are deduplicated by the account ID STS reports: two
/// profiles can be different roles into the same account (e.g. `fed:OpsAdmin-X`
/// and `corp:OpsAdmin-X`), and collecting both would duplicate every row in the
/// evidence output.
async fn collect_inventory_across_targets(
    cli: &Cli,
    targets: &[InventoryTarget],
    inventory_types: &[String],
    inventory_dates: Option<(i64, i64)>,
) -> Vec<Vec<String>> {
    let mut inventory_rows: Vec<Vec<String>> = Vec::new();
    let mut authenticated: Vec<String> = Vec::new();
    let mut skipped: Vec<String> = Vec::new();
    let mut seen_account_ids: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();

    for (idx, target) in targets.iter().enumerate() {
        let profile = target.profile.as_str();
        let account_region = target.region.as_str();

        eprintln!(
            "=== Account {}/{}: {} (profile={}, region={}) ===",
            idx + 1,
            targets.len(),
            target.display,
            profile,
            account_region,
        );

        // No ambient fallback: in a multi-account run it would file the shell
        // account's assets under this profile's name.
        let (probe_config, work_config, using_ambient_credentials) =
            crate::aws_loader::load_cli_probe_and_work_configs_opts(
                account_region,
                Some(profile),
                false,
            )
            .await;

        let identity = crate::audit_log::resolve_aws_identity(&probe_config).await;
        if identity.is_none() {
            eprintln!(
                "  WARN: could not resolve AWS identity for profile '{}' — skipping account. \
                 Re-authenticate (e.g. `aws sso login --profile {}`) and rerun.",
                profile, profile
            );
            skipped.push(format!("{} (profile={})", target.display, profile));
            continue;
        }
        let account_id = crate::aws_loader::print_cli_identity(&identity);

        if let Some(first_profile) = seen_account_ids.get(&account_id) {
            eprintln!(
                "  WARN: profile '{}' resolves to account {}, already collected via profile '{}' \
                 — skipping to avoid duplicate inventory rows.",
                profile, account_id, first_profile
            );
            skipped.push(format!(
                "{} (profile={}, duplicate of {})",
                target.display, profile, first_profile
            ));
            continue;
        }
        seen_account_ids.insert(account_id.clone(), profile.to_string());
        authenticated.push(account_id.clone());

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
            let collector = InventoryCollector::new(&region_work_config, inventory_types.to_vec());
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
        authenticated.len(),
        targets.len(),
        skipped.len(),
        inventory_rows.len()
    );
    if !authenticated.is_empty() {
        eprintln!("    Included: {}", authenticated.join(", "));
    }
    if !skipped.is_empty() {
        eprintln!("    Skipped:  {}", skipped.join(", "));
    }

    inventory_rows
}

/// `--inventory --accounts <patterns>`: inventory every AWS profile on this
/// machine matching the patterns, merged into one CSV/XLSX.
///
/// Unlike `--inventory-all-accounts` this reads no config.toml — the account set
/// comes from `~/.aws/config` and `~/.aws/credentials`, so it tracks whatever
/// profiles the operator actually has.
async fn run_inventory_cli_profiles(cli: &Cli) -> Result<()> {
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

    let patterns = cli
        .accounts
        .as_ref()
        .expect("run_inventory_cli_profiles is only reached when --accounts is set");

    let detected = crate::credentials::aws_profiles::detect_aws_profiles()
        .context("--accounts: failed to read AWS profiles from ~/.aws")?;
    let available: Vec<String> = detected.iter().map(|p| p.name.clone()).collect();
    let selected = crate::cli::resolve_account_profiles(patterns, &available)?;

    // Each profile's own `region` setting wins; --region is the fallback.
    // --regions / --all-regions still override per-account, as elsewhere.
    let targets: Vec<InventoryTarget> = selected
        .iter()
        .map(|name| {
            let region = detected
                .iter()
                .find(|p| &p.name == name)
                .and_then(|p| p.region.clone())
                .filter(|r| !r.trim().is_empty())
                .unwrap_or_else(|| cli.region.clone());
            InventoryTarget {
                profile: name.clone(),
                region,
                display: name.clone(),
            }
        })
        .collect();

    eprintln!(
        "Matched {} AWS profile(s) from {}:",
        targets.len(),
        patterns.join(", ")
    );
    for target in &targets {
        eprintln!("  {} (region={})", target.profile, target.region);
    }

    if cli.accounts_dry_run {
        eprintln!("\n--accounts-dry-run: no AWS calls made, exiting.");
        return Ok(());
    }

    let inventory_types = crate::cli::resolve_inventory_types(cli);
    eprintln!("Inventory asset types: {}", inventory_types.join(", "));

    let inventory_dates = resolve_inventory_dates(cli)?;
    let output_dir = cli.output.clone().unwrap_or_else(|| PathBuf::from("."));
    let inventory_rows =
        collect_inventory_across_targets(cli, &targets, &inventory_types, inventory_dates).await;

    finalize_inventory_outputs(cli, &output_dir, &inventory_rows)?;

    Ok(())
}

/// Split a `--sbom-repos` value into repository names, trimming whitespace and
/// dropping empty entries. An all-empty input yields an empty Vec, which the
/// caller rejects.
fn parse_sbom_repos(list: &str) -> Vec<String> {
    list.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Map the user-facing `--sbom-format` spelling onto the SDK enum.
///
/// This must NOT use `SbomReportFormat::from(&str)`: that only recognises the
/// AWS wire values (`CYCLONEDX_1_4`, `SPDX_2_3`) and turns anything else into an
/// `Unknown` variant, which the Inspector API then rejects. The previous code
/// (`cli.sbom_format.as_str().into()`) had exactly that bug, so
/// `--sbom-format cyclonedx14` — the documented default — produced an invalid
/// request.
fn parse_sbom_format(value: &str) -> Result<aws_sdk_inspector2::types::SbomReportFormat> {
    use aws_sdk_inspector2::types::SbomReportFormat;

    match value.trim().to_lowercase().as_str() {
        "cyclonedx14" | "cyclonedx_1_4" | "cyclonedx" => Ok(SbomReportFormat::Cyclonedx14),
        "spdx23" | "spdx_2_3" | "spdx" => Ok(SbomReportFormat::Spdx23),
        other => {
            anyhow::bail!("unsupported --sbom-format '{other}': expected 'cyclonedx14' or 'spdx23'")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_a_plain_comma_list() {
        assert_eq!(
            parse_sbom_repos("webapp-base,websocket-server"),
            vec!["webapp-base", "websocket-server"]
        );
    }

    #[test]
    fn trims_whitespace_around_names() {
        assert_eq!(
            parse_sbom_repos(" webapp-base , websocket-server "),
            vec!["webapp-base", "websocket-server"]
        );
    }

    #[test]
    fn drops_empty_entries_from_trailing_and_doubled_commas() {
        assert_eq!(parse_sbom_repos("a,,b,"), vec!["a", "b"]);
    }

    #[test]
    fn preserves_namespaced_repository_names() {
        assert_eq!(
            parse_sbom_repos("team/service,other"),
            vec!["team/service", "other"]
        );
    }

    #[test]
    fn all_empty_input_yields_nothing_so_the_caller_can_reject_it() {
        assert!(parse_sbom_repos("").is_empty());
        assert!(parse_sbom_repos("  ").is_empty());
        assert!(parse_sbom_repos(", ,").is_empty());
    }

    #[test]
    fn single_name_needs_no_comma() {
        assert_eq!(parse_sbom_repos("solo"), vec!["solo"]);
    }

    #[test]
    fn parses_the_documented_format_spellings() {
        use aws_sdk_inspector2::types::SbomReportFormat;

        assert_eq!(
            parse_sbom_format("cyclonedx14").expect("cyclonedx14 is valid"),
            SbomReportFormat::Cyclonedx14
        );
        assert_eq!(
            parse_sbom_format("spdx23").expect("spdx23 is valid"),
            SbomReportFormat::Spdx23
        );
    }

    #[test]
    fn format_parsing_is_case_and_whitespace_tolerant() {
        use aws_sdk_inspector2::types::SbomReportFormat;

        assert_eq!(
            parse_sbom_format("  CycloneDX14 ").expect("valid"),
            SbomReportFormat::Cyclonedx14
        );
        assert_eq!(
            parse_sbom_format("SPDX_2_3").expect("valid"),
            SbomReportFormat::Spdx23
        );
    }

    #[test]
    fn format_parsing_rejects_unknown_values_instead_of_producing_unknown_variant() {
        // The bug this replaces: `"nonsense".into()` yielded Unknown("nonsense")
        // and failed only later, as an opaque AWS ValidationException.
        let err = parse_sbom_format("nonsense").expect_err("must be rejected");
        let msg = format!("{err}");
        assert!(
            msg.contains("nonsense"),
            "error should name the bad value: {msg}"
        );
        assert!(
            msg.contains("cyclonedx14"),
            "error should list valid values: {msg}"
        );
    }

    #[test]
    fn the_cli_default_format_parses() {
        // --sbom-format's clap default_value is "cyclonedx14"; if that stops
        // parsing, every default SBOM run breaks.
        assert!(parse_sbom_format("cyclonedx14").is_ok());
    }
}
