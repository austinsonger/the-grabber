//! Headless CLI path for the non-AWS providers.
//!
//! `run_standard_cli` is AWS-only: it builds an `AwsProviderFactory` and
//! nothing else. This module is its counterpart for Okta, Tenable, Elastic,
//! and GitHub — resolve accounts from the merged config (or from CLI/env
//! credentials when there is no config), build the provider client, hand the
//! selected keys to that provider's `ProviderFactory`, and drive the resulting
//! collectors through the same `collect_ops` runners the AWS path uses.
//!
//! Output layout matches the TUI: `{base}/{account name}/{YYYY}/{MM-MMM}/`.

mod elastic;
mod github;
mod okta;
mod tenable;

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::Utc;

use crate::app_config::{self, Account};
use crate::audit_log;
use crate::cli::Cli;
use crate::evidence::{CollectParams, CsvCollector, EvidenceCollector, JsonCollector};
use crate::providers::CloudProvider;
use crate::runner::collect_ops::{
    run_csv_collectors, run_json_collectors, run_json_inv_collectors,
};
use crate::runner::output::date_path_suffix;

/// Days of history used when a provider run specifies no window flags.
/// Okta, GitHub, and Elastic all have time-windowed collectors (system log,
/// audit log, alerts) that would otherwise export their full retained history.
const DEFAULT_PROVIDER_LOOKBACK_DAYS: i64 = 30;

/// True when exactly one non-AWS provider mode flag was passed.
pub fn provider_mode_selected(cli: &Cli) -> bool {
    cli.okta.okta_enabled
        || cli.tenable.tenable_enabled
        || cli.elastic.elastic_enabled
        || cli.github.github_enabled
}

/// Entry point for `--okta` / `--tenable` / `--elastic` / `--github`.
pub async fn run_provider_cli(cli: &Cli) -> Result<()> {
    let modes = [
        (cli.okta.okta_enabled, "--okta"),
        (cli.tenable.tenable_enabled, "--tenable"),
        (cli.elastic.elastic_enabled, "--elastic"),
        (cli.github.github_enabled, "--github"),
    ];
    let active: Vec<&str> = modes
        .iter()
        .filter(|(on, _)| *on)
        .map(|(_, name)| *name)
        .collect();
    if active.len() > 1 {
        anyhow::bail!(
            "{} are mutually exclusive — run one provider per invocation",
            active.join(" and ")
        );
    }

    if cli.inventory {
        anyhow::bail!("--inventory is AWS-only and cannot be combined with a provider mode flag");
    }
    if cli.poam {
        anyhow::bail!("--poam cannot be combined with a provider mode flag");
    }
    // The provider dispatch in main.rs preempts the POA&M dispatch, so these
    // would otherwise be parsed and then silently discarded.
    let poam_item_flags = [
        (cli.poam_add_item.is_some(), "--poam-add-item"),
        (cli.poam_remove_item.is_some(), "--poam-remove-item"),
        (cli.poam_item_title.is_some(), "--poam-item-title"),
        (
            cli.poam_item_description.is_some(),
            "--poam-item-description",
        ),
    ];
    let poam_item_set: Vec<&str> = poam_item_flags
        .iter()
        .filter(|(on, _)| *on)
        .map(|(_, name)| *name)
        .collect();
    if !poam_item_set.is_empty() {
        anyhow::bail!(
            "{} cannot be combined with a provider mode flag \
             — run the POA&M workflow in its own invocation",
            poam_item_set.join(", ")
        );
    }
    if cli.collectors.is_some() {
        anyhow::bail!(
            "--collectors selects AWS collectors; use --<provider>-collectors \
             (e.g. --okta-collectors okta-users) with a provider mode flag"
        );
    }
    if cli.all_regions || cli.regions.is_some() {
        anyhow::bail!("--all-regions/--regions are AWS-only and do not apply to provider modes");
    }

    if cli.okta.okta_enabled {
        return okta::run(cli).await;
    }
    if cli.tenable.tenable_enabled {
        return tenable::run(cli).await;
    }
    if cli.elastic.elastic_enabled {
        return elastic::run(cli).await;
    }
    if cli.github.github_enabled {
        return github::run(cli).await;
    }

    Ok(())
}

/// Accounts of `provider` from the merged config (config.toml plus the sibling
/// `*-config.toml` files), optionally narrowed to one by `name`.
///
/// Returns an empty vec only when there is genuinely no configured account for
/// this provider (no config file, or a config with no `[[account]]` of that
/// provider) — callers fall back to CLI-flag/env credentials in that case.
///
/// A `--<provider>-account` name that matches nothing is an *error*, not an
/// empty result: falling through to env credentials there would collect some
/// other tenant and label the evidence with the mistyped name.
pub(crate) fn accounts_for(provider: CloudProvider, name: Option<&str>) -> Result<Vec<Account>> {
    let Some(cfg) = app_config::load_config() else {
        return Ok(Vec::new());
    };
    let of_provider: Vec<Account> = cfg
        .account
        .into_iter()
        .filter(|a| a.provider == provider)
        .collect();
    if of_provider.is_empty() {
        return Ok(Vec::new());
    }
    let Some(requested) = name else {
        return Ok(of_provider);
    };

    let known: Vec<String> = of_provider.iter().map(|a| a.name.clone()).collect();
    let matched: Vec<Account> = of_provider
        .into_iter()
        .filter(|a| a.name.eq_ignore_ascii_case(requested))
        .collect();
    if matched.is_empty() {
        anyhow::bail!(
            "no [[account]] named '{}' for provider {} (known: {})",
            requested,
            provider.to_string().to_ascii_lowercase(),
            known.join(", ")
        );
    }
    Ok(matched)
}

/// First non-blank of: an explicit CLI flag, then an environment variable.
/// Blank/whitespace values at either level are treated as absent.
pub(crate) fn flag_or_env(flag: Option<String>, env_var: &str) -> Option<String> {
    flag.filter(|s| !s.trim().is_empty())
        .or_else(|| std::env::var(env_var).ok())
        .filter(|s| !s.trim().is_empty())
}

/// A credential override flag is layered onto *every* account in the run, so
/// with more than one matched account it would point them all at the same
/// tenant and write that one tenant's data out under several account names.
/// `provider` is the lowercase flag prefix, e.g. `okta`.
pub(crate) fn guard_credential_overrides(
    provider: &str,
    set_flags: &[&str],
    matched: usize,
) -> Result<()> {
    if set_flags.is_empty() || matched <= 1 {
        return Ok(());
    }
    anyhow::bail!(
        "{} would be applied to all {} matched {} accounts, so every account would \
         collect the same tenant and the evidence would be labelled with {} different \
         account names. Narrow the run with --{}-account <name>.",
        set_flags.join(", "),
        matched,
        provider,
        matched,
        provider
    );
}

/// Warn when two or more accounts in this run resolve to the same output
/// directory. Per-account CSV/JSON files are account-prefixed and survive, but
/// the per-run artifacts have fixed names and the last account wins.
pub(crate) fn warn_shared_output_dirs(cli: &Cli, accounts: &[(&str, Option<&str>)]) {
    let mut by_dir: BTreeMap<PathBuf, Vec<&str>> = BTreeMap::new();
    for (name, dir) in accounts {
        by_dir
            .entry(provider_output_dir(cli, name, *dir))
            .or_default()
            .push(name);
    }
    for (dir, names) in by_dir {
        if names.len() > 1 {
            eprintln!(
                "WARN: accounts {} all resolve to the same output directory {} — \
                 per-run artifacts (RUN-MANIFEST-*.json, fedramp-coverage-actual.csv) \
                 have fixed names, so the last account to finish overwrites the others. \
                 Pass --output <dir> to give each account its own subdirectory.",
                names.join(", "),
                dir.display()
            );
        }
    }
}

/// Build the collection window from `--lookback` or `--start-date`/`--end-date`.
/// Defaults to the last [`DEFAULT_PROVIDER_LOOKBACK_DAYS`] days and says so on
/// stderr, so a bare `grabber --okta` never silently exports full history.
pub(crate) fn resolve_window(cli: &Cli) -> Result<CollectParams> {
    let today = Utc::now().date_naive();

    let (start_date, end_date) = if let Some(ref lb) = cli.lookback {
        if cli.start_date.is_some() || cli.end_date.is_some() {
            anyhow::bail!("--lookback cannot be combined with --start-date or --end-date");
        }
        (crate::cli::parse_lookback(lb)?, today)
    } else if let Some(ref start) = cli.start_date {
        let end = cli
            .end_date
            .as_deref()
            .context("--end-date is required when --start-date is provided")?;
        (
            chrono::NaiveDate::parse_from_str(start, "%Y-%m-%d").context("Invalid --start-date")?,
            chrono::NaiveDate::parse_from_str(end, "%Y-%m-%d").context("Invalid --end-date")?,
        )
    } else {
        let start = today - chrono::Duration::days(DEFAULT_PROVIDER_LOOKBACK_DAYS);
        eprintln!(
            "No window flags given — defaulting to the last {} days ({} → {}). \
             Pass --lookback or --start-date/--end-date to override.",
            DEFAULT_PROVIDER_LOOKBACK_DAYS, start, today
        );
        (start, today)
    };

    Ok(CollectParams {
        start_time: start_date
            .and_hms_opt(0, 0, 0)
            .context("invalid start-of-day time")?
            .and_utc(),
        end_time: end_date
            .and_hms_opt(23, 59, 59)
            .context("invalid end-of-day time")?
            .and_utc(),
        filter: cli.filter.clone(),
        include_raw: cli.include_raw,
    })
}

/// Output directory for one provider account, matching the TUI layout.
///
/// `--output` wins and gets the account name appended. Otherwise the account's
/// own `output_dir` is used as-is (it already names the provider, e.g.
/// `./evidence-output/okta`). With neither, files land under `./{name}/`.
/// The `{YYYY}/{MM-MMM}` date hierarchy is appended in every case.
pub(crate) fn provider_output_dir(
    cli: &Cli,
    name: &str,
    account_output_dir: Option<&str>,
) -> PathBuf {
    let base = match (
        cli.output.as_ref(),
        account_output_dir.map(str::trim).filter(|s| !s.is_empty()),
    ) {
        (Some(out), _) => out.join(name),
        (None, Some(dir)) => PathBuf::from(dir),
        (None, None) => PathBuf::from(".").join(name),
    };
    base.join(date_path_suffix())
}

/// The per-account tail shared by all four provider runners: run the three
/// `collect_ops` runners over one account's collectors and write that account's
/// run manifest. Returns the output directory it used so the caller can
/// accumulate the run's directories for the once-per-run zip/signing pass.
///
/// `display_name` names the output directory; `account_id` is what the
/// collectors stamp into filenames and the run manifest (they differ for
/// GitHub, where the directory is the account name but the identity is the org).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_account_collectors(
    cli: &Cli,
    provider: &str,
    display_name: &str,
    account_id: &str,
    account_output_dir: Option<&str>,
    params: &CollectParams,
    timestamp: &str,
    csv_cols: Vec<Box<dyn CsvCollector>>,
    json_inv_cols: Vec<Box<dyn JsonCollector>>,
    evidence_cols: Vec<Box<dyn EvidenceCollector>>,
) -> Result<PathBuf> {
    if csv_cols.is_empty() && json_inv_cols.is_empty() && evidence_cols.is_empty() {
        anyhow::bail!("No {provider} collectors matched the selected keys.");
    }

    let output_dir = provider_output_dir(cli, display_name, account_output_dir);
    eprintln!("  Output: {}", output_dir.display());
    std::fs::create_dir_all(&output_dir)
        .with_context(|| format!("Failed to create output directory {}", output_dir.display()))?;

    let dates = Some((params.start_time.timestamp(), params.end_time.timestamp()));

    let mut outcomes = Vec::new();
    outcomes.extend(run_json_collectors(&evidence_cols, params, "", &output_dir, timestamp).await?);
    outcomes.extend(
        run_json_inv_collectors(&json_inv_cols, account_id, "", &output_dir, timestamp).await?,
    );
    outcomes.extend(
        run_csv_collectors(&csv_cols, account_id, "", &output_dir, dates, timestamp).await?,
    );

    write_provider_run_manifest(cli, timestamp, account_id, params, outcomes, &output_dir);

    Ok(output_dir)
}

/// Per-account run manifest, written into that account's own output directory.
fn write_provider_run_manifest(
    cli: &Cli,
    timestamp: &str,
    account_id: &str,
    params: &CollectParams,
    outcomes: Vec<audit_log::CollectorOutcome>,
    output_dir: &Path,
) {
    if !cli.write_run_manifest {
        return;
    }
    let manifest = audit_log::RunManifest::build(
        timestamp,
        account_id,
        "",
        &params.start_time.format("%Y-%m-%d").to_string(),
        &params.end_time.format("%Y-%m-%d").to_string(),
        outcomes,
    );
    match audit_log::write_run_manifest(output_dir, &manifest) {
        Ok(p) => eprintln!("Run manifest written: {}", p.display()),
        Err(e) => eprintln!("WARN: could not write run manifest: {e}"),
    }
}

/// Once-per-run artifacts: zip and signing, over the union of every account's
/// output. Must be called **after** the account loop — the zip and the signing
/// manifest/key are named from the single run `timestamp`, so doing this per
/// account would have each account truncate the last one's bundle and leave a
/// signing key that only verifies the survivor.
///
/// Chain-of-custody is intentionally skipped — `CustodyEntry` is built around
/// an `AwsIdentity` (account id, caller ARN, user id) that has no meaning for
/// these providers. `--write-chain-of-custody` warns instead of failing.
pub(crate) fn finish_provider_run(
    cli: &Cli,
    timestamp: &str,
    output_dirs: &[PathBuf],
) -> Result<()> {
    if cli.write_chain_of_custody {
        eprintln!(
            "WARN: --write-chain-of-custody is AWS-only (the custody record is keyed \
             on an AWS caller identity) — skipping for this provider run."
        );
    }

    if !cli.zip && !cli.sign {
        return Ok(());
    }

    // Union of every account's files. Two accounts can share a directory, so
    // dedup while preserving order.
    let mut seen = HashSet::new();
    let mut files: Vec<String> = Vec::new();
    for dir in output_dirs {
        for f in crate::signing::collect_dir_files(dir) {
            if seen.insert(f.clone()) {
                files.push(f);
            }
        }
    }

    if files.is_empty() {
        eprintln!("WARN: no evidence files were written — skipping zip/signing.");
        return Ok(());
    }

    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));

    if cli.zip {
        let zip_name = format!("Evidence-{}.zip", timestamp);
        let zip_path = PathBuf::from(&zip_name);
        match crate::zip_bundle::bundle_files(&files, &cwd, &zip_path) {
            Ok(()) => eprintln!("Zip bundle written: {} ({} files)", zip_name, files.len()),
            Err(e) => eprintln!("Zip bundle failed: {e}"),
        }
    }

    if cli.sign {
        // One key for the whole run — a per-account key would only verify the
        // last account's manifest.
        let key = match &cli.signing_key {
            Some(hex) => crate::signing::SigningKey::from_hex(hex)?,
            None => crate::signing::SigningKey::generate()?,
        };
        match crate::signing::sign_files(&files, timestamp, &key, &cwd) {
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
