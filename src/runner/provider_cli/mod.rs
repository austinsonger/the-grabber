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
mod okta;
mod tenable;

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::Utc;

use crate::app_config::{self, Account};
use crate::audit_log;
use crate::cli::Cli;
use crate::evidence::CollectParams;
use crate::providers::CloudProvider;
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
        anyhow::bail!("--github is not wired up yet");
    }

    Ok(())
}

/// Accounts of `provider` from the merged config (config.toml plus the sibling
/// `*-config.toml` files), optionally narrowed to one by `name`.
/// Returns an empty vec when no config file exists — callers fall back to
/// CLI-flag/env credentials in that case.
pub(crate) fn accounts_for(provider: CloudProvider, name: Option<&str>) -> Vec<Account> {
    let Some(cfg) = app_config::load_config() else {
        return Vec::new();
    };
    cfg.account
        .into_iter()
        .filter(|a| a.provider == provider)
        .filter(|a| match name {
            Some(n) => a.name.eq_ignore_ascii_case(n),
            None => true,
        })
        .collect()
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

/// Post-run artifacts shared by every provider: run manifest, zip, signing.
///
/// Chain-of-custody is intentionally skipped — `CustodyEntry` is built around
/// an `AwsIdentity` (account id, caller ARN, user id) that has no meaning for
/// these providers. `--write-chain-of-custody` warns instead of failing.
pub(crate) fn finish_provider_run(
    cli: &Cli,
    timestamp: &str,
    account_id: &str,
    params: &CollectParams,
    outcomes: Vec<audit_log::CollectorOutcome>,
    output_dir: &Path,
) -> Result<()> {
    if cli.write_run_manifest {
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

    if cli.write_chain_of_custody {
        eprintln!(
            "WARN: --write-chain-of-custody is AWS-only (the custody record is keyed \
             on an AWS caller identity) — skipping for this provider run."
        );
    }

    if cli.zip {
        let zip_name = format!("Evidence-{}.zip", timestamp);
        let zip_path = std::path::Path::new(&zip_name);
        match crate::zip_bundle::bundle_dir(output_dir, zip_path) {
            Ok(()) => eprintln!("Zip bundle written: {}", zip_name),
            Err(e) => eprintln!("Zip bundle failed: {e}"),
        }
    }

    if cli.sign {
        let key = match &cli.signing_key {
            Some(hex) => crate::signing::SigningKey::from_hex(hex)?,
            None => crate::signing::SigningKey::generate()?,
        };
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let files = crate::signing::collect_dir_files(output_dir);
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
