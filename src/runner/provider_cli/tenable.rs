//! `--tenable`: headless Tenable evidence collection.

use anyhow::Result;

use crate::cli::Cli;

#[cfg(feature = "tenable")]
pub(super) async fn run(cli: &Cli) -> Result<()> {
    use chrono::Utc;

    use crate::providers::CloudProvider;
    use crate::providers::ProviderFactory as _;
    use crate::runner::collect_ops::{
        run_csv_collectors, run_json_collectors, run_json_inv_collectors,
    };

    let selected = cli.tenable.resolve_collectors()?;
    let params = super::resolve_window(cli)?;
    eprintln!("Tenable collectors: {}", selected.join(", "));

    let scan_ids = cli.tenable.tenable_scan_ids.clone().unwrap_or_default();
    let was_scan_ids = cli.tenable.tenable_was_scan_ids.clone().unwrap_or_default();

    // (site name, base url, access key, secret key, per-account output_dir)
    let mut targets: Vec<(String, String, String, String, Option<String>)> = Vec::new();

    let accounts = super::accounts_for(
        CloudProvider::Tenable,
        cli.tenable.tenable_account.as_deref(),
    );
    if accounts.is_empty() {
        let name = cli
            .tenable
            .tenable_account
            .clone()
            .unwrap_or_else(|| "Tenable".to_string());
        let base_url = cli
            .tenable
            .tenable_url
            .clone()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "https://cloud.tenable.com".to_string());
        let access_key = cli
            .tenable
            .tenable_access_key
            .clone()
            .filter(|s| !s.trim().is_empty())
            .or_else(|| std::env::var("TENABLE_ACCESS_KEY").ok())
            .filter(|s| !s.trim().is_empty());
        let secret_key = cli
            .tenable
            .tenable_secret_key
            .clone()
            .filter(|s| !s.trim().is_empty())
            .or_else(|| std::env::var("TENABLE_SECRET_KEY").ok())
            .filter(|s| !s.trim().is_empty());
        match (access_key, secret_key) {
            (Some(a), Some(s)) => targets.push((name, base_url, a, s, None)),
            _ => anyhow::bail!(
                "No Tenable account found. Add an [[account]] with provider = \"tenable\" to \
                 tenable-config.toml, or pass --tenable-access-key and --tenable-secret-key \
                 (or set TENABLE_ACCESS_KEY and TENABLE_SECRET_KEY)."
            ),
        }
    } else {
        for acct in &accounts {
            let base_url = cli
                .tenable
                .tenable_url
                .clone()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| acct.tenable_url_resolved());
            let access_key = cli
                .tenable
                .tenable_access_key
                .clone()
                .filter(|s| !s.trim().is_empty())
                .or_else(|| acct.tenable_access_key_resolved())
                .filter(|s| !s.trim().is_empty());
            let secret_key = cli
                .tenable
                .tenable_secret_key
                .clone()
                .filter(|s| !s.trim().is_empty())
                .or_else(|| acct.tenable_secret_key_resolved())
                .filter(|s| !s.trim().is_empty());
            match (access_key, secret_key) {
                (Some(a), Some(s)) => {
                    targets.push((acct.name.clone(), base_url, a, s, acct.output_dir.clone()))
                }
                _ => {
                    let flavor = tenable_rs::TenableFlavor::for_url(&base_url);
                    eprintln!(
                        "  ✗ Tenable '{}' — missing access/secret key for {} — skipping. {}",
                        acct.name,
                        flavor.label(),
                        flavor.api_keys_hint()
                    );
                }
            }
        }
        if targets.is_empty() {
            anyhow::bail!("No Tenable account had usable credentials.");
        }
    }

    let timestamp = Utc::now().format("%Y-%m-%d-%H%M%S").to_string();
    let dates = Some((params.start_time.timestamp(), params.end_time.timestamp()));

    for (name, base_url, access_key, secret_key, account_output_dir) in targets {
        let flavor = tenable_rs::TenableFlavor::for_url(&base_url);
        eprintln!(
            "=== Tenable '{}' → {} ({}) ===",
            name,
            base_url,
            flavor.label()
        );

        let (client, _) = tenable_rs::TenableClient::from_url(&base_url, &access_key, &secret_key)
            .map_err(|e| anyhow::anyhow!("Tenable '{name}' — client build failed: {e}"))?;

        let factory = crate::providers::tenable::factory::TenableProviderFactory::new(
            client,
            name.clone(),
            selected.clone(),
            scan_ids.clone(),
            was_scan_ids.clone(),
        );
        let csv_cols = factory.csv_collectors();
        let json_inv_cols = factory.json_collectors();
        let evidence_cols = factory.evidence_collectors();
        if csv_cols.is_empty() && json_inv_cols.is_empty() && evidence_cols.is_empty() {
            anyhow::bail!("No Tenable collectors matched the selected keys.");
        }

        let output_dir = super::provider_output_dir(cli, &name, account_output_dir.as_deref());
        eprintln!("  Output: {}", output_dir.display());

        let mut outcomes = Vec::new();
        outcomes.extend(
            run_json_collectors(&evidence_cols, &params, "", &output_dir, &timestamp).await?,
        );
        outcomes.extend(
            run_json_inv_collectors(&json_inv_cols, &name, "", &output_dir, &timestamp).await?,
        );
        outcomes.extend(
            run_csv_collectors(&csv_cols, &name, "", &output_dir, dates, &timestamp).await?,
        );

        super::finish_provider_run(cli, &timestamp, &name, &params, outcomes, &output_dir)?;
    }

    Ok(())
}

#[cfg(not(feature = "tenable"))]
pub(super) async fn run(_cli: &Cli) -> Result<()> {
    anyhow::bail!("--tenable requires a build with the `tenable` feature enabled")
}
