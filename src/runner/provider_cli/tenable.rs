//! `--tenable`: headless Tenable evidence collection.

use anyhow::Result;

use crate::cli::Cli;

#[cfg(feature = "tenable")]
pub(super) async fn run(cli: &Cli) -> Result<()> {
    use std::path::PathBuf;

    use chrono::Utc;

    use crate::providers::CloudProvider;
    use crate::providers::ProviderFactory as _;

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
    )?;
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
        let access_key =
            super::flag_or_env(cli.tenable.tenable_access_key.clone(), "TENABLE_ACCESS_KEY");
        let secret_key =
            super::flag_or_env(cli.tenable.tenable_secret_key.clone(), "TENABLE_SECRET_KEY");
        match (access_key, secret_key) {
            (Some(a), Some(s)) => targets.push((name, base_url, a, s, None)),
            _ => anyhow::bail!(
                "No Tenable account found. Add an [[account]] with provider = \"tenable\" to \
                 tenable-config.toml, or pass --tenable-access-key and --tenable-secret-key \
                 (or set TENABLE_ACCESS_KEY and TENABLE_SECRET_KEY)."
            ),
        }
    } else {
        let mut overrides: Vec<&str> = Vec::new();
        if cli.tenable.tenable_url.is_some() {
            overrides.push("--tenable-url");
        }
        if cli.tenable.tenable_access_key.is_some() {
            overrides.push("--tenable-access-key");
        }
        if cli.tenable.tenable_secret_key.is_some() {
            overrides.push("--tenable-secret-key");
        }
        super::guard_credential_overrides("tenable", &overrides, accounts.len())?;

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

    let dir_keys: Vec<(&str, Option<&str>)> = targets
        .iter()
        .map(|(name, _, _, _, dir)| (name.as_str(), dir.as_deref()))
        .collect();
    super::warn_shared_output_dirs(cli, &dir_keys);

    let mut output_dirs: Vec<PathBuf> = Vec::new();
    for (name, base_url, access_key, secret_key, account_output_dir) in &targets {
        let flavor = tenable_rs::TenableFlavor::for_url(base_url);
        eprintln!(
            "=== Tenable '{}' → {} ({}) ===",
            name,
            base_url,
            flavor.label()
        );

        let (client, _) =
            match tenable_rs::TenableClient::from_url(base_url, access_key, secret_key) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("  ✗ Tenable '{name}' — client build failed: {e}");
                    continue;
                }
            };

        let factory = crate::providers::tenable::factory::TenableProviderFactory::new(
            client,
            name.clone(),
            selected.clone(),
            scan_ids.clone(),
            was_scan_ids.clone(),
        );

        output_dirs.push(
            super::run_account_collectors(
                cli,
                "Tenable",
                name,
                name,
                account_output_dir.as_deref(),
                &params,
                &timestamp,
                factory.csv_collectors(),
                factory.json_collectors(),
                factory.evidence_collectors(),
            )
            .await?,
        );
    }

    if output_dirs.is_empty() {
        anyhow::bail!("No Tenable account was collected — every account failed to build a client.");
    }

    super::finish_provider_run(cli, &timestamp, &output_dirs)
}

#[cfg(not(feature = "tenable"))]
pub(super) async fn run(_cli: &Cli) -> Result<()> {
    anyhow::bail!("--tenable requires a build with the `tenable` feature enabled")
}
