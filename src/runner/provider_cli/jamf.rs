//! `--jamf`: headless Jamf Pro evidence collection.

use anyhow::Result;

use crate::cli::Cli;

#[cfg(feature = "jamf")]
pub(super) async fn run(cli: &Cli) -> Result<()> {
    use std::path::PathBuf;

    use chrono::Utc;

    use crate::providers::CloudProvider;
    use crate::providers::ProviderFactory as _;

    let selected = cli.jamf.resolve_collectors()?;
    let params = super::resolve_window(cli)?;
    eprintln!("Jamf collectors: {}", selected.join(", "));

    // (tenant name, base url, client id, client secret, per-account output_dir)
    let mut targets: Vec<(String, String, String, String, Option<String>)> = Vec::new();

    let accounts = super::accounts_for(CloudProvider::Jamf, cli.jamf.jamf_account.as_deref())?;
    if accounts.is_empty() {
        let name = cli
            .jamf
            .jamf_account
            .clone()
            .unwrap_or_else(|| "Jamf".to_string());
        let base_url = super::flag_or_env(cli.jamf.jamf_base_url.clone(), "JAMF_BASE_URL");
        let client_id = super::flag_or_env(cli.jamf.jamf_client_id.clone(), "JAMF_CLIENT_ID");
        let client_secret =
            super::flag_or_env(cli.jamf.jamf_client_secret.clone(), "JAMF_CLIENT_SECRET");
        match (base_url, client_id, client_secret) {
            (Some(u), Some(i), Some(s)) => targets.push((name, u, i, s, None)),
            _ => anyhow::bail!(
                "No Jamf account found. Add an [[account]] with provider = \"jamf\" to \
                 jamf-config.toml, or pass --jamf-base-url, --jamf-client-id, and \
                 --jamf-client-secret (or set JAMF_BASE_URL, JAMF_CLIENT_ID, and \
                 JAMF_CLIENT_SECRET)."
            ),
        }
    } else {
        let mut overrides: Vec<&str> = Vec::new();
        if cli.jamf.jamf_base_url.is_some() {
            overrides.push("--jamf-base-url");
        }
        if cli.jamf.jamf_client_id.is_some() {
            overrides.push("--jamf-client-id");
        }
        if cli.jamf.jamf_client_secret.is_some() {
            overrides.push("--jamf-client-secret");
        }
        super::guard_credential_overrides("jamf", &overrides, accounts.len())?;

        for acct in &accounts {
            let base_url = cli
                .jamf
                .jamf_base_url
                .clone()
                .filter(|s| !s.trim().is_empty())
                .or_else(|| acct.jamf_base_url_resolved())
                .filter(|s| !s.trim().is_empty());
            let client_id = cli
                .jamf
                .jamf_client_id
                .clone()
                .filter(|s| !s.trim().is_empty())
                .or_else(|| acct.jamf_client_id_resolved())
                .filter(|s| !s.trim().is_empty());
            let client_secret = cli
                .jamf
                .jamf_client_secret
                .clone()
                .filter(|s| !s.trim().is_empty())
                .or_else(|| acct.jamf_client_secret_resolved())
                .filter(|s| !s.trim().is_empty());
            match (base_url, client_id, client_secret) {
                (Some(u), Some(i), Some(s)) => {
                    targets.push((acct.name.clone(), u, i, s, acct.output_dir.clone()))
                }
                (None, _, _) => eprintln!(
                    "  ✗ Jamf '{}' — missing jamf_base_url (or JAMF_BASE_URL env) — skipping",
                    acct.name
                ),
                (_, None, _) => eprintln!(
                    "  ✗ Jamf '{}' — missing jamf_client_id (or JAMF_CLIENT_ID env) — skipping",
                    acct.name
                ),
                (_, _, None) => eprintln!(
                    "  ✗ Jamf '{}' — missing jamf_client_secret (or JAMF_CLIENT_SECRET env) — skipping",
                    acct.name
                ),
            }
        }
        if targets.is_empty() {
            anyhow::bail!("No Jamf account had usable credentials.");
        }
    }

    let timestamp = Utc::now().format("%Y-%m-%d-%H%M%S").to_string();

    let dir_keys: Vec<(&str, Option<&str>)> = targets
        .iter()
        .map(|(name, _, _, _, dir)| (name.as_str(), dir.as_deref()))
        .collect();
    super::warn_shared_output_dirs(cli, &dir_keys);

    let mut output_dirs: Vec<PathBuf> = Vec::new();
    for (name, base_url, client_id, client_secret, account_output_dir) in &targets {
        eprintln!("=== Jamf '{}' → {} ===", name, base_url);

        let client = match jamf_rs::JamfClient::new(base_url, client_id, client_secret) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("  ✗ Jamf '{name}' — client build failed: {e}");
                continue;
            }
        };

        let factory = crate::providers::jamf::factory::JamfProviderFactory::new(
            client,
            name.clone(),
            selected.clone(),
        );

        output_dirs.push(
            super::run_account_collectors(
                cli,
                "Jamf",
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
        anyhow::bail!("No Jamf account was collected — every account failed to build a client.");
    }

    super::finish_provider_run(cli, &timestamp, &output_dirs)
}

#[cfg(not(feature = "jamf"))]
pub(super) async fn run(_cli: &Cli) -> Result<()> {
    anyhow::bail!("--jamf requires a build with the `jamf` feature enabled")
}
