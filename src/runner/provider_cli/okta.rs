//! `--okta`: headless Okta evidence collection.

use anyhow::Result;

use crate::cli::Cli;

#[cfg(feature = "okta")]
pub(super) async fn run(cli: &Cli) -> Result<()> {
    use std::path::PathBuf;

    use chrono::Utc;

    use crate::providers::CloudProvider;
    use crate::providers::ProviderFactory as _;

    let selected = cli.okta.resolve_collectors()?;
    let params = super::resolve_window(cli)?;
    eprintln!("Okta collectors: {}", selected.join(", "));

    // (tenant name, domain, api token, per-account output_dir)
    let mut targets: Vec<(String, String, String, Option<String>)> = Vec::new();

    let accounts = super::accounts_for(CloudProvider::Okta, cli.okta.okta_account.as_deref())?;
    if accounts.is_empty() {
        let name = cli
            .okta
            .okta_account
            .clone()
            .unwrap_or_else(|| "Okta".to_string());
        let domain = super::flag_or_env(cli.okta.okta_domain.clone(), "OKTA_DOMAIN");
        let token = super::flag_or_env(cli.okta.okta_api_token.clone(), "OKTA_API_TOKEN");
        match (domain, token) {
            (Some(d), Some(t)) => targets.push((name, d, t, None)),
            _ => anyhow::bail!(
                "No Okta account found. Add an [[account]] with provider = \"okta\" to \
                 okta-config.toml, or pass --okta-domain and --okta-api-token \
                 (or set OKTA_DOMAIN and OKTA_API_TOKEN)."
            ),
        }
    } else {
        let mut overrides: Vec<&str> = Vec::new();
        if cli.okta.okta_domain.is_some() {
            overrides.push("--okta-domain");
        }
        if cli.okta.okta_api_token.is_some() {
            overrides.push("--okta-api-token");
        }
        super::guard_credential_overrides("okta", &overrides, accounts.len())?;

        for acct in &accounts {
            let domain = cli
                .okta
                .okta_domain
                .clone()
                .filter(|s| !s.trim().is_empty())
                .or_else(|| acct.okta_domain_resolved())
                .filter(|s| !s.trim().is_empty());
            let token = cli
                .okta
                .okta_api_token
                .clone()
                .filter(|s| !s.trim().is_empty())
                .or_else(|| acct.okta_api_token_resolved())
                .filter(|s| !s.trim().is_empty());
            match (domain, token) {
                (Some(d), Some(t)) => {
                    targets.push((acct.name.clone(), d, t, acct.output_dir.clone()))
                }
                (None, _) => eprintln!(
                    "  ✗ Okta '{}' — missing okta_domain (or OKTA_DOMAIN env) — skipping",
                    acct.name
                ),
                (_, None) => eprintln!(
                    "  ✗ Okta '{}' — missing okta_api_token (or OKTA_API_TOKEN env) — skipping",
                    acct.name
                ),
            }
        }
        if targets.is_empty() {
            anyhow::bail!("No Okta account had usable credentials.");
        }
    }

    let timestamp = Utc::now().format("%Y-%m-%d-%H%M%S").to_string();

    let dir_keys: Vec<(&str, Option<&str>)> = targets
        .iter()
        .map(|(name, _, _, dir)| (name.as_str(), dir.as_deref()))
        .collect();
    super::warn_shared_output_dirs(cli, &dir_keys);

    let mut output_dirs: Vec<PathBuf> = Vec::new();
    for (name, domain, token, account_output_dir) in &targets {
        eprintln!("=== Okta '{}' → {} ===", name, domain);

        let client = match okta_rs::OktaClient::new(domain, token) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("  ✗ Okta '{name}' — client build failed: {e}");
                continue;
            }
        };

        let factory = crate::providers::okta::factory::OktaProviderFactory::new(
            client,
            name.clone(),
            selected.clone(),
        );

        output_dirs.push(
            super::run_account_collectors(
                cli,
                "Okta",
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
        anyhow::bail!("No Okta account was collected — every account failed to build a client.");
    }

    super::finish_provider_run(cli, &timestamp, &output_dirs)
}

#[cfg(not(feature = "okta"))]
pub(super) async fn run(_cli: &Cli) -> Result<()> {
    anyhow::bail!("--okta requires a build with the `okta` feature enabled")
}
