//! `--okta`: headless Okta evidence collection.

use anyhow::Result;

use crate::cli::Cli;

#[cfg(feature = "okta")]
pub(super) async fn run(cli: &Cli) -> Result<()> {
    use chrono::Utc;

    use crate::providers::CloudProvider;
    use crate::providers::ProviderFactory as _;
    use crate::runner::collect_ops::{
        run_csv_collectors, run_json_collectors, run_json_inv_collectors,
    };

    let selected = cli.okta.resolve_collectors()?;
    let params = super::resolve_window(cli)?;
    eprintln!("Okta collectors: {}", selected.join(", "));

    // (tenant name, domain, api token, per-account output_dir)
    let mut targets: Vec<(String, String, String, Option<String>)> = Vec::new();

    let accounts = super::accounts_for(CloudProvider::Okta, cli.okta.okta_account.as_deref());
    if accounts.is_empty() {
        let name = cli
            .okta
            .okta_account
            .clone()
            .unwrap_or_else(|| "Okta".to_string());
        let domain = cli
            .okta
            .okta_domain
            .clone()
            .or_else(|| std::env::var("OKTA_DOMAIN").ok())
            .filter(|s| !s.trim().is_empty());
        let token = cli
            .okta
            .okta_api_token
            .clone()
            .or_else(|| std::env::var("OKTA_API_TOKEN").ok())
            .filter(|s| !s.trim().is_empty());
        match (domain, token) {
            (Some(d), Some(t)) => targets.push((name, d, t, None)),
            _ => anyhow::bail!(
                "No Okta account found. Add an [[account]] with provider = \"okta\" to \
                 okta-config.toml, or pass --okta-domain and --okta-api-token \
                 (or set OKTA_DOMAIN and OKTA_API_TOKEN)."
            ),
        }
    } else {
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
    let dates = Some((params.start_time.timestamp(), params.end_time.timestamp()));

    for (name, domain, token, account_output_dir) in targets {
        eprintln!("=== Okta '{}' → {} ===", name, domain);

        let client = okta_rs::OktaClient::new(&domain, &token)
            .map_err(|e| anyhow::anyhow!("Okta '{name}' — client build failed: {e}"))?;

        let factory = crate::providers::okta::factory::OktaProviderFactory::new(
            client,
            name.clone(),
            selected.clone(),
        );
        let csv_cols = factory.csv_collectors();
        let json_inv_cols = factory.json_collectors();
        let evidence_cols = factory.evidence_collectors();
        if csv_cols.is_empty() && json_inv_cols.is_empty() && evidence_cols.is_empty() {
            anyhow::bail!("No Okta collectors matched the selected keys.");
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

#[cfg(not(feature = "okta"))]
pub(super) async fn run(_cli: &Cli) -> Result<()> {
    anyhow::bail!("--okta requires a build with the `okta` feature enabled")
}
