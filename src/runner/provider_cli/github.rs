//! `--github`: headless GitHub organization evidence collection.

use anyhow::Result;

use crate::cli::Cli;

#[cfg(feature = "github")]
pub(super) async fn run(cli: &Cli) -> Result<()> {
    use chrono::Utc;

    use crate::providers::CloudProvider;
    use crate::providers::ProviderFactory as _;
    use crate::runner::collect_ops::{
        run_csv_collectors, run_json_collectors, run_json_inv_collectors,
    };

    let selected = cli.github.resolve_collectors()?;
    let params = super::resolve_window(cli)?;
    eprintln!("GitHub collectors: {}", selected.join(", "));

    // (account name, org, token, base url, per-account output_dir)
    let mut targets: Vec<(String, String, String, String, Option<String>)> = Vec::new();

    let accounts = super::accounts_for(CloudProvider::Github, cli.github.github_account.as_deref());
    if accounts.is_empty() {
        let name = cli
            .github
            .github_account
            .clone()
            .unwrap_or_else(|| "GitHub".to_string());
        let org = cli
            .github
            .github_org
            .clone()
            .filter(|s| !s.trim().is_empty())
            .or_else(|| std::env::var("GITHUB_ORG").ok())
            .filter(|s| !s.trim().is_empty());
        let token = cli
            .github
            .github_token
            .clone()
            .filter(|s| !s.trim().is_empty())
            .or_else(|| std::env::var("GITHUB_TOKEN").ok())
            .filter(|s| !s.trim().is_empty());
        let base_url = cli
            .github
            .github_base_url
            .clone()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "https://api.github.com".to_string());
        match (org, token) {
            (Some(o), Some(t)) => targets.push((name, o, t, base_url, None)),
            _ => anyhow::bail!(
                "No GitHub account found. Add an [[account]] with provider = \"github\" to \
                 github-config.toml, or pass --github-org and --github-token \
                 (or set GITHUB_ORG and GITHUB_TOKEN)."
            ),
        }
    } else {
        for acct in &accounts {
            let org = cli
                .github
                .github_org
                .clone()
                .filter(|s| !s.trim().is_empty())
                .or_else(|| acct.github_org_resolved())
                .filter(|s| !s.trim().is_empty());
            let token = cli
                .github
                .github_token
                .clone()
                .filter(|s| !s.trim().is_empty())
                .or_else(|| acct.github_token_resolved())
                .filter(|s| !s.trim().is_empty());
            let base_url = cli
                .github
                .github_base_url
                .clone()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| acct.github_base_url_resolved());
            match (org, token) {
                (Some(o), Some(t)) => {
                    targets.push((acct.name.clone(), o, t, base_url, acct.output_dir.clone()))
                }
                (None, _) => eprintln!(
                    "  ✗ GitHub '{}' — missing github_org (or GITHUB_ORG env) — skipping",
                    acct.name
                ),
                (_, None) => eprintln!(
                    "  ✗ GitHub '{}' — missing github_token (or GITHUB_TOKEN env) — skipping",
                    acct.name
                ),
            }
        }
        if targets.is_empty() {
            anyhow::bail!("No GitHub account had usable credentials.");
        }
    }

    let timestamp = Utc::now().format("%Y-%m-%d-%H%M%S").to_string();
    let dates = Some((params.start_time.timestamp(), params.end_time.timestamp()));

    for (name, org, token, base_url, account_output_dir) in targets {
        eprintln!("=== GitHub '{}' → {} ({}) ===", name, org, base_url);

        let client = github_rs::GithubClient::new(&base_url, &token, &org)
            .map_err(|e| anyhow::anyhow!("GitHub '{name}' — client build failed: {e}"))?;

        let factory = crate::providers::github::factory::GithubProviderFactory::new(
            client,
            org.clone(),
            selected.clone(),
        );
        let csv_cols = factory.csv_collectors();
        let json_inv_cols = factory.json_collectors();
        let evidence_cols = factory.evidence_collectors();
        if csv_cols.is_empty() && json_inv_cols.is_empty() && evidence_cols.is_empty() {
            anyhow::bail!("No GitHub collectors matched the selected keys.");
        }

        let output_dir = super::provider_output_dir(cli, &name, account_output_dir.as_deref());
        eprintln!("  Output: {}", output_dir.display());

        let mut outcomes = Vec::new();
        outcomes.extend(
            run_json_collectors(&evidence_cols, &params, "", &output_dir, &timestamp).await?,
        );
        outcomes.extend(
            run_json_inv_collectors(&json_inv_cols, &org, "", &output_dir, &timestamp).await?,
        );
        outcomes
            .extend(run_csv_collectors(&csv_cols, &org, "", &output_dir, dates, &timestamp).await?);

        super::finish_provider_run(cli, &timestamp, &name, &params, outcomes, &output_dir)?;
    }

    Ok(())
}

#[cfg(not(feature = "github"))]
pub(super) async fn run(_cli: &Cli) -> Result<()> {
    anyhow::bail!("--github requires a build with the `github` feature enabled")
}
