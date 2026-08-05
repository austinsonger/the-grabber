//! `--github`: headless GitHub organization evidence collection.

use anyhow::Result;

use crate::cli::Cli;

#[cfg(feature = "github")]
pub(super) async fn run(cli: &Cli) -> Result<()> {
    use std::path::PathBuf;

    use chrono::Utc;

    use crate::providers::CloudProvider;
    use crate::providers::ProviderFactory as _;

    let selected = cli.github.resolve_collectors()?;
    let params = super::resolve_window(cli)?;
    eprintln!("GitHub collectors: {}", selected.join(", "));

    // (account name, org, token, base url, per-account output_dir)
    let mut targets: Vec<(String, String, String, String, Option<String>)> = Vec::new();

    let accounts =
        super::accounts_for(CloudProvider::Github, cli.github.github_account.as_deref())?;
    if accounts.is_empty() {
        let name = cli
            .github
            .github_account
            .clone()
            .unwrap_or_else(|| "GitHub".to_string());
        let org = super::flag_or_env(cli.github.github_org.clone(), "GITHUB_ORG");
        let token = super::flag_or_env(cli.github.github_token.clone(), "GITHUB_TOKEN");
        let base_url = super::flag_or_env(cli.github.github_base_url.clone(), "GITHUB_BASE_URL")
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
        let mut overrides: Vec<&str> = Vec::new();
        if cli.github.github_org.is_some() {
            overrides.push("--github-org");
        }
        if cli.github.github_token.is_some() {
            overrides.push("--github-token");
        }
        if cli.github.github_base_url.is_some() {
            overrides.push("--github-base-url");
        }
        super::guard_credential_overrides("github", &overrides, accounts.len())?;

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

    let dir_keys: Vec<(&str, Option<&str>)> = targets
        .iter()
        .map(|(name, _, _, _, dir)| (name.as_str(), dir.as_deref()))
        .collect();
    super::warn_shared_output_dirs(cli, &dir_keys);

    let mut output_dirs: Vec<PathBuf> = Vec::new();
    for (name, org, token, base_url, account_output_dir) in &targets {
        eprintln!("=== GitHub '{}' → {} ({}) ===", name, org, base_url);

        let client = match github_rs::GithubClient::new(base_url, token, org) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("  ✗ GitHub '{name}' — client build failed: {e}");
                continue;
            }
        };

        let factory = crate::providers::github::factory::GithubProviderFactory::new(
            client,
            org.clone(),
            selected.clone(),
        );

        // The output directory is the account name (matching the TUI's account
        // picker), but the collectors and the run manifest are both keyed on
        // the org — that is what ends up in every filename.
        output_dirs.push(
            super::run_account_collectors(
                cli,
                "GitHub",
                name,
                org,
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
        anyhow::bail!("No GitHub account was collected — every account failed to build a client.");
    }

    super::finish_provider_run(cli, &timestamp, &output_dirs)
}

#[cfg(not(feature = "github"))]
pub(super) async fn run(_cli: &Cli) -> Result<()> {
    anyhow::bail!("--github requires a build with the `github` feature enabled")
}
