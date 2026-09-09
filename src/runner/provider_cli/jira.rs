//! `--jira`: headless Jira evidence collection.

use anyhow::Result;

use crate::cli::Cli;

#[cfg(feature = "jira")]
pub(super) async fn run(cli: &Cli) -> Result<()> {
    use std::path::PathBuf;

    use chrono::Utc;

    use crate::providers::CloudProvider;
    use crate::providers::ProviderFactory as _;

    let selected = cli.jira.resolve_collectors()?;
    let params = super::resolve_window(cli)?;
    eprintln!("Jira collectors: {}", selected.join(", "));

    // (tenant name, domain, email, api token, per-account output_dir)
    let mut targets: Vec<(String, String, String, String, Option<String>)> = Vec::new();

    let accounts = super::accounts_for(CloudProvider::Jira, cli.jira.jira_account.as_deref())?;
    if accounts.is_empty() {
        let name = cli
            .jira
            .jira_account
            .clone()
            .unwrap_or_else(|| "Jira".to_string());
        let domain = super::flag_or_env(cli.jira.jira_domain.clone(), "JIRA_DOMAIN");
        let email = super::flag_or_env(cli.jira.jira_email.clone(), "JIRA_EMAIL");
        let token = super::flag_or_env(cli.jira.jira_api_token.clone(), "JIRA_API_TOKEN");
        match (domain, email, token) {
            (Some(d), Some(e), Some(t)) => targets.push((name, d, e, t, None)),
            _ => anyhow::bail!(
                "No Jira account found. Add an [[account]] with provider = \"jira\" to \
                 jira-config.toml, or pass --jira-domain, --jira-email, and \
                 --jira-api-token (or set JIRA_DOMAIN, JIRA_EMAIL, and JIRA_API_TOKEN)."
            ),
        }
    } else {
        let mut overrides: Vec<&str> = Vec::new();
        if cli.jira.jira_domain.is_some() {
            overrides.push("--jira-domain");
        }
        if cli.jira.jira_email.is_some() {
            overrides.push("--jira-email");
        }
        if cli.jira.jira_api_token.is_some() {
            overrides.push("--jira-api-token");
        }
        super::guard_credential_overrides("jira", &overrides, accounts.len())?;

        for acct in &accounts {
            let domain = cli
                .jira
                .jira_domain
                .clone()
                .filter(|s| !s.trim().is_empty())
                .or_else(|| acct.jira_domain_resolved())
                .filter(|s| !s.trim().is_empty());
            let email = cli
                .jira
                .jira_email
                .clone()
                .filter(|s| !s.trim().is_empty())
                .or_else(|| acct.jira_email_resolved())
                .filter(|s| !s.trim().is_empty());
            let token = cli
                .jira
                .jira_api_token
                .clone()
                .filter(|s| !s.trim().is_empty())
                .or_else(|| acct.jira_api_token_resolved())
                .filter(|s| !s.trim().is_empty());
            match (domain, email, token) {
                (Some(d), Some(e), Some(t)) => {
                    targets.push((acct.name.clone(), d, e, t, acct.output_dir.clone()))
                }
                (None, _, _) => eprintln!(
                    "  ✗ Jira '{}' — missing jira_domain (or JIRA_DOMAIN env) — skipping",
                    acct.name
                ),
                (_, None, _) => eprintln!(
                    "  ✗ Jira '{}' — missing jira_email (or JIRA_EMAIL env) — skipping",
                    acct.name
                ),
                (_, _, None) => eprintln!(
                    "  ✗ Jira '{}' — missing jira_api_token (or JIRA_API_TOKEN env) — skipping",
                    acct.name
                ),
            }
        }
        if targets.is_empty() {
            anyhow::bail!("No Jira account had usable credentials.");
        }
    }

    let timestamp = Utc::now().format("%Y-%m-%d-%H%M%S").to_string();
    let project_keys = cli.jira.resolve_project_keys();
    if !project_keys.is_empty() {
        eprintln!("Jira project keys: {}", project_keys.join(", "));
    }

    let dir_keys: Vec<(&str, Option<&str>)> = targets
        .iter()
        .map(|(name, _, _, _, dir)| (name.as_str(), dir.as_deref()))
        .collect();
    super::warn_shared_output_dirs(cli, &dir_keys);

    let mut output_dirs: Vec<PathBuf> = Vec::new();
    for (name, domain, email, token, account_output_dir) in &targets {
        eprintln!("=== Jira '{}' → {} ===", name, domain);

        let client = match jira_rs::JiraClient::new(domain, email, token) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("  ✗ Jira '{name}' — client build failed: {e}");
                continue;
            }
        };

        let factory = crate::providers::jira::factory::JiraProviderFactory::new(
            client,
            name.clone(),
            selected.clone(),
        );
        // An empty project-key vec would scope the issues collector to nothing,
        // which differs from the TUI default of "every project" — only layer
        // the override on when keys were actually given.
        let factory = if project_keys.is_empty() {
            factory
        } else {
            factory.with_project_keys(project_keys.clone())
        };

        output_dirs.push(
            super::run_account_collectors(
                cli,
                "Jira",
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
        anyhow::bail!("No Jira account was collected — every account failed to build a client.");
    }

    super::finish_provider_run(cli, &timestamp, &output_dirs)
}

#[cfg(not(feature = "jira"))]
pub(super) async fn run(_cli: &Cli) -> Result<()> {
    anyhow::bail!("--jira requires a build with the `jira` feature enabled")
}
