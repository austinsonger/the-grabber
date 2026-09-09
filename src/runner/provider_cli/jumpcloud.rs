//! `--jumpcloud`: headless JumpCloud evidence collection.

use anyhow::Result;

use crate::cli::Cli;

#[cfg(feature = "jumpcloud")]
pub(super) async fn run(cli: &Cli) -> Result<()> {
    use std::path::PathBuf;

    use chrono::Utc;

    use crate::providers::CloudProvider;
    use crate::providers::ProviderFactory as _;

    let selected = cli.jumpcloud.resolve_collectors()?;
    let params = super::resolve_window(cli)?;
    eprintln!("JumpCloud collectors: {}", selected.join(", "));

    // (tenant name, api key, base url, org id, per-account output_dir)
    type Target = (String, String, String, Option<String>, Option<String>);
    let mut targets: Vec<Target> = Vec::new();

    let accounts = super::accounts_for(
        CloudProvider::JumpCloud,
        cli.jumpcloud.jumpcloud_account.as_deref(),
    )?;
    if accounts.is_empty() {
        let name = cli
            .jumpcloud
            .jumpcloud_account
            .clone()
            .unwrap_or_else(|| "JumpCloud".to_string());
        let api_key =
            super::flag_or_env(cli.jumpcloud.jumpcloud_api_key.clone(), "JUMPCLOUD_API_KEY");
        let base_url = super::flag_or_env(
            cli.jumpcloud.jumpcloud_base_url.clone(),
            "JUMPCLOUD_BASE_URL",
        )
        .unwrap_or_else(|| "https://console.jumpcloud.com".to_string());
        let org_id = super::flag_or_env(cli.jumpcloud.jumpcloud_org_id.clone(), "JUMPCLOUD_ORG_ID");
        match api_key {
            Some(k) => targets.push((name, k, base_url, org_id, None)),
            None => anyhow::bail!(
                "No JumpCloud account found. Add an [[account]] with provider = \"jumpcloud\" \
                 to jumpcloud-config.toml, or pass --jumpcloud-api-key (or set JUMPCLOUD_API_KEY)."
            ),
        }
    } else {
        let mut overrides: Vec<&str> = Vec::new();
        if cli.jumpcloud.jumpcloud_api_key.is_some() {
            overrides.push("--jumpcloud-api-key");
        }
        if cli.jumpcloud.jumpcloud_base_url.is_some() {
            overrides.push("--jumpcloud-base-url");
        }
        if cli.jumpcloud.jumpcloud_org_id.is_some() {
            overrides.push("--jumpcloud-org-id");
        }
        super::guard_credential_overrides("jumpcloud", &overrides, accounts.len())?;

        for acct in &accounts {
            let api_key = cli
                .jumpcloud
                .jumpcloud_api_key
                .clone()
                .filter(|s| !s.trim().is_empty())
                .or_else(|| acct.jumpcloud_api_key_resolved())
                .filter(|s| !s.trim().is_empty());
            let base_url = cli
                .jumpcloud
                .jumpcloud_base_url
                .clone()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| acct.jumpcloud_base_url_resolved());
            let org_id = cli
                .jumpcloud
                .jumpcloud_org_id
                .clone()
                .filter(|s| !s.trim().is_empty())
                .or_else(|| acct.jumpcloud_org_id_resolved())
                .filter(|s| !s.trim().is_empty());
            match api_key {
                Some(k) => targets.push((acct.name.clone(), k, base_url, org_id, acct.output_dir.clone())),
                None => eprintln!(
                    "  ✗ JumpCloud '{}' — missing jumpcloud_api_key (or JUMPCLOUD_API_KEY env) — skipping",
                    acct.name
                ),
            }
        }
        if targets.is_empty() {
            anyhow::bail!("No JumpCloud account had usable credentials.");
        }
    }

    let timestamp = Utc::now().format("%Y-%m-%d-%H%M%S").to_string();

    let dir_keys: Vec<(&str, Option<&str>)> = targets
        .iter()
        .map(|(name, _, _, _, dir)| (name.as_str(), dir.as_deref()))
        .collect();
    super::warn_shared_output_dirs(cli, &dir_keys);

    let mut output_dirs: Vec<PathBuf> = Vec::new();
    for (name, api_key, base_url, org_id, account_output_dir) in &targets {
        eprintln!("=== JumpCloud '{}' → {} ===", name, base_url);

        let client = match jumpcloud_rs::JumpCloudClient::new(base_url, api_key, org_id.as_deref())
        {
            Ok(c) => c,
            Err(e) => {
                eprintln!("  ✗ JumpCloud '{name}' — client build failed: {e}");
                continue;
            }
        };

        let factory = crate::providers::jumpcloud::factory::JumpCloudProviderFactory::new(
            client,
            name.clone(),
            org_id.clone().unwrap_or_default(),
            selected.clone(),
        );

        output_dirs.push(
            super::run_account_collectors(
                cli,
                "JumpCloud",
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
        anyhow::bail!(
            "No JumpCloud account was collected — every account failed to build a client."
        );
    }

    super::finish_provider_run(cli, &timestamp, &output_dirs)
}

#[cfg(not(feature = "jumpcloud"))]
pub(super) async fn run(_cli: &Cli) -> Result<()> {
    anyhow::bail!("--jumpcloud requires a build with the `jumpcloud` feature enabled")
}
