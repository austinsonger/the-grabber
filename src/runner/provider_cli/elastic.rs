//! `--elastic`: headless Elastic Security evidence collection.

use anyhow::Result;

use crate::cli::Cli;

#[cfg(feature = "elastic")]
pub(super) async fn run(cli: &Cli) -> Result<()> {
    use std::path::PathBuf;

    use chrono::Utc;

    use crate::providers::CloudProvider;
    use crate::providers::ProviderFactory as _;

    let selected = cli.elastic.resolve_collectors()?;
    let params = super::resolve_window(cli)?;
    eprintln!("Elastic collectors: {}", selected.join(", "));

    // (deployment name, kibana url, es url, api key, per-account output_dir)
    let mut targets: Vec<(String, String, String, String, Option<String>)> = Vec::new();

    let accounts = super::accounts_for(
        CloudProvider::Elastic,
        cli.elastic.elastic_account.as_deref(),
    )?;
    if accounts.is_empty() {
        let name = cli
            .elastic
            .elastic_account
            .clone()
            .unwrap_or_else(|| "Elastic".to_string());
        let kibana_url =
            super::flag_or_env(cli.elastic.elastic_kibana_url.clone(), "ELASTIC_KIBANA_URL");
        let es_url = super::flag_or_env(cli.elastic.elastic_es_url.clone(), "ELASTIC_ES_URL");
        let api_key = super::flag_or_env(cli.elastic.elastic_api_key.clone(), "ELASTIC_API_KEY");
        match (kibana_url, es_url, api_key) {
            (Some(k), Some(e), Some(a)) => targets.push((name, k, e, a, None)),
            _ => anyhow::bail!(
                "No Elastic account found. Add an [[account]] with provider = \"elastic\" to \
                 elastic-config.toml, or pass --elastic-kibana-url, --elastic-es-url and \
                 --elastic-api-key (or set ELASTIC_KIBANA_URL, ELASTIC_ES_URL, ELASTIC_API_KEY)."
            ),
        }
    } else {
        let mut overrides: Vec<&str> = Vec::new();
        if cli.elastic.elastic_kibana_url.is_some() {
            overrides.push("--elastic-kibana-url");
        }
        if cli.elastic.elastic_es_url.is_some() {
            overrides.push("--elastic-es-url");
        }
        if cli.elastic.elastic_api_key.is_some() {
            overrides.push("--elastic-api-key");
        }
        super::guard_credential_overrides("elastic", &overrides, accounts.len())?;

        for acct in &accounts {
            let kibana_url = cli
                .elastic
                .elastic_kibana_url
                .clone()
                .filter(|s| !s.trim().is_empty())
                .or_else(|| acct.elastic_kibana_url_resolved())
                .filter(|s| !s.trim().is_empty());
            let es_url = cli
                .elastic
                .elastic_es_url
                .clone()
                .filter(|s| !s.trim().is_empty())
                .or_else(|| acct.elastic_es_url_resolved())
                .filter(|s| !s.trim().is_empty());
            let api_key = cli
                .elastic
                .elastic_api_key
                .clone()
                .filter(|s| !s.trim().is_empty())
                .or_else(|| acct.elastic_api_key_resolved())
                .filter(|s| !s.trim().is_empty());
            match (kibana_url, es_url, api_key) {
                (Some(k), Some(e), Some(a)) => {
                    targets.push((acct.name.clone(), k, e, a, acct.output_dir.clone()))
                }
                (None, _, _) => eprintln!(
                    "  ✗ Elastic '{}' — missing elastic_kibana_url (or ELASTIC_KIBANA_URL env) — skipping",
                    acct.name
                ),
                (_, None, _) => eprintln!(
                    "  ✗ Elastic '{}' — missing elastic_es_url (or ELASTIC_ES_URL env) — skipping",
                    acct.name
                ),
                (_, _, None) => eprintln!(
                    "  ✗ Elastic '{}' — missing elastic_api_key (or ELASTIC_API_KEY env) — skipping",
                    acct.name
                ),
            }
        }
        if targets.is_empty() {
            anyhow::bail!("No Elastic account had usable credentials.");
        }
    }

    let timestamp = Utc::now().format("%Y-%m-%d-%H%M%S").to_string();

    let dir_keys: Vec<(&str, Option<&str>)> = targets
        .iter()
        .map(|(name, _, _, _, dir)| (name.as_str(), dir.as_deref()))
        .collect();
    super::warn_shared_output_dirs(cli, &dir_keys);

    let mut output_dirs: Vec<PathBuf> = Vec::new();
    for (name, kibana_url, es_url, api_key, account_output_dir) in &targets {
        eprintln!("=== Elastic '{}' → {} ===", name, kibana_url);

        let client = match elastic_rs::ElasticClient::new(kibana_url, es_url, api_key) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("  ✗ Elastic '{name}' — client build failed: {e}");
                continue;
            }
        };

        let factory = crate::providers::elastic::factory::ElasticProviderFactory::new(
            client,
            name.clone(),
            selected.clone(),
        );

        output_dirs.push(
            super::run_account_collectors(
                cli,
                "Elastic",
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
        anyhow::bail!("No Elastic account was collected — every account failed to build a client.");
    }

    super::finish_provider_run(cli, &timestamp, &output_dirs)
}

#[cfg(not(feature = "elastic"))]
pub(super) async fn run(_cli: &Cli) -> Result<()> {
    anyhow::bail!("--elastic requires a build with the `elastic` feature enabled")
}
