//! `--elastic`: headless Elastic Security evidence collection.

use anyhow::Result;

use crate::cli::Cli;

#[cfg(feature = "elastic")]
pub(super) async fn run(cli: &Cli) -> Result<()> {
    use chrono::Utc;

    use crate::providers::CloudProvider;
    use crate::providers::ProviderFactory as _;
    use crate::runner::collect_ops::{
        run_csv_collectors, run_json_collectors, run_json_inv_collectors,
    };

    let selected = cli.elastic.resolve_collectors()?;
    let params = super::resolve_window(cli)?;
    eprintln!("Elastic collectors: {}", selected.join(", "));

    // (deployment name, kibana url, es url, api key, per-account output_dir)
    let mut targets: Vec<(String, String, String, String, Option<String>)> = Vec::new();

    let accounts = super::accounts_for(
        CloudProvider::Elastic,
        cli.elastic.elastic_account.as_deref(),
    );
    if accounts.is_empty() {
        let name = cli
            .elastic
            .elastic_account
            .clone()
            .unwrap_or_else(|| "Elastic".to_string());
        let kibana_url = cli
            .elastic
            .elastic_kibana_url
            .clone()
            .filter(|s| !s.trim().is_empty())
            .or_else(|| std::env::var("ELASTIC_KIBANA_URL").ok())
            .filter(|s| !s.trim().is_empty());
        let es_url = cli
            .elastic
            .elastic_es_url
            .clone()
            .filter(|s| !s.trim().is_empty())
            .or_else(|| std::env::var("ELASTIC_ES_URL").ok())
            .filter(|s| !s.trim().is_empty());
        let api_key = cli
            .elastic
            .elastic_api_key
            .clone()
            .filter(|s| !s.trim().is_empty())
            .or_else(|| std::env::var("ELASTIC_API_KEY").ok())
            .filter(|s| !s.trim().is_empty());
        match (kibana_url, es_url, api_key) {
            (Some(k), Some(e), Some(a)) => targets.push((name, k, e, a, None)),
            _ => anyhow::bail!(
                "No Elastic account found. Add an [[account]] with provider = \"elastic\" to \
                 elastic-config.toml, or pass --elastic-kibana-url, --elastic-es-url and \
                 --elastic-api-key (or set ELASTIC_KIBANA_URL, ELASTIC_ES_URL, ELASTIC_API_KEY)."
            ),
        }
    } else {
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
    let dates = Some((params.start_time.timestamp(), params.end_time.timestamp()));

    for (name, kibana_url, es_url, api_key, account_output_dir) in targets {
        eprintln!("=== Elastic '{}' → {} ===", name, kibana_url);

        let client = elastic_rs::ElasticClient::new(&kibana_url, &es_url, &api_key)
            .map_err(|e| anyhow::anyhow!("Elastic '{name}' — client build failed: {e}"))?;

        let factory = crate::providers::elastic::factory::ElasticProviderFactory::new(
            client,
            name.clone(),
            selected.clone(),
        );
        let csv_cols = factory.csv_collectors();
        let json_inv_cols = factory.json_collectors();
        let evidence_cols = factory.evidence_collectors();
        if csv_cols.is_empty() && json_inv_cols.is_empty() && evidence_cols.is_empty() {
            anyhow::bail!("No Elastic collectors matched the selected keys.");
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

#[cfg(not(feature = "elastic"))]
pub(super) async fn run(_cli: &Cli) -> Result<()> {
    anyhow::bail!("--elastic requires a build with the `elastic` feature enabled")
}
