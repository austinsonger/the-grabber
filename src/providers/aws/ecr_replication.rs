use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_ecr::Client as EcrClient;

use crate::evidence::CsvCollector;

pub struct EcrReplicationCollector {
    client: EcrClient,
}

impl EcrReplicationCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: EcrClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for EcrReplicationCollector {
    fn name(&self) -> &str {
        "ECR Replication"
    }
    fn filename_prefix(&self) -> &str {
        "ECR_Replication"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Rule Index",
            "Destination Region",
            "Destination Account",
            "Repository Filter Type",
            "Repository Filter",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        let resp = match self.client.describe_registry().send().await {
            Ok(r) => r,
            Err(e) => {
                eprintln!("  WARN: ECR describe_registry: {e:#}");
                return Ok(rows);
            }
        };

        let Some(repl_config) = resp.replication_configuration() else {
            return Ok(rows);
        };

        for (idx, rule) in repl_config.rules().iter().enumerate() {
            let filters: String = rule
                .repository_filters()
                .iter()
                .map(|f| f.filter().to_string())
                .collect::<Vec<_>>()
                .join("|");
            let filter_types: String = rule
                .repository_filters()
                .iter()
                .map(|f| f.filter_type().as_str().to_string())
                .collect::<Vec<_>>()
                .join("|");

            for dest in rule.destinations() {
                rows.push(vec![
                    idx.to_string(),
                    dest.region().to_string(),
                    dest.registry_id().to_string(),
                    filter_types.clone(),
                    filters.clone(),
                ]);
            }
        }

        Ok(rows)
    }
}
