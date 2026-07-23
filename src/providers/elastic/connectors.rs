use anyhow::Result;
use async_trait::async_trait;

use elastic_rs::ElasticClient;

use crate::evidence::CsvCollector;

pub struct ElasticConnectorsCollector {
    client: ElasticClient,
}

impl ElasticConnectorsCollector {
    pub fn new(client: ElasticClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for ElasticConnectorsCollector {
    fn name(&self) -> &str {
        "Elastic Alerting Connectors"
    }

    fn filename_prefix(&self) -> &str {
        "Elastic_Alerting_Connectors"
    }

    fn headers(&self) -> &'static [&'static str] {
        &[
            "Connector ID",
            "Name",
            "Type",
            "Preconfigured",
            "Deprecated",
            "Missing Secrets",
            "Referenced By Count",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let connectors = self.client.connectors().find_all().await?;

        let rows = connectors
            .into_iter()
            .map(|c| {
                vec![
                    c.id,
                    c.name,
                    c.connector_type_id,
                    if c.is_preconfigured { "YES" } else { "NO" }.to_string(),
                    if c.is_deprecated { "YES" } else { "NO" }.to_string(),
                    if c.is_missing_secrets { "YES" } else { "NO" }.to_string(),
                    c.referenced_by_count.to_string(),
                ]
            })
            .collect();

        Ok(rows)
    }
}
