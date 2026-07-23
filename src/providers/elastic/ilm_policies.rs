use anyhow::Result;
use async_trait::async_trait;

use elastic_rs::ElasticClient;

use crate::evidence::CsvCollector;

pub struct ElasticIlmPoliciesCollector {
    client: ElasticClient,
}

impl ElasticIlmPoliciesCollector {
    pub fn new(client: ElasticClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for ElasticIlmPoliciesCollector {
    fn name(&self) -> &str {
        "Elastic Index Lifecycle Management Policies"
    }

    fn filename_prefix(&self) -> &str {
        "Elastic_ILM_Policies"
    }

    fn headers(&self) -> &'static [&'static str] {
        &[
            "Policy Name",
            "Modified Date",
            "Has Hot Phase",
            "Has Warm Phase",
            "Has Cold Phase",
            "Has Frozen Phase",
            "Has Delete Phase",
            "Delete Min Age (Retention Period)",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let policies = self.client.ilm().find_all().await?;

        let rows = policies
            .into_iter()
            .map(|p| {
                vec![
                    p.name,
                    p.modified_date.unwrap_or_default(),
                    if p.has_hot_phase { "YES" } else { "NO" }.to_string(),
                    if p.has_warm_phase { "YES" } else { "NO" }.to_string(),
                    if p.has_cold_phase { "YES" } else { "NO" }.to_string(),
                    if p.has_frozen_phase { "YES" } else { "NO" }.to_string(),
                    if p.has_delete_phase { "YES" } else { "NO" }.to_string(),
                    p.delete_min_age.unwrap_or_default(),
                ]
            })
            .collect();

        Ok(rows)
    }
}
