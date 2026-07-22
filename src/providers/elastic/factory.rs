use elastic_rs::ElasticClient;

use crate::evidence::{CsvCollector, EvidenceCollector, JsonCollector};
use crate::providers::{CloudProvider, ProviderFactory};

pub struct ElasticProviderFactory {
    client: ElasticClient,
    deployment_name: String,
    selected: Vec<String>,
}

impl ElasticProviderFactory {
    pub fn new(client: ElasticClient, deployment_name: String, selected: Vec<String>) -> Self {
        Self {
            client,
            deployment_name,
            selected,
        }
    }
}

impl ProviderFactory for ElasticProviderFactory {
    fn provider(&self) -> CloudProvider {
        CloudProvider::Elastic
    }
    fn account_id(&self) -> &str {
        &self.deployment_name
    }
    fn region(&self) -> &str {
        ""
    }

    fn csv_collectors(&self) -> Vec<Box<dyn CsvCollector>> {
        let _ = &self.client;
        let _ = &self.selected;
        Vec::new()
    }
    fn json_collectors(&self) -> Vec<Box<dyn JsonCollector>> {
        Vec::new()
    }
    fn evidence_collectors(&self) -> Vec<Box<dyn EvidenceCollector>> {
        Vec::new()
    }
}
