use tenable_rs::TenableClient;

use crate::evidence::{CsvCollector, EvidenceCollector, JsonCollector};
use crate::providers::{CloudProvider, ProviderFactory};

use super::vulnerabilities::TenableVulnerabilitiesCollector;

pub struct TenableProviderFactory {
    client: TenableClient,
    site_name: String,
    selected: Vec<String>,
}

impl TenableProviderFactory {
    pub fn new(client: TenableClient, site_name: String, selected: Vec<String>) -> Self {
        Self {
            client,
            site_name,
            selected,
        }
    }
}

impl ProviderFactory for TenableProviderFactory {
    fn provider(&self) -> CloudProvider {
        CloudProvider::Tenable
    }
    fn account_id(&self) -> &str {
        &self.site_name
    }
    fn region(&self) -> &str {
        ""
    } // Tenable has no region concept

    fn csv_collectors(&self) -> Vec<Box<dyn CsvCollector>> {
        let mut v: Vec<Box<dyn CsvCollector>> = Vec::new();
        if self.selected.iter().any(|s| s == "tenable-vulns") {
            v.push(Box::new(TenableVulnerabilitiesCollector::new(
                self.client.clone(),
            )));
        }
        v
    }
    fn json_collectors(&self) -> Vec<Box<dyn JsonCollector>> {
        vec![]
    }
    fn evidence_collectors(&self) -> Vec<Box<dyn EvidenceCollector>> {
        vec![]
    }
}
