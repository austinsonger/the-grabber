use crate::evidence::{CsvCollector, EvidenceCollector, JsonCollector};
use crate::providers::{CloudProvider, ProviderFactory};

pub struct GcpProviderFactory {
    project_id: String,
    region: String,
    selected: Vec<String>,
    // credential: google_cloud_auth::Token  — added when first collector ships
}

impl GcpProviderFactory {
    pub fn new(project_id: String, region: String, selected: Vec<String>) -> Self {
        Self {
            project_id,
            region,
            selected,
        }
    }
}

impl ProviderFactory for GcpProviderFactory {
    fn provider(&self) -> CloudProvider {
        CloudProvider::Gcp
    }
    fn account_id(&self) -> &str {
        &self.project_id
    }
    fn region(&self) -> &str {
        &self.region
    }

    fn csv_collectors(&self) -> Vec<Box<dyn CsvCollector>> {
        vec![]
    }
    fn json_collectors(&self) -> Vec<Box<dyn JsonCollector>> {
        vec![]
    }
    fn evidence_collectors(&self) -> Vec<Box<dyn EvidenceCollector>> {
        vec![]
    }
}
