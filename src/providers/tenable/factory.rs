use crate::evidence::{CsvCollector, EvidenceCollector, JsonCollector};
use crate::providers::{CloudProvider, ProviderFactory};

pub struct TenableProviderFactory {
    site_name: String,
    selected:  Vec<String>,
    // client: tenable_rs::TenableClient  — wired in when first collector ships
    // access_key and secret_key are resolved from config/env at construction time
}

impl TenableProviderFactory {
    pub fn new(site_name: String, selected: Vec<String>) -> Self {
        Self { site_name, selected }
    }
}

impl ProviderFactory for TenableProviderFactory {
    fn provider(&self)   -> CloudProvider { CloudProvider::Tenable }
    fn account_id(&self) -> &str          { &self.site_name }
    fn region(&self)     -> &str          { "" }  // Tenable has no region concept

    fn csv_collectors(&self)      -> Vec<Box<dyn CsvCollector>>      { vec![] }
    fn json_collectors(&self)     -> Vec<Box<dyn JsonCollector>>     { vec![] }
    fn evidence_collectors(&self) -> Vec<Box<dyn EvidenceCollector>> { vec![] }
}
