use crate::evidence::{CsvCollector, EvidenceCollector, JsonCollector};
use crate::providers::{CloudProvider, ProviderFactory};

pub struct AzureProviderFactory {
    subscription_id: String,
    region:          String,
    selected:        Vec<String>,
    // credential: Arc<dyn azure_identity::TokenCredential>  — added when first collector ships
}

impl AzureProviderFactory {
    pub fn new(subscription_id: String, region: String, selected: Vec<String>) -> Self {
        Self { subscription_id, region, selected }
    }
}

impl ProviderFactory for AzureProviderFactory {
    fn provider(&self)   -> CloudProvider { CloudProvider::Azure }
    fn account_id(&self) -> &str          { &self.subscription_id }
    fn region(&self)     -> &str          { &self.region }

    fn csv_collectors(&self)      -> Vec<Box<dyn CsvCollector>>      { vec![] }
    fn json_collectors(&self)     -> Vec<Box<dyn JsonCollector>>     { vec![] }
    fn evidence_collectors(&self) -> Vec<Box<dyn EvidenceCollector>> { vec![] }
}
