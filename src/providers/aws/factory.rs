use crate::evidence::{CsvCollector, EvidenceCollector, JsonCollector};
use crate::providers::{CloudProvider, ProviderFactory};

pub struct AwsProviderFactory {
    config:     aws_config::SdkConfig,
    account_id: String,
    region:     String,
    selected:   Vec<String>,
}

impl AwsProviderFactory {
    pub fn new(
        config: aws_config::SdkConfig,
        account_id: String,
        region: String,
        selected: Vec<String>,
    ) -> Self {
        Self { config, account_id, region, selected }
    }
}

impl ProviderFactory for AwsProviderFactory {
    fn provider(&self)   -> CloudProvider { CloudProvider::Aws }
    fn account_id(&self) -> &str          { &self.account_id }
    fn region(&self)     -> &str          { &self.region }

    fn csv_collectors(&self)      -> Vec<Box<dyn CsvCollector>>      { todo!("Phase 2") }
    fn json_collectors(&self)     -> Vec<Box<dyn JsonCollector>>     { todo!("Phase 2") }
    fn evidence_collectors(&self) -> Vec<Box<dyn EvidenceCollector>> { todo!("Phase 2") }
}
