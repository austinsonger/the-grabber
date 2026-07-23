use jumpcloud_rs::JumpCloudClient;

use crate::evidence::{CsvCollector, EvidenceCollector, JsonCollector};
use crate::providers::{CloudProvider, ProviderFactory};

pub struct JumpCloudProviderFactory {
    #[allow(dead_code)]
    client: JumpCloudClient,
    tenant_name: String,
    #[allow(dead_code)]
    org_id: String,
    #[allow(dead_code)]
    selected: Vec<String>,
    #[allow(dead_code)]
    dates: Option<(i64, i64)>,
}

impl JumpCloudProviderFactory {
    pub fn new(
        client: JumpCloudClient,
        tenant_name: String,
        org_id: String,
        selected: Vec<String>,
        dates: Option<(i64, i64)>,
    ) -> Self {
        Self {
            client,
            tenant_name,
            org_id,
            selected,
            dates,
        }
    }
}

impl ProviderFactory for JumpCloudProviderFactory {
    fn provider(&self) -> CloudProvider {
        CloudProvider::JumpCloud
    }
    fn account_id(&self) -> &str {
        &self.tenant_name
    }
    fn region(&self) -> &str {
        ""
    }
    fn csv_collectors(&self) -> Vec<Box<dyn CsvCollector>> {
        Vec::new()
    }
    fn json_collectors(&self) -> Vec<Box<dyn JsonCollector>> {
        Vec::new()
    }
    fn evidence_collectors(&self) -> Vec<Box<dyn EvidenceCollector>> {
        Vec::new()
    }
}
