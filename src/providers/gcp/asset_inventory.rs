//! GCP Cloud Asset Inventory — equivalent to AWS Config resource inventory.

use anyhow::Result;
use async_trait::async_trait;

use crate::evidence::JsonCollector;
use crate::providers::gcp::client::GcpClient;

pub struct AssetInventoryCollector {
    client:     GcpClient,
    project_id: String,
}

impl AssetInventoryCollector {
    pub fn new(client: GcpClient, project_id: impl Into<String>) -> Self {
        Self { client, project_id: project_id.into() }
    }
}

#[async_trait]
impl JsonCollector for AssetInventoryCollector {
    fn name(&self) -> &str { "GCP Asset Inventory" }
    fn filename_prefix(&self) -> &str { "GCP_Asset_Inventory" }

    async fn collect_records(
        &self,
        _account_id: &str,
        _region: &str,
    ) -> Result<Vec<serde_json::Value>> {
        let url = format!(
            "https://cloudasset.googleapis.com/v1/projects/{}/assets?contentType=RESOURCE&pageSize=1000",
            self.project_id
        );
        self.client.paginate(&url, "assets").await
    }
}
