//! GCP Cloud Storage bucket detailed configuration — retention, logging, CORS, lifecycle.

use anyhow::Result;
use async_trait::async_trait;

use crate::evidence::JsonCollector;
use crate::providers::gcp::client::GcpClient;

pub struct CloudStorageConfigCollector {
    client: GcpClient,
    project_id: String,
}

impl CloudStorageConfigCollector {
    pub fn new(client: GcpClient, project_id: impl Into<String>) -> Self {
        Self {
            client,
            project_id: project_id.into(),
        }
    }
}

#[async_trait]
impl JsonCollector for CloudStorageConfigCollector {
    fn name(&self) -> &str {
        "GCP Cloud Storage Config"
    }
    fn filename_prefix(&self) -> &str {
        "GCP_Storage_Config"
    }

    async fn collect_records(
        &self,
        _account_id: &str,
        _region: &str,
    ) -> Result<Vec<serde_json::Value>> {
        let url = format!(
            "https://storage.googleapis.com/storage/v1/b?project={}&maxResults=1000",
            self.project_id
        );
        self.client.paginate(&url, "items").await
    }
}
