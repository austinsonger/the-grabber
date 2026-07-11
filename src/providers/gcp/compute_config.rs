//! GCP Compute Engine project & instance configuration (firewall rules, etc.).

use anyhow::Result;
use async_trait::async_trait;

use crate::evidence::JsonCollector;
use crate::providers::gcp::client::GcpClient;

pub struct ComputeConfigCollector {
    client: GcpClient,
    project_id: String,
}

impl ComputeConfigCollector {
    pub fn new(client: GcpClient, project_id: impl Into<String>) -> Self {
        Self {
            client,
            project_id: project_id.into(),
        }
    }
}

#[async_trait]
impl JsonCollector for ComputeConfigCollector {
    fn name(&self) -> &str {
        "GCP Compute Config"
    }
    fn filename_prefix(&self) -> &str {
        "GCP_Compute_Config"
    }

    async fn collect_records(
        &self,
        _account_id: &str,
        _region: &str,
    ) -> Result<Vec<serde_json::Value>> {
        // Firewall rules give a good configuration picture
        let url = format!(
            "https://compute.googleapis.com/compute/v1/projects/{}/global/firewalls?maxResults=500",
            self.project_id
        );
        self.client.paginate(&url, "items").await
    }
}
