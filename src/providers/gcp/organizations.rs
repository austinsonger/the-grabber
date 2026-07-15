//! GCP organization project listing — equivalent to AWS Organizations account list.

use anyhow::Result;
use async_trait::async_trait;

use crate::evidence::JsonCollector;
use crate::providers::gcp::client::GcpClient;

pub struct OrganizationsCollector {
    client: GcpClient,
    org_id: String,
}

impl OrganizationsCollector {
    pub fn new(client: GcpClient, org_id: impl Into<String>) -> Self {
        Self {
            client,
            org_id: org_id.into(),
        }
    }
}

#[async_trait]
impl JsonCollector for OrganizationsCollector {
    fn name(&self) -> &str {
        "GCP Organizations"
    }
    fn filename_prefix(&self) -> &str {
        "GCP_Organizations"
    }

    async fn collect_records(
        &self,
        _account_id: &str,
        _region: &str,
    ) -> Result<Vec<serde_json::Value>> {
        if self.org_id.is_empty() {
            return Ok(Vec::new());
        }
        let url = format!(
            "https://cloudresourcemanager.googleapis.com/v3/projects?parent=organizations/{}&pageSize=300",
            self.org_id
        );
        self.client.paginate(&url, "projects").await
    }
}
