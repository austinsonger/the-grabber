//! GCP Organization Policy constraints — equivalent to AWS Organizations SCPs.

use anyhow::Result;
use async_trait::async_trait;

use crate::evidence::JsonCollector;
use crate::providers::gcp::client::GcpClient;

pub struct OrgPolicyCollector {
    client: GcpClient,
    project_id: String,
}

impl OrgPolicyCollector {
    pub fn new(client: GcpClient, project_id: impl Into<String>) -> Self {
        Self {
            client,
            project_id: project_id.into(),
        }
    }
}

#[async_trait]
impl JsonCollector for OrgPolicyCollector {
    fn name(&self) -> &str {
        "GCP Org Policy"
    }
    fn filename_prefix(&self) -> &str {
        "GCP_Org_Policy"
    }

    async fn collect_records(
        &self,
        _account_id: &str,
        _region: &str,
    ) -> Result<Vec<serde_json::Value>> {
        let url = format!(
            "https://orgpolicy.googleapis.com/v2/projects/{}/policies?pageSize=100",
            self.project_id
        );
        self.client.paginate(&url, "policies").await
    }
}
