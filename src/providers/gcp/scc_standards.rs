//! GCP SCC Security Health Analytics settings — compliance standards posture.

use anyhow::Result;
use async_trait::async_trait;

use crate::evidence::JsonCollector;
use crate::providers::gcp::client::GcpClient;

pub struct SccStandardsCollector {
    client: GcpClient,
    org_id: String,
}

impl SccStandardsCollector {
    pub fn new(client: GcpClient, org_id: impl Into<String>) -> Self {
        Self {
            client,
            org_id: org_id.into(),
        }
    }
}

#[async_trait]
impl JsonCollector for SccStandardsCollector {
    fn name(&self) -> &str {
        "GCP SCC Standards"
    }
    fn filename_prefix(&self) -> &str {
        "GCP_SCC_Standards"
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
            "https://securitycenter.googleapis.com/v1/organizations/{}/securityHealthAnalyticsSettings",
            self.org_id
        );
        let resp = self.client.get(&url).await?;
        let body: serde_json::Value = resp.json().await?;
        Ok(vec![body])
    }
}
