//! GCP Security Command Center findings — equivalent to AWS GuardDuty/Security Hub findings.

use anyhow::Result;
use async_trait::async_trait;
use serde_json::json;

use crate::evidence::JsonCollector;
use crate::providers::gcp::client::GcpClient;

pub struct SccFindingsCollector {
    client: GcpClient,
    org_id: String,
}

impl SccFindingsCollector {
    pub fn new(client: GcpClient, org_id: impl Into<String>) -> Self {
        Self { client, org_id: org_id.into() }
    }
}

#[async_trait]
impl JsonCollector for SccFindingsCollector {
    fn name(&self) -> &str { "GCP SCC Findings" }
    fn filename_prefix(&self) -> &str { "GCP_SCC_Findings" }

    async fn collect_records(
        &self,
        _account_id: &str,
        _region: &str,
    ) -> Result<Vec<serde_json::Value>> {
        if self.org_id.is_empty() {
            return Ok(Vec::new());
        }
        let url = format!(
            "https://securitycenter.googleapis.com/v1/organizations/{}/sources/-/findings:list",
            self.org_id
        );
        let body = json!({ "pageSize": 1000 });
        self.client.paginate_post(&url, &body, "listFindingsResults").await
    }
}
