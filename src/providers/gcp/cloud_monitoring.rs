//! GCP Cloud Monitoring alert policies — equivalent to AWS CloudWatch alarms.

use anyhow::Result;
use async_trait::async_trait;

use crate::evidence::JsonCollector;
use crate::providers::gcp::client::GcpClient;

pub struct CloudMonitoringCollector {
    client:     GcpClient,
    project_id: String,
}

impl CloudMonitoringCollector {
    pub fn new(client: GcpClient, project_id: impl Into<String>) -> Self {
        Self { client, project_id: project_id.into() }
    }
}

#[async_trait]
impl JsonCollector for CloudMonitoringCollector {
    fn name(&self) -> &str { "GCP Cloud Monitoring" }
    fn filename_prefix(&self) -> &str { "GCP_Cloud_Monitoring" }

    async fn collect_records(
        &self,
        _account_id: &str,
        _region: &str,
    ) -> Result<Vec<serde_json::Value>> {
        let url = format!(
            "https://monitoring.googleapis.com/v3/projects/{}/alertPolicies?pageSize=1000",
            self.project_id
        );
        self.client.paginate(&url, "alertPolicies").await
    }
}
