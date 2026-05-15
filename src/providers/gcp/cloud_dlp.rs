//! GCP Cloud DLP inspect templates — equivalent to AWS Macie.

use anyhow::Result;
use async_trait::async_trait;

use crate::evidence::JsonCollector;
use crate::providers::gcp::client::GcpClient;

pub struct CloudDlpCollector {
    client:     GcpClient,
    project_id: String,
}

impl CloudDlpCollector {
    pub fn new(client: GcpClient, project_id: impl Into<String>) -> Self {
        Self { client, project_id: project_id.into() }
    }
}

#[async_trait]
impl JsonCollector for CloudDlpCollector {
    fn name(&self) -> &str { "GCP Cloud DLP" }
    fn filename_prefix(&self) -> &str { "GCP_Cloud_DLP" }

    async fn collect_records(
        &self,
        _account_id: &str,
        _region: &str,
    ) -> Result<Vec<serde_json::Value>> {
        let url = format!(
            "https://dlp.googleapis.com/v2/projects/{}/inspectTemplates?pageSize=100",
            self.project_id
        );
        self.client.paginate(&url, "inspectTemplates").await
    }
}
