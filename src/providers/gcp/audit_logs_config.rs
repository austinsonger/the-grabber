//! GCP Cloud Logging sinks configuration — equivalent to AWS CloudTrail logging config.

use anyhow::Result;
use async_trait::async_trait;

use crate::evidence::JsonCollector;
use crate::providers::gcp::client::GcpClient;

pub struct AuditLogsConfigCollector {
    client: GcpClient,
    project_id: String,
}

impl AuditLogsConfigCollector {
    pub fn new(client: GcpClient, project_id: impl Into<String>) -> Self {
        Self {
            client,
            project_id: project_id.into(),
        }
    }
}

#[async_trait]
impl JsonCollector for AuditLogsConfigCollector {
    fn name(&self) -> &str {
        "GCP Audit Logs Config"
    }
    fn filename_prefix(&self) -> &str {
        "GCP_Audit_Logs_Config"
    }

    async fn collect_records(
        &self,
        _account_id: &str,
        _region: &str,
    ) -> Result<Vec<serde_json::Value>> {
        let url = format!(
            "https://logging.googleapis.com/v2/projects/{}/sinks?pageSize=1000",
            self.project_id
        );
        self.client.paginate(&url, "sinks").await
    }
}
