//! GCP Pub/Sub topics — equivalent to AWS SNS topics.

use anyhow::Result;
use async_trait::async_trait;

use crate::evidence::CsvCollector;
use crate::providers::gcp::client::GcpClient;

pub struct PubsubTopicsCollector {
    client: GcpClient,
    project_id: String,
}

impl PubsubTopicsCollector {
    pub fn new(client: GcpClient, project_id: impl Into<String>) -> Self {
        Self {
            client,
            project_id: project_id.into(),
        }
    }
}

#[async_trait]
impl CsvCollector for PubsubTopicsCollector {
    fn name(&self) -> &str {
        "GCP Pub/Sub Topics"
    }
    fn filename_prefix(&self) -> &str {
        "GCP_PubSub_Topics"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "project_id",
            "name",
            "kms_key_name",
            "message_retention_duration",
            "labels",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let url = format!(
            "https://pubsub.googleapis.com/v1/projects/{}/topics?pageSize=1000",
            self.project_id
        );
        let topics = self.client.paginate(&url, "topics").await?;

        let rows = topics
            .iter()
            .map(|t| {
                let name_full = t
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_owned();
                let name_short = name_full.split('/').last().unwrap_or("").to_owned();
                let labels = t
                    .get("labels")
                    .map(|l| serde_json::to_string(l).unwrap_or_default())
                    .unwrap_or_default();
                vec![
                    self.project_id.clone(),
                    name_short,
                    t.get("kmsKeyName")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned(),
                    t.get("messageRetentionDuration")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned(),
                    labels,
                ]
            })
            .collect();
        Ok(rows)
    }
}
