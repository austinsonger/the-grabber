//! GCP Secret Manager secrets — equivalent to AWS Secrets Manager.

use anyhow::Result;
use async_trait::async_trait;

use crate::evidence::CsvCollector;
use crate::providers::gcp::client::GcpClient;

pub struct SecretManagerCollector {
    client:     GcpClient,
    project_id: String,
}

impl SecretManagerCollector {
    pub fn new(client: GcpClient, project_id: impl Into<String>) -> Self {
        Self { client, project_id: project_id.into() }
    }
}

#[async_trait]
impl CsvCollector for SecretManagerCollector {
    fn name(&self) -> &str { "GCP Secret Manager" }
    fn filename_prefix(&self) -> &str { "GCP_Secret_Manager" }
    fn headers(&self) -> &'static [&'static str] {
        &["project_id", "name", "create_time", "replication_type",
          "kms_key", "version_count", "labels"]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let url = format!(
            "https://secretmanager.googleapis.com/v1/projects/{}/secrets?pageSize=100",
            self.project_id
        );
        let secrets = self.client.paginate(&url, "secrets").await?;

        let rows = secrets.iter().map(|s| {
            let replication = s
                .get("replication")
                .map(|r| {
                    if r.get("automatic").is_some() {
                        "automatic".to_owned()
                    } else {
                        "user_managed".to_owned()
                    }
                })
                .unwrap_or_default();
            let kms_key = s
                .get("replication")
                .and_then(|r| r.get("automatic"))
                .and_then(|a| a.get("customerManagedEncryption"))
                .and_then(|c| c.get("kmsKeyName"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned();
            let labels = s
                .get("labels")
                .map(|l| serde_json::to_string(l).unwrap_or_default())
                .unwrap_or_default();
            vec![
                self.project_id.clone(),
                s.get("name").and_then(|v| v.as_str()).unwrap_or("").split('/').last().unwrap_or("").to_owned(),
                s.get("createTime").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
                replication,
                kms_key,
                String::new(), // version_count requires separate API call
                labels,
            ]
        }).collect();
        Ok(rows)
    }
}
