//! GCP Secret Manager secret versions — extended metadata for each secret.

use anyhow::Result;
use async_trait::async_trait;

use crate::evidence::JsonCollector;
use crate::providers::gcp::client::GcpClient;

pub struct SecretManagerExtendedCollector {
    client:     GcpClient,
    project_id: String,
}

impl SecretManagerExtendedCollector {
    pub fn new(client: GcpClient, project_id: impl Into<String>) -> Self {
        Self { client, project_id: project_id.into() }
    }
}

#[async_trait]
impl JsonCollector for SecretManagerExtendedCollector {
    fn name(&self) -> &str { "GCP Secret Manager Extended" }
    fn filename_prefix(&self) -> &str { "GCP_Secret_Manager_Extended" }

    async fn collect_records(
        &self,
        _account_id: &str,
        _region: &str,
    ) -> Result<Vec<serde_json::Value>> {
        let secrets_url = format!(
            "https://secretmanager.googleapis.com/v1/projects/{}/secrets?pageSize=100",
            self.project_id
        );
        let secrets = self.client.paginate(&secrets_url, "secrets").await?;

        let mut all = Vec::new();
        for secret in &secrets {
            let name = secret.get("name").and_then(|v| v.as_str()).unwrap_or("").to_owned();
            let versions_url =
                format!("https://secretmanager.googleapis.com/v1/{}/versions?pageSize=100", name);
            let versions = self.client.paginate(&versions_url, "versions").await?;
            all.extend(versions);
        }
        Ok(all)
    }
}
