//! GCP IAM service account keys — equivalent to AWS IAM access keys.

use anyhow::Result;
use async_trait::async_trait;

use crate::evidence::CsvCollector;
use crate::providers::gcp::client::GcpClient;

pub struct IamServiceAccountKeysCollector {
    client: GcpClient,
    project_id: String,
}

impl IamServiceAccountKeysCollector {
    pub fn new(client: GcpClient, project_id: impl Into<String>) -> Self {
        Self {
            client,
            project_id: project_id.into(),
        }
    }
}

#[async_trait]
impl CsvCollector for IamServiceAccountKeysCollector {
    fn name(&self) -> &str {
        "GCP IAM Service Account Keys"
    }
    fn filename_prefix(&self) -> &str {
        "GCP_IAM_SA_Keys"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "project_id",
            "service_account",
            "key_name",
            "key_type",
            "key_origin",
            "key_algorithm",
            "valid_after",
            "valid_before",
            "disabled",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let sa_url = format!(
            "https://iam.googleapis.com/v1/projects/{}/serviceAccounts?pageSize=100",
            self.project_id
        );
        let accounts = self.client.paginate(&sa_url, "accounts").await?;

        let mut rows = Vec::new();
        for sa in &accounts {
            let sa_name = sa
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned();
            let sa_email = sa
                .get("email")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned();
            let keys_url = format!("https://iam.googleapis.com/v1/{}/keys", sa_name);
            let resp = self.client.get(&keys_url).await?;
            let body: serde_json::Value = resp.json().await?;
            if let Some(keys) = body.get("keys").and_then(|k| k.as_array()) {
                for key in keys {
                    rows.push(vec![
                        self.project_id.clone(),
                        sa_email.clone(),
                        key.get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_owned(),
                        key.get("keyType")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_owned(),
                        key.get("keyOrigin")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_owned(),
                        key.get("keyAlgorithm")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_owned(),
                        key.get("validAfterTime")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_owned(),
                        key.get("validBeforeTime")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_owned(),
                        key.get("disabled")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false)
                            .to_string(),
                    ]);
                }
            }
        }
        Ok(rows)
    }
}
