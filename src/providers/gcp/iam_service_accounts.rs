//! GCP IAM service accounts — equivalent to AWS IAM service accounts/roles.

use anyhow::Result;
use async_trait::async_trait;

use crate::evidence::CsvCollector;
use crate::providers::gcp::client::GcpClient;

pub struct IamServiceAccountsCollector {
    client: GcpClient,
    project_id: String,
}

impl IamServiceAccountsCollector {
    pub fn new(client: GcpClient, project_id: impl Into<String>) -> Self {
        Self {
            client,
            project_id: project_id.into(),
        }
    }
}

#[async_trait]
impl CsvCollector for IamServiceAccountsCollector {
    fn name(&self) -> &str {
        "GCP IAM Service Accounts"
    }
    fn filename_prefix(&self) -> &str {
        "GCP_IAM_Service_Accounts"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "project_id",
            "name",
            "email",
            "display_name",
            "description",
            "disabled",
            "oauth2_client_id",
            "unique_id",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let url = format!(
            "https://iam.googleapis.com/v1/projects/{}/serviceAccounts?pageSize=100",
            self.project_id
        );
        let accounts = self.client.paginate(&url, "accounts").await?;

        let rows = accounts
            .iter()
            .map(|sa| {
                vec![
                    self.project_id.clone(),
                    sa.get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned(),
                    sa.get("email")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned(),
                    sa.get("displayName")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned(),
                    sa.get("description")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned(),
                    sa.get("disabled")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false)
                        .to_string(),
                    sa.get("oauth2ClientId")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned(),
                    sa.get("uniqueId")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned(),
                ]
            })
            .collect();
        Ok(rows)
    }
}
