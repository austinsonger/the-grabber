//! GCP Cloud Storage bucket IAM policies — equivalent to AWS S3 bucket policies.

use anyhow::Result;
use async_trait::async_trait;

use crate::evidence::CsvCollector;
use crate::providers::gcp::client::GcpClient;

pub struct CloudStoragePoliciesCollector {
    client: GcpClient,
    project_id: String,
}

impl CloudStoragePoliciesCollector {
    pub fn new(client: GcpClient, project_id: impl Into<String>) -> Self {
        Self {
            client,
            project_id: project_id.into(),
        }
    }
}

#[async_trait]
impl CsvCollector for CloudStoragePoliciesCollector {
    fn name(&self) -> &str {
        "GCP Cloud Storage Policies"
    }
    fn filename_prefix(&self) -> &str {
        "GCP_Storage_Policies"
    }
    fn headers(&self) -> &'static [&'static str] {
        &["project_id", "bucket", "role", "member"]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let list_url = format!(
            "https://storage.googleapis.com/storage/v1/b?project={}&maxResults=1000",
            self.project_id
        );
        let buckets = self.client.paginate(&list_url, "items").await?;

        let mut rows = Vec::new();
        for bucket in &buckets {
            let name = bucket
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned();
            let policy_url = format!("https://storage.googleapis.com/storage/v1/b/{}/iam", name);
            let resp = self.client.get(&policy_url).await?;
            let policy: serde_json::Value = resp.json().await?;

            if let Some(bindings) = policy.get("bindings").and_then(|b| b.as_array()) {
                for binding in bindings {
                    let role = binding
                        .get("role")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned();
                    if let Some(members) = binding.get("members").and_then(|m| m.as_array()) {
                        for member in members {
                            rows.push(vec![
                                self.project_id.clone(),
                                name.clone(),
                                role.clone(),
                                member.as_str().unwrap_or("").to_owned(),
                            ]);
                        }
                    }
                }
            }
        }
        Ok(rows)
    }
}
