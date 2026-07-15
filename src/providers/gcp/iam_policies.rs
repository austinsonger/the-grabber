//! GCP IAM policy bindings for projects — equivalent to AWS IAM policies.

use anyhow::Result;
use async_trait::async_trait;

use crate::evidence::CsvCollector;
use crate::providers::gcp::client::GcpClient;

pub struct IamPoliciesCollector {
    client: GcpClient,
    project_id: String,
}

impl IamPoliciesCollector {
    pub fn new(client: GcpClient, project_id: impl Into<String>) -> Self {
        Self {
            client,
            project_id: project_id.into(),
        }
    }
}

#[async_trait]
impl CsvCollector for IamPoliciesCollector {
    fn name(&self) -> &str {
        "GCP IAM Policies"
    }
    fn filename_prefix(&self) -> &str {
        "GCP_IAM_Policies"
    }
    fn headers(&self) -> &'static [&'static str] {
        &["project_id", "role", "member", "member_type"]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let url = format!(
            "https://cloudresourcemanager.googleapis.com/v1/projects/{}:getIamPolicy",
            self.project_id
        );
        let resp = self.client.post(&url, &serde_json::json!({})).await?;
        let body: serde_json::Value = resp.json().await?;

        let mut rows = Vec::new();
        if let Some(bindings) = body.get("bindings").and_then(|b| b.as_array()) {
            for binding in bindings {
                let role = binding
                    .get("role")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_owned();
                if let Some(members) = binding.get("members").and_then(|m| m.as_array()) {
                    for member in members {
                        let m_str = member.as_str().unwrap_or("").to_owned();
                        let member_type = m_str.split(':').next().unwrap_or("").to_owned();
                        rows.push(vec![
                            self.project_id.clone(),
                            role.clone(),
                            m_str,
                            member_type,
                        ]);
                    }
                }
            }
        }
        Ok(rows)
    }
}
