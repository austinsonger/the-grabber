//! GCP Cloud KMS key IAM policies — equivalent to AWS KMS key policies.

use anyhow::Result;
use async_trait::async_trait;

use crate::evidence::CsvCollector;
use crate::providers::gcp::client::GcpClient;

pub struct KmsPoliciesCollector {
    client: GcpClient,
    project_id: String,
    location: String,
}

impl KmsPoliciesCollector {
    pub fn new(
        client: GcpClient,
        project_id: impl Into<String>,
        location: impl Into<String>,
    ) -> Self {
        Self {
            client,
            project_id: project_id.into(),
            location: location.into(),
        }
    }
}

#[async_trait]
impl CsvCollector for KmsPoliciesCollector {
    fn name(&self) -> &str {
        "GCP KMS Key IAM Policies"
    }
    fn filename_prefix(&self) -> &str {
        "GCP_KMS_Policies"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "project_id",
            "location",
            "key_ring",
            "key_name",
            "role",
            "member",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let loc = if self.location.is_empty() {
            "-"
        } else {
            &self.location
        };
        let rings_url = format!(
            "https://cloudkms.googleapis.com/v1/projects/{}/locations/{}/keyRings?pageSize=100",
            self.project_id, loc
        );
        let rings = self.client.paginate(&rings_url, "keyRings").await?;

        let mut rows = Vec::new();
        for ring in &rings {
            let ring_name = ring
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned();
            let ring_short = ring_name.split('/').last().unwrap_or("").to_owned();
            let keys_url = format!(
                "https://cloudkms.googleapis.com/v1/{}/cryptoKeys?pageSize=100",
                ring_name
            );
            let keys = self.client.paginate(&keys_url, "cryptoKeys").await?;

            for key in &keys {
                let key_name = key
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_owned();
                let key_short = key_name.split('/').last().unwrap_or("").to_owned();
                let policy_url = format!(
                    "https://cloudkms.googleapis.com/v1/{}:getIamPolicy",
                    key_name
                );
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
                                    self.location.clone(),
                                    ring_short.clone(),
                                    key_short.clone(),
                                    role.clone(),
                                    member.as_str().unwrap_or("").to_owned(),
                                ]);
                            }
                        }
                    }
                }
            }
        }

        Ok(rows)
    }
}
