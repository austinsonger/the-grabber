//! GCP Cloud Armor security policies — equivalent to AWS WAF.

use anyhow::Result;
use async_trait::async_trait;

use crate::evidence::CsvCollector;
use crate::providers::gcp::client::GcpClient;

pub struct CloudArmorCollector {
    client: GcpClient,
    project_id: String,
}

impl CloudArmorCollector {
    pub fn new(client: GcpClient, project_id: impl Into<String>) -> Self {
        Self {
            client,
            project_id: project_id.into(),
        }
    }
}

#[async_trait]
impl CsvCollector for CloudArmorCollector {
    fn name(&self) -> &str {
        "GCP Cloud Armor"
    }
    fn filename_prefix(&self) -> &str {
        "GCP_Cloud_Armor"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "project_id",
            "name",
            "type",
            "description",
            "rule_count",
            "fingerprint",
            "creation_timestamp",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let url = format!(
            "https://compute.googleapis.com/compute/v1/projects/{}/global/securityPolicies?maxResults=500",
            self.project_id
        );
        let policies = self.client.paginate(&url, "items").await?;

        let rows = policies
            .iter()
            .map(|p| {
                let rule_count = p
                    .get("rules")
                    .and_then(|v| v.as_array())
                    .map(|a| a.len().to_string())
                    .unwrap_or_else(|| "0".to_owned());
                vec![
                    self.project_id.clone(),
                    p.get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned(),
                    p.get("type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("CLOUD_ARMOR")
                        .to_owned(),
                    p.get("description")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned(),
                    rule_count,
                    p.get("fingerprint")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned(),
                    p.get("creationTimestamp")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned(),
                ]
            })
            .collect();
        Ok(rows)
    }
}
