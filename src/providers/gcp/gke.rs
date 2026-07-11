//! GCP Kubernetes Engine clusters — equivalent to AWS EKS.

use anyhow::Result;
use async_trait::async_trait;

use crate::evidence::CsvCollector;
use crate::providers::gcp::client::GcpClient;

pub struct GkeCollector {
    client: GcpClient,
    project_id: String,
}

impl GkeCollector {
    pub fn new(client: GcpClient, project_id: impl Into<String>) -> Self {
        Self {
            client,
            project_id: project_id.into(),
        }
    }
}

#[async_trait]
impl CsvCollector for GkeCollector {
    fn name(&self) -> &str {
        "GCP GKE Clusters"
    }
    fn filename_prefix(&self) -> &str {
        "GCP_GKE"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "project_id",
            "name",
            "location",
            "status",
            "kubernetes_version",
            "node_count",
            "network",
            "subnetwork",
            "create_time",
            "workload_identity_enabled",
            "shielded_nodes_enabled",
            "autopilot",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let url = format!(
            "https://container.googleapis.com/v1/projects/{}/locations/-/clusters",
            self.project_id
        );
        let resp = self.client.get(&url).await?;
        let body: serde_json::Value = resp.json().await?;
        let clusters = body
            .get("clusters")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        let rows = clusters
            .iter()
            .map(|c| {
                let node_count = c
                    .get("currentNodeCount")
                    .and_then(|v| v.as_i64())
                    .map(|i| i.to_string())
                    .unwrap_or_default();
                let wi = c
                    .get("workloadIdentityConfig")
                    .and_then(|w| w.get("workloadPool"))
                    .and_then(|v| v.as_str())
                    .map(|s| (!s.is_empty()).to_string())
                    .unwrap_or_else(|| "false".to_owned());
                let shielded = c
                    .get("shieldedNodes")
                    .and_then(|s| s.get("enabled"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
                    .to_string();
                let autopilot = c
                    .get("autopilot")
                    .and_then(|a| a.get("enabled"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
                    .to_string();
                vec![
                    self.project_id.clone(),
                    c.get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned(),
                    c.get("location")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned(),
                    c.get("status")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned(),
                    c.get("currentMasterVersion")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned(),
                    node_count,
                    c.get("network")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned(),
                    c.get("subnetwork")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned(),
                    c.get("createTime")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned(),
                    wi,
                    shielded,
                    autopilot,
                ]
            })
            .collect();
        Ok(rows)
    }
}
