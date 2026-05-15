//! GCP VPC networks — equivalent to AWS VPCs.

use anyhow::Result;
use async_trait::async_trait;

use crate::evidence::CsvCollector;
use crate::providers::gcp::client::GcpClient;

pub struct VpcCollector {
    client:     GcpClient,
    project_id: String,
}

impl VpcCollector {
    pub fn new(client: GcpClient, project_id: impl Into<String>) -> Self {
        Self { client, project_id: project_id.into() }
    }
}

#[async_trait]
impl CsvCollector for VpcCollector {
    fn name(&self) -> &str { "GCP VPC Networks" }
    fn filename_prefix(&self) -> &str { "GCP_VPC" }
    fn headers(&self) -> &'static [&'static str] {
        &["project_id", "name", "description", "auto_create_subnetworks",
          "routing_mode", "mtu", "creation_timestamp", "subnetwork_count"]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let url = format!(
            "https://compute.googleapis.com/compute/v1/projects/{}/global/networks?maxResults=500",
            self.project_id
        );
        let networks = self.client.paginate(&url, "items").await?;

        let rows = networks.iter().map(|n| {
            let subnet_count = n
                .get("subnetworks")
                .and_then(|v| v.as_array())
                .map(|a| a.len().to_string())
                .unwrap_or_else(|| "0".to_owned());
            let routing_mode = n
                .get("routingConfig")
                .and_then(|r| r.get("routingMode"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned();
            vec![
                self.project_id.clone(),
                n.get("name").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
                n.get("description").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
                n.get("autoCreateSubnetworks").and_then(|v| v.as_bool()).unwrap_or(false).to_string(),
                routing_mode,
                n.get("mtu").and_then(|v| v.as_i64()).map(|i| i.to_string()).unwrap_or_default(),
                n.get("creationTimestamp").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
                subnet_count,
            ]
        }).collect();
        Ok(rows)
    }
}
