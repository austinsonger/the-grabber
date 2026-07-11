//! GCP Compute Engine instance inventory — equivalent to AWS EC2 instances.

use anyhow::Result;
use async_trait::async_trait;

use crate::evidence::CsvCollector;
use crate::providers::gcp::client::GcpClient;

pub struct ComputeInventoryCollector {
    client:     GcpClient,
    project_id: String,
}

impl ComputeInventoryCollector {
    pub fn new(client: GcpClient, project_id: impl Into<String>) -> Self {
        Self { client, project_id: project_id.into() }
    }
}

#[async_trait]
impl CsvCollector for ComputeInventoryCollector {
    fn name(&self) -> &str { "GCP Compute Inventory" }
    fn filename_prefix(&self) -> &str { "GCP_Compute_Inventory" }
    fn headers(&self) -> &'static [&'static str] {
        &["project_id", "zone", "name", "machine_type", "status",
          "creation_timestamp", "network", "internal_ip", "external_ip",
          "service_account", "labels", "tags"]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        // aggregatedList returns all instances across all zones
        let url = format!(
            "https://compute.googleapis.com/compute/v1/projects/{}/aggregated/instances?maxResults=500",
            self.project_id
        );
        let resp = self.client.get(&url).await?;
        let body: serde_json::Value = resp.json().await?;

        let mut rows = Vec::new();
        if let Some(items) = body.get("items").and_then(|v| v.as_object()) {
            for (zone_key, zone_val) in items {
                let zone = zone_key.trim_start_matches("zones/").to_owned();
                if let Some(instances) = zone_val.get("instances").and_then(|v| v.as_array()) {
                    for inst in instances {
                        let machine_type = inst
                            .get("machineType")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .split('/')
                            .last()
                            .unwrap_or("")
                            .to_owned();

                        let (network, internal_ip, external_ip) = inst
                            .get("networkInterfaces")
                            .and_then(|v| v.as_array())
                            .and_then(|arr| arr.first())
                            .map(|ni| {
                                let net = ni.get("network").and_then(|v| v.as_str()).unwrap_or("").split('/').last().unwrap_or("").to_owned();
                                let internal = ni.get("networkIP").and_then(|v| v.as_str()).unwrap_or("").to_owned();
                                let external = ni
                                    .get("accessConfigs")
                                    .and_then(|v| v.as_array())
                                    .and_then(|arr| arr.first())
                                    .and_then(|ac| ac.get("natIP"))
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_owned();
                                (net, internal, external)
                            })
                            .unwrap_or_default();

                        let sa = inst
                            .get("serviceAccounts")
                            .and_then(|v| v.as_array())
                            .and_then(|arr| arr.first())
                            .and_then(|sa| sa.get("email"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_owned();

                        let labels = inst
                            .get("labels")
                            .map(|l| serde_json::to_string(l).unwrap_or_default())
                            .unwrap_or_default();

                        let tags = inst
                            .get("tags")
                            .and_then(|t| t.get("items"))
                            .map(|l| serde_json::to_string(l).unwrap_or_default())
                            .unwrap_or_default();

                        rows.push(vec![
                            self.project_id.clone(),
                            zone.clone(),
                            inst.get("name").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
                            machine_type,
                            inst.get("status").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
                            inst.get("creationTimestamp").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
                            network,
                            internal_ip,
                            external_ip,
                            sa,
                            labels,
                            tags,
                        ]);
                    }
                }
            }
        }
        Ok(rows)
    }
}
