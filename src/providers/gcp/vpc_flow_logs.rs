//! GCP VPC flow logs configuration — equivalent to AWS VPC Flow Logs.

use anyhow::Result;
use async_trait::async_trait;

use crate::evidence::CsvCollector;
use crate::providers::gcp::client::GcpClient;

pub struct VpcFlowLogsCollector {
    client: GcpClient,
    project_id: String,
}

impl VpcFlowLogsCollector {
    pub fn new(client: GcpClient, project_id: impl Into<String>) -> Self {
        Self {
            client,
            project_id: project_id.into(),
        }
    }
}

#[async_trait]
impl CsvCollector for VpcFlowLogsCollector {
    fn name(&self) -> &str {
        "GCP VPC Flow Logs"
    }
    fn filename_prefix(&self) -> &str {
        "GCP_VPC_Flow_Logs"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "project_id",
            "region",
            "subnetwork",
            "network",
            "flow_logs_enabled",
            "aggregation_interval",
            "flow_sampling",
            "metadata",
            "ip_cidr_range",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        // aggregatedList covers all regions; paginate to avoid dropping pages in
        // large projects that return more than maxResults subnetworks.
        let url = format!(
            "https://compute.googleapis.com/compute/v1/projects/{}/aggregated/subnetworks?maxResults=500",
            self.project_id
        );
        let items = self.client.paginate_aggregated(&url).await?;

        let mut rows = Vec::new();
        for (region_key, region_val) in &items {
            let region = region_key.trim_start_matches("regions/").to_owned();
            if let Some(subnets) = region_val.get("subnetworks").and_then(|v| v.as_array()) {
                for subnet in subnets {
                    let flow_cfg = subnet.get("logConfig");
                    let enabled = flow_cfg
                        .and_then(|l| l.get("enable"))
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false)
                        .to_string();
                    let aggregation = flow_cfg
                        .and_then(|l| l.get("aggregationInterval"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned();
                    let sampling = flow_cfg
                        .and_then(|l| l.get("flowSampling"))
                        .and_then(|v| v.as_f64())
                        .map(|f| f.to_string())
                        .unwrap_or_default();
                    let metadata = flow_cfg
                        .and_then(|l| l.get("metadata"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned();
                    let network = subnet
                        .get("network")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .split('/')
                        .next_back()
                        .unwrap_or("")
                        .to_owned();
                    rows.push(vec![
                        self.project_id.clone(),
                        region.clone(),
                        subnet
                            .get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_owned(),
                        network,
                        enabled,
                        aggregation,
                        sampling,
                        metadata,
                        subnet
                            .get("ipCidrRange")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_owned(),
                    ]);
                }
            }
        }
        Ok(rows)
    }
}
