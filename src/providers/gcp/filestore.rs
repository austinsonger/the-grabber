//! GCP Filestore instances — equivalent to AWS EFS.

use anyhow::Result;
use async_trait::async_trait;

use crate::evidence::CsvCollector;
use crate::providers::gcp::client::GcpClient;

pub struct FilestoreCollector {
    client:     GcpClient,
    project_id: String,
}

impl FilestoreCollector {
    pub fn new(client: GcpClient, project_id: impl Into<String>) -> Self {
        Self { client, project_id: project_id.into() }
    }
}

#[async_trait]
impl CsvCollector for FilestoreCollector {
    fn name(&self) -> &str { "GCP Filestore" }
    fn filename_prefix(&self) -> &str { "GCP_Filestore" }
    fn headers(&self) -> &'static [&'static str] {
        &["project_id", "name", "location", "tier", "state",
          "capacity_gb", "network", "ip_addresses",
          "create_time", "kms_key"]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let url = format!(
            "https://file.googleapis.com/v1/projects/{}/locations/-/instances?pageSize=1000",
            self.project_id
        );
        let instances = self.client.paginate(&url, "instances").await?;

        let rows = instances.iter().map(|inst| {
            let name_full = inst.get("name").and_then(|v| v.as_str()).unwrap_or("").to_owned();
            let name_short = name_full.split('/').last().unwrap_or("").to_owned();
            let location = name_full.split('/').nth(5).unwrap_or("").to_owned();
            let capacity = inst
                .get("fileShares")
                .and_then(|v| v.as_array())
                .and_then(|a| a.first())
                .and_then(|s| s.get("capacityGb"))
                .and_then(|v| v.as_i64())
                .map(|i| i.to_string())
                .unwrap_or_default();
            let (network, ips) = inst
                .get("networks")
                .and_then(|v| v.as_array())
                .and_then(|a| a.first())
                .map(|n| {
                    let net = n.get("network").and_then(|v| v.as_str()).unwrap_or("").to_owned();
                    let ip_list = n
                        .get("ipAddresses")
                        .and_then(|v| v.as_array())
                        .map(|a| a.iter().filter_map(|i| i.as_str()).collect::<Vec<_>>().join(","))
                        .unwrap_or_default();
                    (net, ip_list)
                })
                .unwrap_or_default();
            let kms = inst.get("kmsKeyName").and_then(|v| v.as_str()).unwrap_or("").to_owned();
            vec![
                self.project_id.clone(),
                name_short,
                location,
                inst.get("tier").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
                inst.get("state").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
                capacity,
                network,
                ips,
                inst.get("createTime").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
                kms,
            ]
        }).collect();
        Ok(rows)
    }
}
