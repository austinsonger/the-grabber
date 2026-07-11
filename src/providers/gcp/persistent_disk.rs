//! GCP Persistent Disks — equivalent to AWS EBS.

use anyhow::Result;
use async_trait::async_trait;

use crate::evidence::CsvCollector;
use crate::providers::gcp::client::GcpClient;

pub struct PersistentDiskCollector {
    client: GcpClient,
    project_id: String,
}

impl PersistentDiskCollector {
    pub fn new(client: GcpClient, project_id: impl Into<String>) -> Self {
        Self {
            client,
            project_id: project_id.into(),
        }
    }
}

#[async_trait]
impl CsvCollector for PersistentDiskCollector {
    fn name(&self) -> &str {
        "GCP Persistent Disks"
    }
    fn filename_prefix(&self) -> &str {
        "GCP_Persistent_Disks"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "project_id",
            "zone",
            "name",
            "size_gb",
            "type",
            "status",
            "creation_timestamp",
            "users",
            "labels",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        // aggregatedList covers all zones; paginate to avoid dropping pages in
        // large projects that return more than maxResults disks.
        let url = format!(
            "https://compute.googleapis.com/compute/v1/projects/{}/aggregated/disks?maxResults=500",
            self.project_id
        );
        let items = self.client.paginate_aggregated(&url).await?;

        let mut rows = Vec::new();
        for (zone_key, zone_val) in &items {
            let zone = zone_key.trim_start_matches("zones/").to_owned();
            if let Some(disks) = zone_val.get("disks").and_then(|v| v.as_array()) {
                for disk in disks {
                    let disk_type = disk
                        .get("type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .split('/')
                        .next_back()
                        .unwrap_or("")
                        .to_owned();
                    let users = disk
                        .get("users")
                        .and_then(|v| v.as_array())
                        .map(|a| {
                            a.iter()
                                .filter_map(|u| u.as_str())
                                .map(|s| s.split('/').next_back().unwrap_or(s))
                                .collect::<Vec<_>>()
                                .join(",")
                        })
                        .unwrap_or_default();
                    let labels = disk
                        .get("labels")
                        .map(|l| serde_json::to_string(l).unwrap_or_default())
                        .unwrap_or_default();
                    rows.push(vec![
                        self.project_id.clone(),
                        zone.clone(),
                        disk.get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_owned(),
                        disk.get("sizeGb")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_owned(),
                        disk_type,
                        disk.get("status")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_owned(),
                        disk.get("creationTimestamp")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_owned(),
                        users,
                        labels,
                    ]);
                }
            }
        }
        Ok(rows)
    }
}
