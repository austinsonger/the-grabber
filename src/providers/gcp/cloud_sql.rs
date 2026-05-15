//! GCP Cloud SQL instances — equivalent to AWS RDS.

use anyhow::Result;
use async_trait::async_trait;

use crate::evidence::CsvCollector;
use crate::providers::gcp::client::GcpClient;

pub struct CloudSqlCollector {
    client:     GcpClient,
    project_id: String,
}

impl CloudSqlCollector {
    pub fn new(client: GcpClient, project_id: impl Into<String>) -> Self {
        Self { client, project_id: project_id.into() }
    }
}

#[async_trait]
impl CsvCollector for CloudSqlCollector {
    fn name(&self) -> &str { "GCP Cloud SQL" }
    fn filename_prefix(&self) -> &str { "GCP_Cloud_SQL" }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "project_id", "name", "database_version", "region", "tier",
            "state", "ip_address", "backup_enabled", "high_availability",
            "storage_type", "storage_size_gb", "create_time",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let url = format!(
            "https://sqladmin.googleapis.com/sql/v1beta4/projects/{}/instances",
            self.project_id
        );
        let instances = self.client.paginate(&url, "items").await?;

        let rows = instances.iter().map(|inst| {
            let settings = inst.get("settings");
            let tier = settings
                .and_then(|s| s.get("tier"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned();
            let backup = settings
                .and_then(|s| s.get("backupConfiguration"))
                .and_then(|b| b.get("enabled"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
                .to_string();
            let ha = settings
                .and_then(|s| s.get("availabilityType"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned();
            let storage_type = settings
                .and_then(|s| s.get("dataDiskType"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned();
            let storage_size = settings
                .and_then(|s| s.get("dataDiskSizeGb"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned();
            let ip = inst
                .get("ipAddresses")
                .and_then(|v| v.as_array())
                .and_then(|arr| arr.first())
                .and_then(|i| i.get("ipAddress"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned();
            vec![
                self.project_id.clone(),
                inst.get("name").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
                inst.get("databaseVersion").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
                inst.get("region").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
                tier,
                inst.get("state").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
                ip,
                backup,
                ha,
                storage_type,
                storage_size,
                inst.get("createTime").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
            ]
        }).collect();
        Ok(rows)
    }
}
