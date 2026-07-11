//! GCP Memorystore (Redis) instances — equivalent to AWS ElastiCache.

use anyhow::Result;
use async_trait::async_trait;

use crate::evidence::CsvCollector;
use crate::providers::gcp::client::GcpClient;

pub struct MemorystoreCollector {
    client: GcpClient,
    project_id: String,
}

impl MemorystoreCollector {
    pub fn new(client: GcpClient, project_id: impl Into<String>) -> Self {
        Self {
            client,
            project_id: project_id.into(),
        }
    }
}

#[async_trait]
impl CsvCollector for MemorystoreCollector {
    fn name(&self) -> &str {
        "GCP Memorystore"
    }
    fn filename_prefix(&self) -> &str {
        "GCP_Memorystore"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "project_id",
            "name",
            "location",
            "tier",
            "memory_size_gb",
            "redis_version",
            "state",
            "host",
            "port",
            "auth_enabled",
            "transit_encryption",
            "create_time",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let url = format!(
            "https://redis.googleapis.com/v1/projects/{}/locations/-/instances?pageSize=1000",
            self.project_id
        );
        let instances = self.client.paginate(&url, "instances").await?;

        let rows = instances
            .iter()
            .map(|inst| {
                let name_full = inst
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_owned();
                let name_short = name_full.split('/').last().unwrap_or("").to_owned();
                let location = name_full.split('/').nth(5).unwrap_or("").to_owned();
                let auth = inst
                    .get("authEnabled")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
                    .to_string();
                let tls = inst
                    .get("transitEncryptionMode")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_owned();
                vec![
                    self.project_id.clone(),
                    name_short,
                    location,
                    inst.get("tier")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned(),
                    inst.get("memorySizeGb")
                        .and_then(|v| v.as_i64())
                        .map(|i| i.to_string())
                        .unwrap_or_default(),
                    inst.get("redisVersion")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned(),
                    inst.get("state")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned(),
                    inst.get("host")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned(),
                    inst.get("port")
                        .and_then(|v| v.as_i64())
                        .map(|i| i.to_string())
                        .unwrap_or_default(),
                    auth,
                    tls,
                    inst.get("createTime")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned(),
                ]
            })
            .collect();
        Ok(rows)
    }
}
