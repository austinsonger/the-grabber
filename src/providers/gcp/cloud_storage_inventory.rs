//! GCP Cloud Storage bucket inventory — equivalent to AWS S3 inventory.

use anyhow::Result;
use async_trait::async_trait;

use crate::evidence::CsvCollector;
use crate::providers::gcp::client::GcpClient;

pub struct CloudStorageInventoryCollector {
    client:     GcpClient,
    project_id: String,
}

impl CloudStorageInventoryCollector {
    pub fn new(client: GcpClient, project_id: impl Into<String>) -> Self {
        Self { client, project_id: project_id.into() }
    }
}

#[async_trait]
impl CsvCollector for CloudStorageInventoryCollector {
    fn name(&self) -> &str { "GCP Cloud Storage Inventory" }
    fn filename_prefix(&self) -> &str { "GCP_Storage_Inventory" }
    fn headers(&self) -> &'static [&'static str] {
        &["project_id", "name", "location", "storage_class",
          "time_created", "updated", "versioning_enabled",
          "uniform_bucket_level_access", "public_access_prevention", "labels"]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let url = format!(
            "https://storage.googleapis.com/storage/v1/b?project={}&maxResults=1000",
            self.project_id
        );
        let buckets = self.client.paginate(&url, "items").await?;

        let rows = buckets
            .iter()
            .map(|b| {
                let versioning = b
                    .get("versioning")
                    .and_then(|v| v.get("enabled"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
                    .to_string();
                let ubla = b
                    .get("iamConfiguration")
                    .and_then(|i| i.get("uniformBucketLevelAccess"))
                    .and_then(|u| u.get("enabled"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
                    .to_string();
                let pap = b
                    .get("iamConfiguration")
                    .and_then(|i| i.get("publicAccessPrevention"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_owned();
                let labels = b
                    .get("labels")
                    .map(|l| serde_json::to_string(l).unwrap_or_default())
                    .unwrap_or_default();
                vec![
                    self.project_id.clone(),
                    b.get("name").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
                    b.get("location").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
                    b.get("storageClass").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
                    b.get("timeCreated").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
                    b.get("updated").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
                    versioning,
                    ubla,
                    pap,
                    labels,
                ]
            })
            .collect();
        Ok(rows)
    }
}
