//! GCP Cloud KMS key rings and keys — equivalent to AWS KMS.

use anyhow::Result;
use async_trait::async_trait;

use crate::evidence::CsvCollector;
use crate::providers::gcp::client::GcpClient;

pub struct KmsCollector {
    client:     GcpClient,
    project_id: String,
    location:   String,
}

impl KmsCollector {
    pub fn new(
        client: GcpClient,
        project_id: impl Into<String>,
        location: impl Into<String>,
    ) -> Self {
        Self {
            client,
            project_id: project_id.into(),
            location: location.into(),
        }
    }
}

#[async_trait]
impl CsvCollector for KmsCollector {
    fn name(&self) -> &str { "GCP Cloud KMS" }
    fn filename_prefix(&self) -> &str { "GCP_KMS" }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "project_id", "location", "key_ring", "key_name", "purpose",
            "algorithm", "protection_level", "state", "create_time",
            "rotation_period", "next_rotation_time", "labels",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let loc = if self.location.is_empty() { "-" } else { &self.location };
        let rings_url = format!(
            "https://cloudkms.googleapis.com/v1/projects/{}/locations/{}/keyRings?pageSize=100",
            self.project_id, loc
        );
        let rings = self.client.paginate(&rings_url, "keyRings").await?;

        let mut rows = Vec::new();
        for ring in &rings {
            let ring_name = ring.get("name").and_then(|v| v.as_str()).unwrap_or("").to_owned();
            let ring_short = ring_name.split('/').last().unwrap_or("").to_owned();

            let keys_url = format!(
                "https://cloudkms.googleapis.com/v1/{}/cryptoKeys?pageSize=100&versionView=FULL",
                ring_name
            );
            let keys = self.client.paginate(&keys_url, "cryptoKeys").await?;

            for key in &keys {
                let primary = key.get("primary");
                let algorithm = primary
                    .and_then(|p| p.get("algorithm"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let protection = primary
                    .and_then(|p| p.get("protectionLevel"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let state = primary
                    .and_then(|p| p.get("state"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                let key_short = key
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .split('/')
                    .last()
                    .unwrap_or("")
                    .to_owned();

                rows.push(vec![
                    self.project_id.clone(),
                    self.location.clone(),
                    ring_short.clone(),
                    key_short,
                    key.get("purpose").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
                    algorithm.to_owned(),
                    protection.to_owned(),
                    state.to_owned(),
                    key.get("createTime").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
                    key.get("rotationPeriod").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
                    key.get("nextRotationTime").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
                    key.get("labels")
                        .map(|l| serde_json::to_string(l).unwrap_or_default())
                        .unwrap_or_default(),
                ]);
            }
        }

        Ok(rows)
    }
}
