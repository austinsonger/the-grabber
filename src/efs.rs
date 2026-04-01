use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_efs::Client as EfsClient;

use crate::evidence::CsvCollector;

pub struct EfsCollector {
    client: EfsClient,
}

impl EfsCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: EfsClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for EfsCollector {
    fn name(&self) -> &str { "EFS File Systems" }
    fn filename_prefix(&self) -> &str { "EFS" }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "File System ID", "File System Name", "File System ARN",
            "KMS Key ARN", "Encryption Status", "Region",
        ]
    }

    async fn collect_rows(&self, _account_id: &str, region: &str) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut marker: Option<String> = None;

        loop {
            let mut req = self.client.describe_file_systems();
            if let Some(ref m) = marker {
                req = req.marker(m);
            }
            let resp = req.send().await.context("EFS describe_file_systems")?;

            for fs in resp.file_systems() {
                let fs_id  = fs.file_system_id().to_string();
                let name   = fs.name().unwrap_or("").to_string();
                let arn    = fs.file_system_arn().unwrap_or("").to_string();
                let kms    = fs.kms_key_id().unwrap_or("").to_string();
                let enc    = if fs.encrypted().unwrap_or(false) { "Encrypted" } else { "Not Encrypted" }.to_string();

                rows.push(vec![fs_id, name, arn, kms, enc, region.to_string()]);
            }

            marker = resp.next_marker().map(|s| s.to_string());
            if marker.is_none() { break; }
        }

        Ok(rows)
    }
}
