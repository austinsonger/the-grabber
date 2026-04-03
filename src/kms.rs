use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_kms::Client as KmsClient;
use aws_sdk_kms::types::KeyManagerType;

use crate::evidence::CsvCollector;

pub struct KmsKeyCollector {
    client: KmsClient,
}

impl KmsKeyCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: KmsClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for KmsKeyCollector {
    fn name(&self) -> &str { "KMS Keys" }
    fn filename_prefix(&self) -> &str { "KMS_Keys" }
    fn headers(&self) -> &'static [&'static str] {
        &["Key ID", "ARN", "Key Manager", "Key State", "Rotation Enabled", "Region"]
    }

    async fn collect_rows(&self, _account_id: &str, region: &str, _dates: Option<(i64, i64)>) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut next_marker: Option<String> = None;

        loop {
            let mut req = self.client.list_keys();
            if let Some(ref m) = next_marker {
                req = req.marker(m);
            }
            let resp = req.send().await.context("KMS list_keys")?;

            for key_list_entry in resp.keys() {
                let key_id  = key_list_entry.key_id().unwrap_or("").to_string();
                let key_arn = key_list_entry.key_arn().unwrap_or("").to_string();

                // Describe key for metadata.
                let metadata = match self.client
                    .describe_key()
                    .key_id(&key_id)
                    .send()
                    .await
                {
                    Ok(r) => r.key_metadata().cloned(),
                    Err(_) => None,
                };

                let Some(meta) = metadata else { continue };

                // Skip AWS-managed keys — show only customer-managed.
                if meta.key_manager() == Some(&KeyManagerType::Aws) { continue; }

                let key_manager = meta.key_manager()
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_default();
                let key_state = meta.key_state()
                    .map(|s| s.as_str().to_string())
                    .unwrap_or_default();

                let rotation = match self.client
                    .get_key_rotation_status()
                    .key_id(&key_id)
                    .send()
                    .await
                {
                    Ok(r) => if r.key_rotation_enabled() { "Yes" } else { "No" }.to_string(),
                    Err(_) => "".to_string(),
                };

                rows.push(vec![key_id, key_arn, key_manager, key_state, rotation, region.to_string()]);
            }

            next_marker = if resp.truncated() { resp.next_marker().map(|s| s.to_string()) } else { None };
            if next_marker.is_none() { break; }
        }

        Ok(rows)
    }
}
