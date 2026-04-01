use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_secretsmanager::Client as SmClient;

use crate::evidence::CsvCollector;

pub struct SecretsManagerCollector {
    client: SmClient,
}

impl SecretsManagerCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: SmClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for SecretsManagerCollector {
    fn name(&self) -> &str { "Secrets Manager" }
    fn filename_prefix(&self) -> &str { "Secrets_Manager" }
    fn headers(&self) -> &'static [&'static str] {
        &["Secret Name", "ARN", "Rotation Enabled", "Last Rotated", "Region"]
    }

    async fn collect_rows(&self, _account_id: &str, region: &str) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut next_token: Option<String> = None;

        loop {
            let mut req = self.client.list_secrets();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = req.send().await.context("SecretsManager list_secrets")?;

            for secret in resp.secret_list() {
                let name         = secret.name().unwrap_or("").to_string();
                let arn          = secret.arn().unwrap_or("").to_string();
                let rotation     = if secret.rotation_enabled().unwrap_or(false) { "Yes" } else { "No" }.to_string();
                let last_rotated = secret.last_rotated_date()
                    .map(|d| {
                        chrono::DateTime::<chrono::Utc>::from_timestamp(d.secs(), d.subsec_nanos())
                            .map(|c| c.to_rfc3339())
                            .unwrap_or_default()
                    })
                    .unwrap_or_default();

                rows.push(vec![name, arn, rotation, last_rotated, region.to_string()]);
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() { break; }
        }

        Ok(rows)
    }
}
