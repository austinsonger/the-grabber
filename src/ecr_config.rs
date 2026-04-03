use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_ecr::Client as EcrClient;

use crate::evidence::CsvCollector;

pub struct EcrRepoConfigCollector {
    client: EcrClient,
}

impl EcrRepoConfigCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: EcrClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for EcrRepoConfigCollector {
    fn name(&self) -> &str { "ECR Repository Configuration" }
    fn filename_prefix(&self) -> &str { "ECR_Config" }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Repository Name", "Registry ID", "URI", "Image Tag Mutability",
            "Scan On Push", "Encryption Type", "KMS Key", "Has Lifecycle Policy",
        ]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str, _dates: Option<(i64, i64)>) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut next_token: Option<String> = None;

        loop {
            let mut req = self.client.describe_repositories();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = req.send().await.context("ECR describe_repositories")?;

            for repo in resp.repositories() {
                let name           = repo.repository_name().unwrap_or("").to_string();
                let registry_id    = repo.registry_id().unwrap_or("").to_string();
                let uri            = repo.repository_uri().unwrap_or("").to_string();
                let mutability     = repo.image_tag_mutability()
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_default();
                let scan_on_push   = repo.image_scanning_configuration()
                    .map(|s| s.scan_on_push().to_string())
                    .unwrap_or_else(|| "false".to_string());
                let enc_type       = repo.encryption_configuration()
                    .map(|e| e.encryption_type().as_str().to_string())
                    .unwrap_or_else(|| "AES256".to_string());
                let kms_key        = repo.encryption_configuration()
                    .and_then(|e| e.kms_key())
                    .unwrap_or("")
                    .to_string();

                let has_lifecycle = match self.client
                    .get_lifecycle_policy()
                    .repository_name(&name)
                    .send()
                    .await
                {
                    Ok(r) => if r.lifecycle_policy_text().map(|p| !p.is_empty()).unwrap_or(false) {
                        "Yes"
                    } else {
                        "No"
                    },
                    Err(e) => {
                        let msg = format!("{e}");
                        if msg.contains("LifecyclePolicyNotFoundException") { "No" } else { "Unknown" }
                    }
                }.to_string();

                rows.push(vec![
                    name, registry_id, uri, mutability,
                    scan_on_push, enc_type, kms_key, has_lifecycle,
                ]);
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() { break; }
        }

        Ok(rows)
    }
}
