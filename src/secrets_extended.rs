use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_secretsmanager::Client as SmClient;

use crate::evidence::CsvCollector;

fn fmt_sm_dt(dt: &aws_sdk_secretsmanager::primitives::DateTime) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(dt.secs(), 0)
        .map(|c| c.to_rfc3339())
        .unwrap_or_default()
}

pub struct SecretsManagerPoliciesCollector {
    client: SmClient,
}

impl SecretsManagerPoliciesCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: SmClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for SecretsManagerPoliciesCollector {
    fn name(&self) -> &str { "Secrets Manager Resource Policies" }
    fn filename_prefix(&self) -> &str { "Secrets_Manager_Policies" }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Secret Name", "Secret ARN", "KMS Key ID", "Rotation Enabled",
            "Rotation Interval (days)", "Last Rotated", "Has Resource Policy",
        ]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str, _dates: Option<(i64, i64)>) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut next_token: Option<String> = None;

        loop {
            let mut req = self.client.list_secrets();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = req.send().await.context("SecretsManager list_secrets")?;

            for secret in resp.secret_list() {
                let name        = secret.name().unwrap_or("").to_string();
                let arn         = secret.arn().unwrap_or("").to_string();
                let kms_key     = secret.kms_key_id().unwrap_or("").to_string();
                let rot_enabled = secret.rotation_enabled().unwrap_or(false).to_string();
                let rot_days    = secret.rotation_rules()
                    .and_then(|r| r.automatically_after_days())
                    .map(|n| n.to_string())
                    .unwrap_or_default();
                let last_rotated = secret.last_rotated_date()
                    .map(fmt_sm_dt)
                    .unwrap_or_default();

                let has_policy = match self.client
                    .get_resource_policy()
                    .secret_id(&arn)
                    .send()
                    .await
                {
                    Ok(r) => if r.resource_policy().map(|p| !p.is_empty()).unwrap_or(false) {
                        "Yes"
                    } else {
                        "No"
                    },
                    Err(e) => {
                        let msg = format!("{e}");
                        if msg.contains("ResourceNotFoundException") { "No" } else { "Unknown" }
                    }
                }.to_string();

                rows.push(vec![
                    name, arn, kms_key, rot_enabled,
                    rot_days, last_rotated, has_policy,
                ]);
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() { break; }
        }

        Ok(rows)
    }
}
