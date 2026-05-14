use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_iam::Client as IamClient;

use crate::evidence::JsonCollector;

// ---------------------------------------------------------------------------
// IAM Roles
// ---------------------------------------------------------------------------

pub struct IamRoleCollector {
    client: IamClient,
}

impl IamRoleCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: IamClient::new(config),
        }
    }
}

#[async_trait]
impl JsonCollector for IamRoleCollector {
    fn name(&self) -> &str {
        "IAM Roles"
    }
    fn filename_prefix(&self) -> &str {
        "IAM_Roles"
    }

    async fn collect_records(
        &self,
        _account_id: &str,
        _region: &str,
    ) -> Result<Vec<serde_json::Value>> {
        let mut records = Vec::new();
        let mut marker: Option<String> = None;

        loop {
            let mut req = self.client.list_roles();
            if let Some(ref m) = marker {
                req = req.marker(m);
            }
            let resp = req.send().await.context("IAM list_roles")?;

            for role in resp.roles() {
                let name = role.role_name().to_string();
                let arn = role.arn().to_string();

                let trust_policy: serde_json::Value = serde_json::from_str(&super::url_decode(
                    role.assume_role_policy_document().unwrap_or("{}"),
                ))
                .unwrap_or(serde_json::Value::Null);

                let last_used = role
                    .role_last_used()
                    .and_then(|l| l.last_used_date())
                    .map(|d| super::fmt_iam_dt(d))
                    .unwrap_or_else(|| "Never".to_string());
                let last_used_region = role
                    .role_last_used()
                    .and_then(|l| l.region())
                    .unwrap_or("")
                    .to_string();

                let attached_policies: Vec<String> = match self
                    .client
                    .list_attached_role_policies()
                    .role_name(&name)
                    .send()
                    .await
                {
                    Ok(r) => r
                        .attached_policies()
                        .iter()
                        .filter_map(|p| p.policy_name().map(|s| s.to_string()))
                        .collect(),
                    Err(_) => vec![],
                };

                records.push(serde_json::json!({
                    "role_name":          name,
                    "arn":                arn,
                    "trust_policy":       trust_policy,
                    "attached_policies":  attached_policies,
                    "last_used":          last_used,
                    "last_used_region":   last_used_region,
                }));
            }

            marker = if resp.is_truncated() {
                resp.marker().map(|s| s.to_string())
            } else {
                None
            };
            if marker.is_none() {
                break;
            }
        }

        Ok(records)
    }
}
