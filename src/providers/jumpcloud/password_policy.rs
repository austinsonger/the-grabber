use anyhow::Result;
use async_trait::async_trait;
use jumpcloud_rs::JumpCloudClient;

use crate::evidence::JsonCollector;

pub struct JumpCloudPasswordPolicyCollector {
    client: JumpCloudClient,
    org_id: String,
}

impl JumpCloudPasswordPolicyCollector {
    pub fn new(client: JumpCloudClient, org_id: String) -> Self {
        Self { client, org_id }
    }
}

fn is_password_template(kind: &str, template_type: Option<&str>) -> bool {
    let hay = format!("{} {}", kind, template_type.unwrap_or("")).to_ascii_lowercase();
    hay.contains("password")
}

#[async_trait]
impl JsonCollector for JumpCloudPasswordPolicyCollector {
    fn name(&self) -> &str {
        "JumpCloud Password Policy"
    }

    fn filename_prefix(&self) -> &str {
        "JumpCloud_PasswordPolicy"
    }

    async fn collect_records(
        &self,
        _account_id: &str,
        _region: &str,
    ) -> Result<Vec<serde_json::Value>> {
        // Device-scoped: fetch policies and filter for password templates
        let device_policies = match self.client.policies().list_all().await {
            Ok(policies) => {
                policies
                    .into_iter()
                    .filter(|p| {
                        is_password_template(&p.template.kind, p.template.template_type.as_deref())
                    })
                    .collect::<Vec<_>>()
            }
            Err(jumpcloud_rs::JumpCloudError::Api { status: 404, .. }) => {
                vec![]
            }
            Err(e) => return Err(e.into()),
        };

        // Org-level: fetch organization settings
        let org_password_policy = if self.org_id.is_empty() {
            // If no org_id provided, list all orgs and take the first one
            match self.client.organizations().list_all().await {
                Ok(orgs) => {
                    if let Some(org) = orgs.into_iter().next() {
                        org.settings
                            .as_ref()
                            .and_then(|s| s.get("passwordPolicy"))
                            .cloned()
                            .unwrap_or(serde_json::Value::Null)
                    } else {
                        serde_json::Value::Null
                    }
                }
                Err(jumpcloud_rs::JumpCloudError::Api { status: 404, .. }) => {
                    serde_json::Value::Null
                }
                Err(e) => return Err(e.into()),
            }
        } else {
            // Fetch specific organization by ID
            match self.client.organizations().get(&self.org_id).await {
                Ok(org) => {
                    org.settings
                        .as_ref()
                        .and_then(|s| s.get("passwordPolicy"))
                        .cloned()
                        .unwrap_or(serde_json::Value::Null)
                }
                Err(jumpcloud_rs::JumpCloudError::Api { status: 404, .. }) => {
                    serde_json::Value::Null
                }
                Err(e) => return Err(e.into()),
            }
        };

        // Return both in a single consolidated document
        Ok(vec![serde_json::json!({
            "org_password_policy": org_password_policy,
            "device_password_policies": device_policies,
        })])
    }
}
