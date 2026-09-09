use anyhow::Result;
use async_trait::async_trait;
use jumpcloud_rs::JumpCloudClient;

use crate::evidence::JsonCollector;

pub struct JumpCloudSessionPolicyCollector {
    client: JumpCloudClient,
    org_id: String,
}

impl JumpCloudSessionPolicyCollector {
    pub fn new(client: JumpCloudClient, org_id: String) -> Self {
        Self { client, org_id }
    }
}

fn is_session_template(name: &str, kind: &str, template_type: Option<&str>) -> bool {
    let hay = format!(
        "{} {} {}",
        name,
        kind,
        template_type.unwrap_or("")
    )
    .to_ascii_lowercase();
    hay.contains("session")
        || hay.contains("mfa")
        || hay.contains("lockout")
        || hay.contains("re-auth")
        || hay.contains("reauth")
}

#[async_trait]
impl JsonCollector for JumpCloudSessionPolicyCollector {
    fn name(&self) -> &str {
        "JumpCloud Session Policy"
    }

    fn filename_prefix(&self) -> &str {
        "JumpCloud_SessionPolicy"
    }

    async fn collect_records(
        &self,
        _account_id: &str,
        _region: &str,
    ) -> Result<Vec<serde_json::Value>> {
        // Device-scoped: fetch policies and filter for session templates
        let session_policies = match self.client.policies().list_all().await {
            Ok(policies) => {
                policies
                    .into_iter()
                    .filter(|p| {
                        is_session_template(
                            &p.template.name,
                            &p.template.kind,
                            p.template.template_type.as_deref(),
                        )
                    })
                    .collect::<Vec<_>>()
            }
            Err(jumpcloud_rs::JumpCloudError::Api { status: 404, .. }) => {
                vec![]
            }
            Err(e) => return Err(e.into()),
        };

        // Org-level settings: fetch organization and extract session/MFA/lockout config
        let org_settings = if self.org_id.is_empty() {
            // If no org_id provided, list all orgs and take the first one
            match self.client.organizations().list_all().await {
                Ok(orgs) => {
                    if let Some(org) = orgs.into_iter().next() {
                        org.settings
                            .as_ref()
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
                        .cloned()
                        .unwrap_or(serde_json::Value::Null)
                }
                Err(jumpcloud_rs::JumpCloudError::Api { status: 404, .. }) => {
                    serde_json::Value::Null
                }
                Err(e) => return Err(e.into()),
            }
        };

        // Extract specific session/MFA/lockout settings from org_settings
        let org_session_config = serde_json::json!({
            "mfa": org_settings.get("mfa").cloned().unwrap_or(serde_json::Value::Null),
            "sessionDuration": org_settings.get("sessionDuration").cloned().unwrap_or(serde_json::Value::Null),
            "adminSessionDuration": org_settings.get("adminSessionDuration").cloned().unwrap_or(serde_json::Value::Null),
            "userLockoutAction": org_settings.get("userLockoutAction").cloned().unwrap_or(serde_json::Value::Null),
            "maxLoginAttempts": org_settings.get("maxLoginAttempts").cloned().unwrap_or(serde_json::Value::Null),
        });

        // Return both in a single consolidated document
        Ok(vec![serde_json::json!({
            "org_session_config": org_session_config,
            "device_session_policies": session_policies,
        })])
    }
}
