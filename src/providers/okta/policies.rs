use anyhow::Result;
use async_trait::async_trait;
use okta_rs::OktaClient;
use serde_json::json;

use crate::evidence::JsonCollector;

const POLICY_TYPES: &[&str] = &[
    "OKTA_SIGN_ON",
    "PASSWORD",
    "MFA_ENROLL",
    "IDP_DISCOVERY",
    "ACCESS_POLICY",
    "PROFILE_ENROLLMENT",
];

pub struct OktaPoliciesCollector {
    client: OktaClient,
}
impl OktaPoliciesCollector {
    pub fn new(client: OktaClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl JsonCollector for OktaPoliciesCollector {
    fn name(&self) -> &str {
        "Okta Policies"
    }
    fn filename_prefix(&self) -> &str {
        "Okta_Policies"
    }

    async fn collect_records(
        &self,
        _account_id: &str,
        _region: &str,
    ) -> Result<Vec<serde_json::Value>> {
        let mut out = Vec::new();
        for &policy_type in POLICY_TYPES {
            let policies = match self.client.policies().list_by_type(policy_type).await {
                Ok(p) => p,
                // Some policy types are unavailable on certain Okta plans (e.g. ACCESS_POLICY
                // requires Identity Engine). Treat 400/404 as "not enabled" and skip.
                Err(okta_rs::OktaError::Api { status, .. }) if status == 400 || status == 404 => {
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            for p in policies {
                out.push(json!({
                    "id": p.id,
                    "type": p.policy_type,
                    "name": p.name,
                    "status": p.status,
                    "description": p.description,
                    "priority": p.priority,
                    "system": p.system,
                    "created": p.created,
                    "last_updated": p.last_updated,
                    "conditions": p.conditions,
                    "settings": p.settings,
                }));
            }
        }
        Ok(out)
    }
}
