use anyhow::Result;
use async_trait::async_trait;
use okta_rs::OktaClient;
use serde_json::Value;

use crate::evidence::CsvCollector;

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

/// Serialize a `serde_json::Value` for a CSV cell. Returns an empty string for
/// `Null`, empty objects, or empty arrays so the column stays clean for
/// policies that don't populate the field.
fn json_cell(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::Object(m) if m.is_empty() => String::new(),
        Value::Array(a) if a.is_empty() => String::new(),
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

#[async_trait]
impl CsvCollector for OktaPoliciesCollector {
    fn name(&self) -> &str {
        "Okta Policies"
    }
    fn filename_prefix(&self) -> &str {
        "Okta_Policies"
    }

    fn headers(&self) -> &'static [&'static str] {
        &[
            "Policy ID",
            "Type",
            "Name",
            "Status",
            "Description",
            "Priority",
            "System",
            "Created",
            "Last Updated",
            "Conditions (JSON)",
            "Settings (JSON)",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows: Vec<Vec<String>> = Vec::new();
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
                rows.push(vec![
                    p.id,
                    p.policy_type,
                    p.name,
                    p.status,
                    p.description.unwrap_or_default(),
                    p.priority.map(|n| n.to_string()).unwrap_or_default(),
                    match p.system {
                        Some(true) => "YES".to_string(),
                        Some(false) => "NO".to_string(),
                        None => String::new(),
                    },
                    p.created.unwrap_or_default(),
                    p.last_updated.unwrap_or_default(),
                    json_cell(&p.conditions),
                    json_cell(&p.settings),
                ]);
            }
        }
        Ok(rows)
    }
}
