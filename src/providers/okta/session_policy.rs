use anyhow::Result;
use async_trait::async_trait;
use okta_rs::OktaClient;
use serde_json::Value;

use crate::evidence::CsvCollector;

pub struct OktaSessionPolicyCollector {
    client: OktaClient,
}

impl OktaSessionPolicyCollector {
    pub fn new(client: OktaClient) -> Self {
        Self { client }
    }
}

fn str_field(v: &Value, key: &str) -> String {
    v.get(key)
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string()
}

#[async_trait]
impl CsvCollector for OktaSessionPolicyCollector {
    fn name(&self) -> &str {
        "Okta Session Policy"
    }
    fn filename_prefix(&self) -> &str {
        "Okta_Session_Policy"
    }
    fn headers(&self) -> &'static [&'static str] {
        &["Policy ID", "Name", "Status", "Priority", "System"]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let policies = match self.client.sign_in_widget().sign_on_policies().await {
            Ok(v) => v,
            Err(okta_rs::OktaError::Api { status, .. }) if [401, 403, 404].contains(&status) => {
                return Ok(vec![])
            }
            Err(e) => return Err(e.into()),
        };

        let arr = match policies.as_array() {
            Some(a) => a,
            None => return Ok(vec![]),
        };

        let rows = arr
            .iter()
            .map(|p| {
                let priority = p
                    .get("priority")
                    .and_then(|v| v.as_i64())
                    .map(|n| n.to_string())
                    .unwrap_or_default();
                let system = match p.get("system").and_then(|v| v.as_bool()) {
                    Some(true) => "YES".to_string(),
                    Some(false) => "NO".to_string(),
                    None => String::new(),
                };
                vec![
                    str_field(p, "id"),
                    str_field(p, "name"),
                    str_field(p, "status"),
                    priority,
                    system,
                ]
            })
            .collect();

        Ok(rows)
    }
}
