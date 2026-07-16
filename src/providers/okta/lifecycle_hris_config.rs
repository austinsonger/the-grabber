use anyhow::Result;
use async_trait::async_trait;
use okta_rs::OktaClient;
use serde_json::Value;

use crate::evidence::CsvCollector;

pub struct OktaLifecycleHrisConfigCollector {
    client: OktaClient,
}

impl OktaLifecycleHrisConfigCollector {
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

fn nested_name(v: &Value, key: &str) -> String {
    v.get(key)
        .and_then(|x| x.get("name"))
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string()
}

#[async_trait]
impl CsvCollector for OktaLifecycleHrisConfigCollector {
    fn name(&self) -> &str {
        "Okta Lifecycle HRIS Integration Config"
    }
    fn filename_prefix(&self) -> &str {
        "Okta_Lifecycle_HRIS_Integration_Config"
    }
    fn headers(&self) -> &'static [&'static str] {
        &["Kind", "ID", "Source", "Target", "Notes"]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        let mappings = match self.client.lifecycle().mappings().await {
            Ok(v) => v,
            Err(okta_rs::OktaError::Api { status: 404, .. }) => Value::Null,
            Err(e) => return Err(e.into()),
        };
        if let Some(arr) = mappings.as_array() {
            for m in arr {
                rows.push(vec![
                    "Mapping".to_string(),
                    str_field(m, "id"),
                    nested_name(m, "source"),
                    nested_name(m, "target"),
                    str_field(m, "status"),
                ]);
            }
        }

        let idps = match self.client.lifecycle().idps().await {
            Ok(v) => v,
            Err(okta_rs::OktaError::Api { status: 404, .. }) => Value::Null,
            Err(e) => return Err(e.into()),
        };
        if let Some(arr) = idps.as_array() {
            for i in arr {
                rows.push(vec![
                    "IdP".to_string(),
                    str_field(i, "id"),
                    nested_name(i, "source"),
                    nested_name(i, "target"),
                    str_field(i, "status"),
                ]);
            }
        }

        Ok(rows)
    }
}
