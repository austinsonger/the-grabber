use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_iam::Client as IamClient;

use crate::evidence::CsvCollector;

pub struct IamTrustsCollector {
    client: IamClient,
}

impl IamTrustsCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: IamClient::new(config) }
    }
}

fn url_decode(s: &str) -> String {
    s.replace("%22", "\"").replace("%7B", "{").replace("%7D", "}")
     .replace("%5B", "[").replace("%5D", "]").replace("%3A", ":")
     .replace("%2F", "/").replace("%2C", ",").replace("%20", " ")
     .replace("%0A", " ").replace("+", " ")
}

#[async_trait]
impl CsvCollector for IamTrustsCollector {
    fn name(&self) -> &str { "IAM Role Trust Policies" }
    fn filename_prefix(&self) -> &str { "IAM_Role_Trusts" }
    fn headers(&self) -> &'static [&'static str] {
        &["Role Name", "Trusted Entity", "Entity Type", "External ID", "Conditions", "Cross Account"]
    }

    async fn collect_rows(&self, account_id: &str, _region: &str) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut marker: Option<String> = None;

        loop {
            let mut req = self.client.list_roles();
            if let Some(ref m) = marker {
                req = req.marker(m);
            }
            let resp = req.send().await.context("IAM list_roles")?;

            for role in resp.roles() {
                let role_name = role.role_name().to_string();
                let raw_doc = role.assume_role_policy_document().unwrap_or("");
                let decoded = url_decode(raw_doc);

                let parsed: serde_json::Value = match serde_json::from_str(&decoded) {
                    Ok(v) => v,
                    Err(_) => {
                        rows.push(vec![
                            role_name.clone(),
                            decoded,
                            String::new(),
                            String::new(),
                            String::new(),
                            String::new(),
                        ]);
                        continue;
                    }
                };

                let statements = match parsed.get("Statement").and_then(|s| s.as_array()) {
                    Some(arr) => arr.clone(),
                    None => continue,
                };

                for stmt in &statements {
                    let principal = stmt.get("Principal");
                    let (trusted_entity, entity_type, cross_account) = match principal {
                        None => (String::new(), String::new(), "No".to_string()),
                        Some(p) => {
                            if let Some(s) = p.as_str() {
                                // e.g. "*"
                                (s.to_string(), "AWS".to_string(), "No".to_string())
                            } else if let Some(obj) = p.as_object() {
                                let mut entities = Vec::new();
                                let mut etype = String::new();
                                let mut cross = "No".to_string();

                                for (key, val) in obj {
                                    etype = key.clone();
                                    let arns: Vec<String> = if let Some(arr) = val.as_array() {
                                        arr.iter().filter_map(|v| v.as_str()).map(|s| s.to_string()).collect()
                                    } else if let Some(s) = val.as_str() {
                                        vec![s.to_string()]
                                    } else {
                                        vec![]
                                    };
                                    for arn in &arns {
                                        // Check cross-account: ARN contains an account ID that differs
                                        // IAM ARNs look like arn:aws:iam::123456789012:...
                                        if arn.starts_with("arn:aws") {
                                            let parts: Vec<&str> = arn.splitn(6, ':').collect();
                                            if parts.len() >= 5 {
                                                let arn_account = parts[4];
                                                if !arn_account.is_empty() && arn_account != account_id {
                                                    cross = "Yes".to_string();
                                                }
                                            }
                                        }
                                        entities.push(arn.clone());
                                    }
                                }
                                (entities.join(", "), etype, cross)
                            } else {
                                (p.to_string(), String::new(), "No".to_string())
                            }
                        }
                    };

                    // Extract External ID
                    let external_id = stmt.get("Condition")
                        .and_then(|c| c.get("StringEquals").or_else(|| c.get("StringLike")))
                        .and_then(|se| se.get("sts:ExternalId"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();

                    // Conditions summary: join condition keys
                    let conditions = stmt.get("Condition")
                        .and_then(|c| c.as_object())
                        .map(|obj| obj.keys().cloned().collect::<Vec<_>>().join(", "))
                        .unwrap_or_default();

                    rows.push(vec![
                        role_name.clone(),
                        trusted_entity,
                        entity_type,
                        external_id,
                        conditions,
                        cross_account,
                    ]);
                }
            }

            if resp.is_truncated() {
                marker = resp.marker().map(|s| s.to_string());
            } else {
                break;
            }
        }

        Ok(rows)
    }
}
