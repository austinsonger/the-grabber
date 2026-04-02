use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_organizations::Client as OrgClient;
use aws_sdk_organizations::types::PolicyType;

use crate::evidence::CsvCollector;

pub struct OrganizationsSCPCollector {
    client: OrgClient,
}

impl OrganizationsSCPCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: OrgClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for OrganizationsSCPCollector {
    fn name(&self) -> &str { "Organizations Service Control Policies" }
    fn filename_prefix(&self) -> &str { "Organizations_SCPs" }
    fn headers(&self) -> &'static [&'static str] {
        &["Policy Name", "Policy ID", "Attached Targets", "AWS Managed", "Actions Summary"]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut next_token: Option<String> = None;

        // list_policies with SCP filter
        let first_resp = self.client
            .list_policies()
            .filter(PolicyType::ServiceControlPolicy)
            .send()
            .await;

        match first_resp {
            Err(e) => {
                let msg = format!("{e:#}");
                if msg.contains("AccessDeniedException") || msg.contains("AWSOrganizationsNotInUseException") {
                    eprintln!("  WARN: Organizations list_policies: {msg}");
                    return Ok(rows);
                }
                return Err(e).context("Organizations list_policies");
            }
            Ok(resp) => {
                let policies: Vec<(String, String, bool)> = resp.policies().iter().map(|p| {
                    let name = p.name().unwrap_or("").to_string();
                    let id = p.id().unwrap_or("").to_string();
                    let aws_managed = p.aws_managed();
                    (name, id, aws_managed)
                }).collect();

                next_token = resp.next_token().map(|s| s.to_string());

                for (name, id, aws_managed) in policies {
                    let row = self.build_policy_row(&name, &id, aws_managed).await;
                    rows.push(row);
                }
            }
        }

        loop {
            if next_token.is_none() { break; }
            let mut req = self.client
                .list_policies()
                .filter(PolicyType::ServiceControlPolicy);
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: Organizations list_policies page: {e:#}");
                    break;
                }
            };

            let policies: Vec<(String, String, bool)> = resp.policies().iter().map(|p| {
                let name = p.name().unwrap_or("").to_string();
                let id = p.id().unwrap_or("").to_string();
                let aws_managed = p.aws_managed();
                (name, id, aws_managed)
            }).collect();

            next_token = resp.next_token().map(|s| s.to_string());

            for (name, id, aws_managed) in policies {
                let row = self.build_policy_row(&name, &id, aws_managed).await;
                rows.push(row);
            }
        }

        Ok(rows)
    }
}

impl OrganizationsSCPCollector {
    async fn build_policy_row(&self, name: &str, id: &str, aws_managed: bool) -> Vec<String> {
        // Get attached targets
        let targets_str = match self.client
            .list_targets_for_policy()
            .policy_id(id)
            .send()
            .await
        {
            Ok(resp) => {
                let names: Vec<String> = resp.targets().iter()
                    .take(10)
                    .map(|t| t.name().unwrap_or("").to_string())
                    .collect();
                names.join(", ")
            }
            Err(e) => {
                eprintln!("  WARN: Organizations list_targets_for_policy {id}: {e:#}");
                String::new()
            }
        };

        // Get policy content and extract deny actions
        let actions_summary = match self.client
            .describe_policy()
            .policy_id(id)
            .send()
            .await
        {
            Ok(resp) => {
                let content = resp.policy()
                    .and_then(|p| p.content())
                    .unwrap_or("");
                extract_deny_actions(content)
            }
            Err(e) => {
                eprintln!("  WARN: Organizations describe_policy {id}: {e:#}");
                String::new()
            }
        };

        vec![
            name.to_string(),
            id.to_string(),
            targets_str,
            aws_managed.to_string(),
            actions_summary,
        ]
    }
}

fn extract_deny_actions(content: &str) -> String {
    if content.is_empty() {
        return String::new();
    }
    let parsed: serde_json::Value = match serde_json::from_str(content) {
        Ok(v) => v,
        Err(_) => return String::new(),
    };
    let mut deny_actions: Vec<String> = Vec::new();
    if let Some(stmts) = parsed.get("Statement").and_then(|s| s.as_array()) {
        for stmt in stmts {
            let effect = stmt.get("Effect").and_then(|e| e.as_str()).unwrap_or("");
            if effect.eq_ignore_ascii_case("Deny") {
                if let Some(action) = stmt.get("Action") {
                    if let Some(arr) = action.as_array() {
                        for a in arr.iter().take(3) {
                            if let Some(s) = a.as_str() {
                                deny_actions.push(s.to_string());
                            }
                        }
                    } else if let Some(s) = action.as_str() {
                        deny_actions.push(s.to_string());
                    }
                }
                if deny_actions.len() >= 3 {
                    break;
                }
            }
        }
    }
    deny_actions.join(", ")
}
