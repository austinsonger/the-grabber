use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_organizations::types::PolicyType;
use aws_sdk_organizations::Client as OrgClient;
use std::collections::HashMap;

use crate::evidence::CsvCollector;

pub struct ScpAttachmentsCollector {
    client: OrgClient,
}

impl ScpAttachmentsCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: OrgClient::new(config),
        }
    }
}

fn is_benign(err: &str) -> bool {
    err.contains("AWSOrganizationsNotInUseException")
        || err.contains("AccessDenied")
        || err.contains("AccessDeniedException")
        || err.contains("not in use")
        || err.contains("PolicyTypeNotEnabled")
}

#[async_trait]
impl CsvCollector for ScpAttachmentsCollector {
    fn name(&self) -> &str {
        "SCP Attachments"
    }
    fn filename_prefix(&self) -> &str {
        "SCP_Attachments"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "SCP ID",
            "SCP Name",
            "Target ID",
            "Target Type",
            "Target Name",
            "OU Path",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        // Get the root ID once (used to terminate the OU walk).
        let root_id: Option<String> = match self.client.list_roots().send().await {
            Ok(resp) => resp
                .roots()
                .first()
                .and_then(|r| r.id())
                .map(|s| s.to_string()),
            Err(e) => {
                let msg = format!("{e:#}");
                if is_benign(&msg) {
                    return Ok(rows);
                }
                eprintln!("  WARN: Organizations list_roots: {e:#}");
                None
            }
        };

        // List all SCPs.
        let mut policies: Vec<(String, String)> = Vec::new();
        let mut next_token: Option<String> = None;
        loop {
            let mut req = self
                .client
                .list_policies()
                .filter(PolicyType::ServiceControlPolicy);
            if let Some(t) = next_token.as_ref() {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e:#}");
                    if is_benign(&msg) {
                        return Ok(rows);
                    }
                    eprintln!("  WARN: Organizations list_policies(SCP): {e:#}");
                    return Ok(rows);
                }
            };
            for p in resp.policies() {
                let id = p.id().unwrap_or("").to_string();
                let name = p.name().unwrap_or("").to_string();
                if !id.is_empty() {
                    policies.push((id, name));
                }
            }
            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() {
                break;
            }
        }

        // Cache for OU path lookups: target_id -> "Root/OU1/OU2".
        let mut ou_path_cache: HashMap<String, String> = HashMap::new();
        // Cache for OU names: ou_id -> name.
        let mut ou_name_cache: HashMap<String, String> = HashMap::new();

        for (policy_id, policy_name) in &policies {
            let mut t_token: Option<String> = None;
            loop {
                let mut req = self.client.list_targets_for_policy().policy_id(policy_id);
                if let Some(t) = t_token.as_ref() {
                    req = req.next_token(t);
                }
                let resp = match req.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!(
                            "  WARN: Organizations list_targets_for_policy [{policy_id}]: {e:#}"
                        );
                        break;
                    }
                };
                for t in resp.targets() {
                    let tid = t.target_id().unwrap_or("").to_string();
                    let tname = t.name().unwrap_or("").to_string();
                    let ttype = t
                        .r#type()
                        .map(|x| x.as_str().to_string())
                        .unwrap_or_default();

                    let ou_path = if ttype == "ORGANIZATIONAL_UNIT" {
                        if let Some(p) = ou_path_cache.get(&tid) {
                            p.clone()
                        } else {
                            let p = self
                                .build_ou_path(&tid, root_id.as_deref(), &mut ou_name_cache)
                                .await;
                            ou_path_cache.insert(tid.clone(), p.clone());
                            p
                        }
                    } else {
                        String::new()
                    };

                    rows.push(vec![
                        policy_id.clone(),
                        policy_name.clone(),
                        tid,
                        ttype,
                        tname,
                        ou_path,
                    ]);
                }
                t_token = resp.next_token().map(|s| s.to_string());
                if t_token.is_none() {
                    break;
                }
            }
        }

        Ok(rows)
    }
}

impl ScpAttachmentsCollector {
    async fn ou_name(&self, ou_id: &str, cache: &mut HashMap<String, String>) -> String {
        if let Some(n) = cache.get(ou_id) {
            return n.clone();
        }
        let name = match self
            .client
            .describe_organizational_unit()
            .organizational_unit_id(ou_id)
            .send()
            .await
        {
            Ok(r) => r
                .organizational_unit()
                .and_then(|ou| ou.name())
                .unwrap_or("")
                .to_string(),
            Err(_) => String::new(),
        };
        cache.insert(ou_id.to_string(), name.clone());
        name
    }

    async fn build_ou_path(
        &self,
        start_id: &str,
        root_id: Option<&str>,
        name_cache: &mut HashMap<String, String>,
    ) -> String {
        // Walk up from start_id via list_parents until we hit a root.
        let mut chain: Vec<String> = Vec::new();
        // Resolve the name of the starting OU itself.
        let start_name = self.ou_name(start_id, name_cache).await;
        if !start_name.is_empty() {
            chain.push(start_name);
        }

        let mut current = start_id.to_string();
        for _ in 0..20 {
            let resp = match self.client.list_parents().child_id(&current).send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: Organizations list_parents [{current}]: {e:#}");
                    break;
                }
            };
            let parent = match resp.parents().first() {
                Some(p) => p,
                None => break,
            };
            let parent_id = parent.id().unwrap_or("").to_string();
            let parent_type = parent
                .r#type()
                .map(|x| x.as_str().to_string())
                .unwrap_or_default();

            if parent_type == "ROOT" {
                chain.push("Root".to_string());
                break;
            }
            if let Some(rid) = root_id {
                if parent_id == rid {
                    chain.push("Root".to_string());
                    break;
                }
            }
            if parent_id.is_empty() {
                break;
            }
            let pname = self.ou_name(&parent_id, name_cache).await;
            if !pname.is_empty() {
                chain.push(pname);
            }
            current = parent_id;
        }

        chain.reverse();
        chain.join("/")
    }
}
