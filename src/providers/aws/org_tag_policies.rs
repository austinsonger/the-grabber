use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_organizations::types::PolicyType;
use aws_sdk_organizations::Client as OrgClient;

use crate::evidence::CsvCollector;

pub struct OrgTagPoliciesCollector {
    client: OrgClient,
}

impl OrgTagPoliciesCollector {
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

fn truncate_single_line(s: &str, max_chars: usize) -> String {
    let single: String = s
        .chars()
        .map(|c| {
            if c == '\n' || c == '\r' || c == '\t' {
                ' '
            } else {
                c
            }
        })
        .collect();
    if single.chars().count() > max_chars {
        let truncated: String = single.chars().take(max_chars).collect();
        format!("{truncated}…")
    } else {
        single
    }
}

#[async_trait]
impl CsvCollector for OrgTagPoliciesCollector {
    fn name(&self) -> &str {
        "Organizations Tag Policies"
    }
    fn filename_prefix(&self) -> &str {
        "Org_Tag_Policies"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Policy ID",
            "Policy Name",
            "AWS Managed",
            "Target ID",
            "Target Name",
            "Target Type",
            "Content Excerpt",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        // List all tag policies.
        let mut policy_ids: Vec<(String, String, bool)> = Vec::new();
        let mut next_token: Option<String> = None;
        loop {
            let mut req = self.client.list_policies().filter(PolicyType::TagPolicy);
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
                    eprintln!("  WARN: Organizations list_policies(TAG_POLICY): {e:#}");
                    return Ok(rows);
                }
            };
            for p in resp.policies() {
                let id = p.id().unwrap_or("").to_string();
                let name = p.name().unwrap_or("").to_string();
                let aws_managed = p.aws_managed();
                if !id.is_empty() {
                    policy_ids.push((id, name, aws_managed));
                }
            }
            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() {
                break;
            }
        }

        for (policy_id, policy_name, aws_managed) in &policy_ids {
            // Fetch content excerpt.
            let content_excerpt = match self
                .client
                .describe_policy()
                .policy_id(policy_id)
                .send()
                .await
            {
                Ok(r) => r
                    .policy()
                    .and_then(|p| p.content())
                    .map(|c| truncate_single_line(c, 1000))
                    .unwrap_or_default(),
                Err(e) => {
                    eprintln!("  WARN: Organizations describe_policy [{policy_id}]: {e:#}");
                    String::new()
                }
            };

            // List targets.
            let mut targets: Vec<(String, String, String)> = Vec::new();
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
                    targets.push((tid, tname, ttype));
                }
                t_token = resp.next_token().map(|s| s.to_string());
                if t_token.is_none() {
                    break;
                }
            }

            if targets.is_empty() {
                rows.push(vec![
                    policy_id.clone(),
                    policy_name.clone(),
                    aws_managed.to_string(),
                    String::new(),
                    String::new(),
                    String::new(),
                    content_excerpt.clone(),
                ]);
            } else {
                for (tid, tname, ttype) in targets {
                    rows.push(vec![
                        policy_id.clone(),
                        policy_name.clone(),
                        aws_managed.to_string(),
                        tid,
                        tname,
                        ttype,
                        content_excerpt.clone(),
                    ]);
                }
            }
        }

        Ok(rows)
    }
}
