use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_ssoadmin::Client as SsoAdminClient;

use crate::evidence::CsvCollector;

pub struct IdentityCenterInlineCollector {
    client: SsoAdminClient,
}

impl IdentityCenterInlineCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: SsoAdminClient::new(config),
        }
    }
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
impl CsvCollector for IdentityCenterInlineCollector {
    fn name(&self) -> &str {
        "Identity Center Inline Policies"
    }
    fn filename_prefix(&self) -> &str {
        "IdentityCenter_InlinePolicies"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Permission Set ARN",
            "Permission Set Name",
            "Type",
            "Policy Name / Inline Content",
            "Policy Path",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows: Vec<Vec<String>> = Vec::new();

        // 1. List instances.
        let mut instance_arns: Vec<String> = Vec::new();
        let mut inst_paginator = self.client.list_instances().into_paginator().send();
        while let Some(page) = inst_paginator.next().await {
            let resp = match page {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: Identity Center list_instances: {e:#}");
                    return Ok(rows);
                }
            };
            for inst in resp.instances() {
                if let Some(arn) = inst.instance_arn() {
                    instance_arns.push(arn.to_string());
                }
            }
        }

        for instance_arn in &instance_arns {
            // 2. List permission sets.
            let mut permission_set_arns: Vec<String> = Vec::new();
            let mut ps_paginator = self
                .client
                .list_permission_sets()
                .instance_arn(instance_arn)
                .into_paginator()
                .send();
            while let Some(page) = ps_paginator.next().await {
                let resp = match page {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!(
                            "  WARN: Identity Center list_permission_sets [{instance_arn}]: {e:#}"
                        );
                        break;
                    }
                };
                for ps_arn in resp.permission_sets() {
                    permission_set_arns.push(ps_arn.to_string());
                }
            }

            for ps_arn in &permission_set_arns {
                // 3. Describe permission set for name.
                let ps_name = match self
                    .client
                    .describe_permission_set()
                    .instance_arn(instance_arn)
                    .permission_set_arn(ps_arn)
                    .send()
                    .await
                {
                    Ok(resp) => resp
                        .permission_set()
                        .and_then(|ps| ps.name())
                        .unwrap_or("")
                        .to_string(),
                    Err(e) => {
                        eprintln!(
                            "  WARN: Identity Center describe_permission_set [{ps_arn}]: {e:#}"
                        );
                        String::new()
                    }
                };

                // 4. Inline policy.
                match self
                    .client
                    .get_inline_policy_for_permission_set()
                    .instance_arn(instance_arn)
                    .permission_set_arn(ps_arn)
                    .send()
                    .await
                {
                    Ok(resp) => {
                        let inline = resp.inline_policy().unwrap_or("");
                        if !inline.is_empty() {
                            let content = truncate_single_line(inline, 2000);
                            rows.push(vec![
                                ps_arn.clone(),
                                ps_name.clone(),
                                "Inline".to_string(),
                                content,
                                String::new(),
                            ]);
                        }
                    }
                    Err(e) => {
                        let msg = format!("{e:#}");
                        if !msg.contains("ResourceNotFoundException") {
                            eprintln!(
                                "  WARN: Identity Center get_inline_policy_for_permission_set [{ps_arn}]: {msg}"
                            );
                        }
                    }
                }

                // 5. Customer-managed policy references (paginated).
                let mut cm_token: Option<String> = None;
                loop {
                    let mut req = self
                        .client
                        .list_customer_managed_policy_references_in_permission_set()
                        .instance_arn(instance_arn)
                        .permission_set_arn(ps_arn);
                    if let Some(t) = cm_token.as_ref() {
                        req = req.next_token(t);
                    }
                    let resp = match req.send().await {
                        Ok(r) => r,
                        Err(e) => {
                            eprintln!(
                                "  WARN: Identity Center list_customer_managed_policy_references_in_permission_set [{ps_arn}]: {e:#}"
                            );
                            break;
                        }
                    };
                    for cmp in resp.customer_managed_policy_references() {
                        let pname = cmp.name().to_string();
                        let ppath = cmp.path().unwrap_or("").to_string();
                        rows.push(vec![
                            ps_arn.clone(),
                            ps_name.clone(),
                            "CustomerManaged".to_string(),
                            pname,
                            ppath,
                        ]);
                    }
                    cm_token = resp.next_token().map(|s| s.to_string());
                    if cm_token.is_none() {
                        break;
                    }
                }
            }
        }

        Ok(rows)
    }
}
