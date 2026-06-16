use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_ssoadmin::Client as SsoAdminClient;

use crate::evidence::CsvCollector;

// ══════════════════════════════════════════════════════════════════════════════
// AWS Identity Center (SSO) — Permission Sets and Account Assignments
// ══════════════════════════════════════════════════════════════════════════════

pub struct IdentityCenterCollector {
    client: SsoAdminClient,
}

impl IdentityCenterCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: SsoAdminClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for IdentityCenterCollector {
    fn name(&self) -> &str {
        "Identity Center Assignments"
    }
    fn filename_prefix(&self) -> &str {
        "IdentityCenter_Assignments"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Instance ARN",
            "Permission Set Name",
            "Permission Set ARN",
            "Session Duration",
            "Relay State",
            "Inline Policy Present",
            "Managed Policies",
            "Assigned Account ID",
            "Principal Type",
            "Principal ID",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows: Vec<Vec<String>> = Vec::new();

        // 1. List Identity Center instances. If none configured, return empty.
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
            // 2. List permission sets for this instance.
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
                // 3. Describe the permission set.
                let (ps_name, session_duration, relay_state) = match self
                    .client
                    .describe_permission_set()
                    .instance_arn(instance_arn)
                    .permission_set_arn(ps_arn)
                    .send()
                    .await
                {
                    Ok(resp) => match resp.permission_set() {
                        Some(ps) => (
                            ps.name().unwrap_or("").to_string(),
                            ps.session_duration().unwrap_or("").to_string(),
                            ps.relay_state().unwrap_or("").to_string(),
                        ),
                        None => (String::new(), String::new(), String::new()),
                    },
                    Err(e) => {
                        eprintln!(
                            "  WARN: Identity Center describe_permission_set [{ps_arn}]: {e:#}"
                        );
                        (String::new(), String::new(), String::new())
                    }
                };

                // 4. Managed policies attached to this permission set.
                let mut managed_policy_names: Vec<String> = Vec::new();
                let mut mp_paginator = self
                    .client
                    .list_managed_policies_in_permission_set()
                    .instance_arn(instance_arn)
                    .permission_set_arn(ps_arn)
                    .into_paginator()
                    .send();
                while let Some(page) = mp_paginator.next().await {
                    let resp = match page {
                        Ok(r) => r,
                        Err(e) => {
                            eprintln!(
                                "  WARN: Identity Center list_managed_policies_in_permission_set [{ps_arn}]: {e:#}"
                            );
                            break;
                        }
                    };
                    for p in resp.attached_managed_policies() {
                        if let Some(n) = p.name() {
                            managed_policy_names.push(n.to_string());
                        }
                    }
                }
                let managed_policies_csv = managed_policy_names.join(";");

                // 5. Inline policy presence (best-effort).
                let inline_present = match self
                    .client
                    .get_inline_policy_for_permission_set()
                    .instance_arn(instance_arn)
                    .permission_set_arn(ps_arn)
                    .send()
                    .await
                {
                    Ok(resp) => !resp.inline_policy().unwrap_or("").is_empty(),
                    Err(_) => false,
                };

                // 6. List accounts where this permission set is provisioned.
                let mut account_ids: Vec<String> = Vec::new();
                let mut acct_paginator = self
                    .client
                    .list_accounts_for_provisioned_permission_set()
                    .instance_arn(instance_arn)
                    .permission_set_arn(ps_arn)
                    .into_paginator()
                    .send();
                while let Some(page) = acct_paginator.next().await {
                    let resp = match page {
                        Ok(r) => r,
                        Err(e) => {
                            eprintln!(
                                "  WARN: Identity Center list_accounts_for_provisioned_permission_set [{ps_arn}]: {e:#}"
                            );
                            break;
                        }
                    };
                    for id in resp.account_ids() {
                        account_ids.push(id.to_string());
                    }
                }

                // 7. For each account, list the (principal, permission set) assignments.
                let mut emitted_any = false;
                for acct_id in &account_ids {
                    let mut asn_paginator = self
                        .client
                        .list_account_assignments()
                        .instance_arn(instance_arn)
                        .account_id(acct_id)
                        .permission_set_arn(ps_arn)
                        .into_paginator()
                        .send();
                    while let Some(page) = asn_paginator.next().await {
                        let resp = match page {
                            Ok(r) => r,
                            Err(e) => {
                                eprintln!(
                                    "  WARN: Identity Center list_account_assignments [{acct_id}/{ps_arn}]: {e:#}"
                                );
                                break;
                            }
                        };
                        for a in resp.account_assignments() {
                            let principal_type = a
                                .principal_type()
                                .map(|p| p.as_str().to_string())
                                .unwrap_or_default();
                            let principal_id = a.principal_id().unwrap_or("").to_string();
                            rows.push(vec![
                                instance_arn.clone(),
                                ps_name.clone(),
                                ps_arn.clone(),
                                session_duration.clone(),
                                relay_state.clone(),
                                inline_present.to_string(),
                                managed_policies_csv.clone(),
                                acct_id.clone(),
                                principal_type,
                                principal_id,
                            ]);
                            emitted_any = true;
                        }
                    }
                }

                // If permission set exists but has no assignments, still emit a row
                // showing the permission set configuration.
                if !emitted_any {
                    rows.push(vec![
                        instance_arn.clone(),
                        ps_name.clone(),
                        ps_arn.clone(),
                        session_duration.clone(),
                        relay_state.clone(),
                        inline_present.to_string(),
                        managed_policies_csv.clone(),
                        String::new(),
                        String::new(),
                        String::new(),
                    ]);
                }
            }
        }

        Ok(rows)
    }
}
