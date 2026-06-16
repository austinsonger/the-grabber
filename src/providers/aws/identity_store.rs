use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_identitystore::Client as IdsClient;
use aws_sdk_ssoadmin::Client as SsoAdminClient;

use crate::evidence::CsvCollector;

// ══════════════════════════════════════════════════════════════════════════════
// AWS Identity Store (SSO) — Users, Groups, and Group Memberships
// ══════════════════════════════════════════════════════════════════════════════

pub struct IdentityStoreCollector {
    sso_admin: SsoAdminClient,
    ids: IdsClient,
}

impl IdentityStoreCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            sso_admin: SsoAdminClient::new(config),
            ids: IdsClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for IdentityStoreCollector {
    fn name(&self) -> &str {
        "Identity Store Users & Groups"
    }
    fn filename_prefix(&self) -> &str {
        "IdentityStore_Users_Groups"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Identity Store ID",
            "Type",
            "ID",
            "User/Group Name",
            "Display Name",
            "Email",
            "Group Memberships",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows: Vec<Vec<String>> = Vec::new();

        // 1. Discover Identity Store IDs via SSO Admin instances.
        let mut store_ids: Vec<String> = Vec::new();
        let mut inst_paginator = self.sso_admin.list_instances().into_paginator().send();
        while let Some(page) = inst_paginator.next().await {
            let resp = match page {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: Identity Store list_instances: {e:#}");
                    return Ok(rows);
                }
            };
            for inst in resp.instances() {
                if let Some(id) = inst.identity_store_id() {
                    store_ids.push(id.to_string());
                }
            }
        }

        if store_ids.is_empty() {
            return Ok(rows);
        }

        for store_id in &store_ids {
            // 2. List users.
            let mut user_paginator = self
                .ids
                .list_users()
                .identity_store_id(store_id)
                .into_paginator()
                .send();
            while let Some(page) = user_paginator.next().await {
                let resp = match page {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("  WARN: Identity Store list_users [{store_id}]: {e:#}");
                        break;
                    }
                };
                for u in resp.users() {
                    let email = u
                        .emails()
                        .iter()
                        .find_map(|e| e.value().map(|v| v.to_string()))
                        .unwrap_or_default();
                    rows.push(vec![
                        store_id.clone(),
                        "User".to_string(),
                        u.user_id().to_string(),
                        u.user_name().unwrap_or("").to_string(),
                        u.display_name().unwrap_or("").to_string(),
                        email,
                        String::new(),
                    ]);
                }
            }

            // 3. List groups; for each, collect member IDs.
            let mut group_ids_seen: Vec<(String, String)> = Vec::new(); // (group_id, display_name)
            let mut group_paginator = self
                .ids
                .list_groups()
                .identity_store_id(store_id)
                .into_paginator()
                .send();
            while let Some(page) = group_paginator.next().await {
                let resp = match page {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("  WARN: Identity Store list_groups [{store_id}]: {e:#}");
                        break;
                    }
                };
                for g in resp.groups() {
                    group_ids_seen.push((
                        g.group_id().to_string(),
                        g.display_name().unwrap_or("").to_string(),
                    ));
                }
            }

            for (group_id, display_name) in &group_ids_seen {
                let mut member_ids: Vec<String> = Vec::new();
                let mut mem_paginator = self
                    .ids
                    .list_group_memberships()
                    .identity_store_id(store_id)
                    .group_id(group_id)
                    .into_paginator()
                    .send();
                while let Some(page) = mem_paginator.next().await {
                    let resp = match page {
                        Ok(r) => r,
                        Err(e) => {
                            eprintln!(
                                "  WARN: Identity Store list_group_memberships [{group_id}]: {e:#}"
                            );
                            break;
                        }
                    };
                    for m in resp.group_memberships() {
                        if let Some(mid) = m.member_id() {
                            if let Ok(uid) = mid.as_user_id() {
                                member_ids.push(uid.clone());
                            }
                        }
                    }
                }

                rows.push(vec![
                    store_id.clone(),
                    "Group".to_string(),
                    group_id.clone(),
                    display_name.clone(),
                    display_name.clone(),
                    String::new(),
                    member_ids.join(";"),
                ]);
            }
        }

        Ok(rows)
    }
}
