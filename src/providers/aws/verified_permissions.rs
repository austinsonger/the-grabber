use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_verifiedpermissions::Client as VpClient;

use crate::evidence::CsvCollector;

pub struct VerifiedPermissionsCollector {
    client: VpClient,
}

impl VerifiedPermissionsCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: VpClient::new(config),
        }
    }
}

fn is_benign(err: &str) -> bool {
    err.contains("AccessDenied")
        || err.contains("AccessDeniedException")
        || err.contains("UnauthorizedOperation")
        || err.contains("not available")
        || err.contains("UnknownEndpoint")
        || err.contains("dispatch failure")
        || err.contains("ValidationException")
}

#[async_trait]
impl CsvCollector for VerifiedPermissionsCollector {
    fn name(&self) -> &str {
        "Verified Permissions"
    }
    fn filename_prefix(&self) -> &str {
        "VerifiedPermissions_Stores"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Policy Store ID",
            "Validation Mode",
            "Policy ID",
            "Policy Type",
            "Principal",
            "Resource",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows: Vec<Vec<String>> = Vec::new();

        let mut store_paginator = self.client.list_policy_stores().into_paginator().send();
        while let Some(page) = store_paginator.next().await {
            let resp = match page {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e:#}");
                    if is_benign(&msg) {
                        return Ok(rows);
                    }
                    eprintln!("  WARN: VerifiedPermissions list_policy_stores: {msg}");
                    break;
                }
            };
            for store in resp.policy_stores() {
                let store_id = store.policy_store_id().to_string();

                // Fetch store-level details for validation mode.
                let validation_mode = match self
                    .client
                    .get_policy_store()
                    .policy_store_id(&store_id)
                    .send()
                    .await
                {
                    Ok(s) => s
                        .validation_settings()
                        .map(|v| v.mode().as_str().to_string())
                        .unwrap_or_default(),
                    Err(e) => {
                        let msg = format!("{e:#}");
                        if is_benign(&msg) {
                            String::new()
                        } else {
                            eprintln!(
                                "  WARN: VerifiedPermissions get_policy_store({store_id}): {msg}"
                            );
                            String::new()
                        }
                    }
                };

                // Enumerate policies in store.
                let mut had_any = false;
                let mut p_paginator = self
                    .client
                    .list_policies()
                    .policy_store_id(&store_id)
                    .into_paginator()
                    .send();
                while let Some(page) = p_paginator.next().await {
                    let presp = match page {
                        Ok(r) => r,
                        Err(e) => {
                            let msg = format!("{e:#}");
                            if is_benign(&msg) {
                                break;
                            }
                            eprintln!(
                                "  WARN: VerifiedPermissions list_policies({store_id}): {msg}"
                            );
                            break;
                        }
                    };
                    for p in presp.policies() {
                        had_any = true;
                        let policy_id = p.policy_id().to_string();
                        let policy_type = p.policy_type().as_str().to_string();
                        let principal = p
                            .principal()
                            .map(|pr| format!("{}::{}", pr.entity_type(), pr.entity_id()))
                            .unwrap_or_default();
                        let resource = p
                            .resource()
                            .map(|r| format!("{}::{}", r.entity_type(), r.entity_id()))
                            .unwrap_or_default();
                        rows.push(vec![
                            store_id.clone(),
                            validation_mode.clone(),
                            policy_id,
                            policy_type,
                            principal,
                            resource,
                        ]);
                    }
                }

                if !had_any {
                    rows.push(vec![
                        store_id.clone(),
                        validation_mode.clone(),
                        String::new(),
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
