use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_rolesanywhere::Client as RolesAnywhereClient;

use crate::evidence::CsvCollector;

pub struct IamRolesAnywhereCollector {
    client: RolesAnywhereClient,
}

impl IamRolesAnywhereCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: RolesAnywhereClient::new(config),
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

fn truncate(s: &str, max_chars: usize) -> String {
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
        let t: String = single.chars().take(max_chars).collect();
        format!("{t}…")
    } else {
        single
    }
}

#[async_trait]
impl CsvCollector for IamRolesAnywhereCollector {
    fn name(&self) -> &str {
        "IAM Roles Anywhere"
    }
    fn filename_prefix(&self) -> &str {
        "IAM_RolesAnywhere"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Type",
            "ID",
            "Name",
            "Enabled",
            "Source / Role ARNs",
            "Notification / Session Policy",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows: Vec<Vec<String>> = Vec::new();

        // Trust anchors (paginated).
        let mut ta_paginator = self.client.list_trust_anchors().into_paginator().send();
        while let Some(page) = ta_paginator.next().await {
            let resp = match page {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e:#}");
                    if is_benign(&msg) {
                        return Ok(rows);
                    }
                    eprintln!("  WARN: RolesAnywhere list_trust_anchors: {msg}");
                    break;
                }
            };
            for ta in resp.trust_anchors() {
                let id = ta.trust_anchor_id().unwrap_or("").to_string();
                let name = ta.name().unwrap_or("").to_string();
                let enabled = ta.enabled().map(|b| b.to_string()).unwrap_or_default();
                let source = ta
                    .source()
                    .and_then(|s| s.source_type())
                    .map(|st| st.as_str().to_string())
                    .unwrap_or_default();
                let notif_count = ta.notification_settings().len().to_string();
                rows.push(vec![
                    "TrustAnchor".to_string(),
                    id,
                    name,
                    enabled,
                    source,
                    notif_count,
                ]);
            }
        }

        // Profiles (paginated).
        let mut p_paginator = self.client.list_profiles().into_paginator().send();
        while let Some(page) = p_paginator.next().await {
            let resp = match page {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e:#}");
                    if is_benign(&msg) {
                        return Ok(rows);
                    }
                    eprintln!("  WARN: RolesAnywhere list_profiles: {msg}");
                    break;
                }
            };
            for p in resp.profiles() {
                let id = p.profile_id().unwrap_or("").to_string();
                let name = p.name().unwrap_or("").to_string();
                let enabled = p.enabled().map(|b| b.to_string()).unwrap_or_default();
                let role_arns = p.role_arns().join(", ");
                let session_policy = p
                    .session_policy()
                    .map(|s| truncate(s, 500))
                    .unwrap_or_default();
                rows.push(vec![
                    "Profile".to_string(),
                    id,
                    name,
                    enabled,
                    role_arns,
                    session_policy,
                ]);
            }
        }

        Ok(rows)
    }
}
