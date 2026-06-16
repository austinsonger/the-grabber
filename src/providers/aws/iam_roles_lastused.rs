use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_iam::Client as IamClient;

use crate::evidence::CsvCollector;

pub struct IamRolesLastUsedCollector {
    client: IamClient,
}

impl IamRolesLastUsedCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: IamClient::new(config),
        }
    }
}

fn fmt_dt(dt: &aws_sdk_iam::primitives::DateTime) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(dt.secs(), dt.subsec_nanos())
        .map(|c| c.to_rfc3339())
        .unwrap_or_default()
}

fn days_since(dt: &aws_sdk_iam::primitives::DateTime) -> String {
    let now = chrono::Utc::now().timestamp();
    let delta = now - dt.secs();
    if delta < 0 {
        return String::new();
    }
    (delta / 86_400).to_string()
}

#[async_trait]
impl CsvCollector for IamRolesLastUsedCollector {
    fn name(&self) -> &str {
        "IAM Roles Last Used"
    }
    fn filename_prefix(&self) -> &str {
        "IAM_Roles_LastUsed"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Role Name",
            "ARN",
            "Created Date",
            "Last Used Date",
            "Last Used Region",
            "Days Since Last Use",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows: Vec<Vec<String>> = Vec::new();

        // 1. Page through all roles, skipping service-linked roles.
        let mut role_names: Vec<String> = Vec::new();
        let mut marker: Option<String> = None;
        loop {
            let mut req = self.client.list_roles();
            if let Some(ref m) = marker {
                req = req.marker(m);
            }
            let resp = req
                .send()
                .await
                .context("IAM list_roles (roles last used)")?;
            for r in resp.roles() {
                let arn = r.arn();
                if arn.contains(":role/aws-service-role/") {
                    continue;
                }
                role_names.push(r.role_name().to_string());
            }
            if resp.is_truncated() {
                marker = resp.marker().map(|s| s.to_string());
                if marker.is_none() {
                    break;
                }
            } else {
                break;
            }
        }

        // 2. For each role, GetRole to read RoleLastUsed.
        for name in &role_names {
            let resp = match self.client.get_role().role_name(name).send().await {
                Ok(r) => r,
                Err(e) => {
                    rows.push(vec![
                        name.clone(),
                        format!("# get_role failed: {}", e),
                        String::new(),
                        String::new(),
                        String::new(),
                        String::new(),
                    ]);
                    continue;
                }
            };

            let role = match resp.role() {
                Some(r) => r,
                None => continue,
            };

            let arn = role.arn().to_string();
            let created = fmt_dt(role.create_date());

            let (last_used, last_region, days) = match role.role_last_used() {
                Some(lu) => {
                    let lud = lu.last_used_date();
                    let date_str = lud.map(fmt_dt).unwrap_or_default();
                    let region_str = lu.region().unwrap_or("").to_string();
                    let days_str = lud.map(days_since).unwrap_or_default();
                    (date_str, region_str, days_str)
                }
                None => (String::new(), String::new(), String::new()),
            };

            rows.push(vec![
                role.role_name().to_string(),
                arn,
                created,
                last_used,
                last_region,
                days,
            ]);
        }

        Ok(rows)
    }
}
