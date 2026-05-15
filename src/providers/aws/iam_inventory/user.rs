use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_iam::Client as IamClient;

use crate::evidence::CsvCollector;

// ---------------------------------------------------------------------------
// IAM Users
// ---------------------------------------------------------------------------

pub struct IamUserCollector {
    client: IamClient,
}

impl IamUserCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: IamClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for IamUserCollector {
    fn name(&self) -> &str {
        "IAM Users"
    }
    fn filename_prefix(&self) -> &str {
        "IAM_Users"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "User Name",
            "ARN",
            "MFA Enabled",
            "Password Last Used",
            "Access Key Status",
            "Created Date",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut marker: Option<String> = None;

        loop {
            let mut req = self.client.list_users();
            if let Some(ref m) = marker {
                req = req.marker(m);
            }
            let resp = req.send().await.context("IAM list_users")?;

            for user in resp.users() {
                let name = user.user_name().to_string();
                let arn = user.arn().to_string();
                let created = super::fmt_iam_dt(user.create_date());
                let pw_last = user
                    .password_last_used()
                    .map(super::fmt_iam_dt)
                    .unwrap_or_else(|| "Never".to_string());

                let mfa_enabled = match self.client.list_mfa_devices().user_name(&name).send().await
                {
                    Ok(r) => if r.mfa_devices().is_empty() {
                        "No"
                    } else {
                        "Yes"
                    }
                    .to_string(),
                    Err(_) => "".to_string(),
                };

                let key_status = match self.client.list_access_keys().user_name(&name).send().await
                {
                    Ok(r) => {
                        let statuses: Vec<String> = r
                            .access_key_metadata()
                            .iter()
                            .map(|k| k.status().map(|s| s.as_str()).unwrap_or("").to_string())
                            .collect();
                        statuses.join(", ")
                    }
                    Err(_) => "".to_string(),
                };

                rows.push(vec![name, arn, mfa_enabled, pw_last, key_status, created]);
            }

            marker = if resp.is_truncated() {
                resp.marker().map(|s| s.to_string())
            } else {
                None
            };
            if marker.is_none() {
                break;
            }
        }

        Ok(rows)
    }
}
