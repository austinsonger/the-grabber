use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_iam::Client as IamClient;

use crate::evidence::CsvCollector;

// ---------------------------------------------------------------------------
// IAM Access Keys
// ---------------------------------------------------------------------------

pub struct IamAccessKeyCollector {
    client: IamClient,
}

impl IamAccessKeyCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: IamClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for IamAccessKeyCollector {
    fn name(&self) -> &str {
        "IAM Access Keys"
    }
    fn filename_prefix(&self) -> &str {
        "IAM_Access_Keys"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "User Name",
            "Access Key ID",
            "Status",
            "Created Date",
            "Last Used",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        // Collect all usernames first.
        let mut user_names: Vec<String> = Vec::new();
        let mut marker: Option<String> = None;
        loop {
            let mut req = self.client.list_users();
            if let Some(ref m) = marker {
                req = req.marker(m);
            }
            let resp = req.send().await.context("IAM list_users (access keys)")?;
            for u in resp.users() {
                user_names.push(u.user_name().to_string());
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

        // Fetch access keys for each user.
        for user_name in &user_names {
            let key_resp = match self
                .client
                .list_access_keys()
                .user_name(user_name)
                .send()
                .await
            {
                Ok(r) => r,
                Err(_) => continue,
            };

            for key_meta in key_resp.access_key_metadata() {
                let key_id = key_meta.access_key_id().unwrap_or("").to_string();
                let status = key_meta
                    .status()
                    .map(|s| s.as_str())
                    .unwrap_or("")
                    .to_string();
                let created = key_meta
                    .create_date()
                    .map(|d| super::fmt_iam_dt(d))
                    .unwrap_or_default();

                let last_used = match self
                    .client
                    .get_access_key_last_used()
                    .access_key_id(&key_id)
                    .send()
                    .await
                {
                    Ok(r) => r
                        .access_key_last_used()
                        .and_then(|l| l.last_used_date())
                        .map(|d| super::fmt_iam_dt(d))
                        .unwrap_or_else(|| "Never".to_string()),
                    Err(_) => "".to_string(),
                };

                rows.push(vec![user_name.clone(), key_id, status, created, last_used]);
            }
        }

        Ok(rows)
    }
}
