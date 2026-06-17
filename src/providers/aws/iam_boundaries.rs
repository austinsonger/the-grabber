use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_iam::Client as IamClient;

use crate::evidence::CsvCollector;

pub struct IamBoundariesCollector {
    client: IamClient,
}

impl IamBoundariesCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: IamClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for IamBoundariesCollector {
    fn name(&self) -> &str {
        "IAM Permissions Boundaries"
    }
    fn filename_prefix(&self) -> &str {
        "IAM_Boundaries"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Principal Type",
            "Principal ARN",
            "Has Boundary",
            "Boundary Policy ARN",
            "Boundary Type",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows: Vec<Vec<String>> = Vec::new();

        // Users (paginated).
        let mut user_token: Option<String> = None;
        loop {
            let mut req = self.client.list_users();
            if let Some(t) = user_token.as_ref() {
                req = req.marker(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: IAM list_users: {e:#}");
                    break;
                }
            };
            for u in resp.users() {
                let arn = u.arn().to_string();
                let (has, boundary_arn, btype) = match u.permissions_boundary() {
                    Some(b) => (
                        "Yes".to_string(),
                        b.permissions_boundary_arn()
                            .map(|s| s.to_string())
                            .unwrap_or_default(),
                        b.permissions_boundary_type()
                            .map(|t| t.as_str().to_string())
                            .unwrap_or_default(),
                    ),
                    None => ("No".to_string(), String::new(), String::new()),
                };
                rows.push(vec!["User".to_string(), arn, has, boundary_arn, btype]);
            }
            if resp.is_truncated() {
                user_token = resp.marker().map(|s| s.to_string());
                if user_token.is_none() {
                    break;
                }
            } else {
                break;
            }
        }

        // Roles (paginated). Skip service-linked roles.
        let mut role_token: Option<String> = None;
        loop {
            let mut req = self.client.list_roles();
            if let Some(t) = role_token.as_ref() {
                req = req.marker(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: IAM list_roles: {e:#}");
                    break;
                }
            };
            for r in resp.roles() {
                let arn = r.arn().to_string();
                if arn.contains(":role/aws-service-role/") {
                    continue;
                }
                let (has, boundary_arn, btype) = match r.permissions_boundary() {
                    Some(b) => (
                        "Yes".to_string(),
                        b.permissions_boundary_arn()
                            .map(|s| s.to_string())
                            .unwrap_or_default(),
                        b.permissions_boundary_type()
                            .map(|t| t.as_str().to_string())
                            .unwrap_or_default(),
                    ),
                    None => ("No".to_string(), String::new(), String::new()),
                };
                rows.push(vec!["Role".to_string(), arn, has, boundary_arn, btype]);
            }
            if resp.is_truncated() {
                role_token = resp.marker().map(|s| s.to_string());
                if role_token.is_none() {
                    break;
                }
            } else {
                break;
            }
        }

        Ok(rows)
    }
}
