use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_iam::Client as IamClient;

use crate::evidence::CsvCollector;

// ---------------------------------------------------------------------------
// IAM Policies (customer-managed)
// ---------------------------------------------------------------------------

pub struct IamPolicyCollector {
    client: IamClient,
}

impl IamPolicyCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: IamClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for IamPolicyCollector {
    fn name(&self) -> &str {
        "IAM Policies"
    }
    fn filename_prefix(&self) -> &str {
        "IAM_Policies"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Policy Name",
            "ARN",
            "Policy Type",
            "Attached Entities",
            "Permissions Summary",
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

        // Only customer-managed policies to avoid thousands of AWS-managed rows.
        loop {
            let mut req = self
                .client
                .list_policies()
                .scope(aws_sdk_iam::types::PolicyScopeType::Local);
            if let Some(ref m) = marker {
                req = req.marker(m);
            }
            let resp = req.send().await.context("IAM list_policies")?;

            for policy in resp.policies() {
                let name = policy.policy_name().unwrap_or("").to_string();
                let arn = policy.arn().unwrap_or("").to_string();
                let policy_type = "Customer Managed".to_string();
                let attached = policy
                    .attachment_count()
                    .map(|n| n.to_string())
                    .unwrap_or_default();
                let default_ver = policy.default_version_id().unwrap_or("").to_string();

                let perms_summary = if !arn.is_empty() && !default_ver.is_empty() {
                    match self
                        .client
                        .get_policy_version()
                        .policy_arn(&arn)
                        .version_id(&default_ver)
                        .send()
                        .await
                    {
                        Ok(r) => {
                            let doc = r
                                .policy_version()
                                .and_then(|v| v.document())
                                .map(|d| super::url_decode(d))
                                .unwrap_or_default();
                            // Extract actions from policy document (very rough summary).
                            super::summarize_policy_actions(&doc)
                        }
                        Err(_) => "".to_string(),
                    }
                } else {
                    "".to_string()
                };

                rows.push(vec![name, arn, policy_type, attached, perms_summary]);
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
