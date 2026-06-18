use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_fms::Client as FmsClient;

use crate::evidence::CsvCollector;

pub struct FmsPoliciesCollector {
    client: FmsClient,
}

impl FmsPoliciesCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: FmsClient::new(config),
        }
    }
}

fn is_benign(err: &str) -> bool {
    err.contains("AccessDenied")
        || err.contains("AccessDeniedException")
        || err.contains("UnauthorizedOperation")
        || err.contains("InvalidOperationException")
        || err.contains("not available")
        || err.contains("UnknownEndpoint")
        || err.contains("dispatch failure")
        || err.contains("ResourceNotFoundException")
}

#[async_trait]
impl CsvCollector for FmsPoliciesCollector {
    fn name(&self) -> &str {
        "Firewall Manager Policies"
    }
    fn filename_prefix(&self) -> &str {
        "FirewallManager_Policies"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Policy ID",
            "Name",
            "Resource Type",
            "Security Service Type",
            "Remediation Enabled",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows: Vec<Vec<String>> = Vec::new();

        let mut paginator = self.client.list_policies().into_paginator().send();
        while let Some(page) = paginator.next().await {
            let resp = match page {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e:#}");
                    if is_benign(&msg) {
                        return Ok(rows);
                    }
                    eprintln!("  WARN: FMS list_policies: {msg}");
                    break;
                }
            };
            for p in resp.policy_list() {
                let id = p.policy_id().unwrap_or("").to_string();
                let name = p.policy_name().unwrap_or("").to_string();
                let resource_type = p.resource_type().unwrap_or("").to_string();
                let svc_type = p
                    .security_service_type()
                    .map(|s| s.as_str().to_string())
                    .unwrap_or_default();
                let remediation = p.remediation_enabled().to_string();
                rows.push(vec![id, name, resource_type, svc_type, remediation]);
            }
        }

        Ok(rows)
    }
}
