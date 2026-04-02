use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_securityhub::Client as ShClient;

use crate::evidence::CsvCollector;

pub struct SecurityHubStandardsCollector {
    client: ShClient,
}

impl SecurityHubStandardsCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: ShClient::new(config) }
    }
}

/// Extract a human-readable name from a standards ARN.
/// e.g. "arn:aws:securityhub:::standards/aws-foundational-security-best-practices/v/1.0.0"
/// → "aws-foundational-security-best-practices v1.0.0"
fn standard_name_from_arn(arn: &str) -> String {
    // Find "standards/" in the ARN and take the rest
    if let Some(pos) = arn.find("standards/") {
        let after = &arn[pos + "standards/".len()..];
        // after looks like "aws-foundational-security-best-practices/v/1.0.0"
        let parts: Vec<&str> = after.splitn(3, '/').collect();
        match parts.as_slice() {
            [name, _, version] => format!("{} v{}", name, version),
            [name, version] => format!("{} {}", name, version),
            [name] => name.to_string(),
            _ => after.to_string(),
        }
    } else {
        arn.to_string()
    }
}

#[async_trait]
impl CsvCollector for SecurityHubStandardsCollector {
    fn name(&self) -> &str { "Security Hub Enabled Standards" }
    fn filename_prefix(&self) -> &str { "SecurityHub_Standards" }
    fn headers(&self) -> &'static [&'static str] {
        &["Standard Name", "Standards ARN", "Status", "Subscribed At"]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut next_token: Option<String> = None;

        loop {
            let mut req = self.client.get_enabled_standards();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: SecurityHub get_enabled_standards: {e:#}");
                    break;
                }
            };

            for sub in resp.standards_subscriptions() {
                let standards_arn = sub.standards_arn().unwrap_or("").to_string();
                let standard_name = standard_name_from_arn(&standards_arn);
                let status = sub.standards_status()
                    .map(|s| s.as_str().to_string())
                    .unwrap_or_default();
                let subscribed_at = sub.standards_subscription_arn()
                    .unwrap_or("")
                    .to_string();

                rows.push(vec![
                    standard_name,
                    standards_arn,
                    status,
                    subscribed_at,
                ]);
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() { break; }
        }

        Ok(rows)
    }
}
