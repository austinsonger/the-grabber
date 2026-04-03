use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_wafv2::Client as WafClient;
use aws_sdk_wafv2::types::Scope;

use crate::evidence::CsvCollector;

pub struct WafLoggingCollector {
    client: WafClient,
}

impl WafLoggingCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: WafClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for WafLoggingCollector {
    fn name(&self) -> &str { "WAFv2 Logging Configuration" }
    fn filename_prefix(&self) -> &str { "WAF_Logging" }
    fn headers(&self) -> &'static [&'static str] {
        &["Web ACL Name", "Web ACL ARN", "Logging Enabled", "Log Destination", "Sampled Requests Enabled"]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str, _dates: Option<(i64, i64)>) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut next_marker: Option<String> = None;

        loop {
            let mut req = self.client
                .list_web_acls()
                .scope(Scope::Regional)
                .limit(100);
            if let Some(ref m) = next_marker {
                req = req.next_marker(m);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: WAFv2 list_web_acls: {e:#}");
                    break;
                }
            };

            for acl_summary in resp.web_acls() {
                let acl_name = acl_summary.name().unwrap_or("").to_string();
                let acl_arn = acl_summary.arn().unwrap_or("").to_string();

                // Try to get logging configuration
                let (logging_enabled, log_destination) = match self.client
                    .get_logging_configuration()
                    .resource_arn(&acl_arn)
                    .send()
                    .await
                {
                    Ok(resp) => {
                        let dest = resp.logging_configuration()
                            .and_then(|lc| lc.log_destination_configs().first())
                            .map(|d| d.to_string())
                            .unwrap_or_default();
                        ("Yes".to_string(), dest)
                    }
                    Err(e) => {
                        let msg = format!("{e}");
                        if msg.contains("WafNonexistentItemException") || msg.contains("WAFNonexistentItemException") {
                            ("No".to_string(), String::new())
                        } else {
                            eprintln!("  WARN: WAFv2 get_logging_configuration for {acl_name}: {e:#}");
                            ("Unknown".to_string(), String::new())
                        }
                    }
                };

                rows.push(vec![
                    acl_name,
                    acl_arn,
                    logging_enabled,
                    log_destination,
                    "N/A".to_string(),
                ]);
            }

            next_marker = resp.next_marker().map(|s| s.to_string());
            if next_marker.is_none() { break; }
        }

        Ok(rows)
    }
}
