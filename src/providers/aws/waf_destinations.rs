use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_wafv2::types::Scope;
use aws_sdk_wafv2::Client as WafClient;

use crate::evidence::CsvCollector;

pub struct WafDestinationsCollector {
    client: WafClient,
}

impl WafDestinationsCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: WafClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for WafDestinationsCollector {
    fn name(&self) -> &str {
        "WAF Logging Destinations"
    }
    fn filename_prefix(&self) -> &str {
        "WAF_LoggingDestinations_Sampled"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Web ACL Name",
            "Web ACL ARN",
            "Logging Enabled",
            "Log Destinations",
            "Redacted Fields Count",
            "Logging Filter Present",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut next_marker: Option<String> = None;

        loop {
            let mut req = self
                .client
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

                let (logging_enabled, destinations, redacted_count, filter_present) = match self
                    .client
                    .get_logging_configuration()
                    .resource_arn(&acl_arn)
                    .send()
                    .await
                {
                    Ok(resp) => {
                        if let Some(lc) = resp.logging_configuration() {
                            let dests = lc.log_destination_configs().join(" | ");
                            let redacted = lc.redacted_fields().len().to_string();
                            let filter = if lc.logging_filter().is_some() {
                                "Yes"
                            } else {
                                "No"
                            };
                            ("Yes".to_string(), dests, redacted, filter.to_string())
                        } else {
                            (
                                "No".to_string(),
                                String::new(),
                                "0".to_string(),
                                "No".to_string(),
                            )
                        }
                    }
                    Err(e) => {
                        let msg = format!("{e}");
                        if msg.contains("WafNonexistentItemException")
                            || msg.contains("WAFNonexistentItemException")
                        {
                            (
                                "No".to_string(),
                                String::new(),
                                "0".to_string(),
                                "No".to_string(),
                            )
                        } else {
                            eprintln!(
                                "  WARN: WAFv2 get_logging_configuration for {acl_name}: {e:#}"
                            );
                            (
                                "Unknown".to_string(),
                                String::new(),
                                "0".to_string(),
                                "No".to_string(),
                            )
                        }
                    }
                };

                rows.push(vec![
                    acl_name,
                    acl_arn,
                    logging_enabled,
                    destinations,
                    redacted_count,
                    filter_present,
                ]);
            }

            next_marker = resp.next_marker().map(|s| s.to_string());
            if next_marker.is_none() {
                break;
            }
        }

        Ok(rows)
    }
}
