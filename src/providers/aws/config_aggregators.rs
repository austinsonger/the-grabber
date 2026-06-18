use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_config::Client as ConfigClient;

use crate::evidence::CsvCollector;

pub struct ConfigAggregatorsCollector {
    client: ConfigClient,
}

impl ConfigAggregatorsCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: ConfigClient::new(config),
        }
    }
}

fn is_benign(err: &str) -> bool {
    err.contains("AccessDenied")
        || err.contains("ResourceNotFoundException")
        || err.contains("not enabled")
}

#[async_trait]
impl CsvCollector for ConfigAggregatorsCollector {
    fn name(&self) -> &str {
        "Config Aggregators"
    }
    fn filename_prefix(&self) -> &str {
        "Config_Aggregators"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Aggregator Name",
            "Source Type",
            "Account / Region Count",
            "Org Aggregator",
            "ARN",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows: Vec<Vec<String>> = Vec::new();
        let mut next_token: Option<String> = None;

        loop {
            let mut req = self.client.describe_configuration_aggregators();
            if let Some(t) = next_token.as_ref() {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e:#}");
                    if is_benign(&msg) {
                        return Ok(rows);
                    }
                    eprintln!("  WARN: Config describe_configuration_aggregators: {e:#}");
                    break;
                }
            };

            for agg in resp.configuration_aggregators() {
                let name = agg
                    .configuration_aggregator_name()
                    .unwrap_or("")
                    .to_string();
                let arn = agg.configuration_aggregator_arn().unwrap_or("").to_string();

                let acct_sources = agg.account_aggregation_sources();
                let org_source = agg.organization_aggregation_source();

                let source_type = if !acct_sources.is_empty() {
                    "Accounts".to_string()
                } else if org_source.is_some() {
                    "Organization".to_string()
                } else {
                    String::new()
                };

                let acct_region_count = if let Some(first) = acct_sources.first() {
                    let acct_n = first.account_ids().len();
                    let region_n = first.aws_regions().len();
                    format!(
                        "{acct_n} accts / {region_n} regions (sources={})",
                        acct_sources.len()
                    )
                } else if let Some(o) = org_source {
                    let region_n = o.aws_regions().len();
                    format!("org / {region_n} regions / all={}", o.all_aws_regions())
                } else {
                    String::new()
                };

                let org_aggregator = if let Some(o) = org_source {
                    let role_present = if !o.role_arn().is_empty() {
                        "Yes"
                    } else {
                        "No"
                    };
                    format!("role={role_present}, all_regions={}", o.all_aws_regions())
                } else {
                    "None".to_string()
                };

                rows.push(vec![
                    name,
                    source_type,
                    acct_region_count,
                    org_aggregator,
                    arn,
                ]);
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() {
                break;
            }
        }

        Ok(rows)
    }
}
