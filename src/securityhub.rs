use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_securityhub::Client as ShClient;
use aws_sdk_securityhub::types::{AwsSecurityFindingFilters, StringFilter, StringFilterComparison};

use crate::evidence::CsvCollector;

pub struct SecurityHubCollector {
    client: ShClient,
}

impl SecurityHubCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: ShClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for SecurityHubCollector {
    fn name(&self) -> &str { "Security Hub Findings" }
    fn filename_prefix(&self) -> &str { "SecurityHub_Findings" }
    fn headers(&self) -> &'static [&'static str] {
        &["Control ID", "Severity", "Compliance Status", "Resource ARN", "Region"]
    }

    async fn collect_rows(&self, _account_id: &str, region: &str) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        // Filter to FAILED compliance findings only.
        let filters = AwsSecurityFindingFilters::builder()
            .compliance_status(
                StringFilter::builder()
                    .value("FAILED")
                    .comparison(StringFilterComparison::Equals)
                    .build()?,
            )
            .record_state(
                StringFilter::builder()
                    .value("ACTIVE")
                    .comparison(StringFilterComparison::Equals)
                    .build()?,
            )
            .build();

        let mut next_token: Option<String> = None;

        loop {
            let mut req = self.client
                .get_findings()
                .filters(filters.clone())
                .max_results(100);
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: Security Hub get_findings: {e:#}");
                    break;
                }
            };

            for finding in resp.findings() {
                let control_id = finding.compliance()
                    .and_then(|c| c.security_control_id())
                    .or_else(|| {
                        // Fall back to extracting from generator_id.
                        finding.generator_id().rsplit('/').next()
                    })
                    .unwrap_or("")
                    .to_string();

                let severity = finding.severity()
                    .and_then(|s| s.label())
                    .map(|l| l.as_str())
                    .unwrap_or("")
                    .to_string();

                let compliance_status = finding.compliance()
                    .and_then(|c| c.status())
                    .map(|s| s.as_str())
                    .unwrap_or("")
                    .to_string();

                let resource_arn = finding.resources()
                    .first()
                    .map(|r| r.id())
                    .unwrap_or("")
                    .to_string();

                rows.push(vec![
                    control_id, severity, compliance_status,
                    resource_arn, region.to_string(),
                ]);
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() { break; }
        }

        Ok(rows)
    }
}
