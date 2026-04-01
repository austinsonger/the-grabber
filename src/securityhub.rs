use anyhow::Result;
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

        let compliance_filter = StringFilter::builder()
            .value("FAILED")
            .comparison(StringFilterComparison::Equals)
            .build();

        let record_filter = StringFilter::builder()
            .value("ACTIVE")
            .comparison(StringFilterComparison::Equals)
            .build();

        let filters = AwsSecurityFindingFilters::builder()
            .compliance_status(compliance_filter)
            .record_state(record_filter)
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
                    .map(|s| s.to_string())
                    .or_else(|| {
                        finding.generator_id()
                            .and_then(|gid| gid.rsplit('/').next())
                            .map(|s| s.to_string())
                    })
                    .unwrap_or_default();

                let severity = finding.severity()
                    .and_then(|s| s.label())
                    .map(|l| l.as_str().to_string())
                    .unwrap_or_default();

                let compliance_status = finding.compliance()
                    .and_then(|c| c.status())
                    .map(|s| s.as_str().to_string())
                    .unwrap_or_default();

                let resource_arn = finding.resources()
                    .first()
                    .and_then(|r| r.id())
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
