use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_ssm::Client as SsmClient;

use crate::evidence::CsvCollector;

fn fmt_ssm_dt(dt: &aws_sdk_ssm::primitives::DateTime) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(dt.secs(), 0)
        .map(|c| c.to_rfc3339())
        .unwrap_or_default()
}

pub struct SsmComplianceSummaryCollector {
    client: SsmClient,
}

impl SsmComplianceSummaryCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: SsmClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for SsmComplianceSummaryCollector {
    fn name(&self) -> &str {
        "SSM Compliance Summary"
    }
    fn filename_prefix(&self) -> &str {
        "SSM_Compliance_Summary"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Resource ID",
            "Resource Type",
            "Compliance Type",
            "Overall Severity",
            "Compliant Count",
            "Non-Compliant Count",
            "Last Execution Time",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut next_token: Option<String> = None;

        loop {
            let mut req = self.client.list_resource_compliance_summaries();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: SSM list_resource_compliance_summaries: {e:#}");
                    break;
                }
            };

            for item in resp.resource_compliance_summary_items() {
                let resource_id = item.resource_id().unwrap_or("").to_string();
                let resource_type = item.resource_type().unwrap_or("").to_string();
                let compliance_type = item.compliance_type().unwrap_or("").to_string();
                let severity = item
                    .overall_severity()
                    .map(|s| s.as_str().to_string())
                    .unwrap_or_default();
                let compliant_count = item
                    .compliant_summary()
                    .map(|s| s.compliant_count().to_string())
                    .unwrap_or_default();
                let non_compliant_count = item
                    .non_compliant_summary()
                    .map(|s| s.non_compliant_count().to_string())
                    .unwrap_or_default();
                let last_exec = item
                    .execution_summary()
                    .map(|s| fmt_ssm_dt(s.execution_time()))
                    .unwrap_or_default();

                rows.push(vec![
                    resource_id,
                    resource_type,
                    compliance_type,
                    severity,
                    compliant_count,
                    non_compliant_count,
                    last_exec,
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
