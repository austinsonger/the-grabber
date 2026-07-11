use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_ssm::Client as SsmClient;

use crate::evidence::CsvCollector;

pub struct SsmPatchSummaryCollector {
    client: SsmClient,
}

impl SsmPatchSummaryCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: SsmClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for SsmPatchSummaryCollector {
    fn name(&self) -> &str {
        "SSM Patch Summary"
    }
    fn filename_prefix(&self) -> &str {
        "SSM_Patch_Summary"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Instance ID",
            "Compliance Status",
            "Critical Count",
            "Security Count",
            "Other Count",
            "Missing Count",
            "Installed Count",
            "Operation",
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
            let mut req = self.client.describe_instance_patch_states();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: SSM describe_instance_patch_states: {e:#}");
                    break;
                }
            };

            for state in resp.instance_patch_states() {
                let instance_id = state.instance_id().to_string();
                let missing = state.missing_count();
                let failed = state.failed_count();
                let compliance = if missing > 0 || failed > 0 {
                    "NON_COMPLIANT"
                } else {
                    "COMPLIANT"
                };
                let critical = state
                    .critical_non_compliant_count()
                    .unwrap_or(0)
                    .to_string();
                let security = state
                    .security_non_compliant_count()
                    .unwrap_or(0)
                    .to_string();
                let other = state.other_non_compliant_count().unwrap_or(0).to_string();
                let installed = state.installed_count().to_string();
                let operation = state.operation().as_str().to_string();

                rows.push(vec![
                    instance_id,
                    compliance.to_string(),
                    critical,
                    security,
                    other,
                    missing.to_string(),
                    installed,
                    operation,
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
