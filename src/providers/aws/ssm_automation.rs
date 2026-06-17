use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_ssm::types::{AutomationExecutionFilter, AutomationExecutionFilterKey};
use aws_sdk_ssm::Client as SsmClient;

use crate::evidence::CsvCollector;

fn fmt_ssm_dt(dt: &aws_sdk_ssm::primitives::DateTime) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(dt.secs(), 0)
        .map(|c| c.to_rfc3339())
        .unwrap_or_default()
}

pub struct SsmAutomationCollector {
    client: SsmClient,
}

impl SsmAutomationCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: SsmClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for SsmAutomationCollector {
    fn name(&self) -> &str {
        "SSM Automation Executions"
    }
    fn filename_prefix(&self) -> &str {
        "SSM_Automation_Executions"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Execution ID",
            "Document Name",
            "Start Time",
            "End Time",
            "Status",
            "Executed By",
            "Target Resources",
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

        // Default to last 90 days.
        let cutoff = chrono::Utc::now() - chrono::Duration::days(90);
        let cutoff_str = cutoff.format("%Y-%m-%dT%H:%M:%SZ").to_string();

        let filter = match AutomationExecutionFilter::builder()
            .key(AutomationExecutionFilterKey::StartTimeAfter)
            .values(cutoff_str)
            .build()
        {
            Ok(f) => f,
            Err(e) => {
                eprintln!("  WARN: SSM AutomationExecutionFilter build: {e:#}");
                return Ok(rows);
            }
        };

        loop {
            let mut req = self
                .client
                .describe_automation_executions()
                .filters(filter.clone());
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: SSM describe_automation_executions: {e:#}");
                    break;
                }
            };

            for exec in resp.automation_execution_metadata_list() {
                let exec_id = exec.automation_execution_id().unwrap_or("").to_string();
                let doc_name = exec.document_name().unwrap_or("").to_string();
                let start_time = exec
                    .execution_start_time()
                    .map(fmt_ssm_dt)
                    .unwrap_or_default();
                let end_time = exec
                    .execution_end_time()
                    .map(fmt_ssm_dt)
                    .unwrap_or_default();
                let status = exec
                    .automation_execution_status()
                    .map(|s| s.as_str().to_string())
                    .unwrap_or_default();
                let executed_by = exec.executed_by().unwrap_or("").to_string();

                // Prefer single `target`; fall back to concatenating `targets`.
                let target_resources = if let Some(t) = exec.target() {
                    t.to_string()
                } else {
                    exec.targets()
                        .iter()
                        .map(|t| {
                            let key = t.key().unwrap_or("");
                            let values = t.values().join(",");
                            format!("{key}={values}")
                        })
                        .collect::<Vec<_>>()
                        .join(";")
                };

                rows.push(vec![
                    exec_id,
                    doc_name,
                    start_time,
                    end_time,
                    status,
                    executed_by,
                    target_resources,
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
