use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_ssm::Client as SsmClient;

use crate::evidence::CsvCollector;

pub struct SsmPatchExecutionCollector {
    client: SsmClient,
}

impl SsmPatchExecutionCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: SsmClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for SsmPatchExecutionCollector {
    fn name(&self) -> &str {
        "SSM Patch Execution History"
    }
    fn filename_prefix(&self) -> &str {
        "SSM_Patch_Execution"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Command ID",
            "Instance ID",
            "Requested Date Time",
            "Completed Date Time",
            "Status",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        use aws_sdk_ssm::types::CommandFilterKey;

        let mut rows = Vec::new();
        let mut next_token: Option<String> = None;

        // Filter to patch-baseline run commands
        let filter = aws_sdk_ssm::types::CommandFilter::builder()
            .key(CommandFilterKey::DocumentName)
            .value("AWS-RunPatchBaseline")
            .build()
            .unwrap_or_else(|_| {
                aws_sdk_ssm::types::CommandFilter::builder()
                    .key(CommandFilterKey::DocumentName)
                    .value("AWS-RunPatchBaseline")
                    .build()
                    .expect("build CommandFilter")
            });

        loop {
            let mut req = self.client.list_commands().filters(filter.clone());
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: SSM list_commands: {e:#}");
                    break;
                }
            };

            for cmd in resp.commands() {
                let command_id = cmd.command_id().unwrap_or("").to_string();
                let requested_dt = cmd
                    .requested_date_time()
                    .map(|d| super::epoch_to_rfc3339(d.secs()))
                    .unwrap_or_default();
                let status = cmd
                    .status()
                    .map(|s| s.as_str().to_string())
                    .unwrap_or_default();
                let status_detail = cmd.status_details().unwrap_or("").to_string();
                // Instances: join the first few target instance IDs
                let instances: Vec<&str> = cmd.instance_ids().iter().map(|s| s.as_str()).collect();
                let instance_summary = if instances.is_empty() {
                    "N/A (targets)".to_string()
                } else {
                    instances.join(", ")
                };

                rows.push(vec![
                    command_id,
                    instance_summary,
                    requested_dt,
                    status_detail, // completed_date_time not directly available; use status_details
                    status,
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
