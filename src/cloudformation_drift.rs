use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_cloudformation::Client as CfnClient;

use crate::evidence::CsvCollector;

pub struct CloudFormationDriftCollector {
    client: CfnClient,
}

impl CloudFormationDriftCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: CfnClient::new(config) }
    }
}

#[async_trait]
impl CsvCollector for CloudFormationDriftCollector {
    fn name(&self) -> &str { "CloudFormation Stack Drift" }
    fn filename_prefix(&self) -> &str { "CloudFormation_Drift" }
    fn headers(&self) -> &'static [&'static str] {
        &["Stack Name", "Stack Status", "Drift Status", "Last Drift Check",
          "Drifted Resource Count", "Resource Drifts"]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut next_token: Option<String> = None;

        loop {
            let mut req = self.client.describe_stacks();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: CloudFormation describe_stacks: {e:#}");
                    break;
                }
            };

            for stack in resp.stacks() {
                let stack_name   = stack.stack_name().unwrap_or("").to_string();
                let stack_status = stack.stack_status()
                    .map(|s| s.as_str().to_string())
                    .unwrap_or_default();

                let (drift_status, last_check) = if let Some(di) = stack.drift_information() {
                    let status = di.stack_drift_status()
                        .map(|s| s.as_str().to_string())
                        .unwrap_or_else(|| "NOT_CHECKED".to_string());
                    let check  = di.last_check_timestamp()
                        .map(|d| {
                            chrono::DateTime::<chrono::Utc>::from_timestamp(d.secs(), 0)
                                .map(|c| c.to_rfc3339())
                                .unwrap_or_default()
                        })
                        .unwrap_or_default();
                    (status, check)
                } else {
                    ("NOT_CHECKED".to_string(), String::new())
                };

                // If drifted, fetch resource-level drift details
                let (drifted_count, resource_drifts_summary) = if drift_status == "DRIFTED" {
                    match self.client
                        .describe_stack_resource_drifts()
                        .stack_name(&stack_name)
                        .send()
                        .await
                    {
                        Ok(r) => {
                            let drifts: Vec<String> = r.stack_resource_drifts()
                                .iter()
                                .map(|d| {
                                    let lid    = d.logical_resource_id().unwrap_or("");
                                    let rtype  = d.resource_type().unwrap_or("?");
                                    let status = d.stack_resource_drift_status()
                                        .map(|s| s.as_str())
                                        .unwrap_or("UNKNOWN");
                                    format!("{lid}({rtype})={status}")
                                })
                                .collect();
                            let count = drifts.len().to_string();
                            (count, drifts.join("; "))
                        }
                        Err(e) => {
                            eprintln!("  WARN: CloudFormation describe_stack_resource_drifts {stack_name}: {e:#}");
                            ("0".to_string(), String::new())
                        }
                    }
                } else {
                    ("0".to_string(), String::new())
                };

                rows.push(vec![
                    stack_name, stack_status, drift_status, last_check,
                    drifted_count, resource_drifts_summary,
                ]);
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() { break; }
        }

        Ok(rows)
    }
}
