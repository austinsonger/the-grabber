use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_sfn::types::ExecutionStatus;
use aws_sdk_sfn::Client as SfnClient;

use crate::evidence::CsvCollector;

// ---------------------------------------------------------------------------
// Step Functions — state machines with logging config and recent failed
// execution counts.
// ---------------------------------------------------------------------------

fn fmt_sfn_dt(dt: &aws_sdk_sfn::primitives::DateTime) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(dt.secs(), 0)
        .map(|c| c.to_rfc3339())
        .unwrap_or_default()
}

pub struct StepFunctionsExecutionsCollector {
    client: SfnClient,
}

impl StepFunctionsExecutionsCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: SfnClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for StepFunctionsExecutionsCollector {
    fn name(&self) -> &str {
        "Step Functions Executions"
    }
    fn filename_prefix(&self) -> &str {
        "StepFunctions_Executions"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "State Machine ARN",
            "Name",
            "Type",
            "Logging Level",
            "Recent Failed Count",
            "Latest Failure Time",
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
            let mut req = self.client.list_state_machines();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e:#}");
                    if msg.contains("not supported")
                        || msg.contains("not available")
                        || msg.contains("UnsupportedOperation")
                    {
                        return Ok(rows);
                    }
                    eprintln!("  WARN: SFN list_state_machines: {e:#}");
                    return Ok(rows);
                }
            };

            for sm in resp.state_machines() {
                let arn = sm.state_machine_arn().to_string();
                let name = sm.name().to_string();
                let sm_type = sm.r#type().as_str().to_string();

                // describe_state_machine — for logging level
                let logging_level = match self
                    .client
                    .describe_state_machine()
                    .state_machine_arn(&arn)
                    .send()
                    .await
                {
                    Ok(d) => d
                        .logging_configuration()
                        .and_then(|lc| lc.level())
                        .map(|l| l.as_str().to_string())
                        .unwrap_or_default(),
                    Err(e) => {
                        eprintln!("  WARN: SFN describe_state_machine {arn}: {e:#}");
                        String::new()
                    }
                };

                // list_executions filtered to FAILED, max 50
                let (failed_count, latest_failure) = match self
                    .client
                    .list_executions()
                    .state_machine_arn(&arn)
                    .status_filter(ExecutionStatus::Failed)
                    .max_results(50)
                    .send()
                    .await
                {
                    Ok(r) => {
                        let execs = r.executions();
                        let count: usize = execs.len();
                        let latest = execs
                            .iter()
                            .map(|e| e.start_date())
                            .max_by_key(|d| d.secs())
                            .map(fmt_sfn_dt)
                            .unwrap_or_default();
                        (count, latest)
                    }
                    Err(e) => {
                        eprintln!("  WARN: SFN list_executions {arn}: {e:#}");
                        (0usize, String::new())
                    }
                };

                rows.push(vec![
                    arn,
                    name,
                    sm_type,
                    logging_level,
                    failed_count.to_string(),
                    latest_failure,
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
