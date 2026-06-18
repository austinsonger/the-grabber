use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_cloudformation::Client as CfnClient;

use crate::evidence::CsvCollector;

fn fmt_dt(dt: &aws_sdk_cloudformation::primitives::DateTime) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(dt.secs(), 0)
        .map(|c| c.to_rfc3339())
        .unwrap_or_default()
}

fn is_benign(err: &str) -> bool {
    err.contains("AccessDenied")
        || err.contains("ResourceNotFoundException")
        || err.contains("ValidationException")
        || err.contains("not enabled")
        || err.contains("not subscribed")
        || err.contains("UnknownService")
        || err.contains("dispatch failure")
        || err.contains("StackSetNotFound")
        || err.contains("could not be found")
}

pub struct CfnStackSetsCollector {
    client: CfnClient,
}

impl CfnStackSetsCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: CfnClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for CfnStackSetsCollector {
    fn name(&self) -> &str {
        "CloudFormation StackSets Drift"
    }
    fn filename_prefix(&self) -> &str {
        "CFN_StackSets_Drift"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "StackSet Name",
            "Account",
            "Region",
            "Stack Status",
            "Drift Status",
            "Last Drift Check",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows: Vec<Vec<String>> = Vec::new();

        // Collect stack set names (paginated).
        let mut stack_set_names: Vec<String> = Vec::new();
        let mut next_token: Option<String> = None;
        loop {
            let mut req = self.client.list_stack_sets();
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
                    eprintln!("  WARN: CloudFormation list_stack_sets: {e:#}");
                    break;
                }
            };

            for s in resp.summaries() {
                if let Some(name) = s.stack_set_name() {
                    stack_set_names.push(name.to_string());
                }
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() {
                break;
            }
        }

        // For each stack set, list instances.
        for ss_name in &stack_set_names {
            let mut next_token: Option<String> = None;
            loop {
                let mut req = self.client.list_stack_instances().stack_set_name(ss_name);
                if let Some(t) = next_token.as_ref() {
                    req = req.next_token(t);
                }
                let resp = match req.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        let msg = format!("{e:#}");
                        if !is_benign(&msg) {
                            eprintln!(
                                "  WARN: CloudFormation list_stack_instances({ss_name}): {e:#}"
                            );
                        }
                        break;
                    }
                };

                for inst in resp.summaries() {
                    let account = inst.account().unwrap_or("").to_string();
                    let region = inst.region().unwrap_or("").to_string();
                    let stack_status = inst
                        .status()
                        .map(|s| s.as_str().to_string())
                        .unwrap_or_default();
                    let drift_status = inst
                        .drift_status()
                        .map(|s| s.as_str().to_string())
                        .unwrap_or_default();
                    let last_check = inst
                        .last_drift_check_timestamp()
                        .map(fmt_dt)
                        .unwrap_or_default();

                    rows.push(vec![
                        ss_name.clone(),
                        account,
                        region,
                        stack_status,
                        drift_status,
                        last_check,
                    ]);
                }

                next_token = resp.next_token().map(|s| s.to_string());
                if next_token.is_none() {
                    break;
                }
            }
        }

        Ok(rows)
    }
}
