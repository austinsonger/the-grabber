use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_ec2::Client as Ec2Client;
use aws_sdk_savingsplans::Client as SpClient;

use crate::evidence::CsvCollector;

pub struct SavingsPlansCollector {
    sp_client: SpClient,
    ec2_client: Ec2Client,
}

impl SavingsPlansCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            sp_client: SpClient::new(config),
            ec2_client: Ec2Client::new(config),
        }
    }
}

fn is_benign(err: &str) -> bool {
    err.contains("AccessDenied")
        || err.contains("AccessDeniedException")
        || err.contains("UnauthorizedOperation")
        || err.contains("not enabled")
        || err.contains("not supported")
        || err.contains("OptInRequired")
        || err.contains("ValidationException")
}

fn fmt_ec2_dt(dt: &aws_sdk_ec2::primitives::DateTime) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(dt.secs(), dt.subsec_nanos())
        .map(|c| c.to_rfc3339())
        .unwrap_or_default()
}

#[async_trait]
impl CsvCollector for SavingsPlansCollector {
    fn name(&self) -> &str {
        "Savings Plans & Reserved Instances"
    }
    fn filename_prefix(&self) -> &str {
        "Savings_Plans_RIs"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Type",
            "ID",
            "Instance Type / Plan Type",
            "State",
            "Start",
            "End",
            "Commitment / Price",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        // 1. Savings Plans (paginated via next_token).
        let mut next_token: Option<String> = None;
        loop {
            let mut req = self.sp_client.describe_savings_plans();
            if let Some(t) = next_token.as_ref() {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e:#}");
                    if is_benign(&msg) {
                        break;
                    }
                    eprintln!("  WARN: SavingsPlans describe_savings_plans: {e:#}");
                    break;
                }
            };

            for sp in resp.savings_plans() {
                let id = sp.savings_plan_id().unwrap_or("").to_string();
                let plan_type = sp
                    .savings_plan_type()
                    .map(|t| t.as_str().to_string())
                    .unwrap_or_default();
                let state = sp
                    .state()
                    .map(|s| s.as_str().to_string())
                    .unwrap_or_default();
                let start = sp.start().unwrap_or("").to_string();
                let end = sp.end().unwrap_or("").to_string();
                let commitment = sp.commitment().unwrap_or("").to_string();
                let payment_option = sp
                    .payment_option()
                    .map(|p| p.as_str().to_string())
                    .unwrap_or_default();
                let commitment_detail = if payment_option.is_empty() {
                    commitment
                } else {
                    format!("{commitment} ({payment_option})")
                };

                rows.push(vec![
                    "SavingsPlan".to_string(),
                    id,
                    plan_type,
                    state,
                    start,
                    end,
                    commitment_detail,
                ]);
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() {
                break;
            }
        }

        // 2. Reserved Instances (single, non-paginated).
        match self.ec2_client.describe_reserved_instances().send().await {
            Ok(resp) => {
                for ri in resp.reserved_instances() {
                    let id = ri.reserved_instances_id().unwrap_or("").to_string();
                    let instance_type = ri
                        .instance_type()
                        .map(|t| t.as_str().to_string())
                        .unwrap_or_default();
                    let state = ri
                        .state()
                        .map(|s| s.as_str().to_string())
                        .unwrap_or_default();
                    let start = ri.start().map(fmt_ec2_dt).unwrap_or_default();
                    let end = ri.end().map(fmt_ec2_dt).unwrap_or_default();
                    let price = ri
                        .fixed_price()
                        .map(|p| format!("{p:.2}"))
                        .unwrap_or_default();

                    rows.push(vec![
                        "ReservedInstance".to_string(),
                        id,
                        instance_type,
                        state,
                        start,
                        end,
                        price,
                    ]);
                }
            }
            Err(e) => {
                let msg = format!("{e:#}");
                if !is_benign(&msg) {
                    eprintln!("  WARN: EC2 describe_reserved_instances: {e:#}");
                }
            }
        }

        Ok(rows)
    }
}
