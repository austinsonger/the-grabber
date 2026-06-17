use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_budgets::Client as BudgetsClient;

use crate::evidence::CsvCollector;

pub struct BudgetsCollector {
    client: BudgetsClient,
}

impl BudgetsCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: BudgetsClient::new(config),
        }
    }
}

fn is_benign(err: &str) -> bool {
    err.contains("AccessDenied")
        || err.contains("AccessDeniedException")
        || err.contains("UnauthorizedOperation")
        || err.contains("not enabled")
        || err.contains("NotFoundException")
}

#[async_trait]
impl CsvCollector for BudgetsCollector {
    fn name(&self) -> &str {
        "Budgets"
    }
    fn filename_prefix(&self) -> &str {
        "Budgets"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Budget Name",
            "Type",
            "Time Unit",
            "Limit",
            "Actual Spend",
            "Forecasted Spend",
        ]
    }

    async fn collect_rows(
        &self,
        account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        if account_id.is_empty() {
            eprintln!("  WARN: Budgets requires account_id; skipping");
            return Ok(Vec::new());
        }

        let mut rows = Vec::new();
        let mut next_token: Option<String> = None;

        loop {
            let mut req = self.client.describe_budgets().account_id(account_id);
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
                    eprintln!("  WARN: Budgets describe_budgets: {e:#}");
                    break;
                }
            };

            for b in resp.budgets() {
                let name = b.budget_name().to_string();
                let b_type = b.budget_type().as_str().to_string();
                let time_unit = b.time_unit().as_str().to_string();
                let limit = b
                    .budget_limit()
                    .map(|s| format!("{} {}", s.amount(), s.unit()))
                    .unwrap_or_default();
                let actual = b
                    .calculated_spend()
                    .and_then(|c| c.actual_spend())
                    .map(|s| format!("{} {}", s.amount(), s.unit()))
                    .unwrap_or_default();
                let forecasted = b
                    .calculated_spend()
                    .and_then(|c| c.forecasted_spend())
                    .map(|s| format!("{} {}", s.amount(), s.unit()))
                    .unwrap_or_default();

                rows.push(vec![name, b_type, time_unit, limit, actual, forecasted]);
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() {
                break;
            }
        }

        Ok(rows)
    }
}
