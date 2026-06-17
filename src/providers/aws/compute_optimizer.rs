use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_computeoptimizer::Client as CoClient;

use crate::evidence::CsvCollector;

pub struct ComputeOptimizerCollector {
    client: CoClient,
}

impl ComputeOptimizerCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: CoClient::new(config),
        }
    }
}

fn is_benign(err: &str) -> bool {
    err.contains("OptInRequired")
        || err.contains("AccessDenied")
        || err.contains("AccessDeniedException")
        || err.contains("ServiceUnavailable")
        || err.contains("not enrolled")
        || err.contains("not opted in")
}

#[async_trait]
impl CsvCollector for ComputeOptimizerCollector {
    fn name(&self) -> &str {
        "Compute Optimizer Recommendations"
    }
    fn filename_prefix(&self) -> &str {
        "Compute_Optimizer"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Resource Type",
            "ARN",
            "Current Config",
            "Finding",
            "Recommended Config",
            "Est. Monthly Savings ($)",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        // EC2 instance recommendations.
        let mut next_token: Option<String> = None;
        loop {
            let mut req = self.client.get_ec2_instance_recommendations();
            if let Some(t) = next_token.as_ref() {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e:#}");
                    if is_benign(&msg) {
                        eprintln!("  WARN: ComputeOptimizer EC2 (benign): {msg}");
                        return Ok(rows);
                    }
                    eprintln!("  WARN: ComputeOptimizer get_ec2_instance_recommendations: {e:#}");
                    break;
                }
            };
            for rec in resp.instance_recommendations() {
                let arn = rec.instance_arn().unwrap_or("").to_string();
                let cur = rec.current_instance_type().unwrap_or("").to_string();
                let finding = rec
                    .finding()
                    .map(|f| f.as_str().to_string())
                    .unwrap_or_default();
                let opts = rec.recommendation_options();
                let (recommended, savings) = if let Some(opt) = opts.first() {
                    let rec_type = opt.instance_type().unwrap_or("").to_string();
                    let s = opt
                        .savings_opportunity()
                        .and_then(|s| s.estimated_monthly_savings())
                        .map(|s| format!("{:.2}", s.value()))
                        .unwrap_or_default();
                    (rec_type, s)
                } else {
                    (String::new(), String::new())
                };
                rows.push(vec![
                    "EC2".to_string(),
                    arn,
                    cur,
                    finding,
                    recommended,
                    savings,
                ]);
            }
            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() {
                break;
            }
        }

        // Lambda function recommendations.
        let mut next_token: Option<String> = None;
        loop {
            let mut req = self.client.get_lambda_function_recommendations();
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
                    eprintln!(
                        "  WARN: ComputeOptimizer get_lambda_function_recommendations: {e:#}"
                    );
                    break;
                }
            };
            for rec in resp.lambda_function_recommendations() {
                let arn = rec.function_arn().unwrap_or("").to_string();
                let cur = format!("{} MB", rec.current_memory_size());
                let finding = rec
                    .finding()
                    .map(|f| f.as_str().to_string())
                    .unwrap_or_default();
                let opts = rec.memory_size_recommendation_options();
                let (recommended, savings) = if let Some(opt) = opts.first() {
                    let rec_size = format!("{} MB", opt.memory_size());
                    let s = opt
                        .savings_opportunity()
                        .and_then(|s| s.estimated_monthly_savings())
                        .map(|s| format!("{:.2}", s.value()))
                        .unwrap_or_default();
                    (rec_size, s)
                } else {
                    (String::new(), String::new())
                };
                rows.push(vec![
                    "Lambda".to_string(),
                    arn,
                    cur,
                    finding,
                    recommended,
                    savings,
                ]);
            }
            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() {
                break;
            }
        }

        // EBS volume recommendations.
        let mut next_token: Option<String> = None;
        loop {
            let mut req = self.client.get_ebs_volume_recommendations();
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
                    eprintln!("  WARN: ComputeOptimizer get_ebs_volume_recommendations: {e:#}");
                    break;
                }
            };
            for rec in resp.volume_recommendations() {
                let arn = rec.volume_arn().unwrap_or("").to_string();
                let cur = rec
                    .current_configuration()
                    .and_then(|c| c.volume_type())
                    .unwrap_or("")
                    .to_string();
                let finding = rec
                    .finding()
                    .map(|f| f.as_str().to_string())
                    .unwrap_or_default();
                let opts = rec.volume_recommendation_options();
                let (recommended, savings) = if let Some(opt) = opts.first() {
                    let rec_type = opt
                        .configuration()
                        .and_then(|c| c.volume_type())
                        .unwrap_or("")
                        .to_string();
                    let s = opt
                        .savings_opportunity()
                        .and_then(|s| s.estimated_monthly_savings())
                        .map(|s| format!("{:.2}", s.value()))
                        .unwrap_or_default();
                    (rec_type, s)
                } else {
                    (String::new(), String::new())
                };
                rows.push(vec![
                    "EBS".to_string(),
                    arn,
                    cur,
                    finding,
                    recommended,
                    savings,
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
