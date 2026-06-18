use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_resiliencehub::Client as ResilienceHubClient;

use crate::evidence::CsvCollector;

fn fmt_rh_dt(dt: &aws_sdk_resiliencehub::primitives::DateTime) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(dt.secs(), 0)
        .map(|c| c.to_rfc3339())
        .unwrap_or_default()
}

pub struct ResilienceHubCollector {
    client: ResilienceHubClient,
}

impl ResilienceHubCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: ResilienceHubClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for ResilienceHubCollector {
    fn name(&self) -> &str {
        "Resilience Hub Apps"
    }
    fn filename_prefix(&self) -> &str {
        "ResilienceHub_Apps"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "App ARN",
            "App Name",
            "Compliance Status",
            "Resiliency Score",
            "Last Eval",
            "Recent Assessment Status",
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
            let mut req = self.client.list_apps();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e:#}");
                    if msg.contains("AccessDenied") || msg.contains("ResourceNotFound") {
                        return Ok(rows);
                    }
                    eprintln!("  WARN: ResilienceHub list_apps: {msg}");
                    return Ok(rows);
                }
            };

            for app in resp.app_summaries() {
                let arn = app.app_arn().to_string();
                let name = app.name().to_string();
                let compliance = app
                    .compliance_status()
                    .map(|s| s.as_str().to_string())
                    .unwrap_or_default();
                let score = format!("{:.2}", app.resiliency_score());
                let last_eval = app
                    .last_app_compliance_evaluation_time()
                    .map(fmt_rh_dt)
                    .unwrap_or_default();

                // Recent assessment status — first item from list_app_assessments.
                let mut recent_status = String::new();
                let mut a_token: Option<String> = None;
                'assess: loop {
                    let mut areq = self.client.list_app_assessments().app_arn(&arn);
                    if let Some(ref t) = a_token {
                        areq = areq.next_token(t);
                    }
                    let aresp = match areq.send().await {
                        Ok(r) => r,
                        Err(e) => {
                            let msg = format!("{e:#}");
                            if msg.contains("AccessDenied") || msg.contains("ResourceNotFound") {
                                break 'assess;
                            }
                            eprintln!("  WARN: ResilienceHub list_app_assessments: {msg}");
                            break 'assess;
                        }
                    };
                    if let Some(first) = aresp.assessment_summaries().first() {
                        recent_status = first.assessment_status().as_str().to_string();
                        break 'assess;
                    }
                    a_token = aresp.next_token().map(|s| s.to_string());
                    if a_token.is_none() {
                        break 'assess;
                    }
                }

                rows.push(vec![arn, name, compliance, score, last_eval, recent_status]);
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() {
                break;
            }
        }

        Ok(rows)
    }
}
