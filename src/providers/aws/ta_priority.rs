use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_trustedadvisor::Client as TaClient;

use crate::evidence::CsvCollector;

fn is_access_denied(err: &str) -> bool {
    err.contains("AccessDenied")
        || err.contains("Enterprise Support")
        || err.contains("subscription")
}

fn is_benign(err: &str) -> bool {
    err.contains("AccessDenied")
        || err.contains("ResourceNotFoundException")
        || err.contains("ValidationException")
        || err.contains("not enabled")
        || err.contains("not subscribed")
        || err.contains("UnknownService")
        || err.contains("dispatch failure")
}

pub struct TaPriorityCollector {
    client: TaClient,
}

impl TaPriorityCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: TaClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for TaPriorityCollector {
    fn name(&self) -> &str {
        "Trusted Advisor Priority"
    }
    fn filename_prefix(&self) -> &str {
        "TrustedAdvisor_Priority"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Recommendation ID",
            "Name",
            "Services",
            "Pillars",
            "Status",
            "Lifecycle Stage",
            "Error Count",
            "Warning Count",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows: Vec<Vec<String>> = Vec::new();
        let mut next_token: Option<String> = None;

        loop {
            let mut req = self.client.list_recommendations();
            if let Some(t) = next_token.as_ref() {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e:#}");
                    if is_access_denied(&msg) {
                        rows.push(vec![
                            "".to_string(),
                            "Enterprise Support required".to_string(),
                            "".to_string(),
                            "".to_string(),
                            "".to_string(),
                            "".to_string(),
                            "0".to_string(),
                            "0".to_string(),
                        ]);
                        return Ok(rows);
                    }
                    if is_benign(&msg) {
                        return Ok(rows);
                    }
                    eprintln!("  WARN: TrustedAdvisor list_recommendations: {e:#}");
                    break;
                }
            };

            for r in resp.recommendation_summaries() {
                let id = r.id().to_string();
                let name = r.name().to_string();
                let services = r.aws_services().join(",");
                let pillars = r
                    .pillars()
                    .iter()
                    .map(|p| p.as_str().to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                let status = r.status().as_str().to_string();
                let lifecycle = r
                    .lifecycle_stage()
                    .map(|s| s.as_str().to_string())
                    .unwrap_or_default();
                let (err_count, warn_count) = match r.resources_aggregates() {
                    Some(a) => (a.error_count(), a.warning_count()),
                    None => (0i64, 0i64),
                };

                rows.push(vec![
                    id,
                    name,
                    services,
                    pillars,
                    status,
                    lifecycle,
                    err_count.to_string(),
                    warn_count.to_string(),
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
