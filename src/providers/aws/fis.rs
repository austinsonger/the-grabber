use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_fis::Client as FisClient;

use crate::evidence::CsvCollector;

pub struct FisCollector {
    client: FisClient,
}

impl FisCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: FisClient::new(config),
        }
    }
}

fn is_benign(err: &str) -> bool {
    err.contains("AccessDenied")
        || err.contains("UnauthorizedOperation")
        || err.contains("not supported")
        || err.contains("not enabled")
        || err.contains("ValidationException")
}

fn fmt_dt(dt: &aws_sdk_fis::primitives::DateTime) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(dt.secs(), dt.subsec_nanos())
        .map(|c| c.to_rfc3339())
        .unwrap_or_default()
}

#[async_trait]
impl CsvCollector for FisCollector {
    fn name(&self) -> &str {
        "FIS Experiments"
    }
    fn filename_prefix(&self) -> &str {
        "FIS_Experiments"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Type",
            "ID",
            "Template ID / Description",
            "State / Creation Time",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        // ── Experiment Templates ──────────────────────────────────────
        let mut tmpl_token: Option<String> = None;
        loop {
            let mut req = self.client.list_experiment_templates();
            if let Some(t) = tmpl_token.as_ref() {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e:#}");
                    if is_benign(&msg) {
                        return Ok(rows);
                    }
                    eprintln!("  WARN: FIS list_experiment_templates: {e:#}");
                    break;
                }
            };

            for t in resp.experiment_templates() {
                let id = t.id().unwrap_or("").to_string();
                let description = t.description().unwrap_or("").to_string();
                let created = t.creation_time().map(fmt_dt).unwrap_or_default();
                rows.push(vec!["Template".to_string(), id, description, created]);
            }

            tmpl_token = resp.next_token().map(|s| s.to_string());
            if tmpl_token.is_none() {
                break;
            }
        }

        // ── Experiments ───────────────────────────────────────────────
        let mut exp_token: Option<String> = None;
        loop {
            let mut req = self.client.list_experiments();
            if let Some(t) = exp_token.as_ref() {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e:#}");
                    if is_benign(&msg) {
                        return Ok(rows);
                    }
                    eprintln!("  WARN: FIS list_experiments: {e:#}");
                    break;
                }
            };

            for e in resp.experiments() {
                let id = e.id().unwrap_or("").to_string();
                let template_id = e.experiment_template_id().unwrap_or("").to_string();
                let status = e
                    .state()
                    .and_then(|s| s.status())
                    .map(|s| s.as_str().to_string())
                    .unwrap_or_default();
                let created = e.creation_time().map(fmt_dt).unwrap_or_default();
                let state_created = if created.is_empty() {
                    status
                } else if status.is_empty() {
                    created
                } else {
                    format!("{status} / {created}")
                };
                rows.push(vec![
                    "Experiment".to_string(),
                    id,
                    template_id,
                    state_created,
                ]);
            }

            exp_token = resp.next_token().map(|s| s.to_string());
            if exp_token.is_none() {
                break;
            }
        }

        Ok(rows)
    }
}
