use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_controltower::Client as CtClient;

use crate::evidence::CsvCollector;

pub struct ControlTowerCollector {
    client: CtClient,
}

impl ControlTowerCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: CtClient::new(config),
        }
    }
}

fn is_benign(err: &str) -> bool {
    err.contains("AccessDenied")
        || err.contains("ResourceNotFoundException")
        || err.contains("ValidationException")
        || err.contains("UnsupportedOperation")
        || err.contains("not enabled")
}

#[async_trait]
impl CsvCollector for ControlTowerCollector {
    fn name(&self) -> &str {
        "Control Tower Baselines & Guardrails"
    }
    fn filename_prefix(&self) -> &str {
        "ControlTower_Guardrails"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Type",
            "Target Identifier",
            "Baseline/Control ARN",
            "Baseline Version",
            "Status",
            "Drift Status",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        // ── Landing Zones ─────────────────────────────────────────────
        let mut lz_token: Option<String> = None;
        loop {
            let mut req = self.client.list_landing_zones();
            if let Some(t) = lz_token.as_ref() {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e:#}");
                    if is_benign(&msg) {
                        return Ok(rows);
                    }
                    eprintln!("  WARN: ControlTower list_landing_zones: {e:#}");
                    break;
                }
            };

            for lz in resp.landing_zones() {
                let arn = lz.arn().unwrap_or("").to_string();
                if arn.is_empty() {
                    continue;
                }
                let (version, status) = match self
                    .client
                    .get_landing_zone()
                    .landing_zone_identifier(&arn)
                    .send()
                    .await
                {
                    Ok(g) => {
                        if let Some(detail) = g.landing_zone() {
                            let v = detail.version().to_string();
                            let s = detail
                                .status()
                                .map(|st| st.as_str().to_string())
                                .unwrap_or_default();
                            (v, s)
                        } else {
                            (String::new(), String::new())
                        }
                    }
                    Err(_) => (String::new(), String::new()),
                };
                rows.push(vec![
                    "LandingZone".to_string(),
                    String::new(),
                    arn,
                    version,
                    status,
                    String::new(),
                ]);
            }

            lz_token = resp.next_token().map(|s| s.to_string());
            if lz_token.is_none() {
                break;
            }
        }

        // ── Enabled Baselines ─────────────────────────────────────────
        let mut eb_token: Option<String> = None;
        loop {
            let mut req = self.client.list_enabled_baselines();
            if let Some(t) = eb_token.as_ref() {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e:#}");
                    if is_benign(&msg) {
                        return Ok(rows);
                    }
                    eprintln!("  WARN: ControlTower list_enabled_baselines: {e:#}");
                    break;
                }
            };

            for eb in resp.enabled_baselines() {
                let target = eb.target_identifier().to_string();
                let baseline = eb.baseline_identifier().to_string();
                let version = eb
                    .baseline_version()
                    .map(|s| s.to_string())
                    .unwrap_or_default();
                let status = eb
                    .status_summary()
                    .and_then(|s| s.status())
                    .map(|s| s.as_str().to_string())
                    .unwrap_or_default();
                let drift = eb
                    .drift_status_summary()
                    .and_then(|d| d.types())
                    .map(|t| format!("{:?}", t))
                    .unwrap_or_default();
                rows.push(vec![
                    "EnabledBaseline".to_string(),
                    target,
                    baseline,
                    version,
                    status,
                    drift,
                ]);
            }

            eb_token = resp.next_token().map(|s| s.to_string());
            if eb_token.is_none() {
                break;
            }
        }

        Ok(rows)
    }
}
