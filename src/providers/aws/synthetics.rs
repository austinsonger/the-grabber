use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_synthetics::Client as SyntheticsClient;

use crate::evidence::CsvCollector;

pub struct SyntheticsCanariesCollector {
    client: SyntheticsClient,
}

impl SyntheticsCanariesCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: SyntheticsClient::new(config),
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

fn fmt_dt(dt: &aws_sdk_synthetics::primitives::DateTime) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(dt.secs(), dt.subsec_nanos())
        .map(|c| c.to_rfc3339())
        .unwrap_or_default()
}

#[async_trait]
impl CsvCollector for SyntheticsCanariesCollector {
    fn name(&self) -> &str {
        "CloudWatch Synthetics Canaries"
    }
    fn filename_prefix(&self) -> &str {
        "Synthetics_Canaries"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Canary Name",
            "Runtime Version",
            "Schedule",
            "State",
            "Last Started",
            "Last Modified",
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
            let mut req = self.client.describe_canaries();
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
                    eprintln!("  WARN: Synthetics describe_canaries: {e:#}");
                    break;
                }
            };

            for c in resp.canaries() {
                let name = c.name().unwrap_or("").to_string();
                let runtime = c.runtime_version().unwrap_or("").to_string();
                let schedule = c
                    .schedule()
                    .and_then(|s| s.expression())
                    .unwrap_or("")
                    .to_string();
                let state = c
                    .status()
                    .and_then(|s| s.state())
                    .map(|s| s.as_str().to_string())
                    .unwrap_or_default();
                let last_started = c
                    .timeline()
                    .and_then(|t| t.last_started())
                    .map(fmt_dt)
                    .unwrap_or_default();
                let last_modified = c
                    .timeline()
                    .and_then(|t| t.last_modified())
                    .map(fmt_dt)
                    .unwrap_or_default();

                rows.push(vec![
                    name,
                    runtime,
                    schedule,
                    state,
                    last_started,
                    last_modified,
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
