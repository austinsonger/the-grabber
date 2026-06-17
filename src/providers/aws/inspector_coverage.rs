use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_inspector2::Client as Inspector2Client;

use crate::evidence::CsvCollector;

pub struct Inspector2CoverageCollector {
    client: Inspector2Client,
}

impl Inspector2CoverageCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: Inspector2Client::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for Inspector2CoverageCollector {
    fn name(&self) -> &str {
        "Inspector2 Coverage"
    }
    fn filename_prefix(&self) -> &str {
        "Inspector2_Coverage"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Resource ID",
            "Resource Type",
            "Scan Status",
            "Scan Status Reason",
            "Scan Type",
            "Account ID",
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
            let mut req = self.client.list_coverage().max_results(500);
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }

            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e:#}");
                    if msg.contains("AccessDeniedException")
                        || msg.contains("ResourceNotFoundException")
                        || msg.contains("ValidationException")
                        || msg.contains("BadRequestException")
                    {
                        eprintln!("  WARN: Inspector2 list_coverage (not enabled?): {msg}");
                        return Ok(rows);
                    }
                    eprintln!("  WARN: Inspector2 list_coverage: {msg}");
                    break;
                }
            };

            for r in resp.covered_resources() {
                let resource_id = r.resource_id().to_string();
                let resource_type = r.resource_type().as_str().to_string();
                let (scan_status, scan_status_reason) = r
                    .scan_status()
                    .map(|s| {
                        (
                            s.status_code().as_str().to_string(),
                            s.reason().as_str().to_string(),
                        )
                    })
                    .unwrap_or_default();
                let scan_type = r.scan_type().as_str().to_string();
                let account_id = r.account_id().to_string();

                rows.push(vec![
                    resource_id,
                    resource_type,
                    scan_status,
                    scan_status_reason,
                    scan_type,
                    account_id,
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
