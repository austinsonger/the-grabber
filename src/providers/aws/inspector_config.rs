use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_inspector2::Client as Inspector2Client;

use crate::evidence::CsvCollector;

pub struct InspectorConfigCollector {
    client: Inspector2Client,
}

impl InspectorConfigCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: Inspector2Client::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for InspectorConfigCollector {
    fn name(&self) -> &str {
        "Inspector2 Configuration"
    }
    fn filename_prefix(&self) -> &str {
        "Inspector_Config"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Resource Type",
            "Scan Status",
            "Scan Type",
            "EC2 Status",
            "ECR Status",
            "Lambda Status",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let resp = match self.client.get_configuration().send().await {
            Ok(r) => r,
            Err(e) => {
                eprintln!("  WARN: Inspector2 get_configuration (not enabled?): {e:#}");
                return Ok(vec![]);
            }
        };

        let mut rows = Vec::new();

        let ec2_status = resp
            .ec2_configuration()
            .and_then(|c| c.scan_mode_state())
            .map(|s| format!("{s:?}"))
            .unwrap_or_else(|| "Not Configured".to_string());

        let ecr_status = resp
            .ecr_configuration()
            .and_then(|c| c.rescan_duration_state())
            .map(|d| format!("{d:?}"))
            .unwrap_or_else(|| "Not Configured".to_string());

        let lambda_status = resp
            .ec2_configuration()
            .and_then(|c| c.scan_mode_state())
            .map(|s| format!("EC2:{s:?}"))
            .unwrap_or_else(|| "Not Configured".to_string());

        rows.push(vec![
            "All".to_string(),
            "Configured".to_string(),
            "Vulnerability Scan".to_string(),
            ec2_status,
            ecr_status,
            lambda_status,
        ]);

        // Coverage: proves resources are actually being scanned right now,
        // not just that scan-mode is configured (NIST-1557 / RA-05f.).
        let mut next_token: Option<String> = None;
        let mut covered = 0i64;
        let mut uncovered = 0i64;
        let mut coverage_query_succeeded = false;
        loop {
            let mut req = self.client.list_coverage();
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: Inspector2 list_coverage: {e:#}");
                    break;
                }
            };
            coverage_query_succeeded = true;
            for cov in resp.covered_resources() {
                // `ScanStatus::status_code()` is a required field on the SDK type,
                // so it returns `&ScanStatusCode` directly (not `Option`); only
                // `scan_status()` itself is optional.
                match cov.scan_status().map(|s| s.status_code()) {
                    Some(code) if code.as_str() == "ACTIVE" => covered += 1,
                    _ => uncovered += 1,
                }
            }
            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() {
                break;
            }
        }
        let (covered_str, uncovered_str) = if coverage_query_succeeded {
            (
                format!("{covered} active"),
                format!("{uncovered} not active"),
            )
        } else {
            (
                "N/A (query failed)".to_string(),
                "N/A (query failed)".to_string(),
            )
        };
        rows.push(vec![
            "Coverage Summary".to_string(),
            "N/A".to_string(),
            "Resource Coverage".to_string(),
            covered_str,
            uncovered_str,
            String::new(),
        ]);

        Ok(rows)
    }
}
