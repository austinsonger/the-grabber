use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_inspector2::Client as Inspector2Client;

use crate::evidence::CsvCollector;

pub struct InspectorCollector {
    client: Inspector2Client,
}

impl InspectorCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: Inspector2Client::new(config) }
    }
}

#[async_trait]
impl CsvCollector for InspectorCollector {
    fn name(&self) -> &str { "Inspector2 Findings" }
    fn filename_prefix(&self) -> &str { "Inspector2_Findings" }
    fn headers(&self) -> &'static [&'static str] {
        &["Finding ARN", "Type", "Severity", "CVE ID", "Resource ID", "Status", "Fix Available"]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut next_token: Option<String> = None;

        loop {
            let mut req = self.client
                .list_findings()
                .max_results(100);
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
                    {
                        eprintln!("  WARN: Inspector2 list_findings (not enabled?): {msg}");
                        return Ok(rows);
                    }
                    eprintln!("  WARN: Inspector2 list_findings: {msg}");
                    break;
                }
            };

            for finding in resp.findings() {
                let finding_arn = finding.finding_arn().to_string();
                let f_type = finding.r#type().as_str().to_string();
                let severity = finding.severity().as_str().to_string();
                let cve_id = finding.package_vulnerability_details()
                    .map(|d| d.vulnerability_id().to_string())
                    .unwrap_or_default();
                let resource_id = finding.resources()
                    .first()
                    .map(|r| r.id().to_string())
                    .unwrap_or_default();
                let status = finding.status().as_str().to_string();
                let fix_available = finding.fix_available()
                    .map(|f| f.as_str().to_string())
                    .unwrap_or_default();

                rows.push(vec![
                    finding_arn,
                    f_type,
                    severity,
                    cve_id,
                    resource_id,
                    status,
                    fix_available,
                ]);
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() { break; }
        }

        Ok(rows)
    }
}
