use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_inspector2::Client as Inspector2Client;

use crate::evidence::CsvCollector;

fn epoch_to_rfc3339(secs: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(secs, 0)
        .map(|c| c.to_rfc3339())
        .unwrap_or_default()
}

pub struct InspectorFindingsHistoryCollector {
    client: Inspector2Client,
}

impl InspectorFindingsHistoryCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self { client: Inspector2Client::new(config) }
    }
}

#[async_trait]
impl CsvCollector for InspectorFindingsHistoryCollector {
    fn name(&self) -> &str { "Inspector2 Findings History" }
    fn filename_prefix(&self) -> &str { "Inspector_Findings_History" }
    fn headers(&self) -> &'static [&'static str] {
        &["Finding ID", "First Observed At", "Last Observed At",
          "Status", "Severity", "Resource ID", "Title"]
    }

    async fn collect_rows(&self, _account_id: &str, _region: &str) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let mut next_token: Option<String> = None;

        loop {
            let mut req = self.client.list_findings().max_results(100);
            if let Some(ref t) = next_token {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  WARN: Inspector2 list_findings (history): {e:#}");
                    break;
                }
            };

            for finding in resp.findings() {
                let finding_id = finding.finding_arn().to_string();

                let first_observed = epoch_to_rfc3339(finding.first_observed_at().secs());
                let last_observed  = epoch_to_rfc3339(finding.last_observed_at().secs());

                let status   = finding.status().as_str().to_string();
                let severity = format!("{:?}", finding.severity());

                let resource_id = finding.resources()
                    .first()
                    .map(|r| r.id().to_string())
                    .unwrap_or_default();

                let title = finding.title().unwrap_or("").to_string();

                rows.push(vec![
                    finding_id, first_observed, last_observed,
                    status, severity, resource_id, title,
                ]);
            }

            next_token = resp.next_token().map(|s| s.to_string());
            if next_token.is_none() { break; }
        }

        Ok(rows)
    }
}
