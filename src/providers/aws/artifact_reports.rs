use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_artifact::Client as ArtifactClient;

use crate::evidence::CsvCollector;

pub struct ArtifactReportsCollector {
    client: ArtifactClient,
}

impl ArtifactReportsCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: ArtifactClient::new(config),
        }
    }
}

#[async_trait]
impl CsvCollector for ArtifactReportsCollector {
    fn name(&self) -> &str {
        "AWS Artifact Reports"
    }
    fn filename_prefix(&self) -> &str {
        "Artifact_Reports"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Report ID",
            "Name",
            "Series",
            "Category",
            "State",
            "Periodic Update",
            "Last Modified",
            "Acceptance Type",
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
            let mut req = self.client.list_reports();
            if let Some(t) = next_token.as_ref() {
                req = req.next_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("{e}");
                    if msg.contains("AccessDenied")
                        || msg.contains("not supported")
                        || msg.contains("ValidationException")
                    {
                        return Ok(rows);
                    }
                    eprintln!("  WARN: Artifact list_reports: {e:#}");
                    return Ok(rows);
                }
            };

            for r in resp.reports() {
                let id = r.id().unwrap_or("").to_string();
                let name = r.name().unwrap_or("").to_string();
                let series = r.series().unwrap_or("").to_string();
                let category = r.category().unwrap_or("").to_string();
                let state = r
                    .state()
                    .map(|s| s.as_str().to_string())
                    .unwrap_or_default();
                let last_modified = r.period_end().map(|t| t.to_string()).unwrap_or_default();
                let acceptance = r
                    .acceptance_type()
                    .map(|a| a.as_str().to_string())
                    .unwrap_or_default();

                rows.push(vec![
                    id,
                    name,
                    series,
                    category,
                    state,
                    String::new(),
                    last_modified,
                    acceptance,
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
