use anyhow::Result;
use async_trait::async_trait;
use aws_sdk_macie2::Client as MacieClient;

use crate::evidence::CsvCollector;

pub struct MacieJobsCollector {
    client: MacieClient,
}

impl MacieJobsCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: MacieClient::new(config),
        }
    }
}

fn is_benign(err: &str) -> bool {
    err.contains("AccessDenied")
        || err.contains("AccessDeniedException")
        || err.contains("UnauthorizedOperation")
        || err.contains("not enabled")
        || err.contains("ValidationException")
}

fn fmt_dt(dt: &aws_sdk_macie2::primitives::DateTime) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(dt.secs(), 0)
        .map(|c| c.to_rfc3339())
        .unwrap_or_default()
}

#[async_trait]
impl CsvCollector for MacieJobsCollector {
    fn name(&self) -> &str {
        "Macie Classification Jobs"
    }
    fn filename_prefix(&self) -> &str {
        "Macie_Classification_Jobs"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Job ID",
            "Name",
            "Job Type",
            "Status",
            "Created At",
            "Last Run",
            "Bucket Definitions Count",
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
            let mut req = self.client.list_classification_jobs();
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
                    eprintln!("  WARN: Macie list_classification_jobs: {e:#}");
                    break;
                }
            };

            for j in resp.items() {
                let job_id = j.job_id().unwrap_or("").to_string();
                let name = j.name().unwrap_or("").to_string();
                let job_type = j
                    .job_type()
                    .map(|t| t.as_str().to_string())
                    .unwrap_or_default();
                let status = j
                    .job_status()
                    .map(|s| s.as_str().to_string())
                    .unwrap_or_default();
                let created_at = j.created_at().map(fmt_dt).unwrap_or_default();
                let last_run = String::new();
                let bucket_count = j.bucket_definitions().len().to_string();

                rows.push(vec![
                    job_id,
                    name,
                    job_type,
                    status,
                    created_at,
                    last_run,
                    bucket_count,
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
