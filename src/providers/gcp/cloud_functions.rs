//! GCP Cloud Functions — equivalent to AWS Lambda.

use anyhow::Result;
use async_trait::async_trait;

use crate::evidence::CsvCollector;
use crate::providers::gcp::client::GcpClient;

pub struct CloudFunctionsCollector {
    client: GcpClient,
    project_id: String,
}

impl CloudFunctionsCollector {
    pub fn new(client: GcpClient, project_id: impl Into<String>) -> Self {
        Self {
            client,
            project_id: project_id.into(),
        }
    }
}

#[async_trait]
impl CsvCollector for CloudFunctionsCollector {
    fn name(&self) -> &str {
        "GCP Cloud Functions"
    }
    fn filename_prefix(&self) -> &str {
        "GCP_Cloud_Functions"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "project_id",
            "name",
            "state",
            "runtime",
            "entry_point",
            "memory_mb",
            "timeout",
            "region",
            "create_time",
            "update_time",
            "trigger_type",
            "service_account",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let url = format!(
            "https://cloudfunctions.googleapis.com/v2/projects/{}/locations/-/functions?pageSize=1000",
            self.project_id
        );
        let functions = self.client.paginate(&url, "functions").await?;

        let rows = functions
            .iter()
            .map(|f| {
                let build = f.get("buildConfig");
                let service = f.get("serviceConfig");
                let runtime = build
                    .and_then(|b| b.get("runtime"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_owned();
                let entry_point = build
                    .and_then(|b| b.get("entryPoint"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_owned();
                let memory = service
                    .and_then(|s| s.get("availableMemory"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_owned();
                let timeout = service
                    .and_then(|s| s.get("timeoutSeconds"))
                    .and_then(|v| v.as_i64())
                    .map(|i| i.to_string())
                    .unwrap_or_default();
                let sa = service
                    .and_then(|s| s.get("serviceAccountEmail"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_owned();
                let trigger_type = f
                    .get("eventTrigger")
                    .map(|_| "event")
                    .or_else(|| f.get("httpsTrigger").map(|_| "https"))
                    .unwrap_or("unknown")
                    .to_owned();
                let name_full = f
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_owned();
                let name_short = name_full.split('/').last().unwrap_or("").to_owned();
                let region = name_full.split('/').nth(5).unwrap_or("").to_owned();
                vec![
                    self.project_id.clone(),
                    name_short,
                    f.get("state")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned(),
                    runtime,
                    entry_point,
                    memory,
                    timeout,
                    region,
                    f.get("createTime")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned(),
                    f.get("updateTime")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned(),
                    trigger_type,
                    sa,
                ]
            })
            .collect();
        Ok(rows)
    }
}
