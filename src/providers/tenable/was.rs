use anyhow::Result;
use async_trait::async_trait;

use tenable_rs::TenableClient;

use crate::evidence::CsvCollector;

pub struct TenableWasCollector {
    client: TenableClient,
}

impl TenableWasCollector {
    pub fn new(client: TenableClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for TenableWasCollector {
    fn name(&self) -> &str {
        "Tenable Web App Scanning"
    }

    fn filename_prefix(&self) -> &str {
        "Tenable_WAS_Findings"
    }

    fn headers(&self) -> &'static [&'static str] {
        &[
            "Scan ID",
            "Scan Name",
            "App URI",
            "Finding ID",
            "Plugin ID",
            "Name",
            "Severity",
            "URL",
            "Remediation",
            "First Seen",
            "Last Seen",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        // A 404 means the tenant does not have WAS licensed; return an empty
        // file rather than failing the whole collection run.
        let scans = match self.client.was().list_scans().await {
            Ok(s) => s,
            Err(tenable_rs::TenableError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };
        let mut rows = Vec::new();
        for scan in &scans {
            let vulns = self
                .client
                .was()
                .list_vulns(&scan.scan_id)
                .await
                .unwrap_or_default();
            for v in vulns {
                rows.push(vec![
                    scan.scan_id.clone(),
                    scan.name.clone().unwrap_or_default(),
                    scan.application_uri.clone().unwrap_or_default(),
                    v.finding_id,
                    v.plugin_id.map(|i| i.to_string()).unwrap_or_default(),
                    v.name.unwrap_or_default(),
                    v.severity.unwrap_or_default(),
                    v.url.unwrap_or_default(),
                    v.remediation.unwrap_or_default(),
                    v.first_seen.unwrap_or_default(),
                    v.last_seen.unwrap_or_default(),
                ]);
            }
        }
        Ok(rows)
    }
}
