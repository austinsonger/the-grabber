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
            // Finding identity
            "Finding ID",
            "State",
            "First Found",
            "Last Found",
            // Target
            "URL",
            "HTTP Method",
            "Input Type",
            "Input Name",
            // Plugin
            "Plugin ID",
            "Plugin Name",
            "Risk Factor",
            "Synopsis",
            "Description",
            "Solution",
            "CVEs",
            // Scoring
            "Severity",
            "Severity ID",
            "CVSS Base Score",
            "CVSS3 Base Score",
            "VPR Score",
            // Scan
            "Scan ID",
            "Scan Started At",
            "Scan Completed At",
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
        let findings = match self.client.was().export_all(None).await {
            Ok(f) => f,
            Err(tenable_rs::TenableError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };

        let rows = findings
            .into_iter()
            .map(|f| {
                let plugin = f.plugin.as_ref();
                let scan = f.scan.as_ref();
                vec![
                    f.finding_id,
                    f.state.unwrap_or_default(),
                    f.first_found.unwrap_or_default(),
                    f.last_found.unwrap_or_default(),
                    f.url.unwrap_or_default(),
                    f.http_method.unwrap_or_default(),
                    f.input_type.unwrap_or_default(),
                    f.input_name.unwrap_or_default(),
                    plugin
                        .and_then(|p| p.id)
                        .map(|i| i.to_string())
                        .unwrap_or_default(),
                    plugin.and_then(|p| p.name.clone()).unwrap_or_default(),
                    plugin
                        .and_then(|p| p.risk_factor.clone())
                        .unwrap_or_default(),
                    plugin.and_then(|p| p.synopsis.clone()).unwrap_or_default(),
                    plugin
                        .and_then(|p| p.description.clone())
                        .unwrap_or_default()
                        .replace(['\n', '\r'], " "),
                    plugin.and_then(|p| p.solution.clone()).unwrap_or_default(),
                    plugin
                        .and_then(|p| p.cve.clone())
                        .unwrap_or_default()
                        .join("; "),
                    f.severity.unwrap_or_default(),
                    f.severity_id.map(|i| i.to_string()).unwrap_or_default(),
                    plugin
                        .and_then(|p| p.cvss_base_score)
                        .map(|s| format!("{s:.1}"))
                        .unwrap_or_default(),
                    plugin
                        .and_then(|p| p.cvss3_base_score)
                        .map(|s| format!("{s:.1}"))
                        .unwrap_or_default(),
                    plugin
                        .and_then(|p| p.vpr_score)
                        .map(|s| format!("{s:.1}"))
                        .unwrap_or_default(),
                    scan.and_then(|s| s.scan_id.clone()).unwrap_or_default(),
                    scan.and_then(|s| s.started_at.clone()).unwrap_or_default(),
                    scan.and_then(|s| s.completed_at.clone())
                        .unwrap_or_default(),
                ]
            })
            .collect();

        Ok(rows)
    }
}
