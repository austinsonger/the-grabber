use anyhow::Result;
use async_trait::async_trait;

use tenable_rs::TenableClient;

use crate::evidence::CsvCollector;

pub struct TenableWasCollector {
    client: TenableClient,
    /// WAS scan UUIDs selected by the user. When non-empty, findings are
    /// filtered to only those whose scan.scan_id matches. When empty, all
    /// findings across all time are included.
    scan_ids: Vec<String>,
}

impl TenableWasCollector {
    pub fn new(client: TenableClient, scan_ids: Vec<String>) -> Self {
        Self { client, scan_ids }
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
        // WAS export rejects both the `{"filters": ...}` envelope and a `since`
        // field at the top level (Unknown property errors). Send no body params
        // and accept the API's default time window.
        let mut findings = match self.client.was().export_all(None).await {
            Ok(f) => f,
            Err(tenable_rs::TenableError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };

        // If the user selected specific WAS scans, restrict to those.
        if !self.scan_ids.is_empty() {
            findings.retain(|f| {
                f.scan
                    .as_ref()
                    .and_then(|s| s.scan_id.as_deref())
                    .map(|id| self.scan_ids.iter().any(|sel| sel == id))
                    .unwrap_or(false)
            });
        }

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
