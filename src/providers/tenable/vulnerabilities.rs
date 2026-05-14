use anyhow::Result;
use async_trait::async_trait;

use tenable_rs::TenableClient;

use crate::evidence::CsvCollector;

pub struct TenableVulnerabilitiesCollector {
    client: TenableClient,
}

impl TenableVulnerabilitiesCollector {
    pub fn new(client: TenableClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for TenableVulnerabilitiesCollector {
    fn name(&self) -> &str {
        "Tenable Vulnerability Findings"
    }

    fn filename_prefix(&self) -> &str {
        "Tenable_Vulnerability_Findings"
    }

    fn headers(&self) -> &'static [&'static str] {
        &[
            // Asset
            "Asset ID",
            "Hostname",
            "FQDN",
            "IPv4",
            "IPv6",
            "OS",
            "Device Type",
            // Plugin / Vulnerability
            "Plugin ID",
            "Plugin Name",
            "Family",
            "Synopsis",
            "Description",
            "Solution",
            "CVEs",
            "CPEs",
            "Has Patch",
            // Scoring
            "Severity",
            "Severity ID",
            "Risk Factor",
            "CVSS Base Score",
            "CVSS Vector",
            "CVSS3 Base Score",
            "CVSS3 Vector",
            "VPR Score",
            // Port
            "Port",
            "Protocol",
            "Service",
            // Scan
            "Scan UUID",
            "Scan Started At",
            "Scan Completed At",
            // Lifecycle
            "State",
            "First Found",
            "Last Found",
            "Last Fixed",
            "Source",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let findings = self.client.vulns().export_all(None).await?;

        let rows = findings
            .into_iter()
            .map(|f| {
                vec![
                    // Asset
                    f.asset.id,
                    f.asset.hostname.unwrap_or_default(),
                    f.asset.fqdn.unwrap_or_default().join("; "),
                    f.asset.ipv4.unwrap_or_default().join("; "),
                    f.asset.ipv6.unwrap_or_default().join("; "),
                    f.asset.operating_system.unwrap_or_default().join("; "),
                    f.asset.device_type.unwrap_or_default(),
                    // Plugin
                    f.plugin.id.to_string(),
                    f.plugin.name,
                    f.plugin.family.unwrap_or_default(),
                    f.plugin.synopsis.unwrap_or_default(),
                    f.plugin
                        .description
                        .unwrap_or_default()
                        .replace('\n', " ")
                        .replace('\r', " "),
                    f.plugin.solution.unwrap_or_default(),
                    f.plugin.cve.unwrap_or_default().join("; "),
                    f.plugin.cpe.unwrap_or_default().join("; "),
                    f.plugin
                        .has_patch
                        .map(|b| if b { "YES" } else { "NO" })
                        .unwrap_or_default()
                        .to_string(),
                    // Scoring
                    format!("{:?}", f.severity),
                    f.severity_id.to_string(),
                    f.plugin.risk_factor.unwrap_or_default(),
                    f.plugin
                        .cvss_base_score
                        .map(|s| format!("{s:.1}"))
                        .unwrap_or_default(),
                    f.plugin.cvss_vector.unwrap_or_default(),
                    f.plugin
                        .cvss3_base_score
                        .map(|s| format!("{s:.1}"))
                        .unwrap_or_default(),
                    f.plugin.cvss3_vector.unwrap_or_default(),
                    f.plugin
                        .vpr_score
                        .map(|s| format!("{s:.1}"))
                        .unwrap_or_default(),
                    // Port
                    f.port.port.to_string(),
                    f.port.protocol,
                    f.port.service.unwrap_or_default(),
                    // Scan
                    f.scan.uuid.unwrap_or_default(),
                    f.scan.started_at.unwrap_or_default(),
                    f.scan.completed_at.unwrap_or_default(),
                    // Lifecycle
                    f.state,
                    f.first_found.unwrap_or_default(),
                    f.last_found.unwrap_or_default(),
                    f.last_fixed.unwrap_or_default(),
                    f.source.unwrap_or_default(),
                ]
            })
            .collect();

        Ok(rows)
    }
}
