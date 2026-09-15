use anyhow::Result;
use async_trait::async_trait;
use crowdstrike_rs::CrowdStrikeClient;
use serde_json::Value;

use crate::evidence::CsvCollector;

pub struct CrowdStrikeVulnerabilitiesCollector {
    client: CrowdStrikeClient,
}

impl CrowdStrikeVulnerabilitiesCollector {
    pub fn new(client: CrowdStrikeClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for CrowdStrikeVulnerabilitiesCollector {
    fn name(&self) -> &str {
        "CrowdStrike Vulnerabilities"
    }
    fn filename_prefix(&self) -> &str {
        "CrowdStrike_Vulnerabilities"
    }

    fn headers(&self) -> &'static [&'static str] {
        &[
            "Vulnerability ID",
            "CVE ID",
            "Severity",
            "Status",
            "Base Score",
            "Exploit Status",
            "Hostname",
            "Device ID",
            "Platform",
            "Created",
            "Updated",
            "Closed",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let vulns = match self.client.vulnerabilities().list_all().await {
            Ok(v) => v,
            Err(crowdstrike_rs::CrowdStrikeError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };
        let rows = vulns
            .into_iter()
            .map(|v| {
                let cve_id = v
                    .cve
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                let severity = v
                    .cve
                    .get("severity")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                let base_score = v
                    .cve
                    .get("base_score")
                    .map(|s| s.to_string())
                    .unwrap_or_default();
                let exploit_status = v
                    .cve
                    .get("exploit_status")
                    .map(|s| s.to_string())
                    .unwrap_or_default();
                let hostname = v
                    .host_info
                    .get("hostname")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                let device_id = v
                    .host_info
                    .get("instance_id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                let platform = v
                    .host_info
                    .get("platform")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                vec![
                    v.id,
                    cve_id,
                    severity,
                    v.status.unwrap_or_default(),
                    base_score,
                    exploit_status,
                    hostname,
                    device_id,
                    platform,
                    v.created_timestamp.unwrap_or_default(),
                    v.updated_timestamp.unwrap_or_default(),
                    v.closed_timestamp.unwrap_or_default(),
                ]
            })
            .collect();
        Ok(rows)
    }
}
