use anyhow::Result;
use async_trait::async_trait;

use tenable_rs::TenableClient;

use crate::evidence::CsvCollector;

pub struct TenableComplianceCollector {
    client: TenableClient,
}

impl TenableComplianceCollector {
    pub fn new(client: TenableClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for TenableComplianceCollector {
    fn name(&self) -> &str {
        "Tenable Compliance Findings"
    }

    fn filename_prefix(&self) -> &str {
        "Tenable_Compliance_Findings"
    }

    fn headers(&self) -> &'static [&'static str] {
        &[
            // Asset
            "Asset ID",
            "Asset Hostname",
            "Asset FQDN",
            "Asset IPv4",
            // Check
            "Check ID",
            "Check Name",
            "Check Info",
            "Status",
            "Expected Value",
            "Actual Value",
            // Policy
            "Policy Name",
            "Audit File",
            "References",
            // Lifecycle
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
        let findings = match self.client.compliance().export_all(None).await {
            Ok(f) => f,
            Err(tenable_rs::TenableError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };

        let rows = findings
            .into_iter()
            .map(|f| {
                vec![
                    f.asset.id,
                    f.asset.hostname.unwrap_or_default(),
                    f.asset.fqdn.unwrap_or_default(),
                    f.asset.ipv4.unwrap_or_default(),
                    f.check_id.unwrap_or_default(),
                    f.check_name.unwrap_or_default(),
                    f.check_info.unwrap_or_default().replace(['\n', '\r'], " "),
                    format!("{:?}", f.status),
                    f.expected_value.unwrap_or_default(),
                    f.actual_value.unwrap_or_default(),
                    f.policy_name.unwrap_or_default(),
                    f.audit_file.unwrap_or_default(),
                    f.reference.unwrap_or_default().join("; "),
                    f.first_seen.unwrap_or_default(),
                    f.last_seen.unwrap_or_default(),
                ]
            })
            .collect();

        Ok(rows)
    }
}
