use anyhow::Result;
use async_trait::async_trait;

use tenable_rs::TenableClient;

use crate::evidence::CsvCollector;

pub struct TenablePciAsvCollector {
    client: TenableClient,
}

impl TenablePciAsvCollector {
    pub fn new(client: TenableClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for TenablePciAsvCollector {
    fn name(&self) -> &str {
        "Tenable PCI ASV Compliance"
    }

    fn filename_prefix(&self) -> &str {
        "Tenable_PCI_ASV_Compliance"
    }

    fn headers(&self) -> &'static [&'static str] {
        &[
            "Asset ID",
            "Hostname",
            "IPv4",
            "Check Name",
            "Status",
            "Policy",
            "Reference",
            "First Found",
            "Last Found",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let findings = self.client.compliance().export_all(None).await?;
        let rows = findings
            .into_iter()
            .map(|f| {
                vec![
                    f.asset.id,
                    f.asset.hostname.unwrap_or_default(),
                    f.asset.ipv4.unwrap_or_default(),
                    f.check_name.unwrap_or_default(),
                    format!("{:?}", f.status),
                    f.policy_name.unwrap_or_default(),
                    f.reference.unwrap_or_default().join("; "),
                    f.first_seen.unwrap_or_default(),
                    f.last_seen.unwrap_or_default(),
                ]
            })
            .collect();
        Ok(rows)
    }
}
