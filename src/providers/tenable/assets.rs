use anyhow::Result;
use async_trait::async_trait;

use tenable_rs::TenableClient;

use crate::evidence::CsvCollector;

pub struct TenableAssetsCollector {
    client: TenableClient,
}

impl TenableAssetsCollector {
    pub fn new(client: TenableClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for TenableAssetsCollector {
    fn name(&self) -> &str {
        "Tenable Assets"
    }

    fn filename_prefix(&self) -> &str {
        "Tenable_Assets"
    }

    fn headers(&self) -> &'static [&'static str] {
        &[
            "Asset ID",
            "Hostname",
            "FQDNs",
            "IPv4 Addresses",
            "IPv6 Addresses",
            "MAC Addresses",
            "Operating System",
            "Agent Name",
            "Network Name",
            "Tracking Method",
            "Has Agent",
            "Is Licensed",
            "Exposure Score",
            "Sources",
            "Tags",
            "First Seen",
            "Last Seen",
            "Created At",
            "Updated At",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let assets = match self.client.assets().export_all(None, None).await {
            Ok(a) => a,
            Err(tenable_rs::TenableError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };

        let rows = assets
            .into_iter()
            .map(|a| {
                let tags = a
                    .tags
                    .unwrap_or_default()
                    .into_iter()
                    .map(|t| format!("{}={}", t.key, t.value))
                    .collect::<Vec<_>>()
                    .join("; ");
                let sources = a
                    .sources
                    .unwrap_or_default()
                    .into_iter()
                    .map(|s| s.name)
                    .collect::<Vec<_>>()
                    .join("; ");
                vec![
                    a.id,
                    a.hostname.unwrap_or_default().join("; "),
                    a.fqdn.unwrap_or_default().join("; "),
                    a.ipv4.unwrap_or_default().join("; "),
                    a.ipv6.unwrap_or_default().join("; "),
                    a.mac_address.unwrap_or_default().join("; "),
                    a.operating_system.unwrap_or_default().join("; "),
                    a.agent_name.unwrap_or_default().join("; "),
                    a.network_name.unwrap_or_default(),
                    a.tracking_method.unwrap_or_default(),
                    a.has_agent
                        .map(|b| if b { "YES" } else { "NO" })
                        .unwrap_or_default()
                        .to_string(),
                    a.is_licensed
                        .map(|b| if b { "YES" } else { "NO" })
                        .unwrap_or_default()
                        .to_string(),
                    a.exposure_score
                        .map(|s| format!("{s:.1}"))
                        .unwrap_or_default(),
                    sources,
                    tags,
                    a.first_seen.unwrap_or_default(),
                    a.last_seen.unwrap_or_default(),
                    a.created_at.unwrap_or_default(),
                    a.updated_at.unwrap_or_default(),
                ]
            })
            .collect();

        Ok(rows)
    }
}
