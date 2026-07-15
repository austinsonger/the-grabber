//! GCP SCC organization settings configuration.

use anyhow::Result;
use async_trait::async_trait;

use crate::evidence::CsvCollector;
use crate::providers::gcp::client::GcpClient;

pub struct SccConfigCollector {
    client: GcpClient,
    org_id: String,
}

impl SccConfigCollector {
    pub fn new(client: GcpClient, org_id: impl Into<String>) -> Self {
        Self {
            client,
            org_id: org_id.into(),
        }
    }
}

#[async_trait]
impl CsvCollector for SccConfigCollector {
    fn name(&self) -> &str {
        "GCP SCC Config"
    }
    fn filename_prefix(&self) -> &str {
        "GCP_SCC_Config"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "org_id",
            "name",
            "enable_asset_discovery",
            "asset_discovery_config",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        if self.org_id.is_empty() {
            return Ok(Vec::new());
        }
        let url = format!(
            "https://securitycenter.googleapis.com/v1/organizations/{}/organizationSettings",
            self.org_id
        );
        let resp = self.client.get(&url).await?;
        let body: serde_json::Value = resp.json().await?;
        let row = vec![
            self.org_id.clone(),
            body.get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned(),
            body.get("enableAssetDiscovery")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
                .to_string(),
            body.get("assetDiscoveryConfig")
                .map(|v| serde_json::to_string(v).unwrap_or_default())
                .unwrap_or_default(),
        ];
        Ok(vec![row])
    }
}
