use anyhow::Result;
use async_trait::async_trait;
use crowdstrike_rs::CrowdStrikeClient;

use crate::evidence::CsvCollector;

pub struct CrowdStrikeHostsCollector {
    client: CrowdStrikeClient,
}

impl CrowdStrikeHostsCollector {
    pub fn new(client: CrowdStrikeClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for CrowdStrikeHostsCollector {
    fn name(&self) -> &str {
        "CrowdStrike Hosts"
    }
    fn filename_prefix(&self) -> &str {
        "CrowdStrike_Hosts"
    }

    fn headers(&self) -> &'static [&'static str] {
        &[
            "Device ID",
            "Hostname",
            "Platform",
            "OS Version",
            "Agent Version",
            "First Seen",
            "Last Seen",
            "Status",
            "External IP",
            "Local IP",
            "MAC Address",
            "Serial Number",
            "System Manufacturer",
            "System Product Name",
            "Reduced Functionality Mode",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let hosts = match self.client.hosts().list_all().await {
            Ok(h) => h,
            Err(crowdstrike_rs::CrowdStrikeError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };
        let rows = hosts
            .into_iter()
            .map(|h| {
                vec![
                    h.device_id,
                    h.hostname.unwrap_or_default(),
                    h.platform_name.unwrap_or_default(),
                    h.os_version.unwrap_or_default(),
                    h.agent_version.unwrap_or_default(),
                    h.first_seen.unwrap_or_default(),
                    h.last_seen.unwrap_or_default(),
                    h.status.unwrap_or_default(),
                    h.external_ip.unwrap_or_default(),
                    h.local_ip.unwrap_or_default(),
                    h.mac_address.unwrap_or_default(),
                    h.serial_number.unwrap_or_default(),
                    h.system_manufacturer.unwrap_or_default(),
                    h.system_product_name.unwrap_or_default(),
                    h.reduced_functionality_mode.unwrap_or_default(),
                ]
            })
            .collect();
        Ok(rows)
    }
}
