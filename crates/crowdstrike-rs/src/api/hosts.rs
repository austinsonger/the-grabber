use serde::Deserialize;

use crate::client::CrowdStrikeClient;
use crate::error::CrowdStrikeError;
use crate::types::host::Host;

pub struct HostsApi<'c>(pub(crate) &'c CrowdStrikeClient);

#[derive(Debug, Deserialize)]
struct DevicesResponse {
    #[serde(default)]
    resources: Vec<Host>,
}

impl<'c> HostsApi<'c> {
    /// GET /devices/combined/devices/v1 — full host inventory.
    /// Offset-paginated: stops when a page returns fewer than `limit` rows.
    pub async fn list_all(&self) -> Result<Vec<Host>, CrowdStrikeError> {
        let limit = 500u32;
        let mut offset = 0u32;
        let mut all = Vec::new();
        loop {
            let path = format!("/devices/combined/devices/v1?limit={limit}&offset={offset}");
            let resp = self.0.get(&path).await?;
            if !resp.status().is_success() {
                let status = resp.status().as_u16();
                let message = resp.text().await.unwrap_or_default();
                return Err(CrowdStrikeError::Api { status, message });
            }
            let page: DevicesResponse = resp.json().await?;
            let got = page.resources.len() as u32;
            all.extend(page.resources);
            if got < limit {
                break;
            }
            offset += got;
        }
        Ok(all)
    }
}
