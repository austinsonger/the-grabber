use serde::Deserialize;

use crate::client::JamfClient;
use crate::error::JamfError;

#[derive(Debug, Clone, Deserialize)]
pub struct JamfMobileDevice {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default, rename = "serialNumber")]
    pub serial_number: String,
    #[serde(default)]
    pub model: String,
    #[serde(default, rename = "osVersion")]
    pub os_version: String,
    #[serde(default, rename = "lastEnrolledDate")]
    pub last_enrolled_date: Option<String>,
    #[serde(default)]
    pub managed: bool,
    #[serde(default)]
    pub supervised: bool,
}

pub struct MobileDevicesApi<'c>(pub(crate) &'c JamfClient);

impl<'c> MobileDevicesApi<'c> {
    /// GET /api/v2/mobile-devices/detail — full inventory.
    pub async fn list_all(&self) -> Result<Vec<JamfMobileDevice>, JamfError> {
        self.0.get_all_paged("/api/v2/mobile-devices/detail").await
    }
}
