use serde::Deserialize;

use crate::client::JamfClient;
use crate::error::JamfError;

#[derive(Debug, Clone, Deserialize)]
pub struct JamfComputer {
    pub id: String,
    pub general: ComputerGeneral,
    pub hardware: ComputerHardware,
    #[serde(rename = "operatingSystem")]
    pub operating_system: ComputerOperatingSystem,
    pub security: ComputerSecurity,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ComputerGeneral {
    #[serde(default)]
    pub name: String,
    #[serde(default, rename = "lastContactTime")]
    pub last_contact_time: Option<String>,
    #[serde(default, rename = "remoteManagement")]
    pub remote_management: RemoteManagement,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RemoteManagement {
    #[serde(default)]
    pub managed: bool,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ComputerHardware {
    #[serde(default)]
    pub model: String,
    #[serde(default, rename = "serialNumber")]
    pub serial_number: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ComputerOperatingSystem {
    #[serde(default)]
    pub version: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ComputerSecurity {
    #[serde(default, rename = "fileVault2Status")]
    pub filevault2_status: String,
}

pub struct ComputersApi<'c>(pub(crate) &'c JamfClient);

impl<'c> ComputersApi<'c> {
    /// GET /api/v1/computers-inventory — full inventory, all sections.
    pub async fn list_all(&self) -> Result<Vec<JamfComputer>, JamfError> {
        self.0
            .get_all_paged("/api/v1/computers-inventory?section=GENERAL&section=HARDWARE&section=OPERATING_SYSTEM&section=SECURITY")
            .await
    }
}
