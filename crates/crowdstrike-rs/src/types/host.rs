use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Host {
    pub device_id: String,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub platform_name: Option<String>,
    #[serde(default)]
    pub os_version: Option<String>,
    #[serde(default)]
    pub agent_version: Option<String>,
    #[serde(default)]
    pub first_seen: Option<String>,
    #[serde(default)]
    pub last_seen: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub external_ip: Option<String>,
    #[serde(default)]
    pub local_ip: Option<String>,
    #[serde(default)]
    pub mac_address: Option<String>,
    #[serde(default)]
    pub serial_number: Option<String>,
    #[serde(default)]
    pub system_manufacturer: Option<String>,
    #[serde(default)]
    pub system_product_name: Option<String>,
    #[serde(default)]
    pub reduced_functionality_mode: Option<String>,
}
