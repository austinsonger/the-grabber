use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetRecord {
    pub id:                         String,
    pub fqdn:                       Option<Vec<String>>,
    pub ipv4:                       Option<Vec<String>>,
    pub ipv6:                       Option<Vec<String>>,
    pub mac_address:                Option<Vec<String>>,
    pub hostname:                   Option<Vec<String>>,
    pub operating_system:           Option<Vec<String>>,
    pub agent_name:                 Option<Vec<String>>,
    pub bios_uuid:                  Option<Vec<String>>,
    pub installed_software:         Option<Vec<String>>,
    pub network_interfaces:         Option<Vec<NetworkInterface>>,
    pub tags:                       Option<Vec<Tag>>,
    pub sources:                    Option<Vec<AssetSource>>,
    pub ssh_fingerprints:           Option<Vec<String>>,

    // Timestamps
    pub created_at:                 Option<String>,
    pub updated_at:                 Option<String>,
    pub deleted_at:                 Option<String>,
    pub first_seen:                 Option<String>,
    pub last_seen:                  Option<String>,
    pub last_authenticated_results: Option<String>,
    pub last_licensed_scan_results: Option<String>,
    pub last_scan_target:           Option<String>,
    pub terminated_at:              Option<String>,

    // Identity / network
    pub network_id:    Option<String>,
    pub network_name:  Option<String>,
    pub tracking_method: Option<String>,

    // Lifecycle flags
    pub has_agent:          Option<bool>,
    pub has_plugin_results: Option<bool>,
    pub is_deleted:         Option<bool>,
    pub is_licensed:        Option<bool>,
    pub is_public:          Option<bool>,

    // Risk
    pub exposure_score: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub name:        Option<String>,
    pub ipv4:        Option<Vec<String>>,
    pub ipv6:        Option<Vec<String>>,
    pub mac_address: Option<Vec<String>>,
    pub fqdn:        Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tag {
    pub key:   String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetSource {
    pub name:       String,
    pub first_seen: Option<String>,
    pub last_seen:  Option<String>,
}
