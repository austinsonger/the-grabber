use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct System {
    #[serde(rename = "_id", alias = "id")]
    pub id: String,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub os: String,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub arch: Option<String>,
    #[serde(default)]
    pub agent_version: Option<String>,
    #[serde(default)]
    pub active: bool,
    #[serde(default)]
    pub allow_ssh_password_authentication: bool,
    #[serde(default)]
    pub allow_ssh_root_login: bool,
    #[serde(default)]
    pub allow_multi_factor_authentication: bool,
    #[serde(default)]
    pub allow_public_key_authentication: bool,
    #[serde(default)]
    pub created: Option<String>,
    #[serde(default)]
    pub last_contact: Option<String>,
    #[serde(default)]
    pub template_name: Option<String>,
    #[serde(default)]
    pub remote_ip: Option<String>,
    #[serde(default)]
    pub fde: Option<Fde>,
    #[serde(default)]
    pub os_meta: Option<serde_json::Value>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fde {
    #[serde(default)]
    pub active: bool,
    #[serde(default)]
    pub key_present: bool,
}
