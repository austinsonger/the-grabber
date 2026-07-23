use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Administrator {
    #[serde(rename = "_id", alias = "id")]
    pub id: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub firstname: String,
    #[serde(default)]
    pub lastname: String,
    #[serde(default)]
    pub enable_mfa: bool,
    #[serde(default)]
    pub api_key_binding: Option<String>,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default, rename = "roleName")]
    pub role_name: Option<String>,
    #[serde(default)]
    pub created: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}
