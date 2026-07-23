use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Organization {
    #[serde(rename = "_id", alias = "id")]
    pub id: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub settings: Option<serde_json::Value>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}
