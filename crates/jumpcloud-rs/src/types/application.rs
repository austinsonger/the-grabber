use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Application {
    #[serde(rename = "_id", alias = "id")]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub display_label: Option<String>,
    #[serde(default)]
    pub sso_url: Option<String>,
    #[serde(default)]
    pub active: bool,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub learn_more: Option<String>,
    #[serde(default)]
    pub sso: Option<serde_json::Value>,
    #[serde(default)]
    pub config: Option<serde_json::Value>,
    #[serde(default)]
    pub created: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}
