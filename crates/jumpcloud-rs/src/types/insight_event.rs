use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InsightEvent {
    pub id: String,
    pub event_type: String,
    pub service: String,
    pub timestamp: String,
    #[serde(default)]
    pub initiated_by: Option<serde_json::Value>,
    #[serde(default)]
    pub resource: Option<serde_json::Value>,
    #[serde(default)]
    pub changes: Option<serde_json::Value>,
    #[serde(default)]
    pub geoip: Option<serde_json::Value>,
    #[serde(default)]
    pub useragent: Option<serde_json::Value>,
    #[serde(default)]
    pub success: Option<bool>,
    #[serde(flatten)]
    pub raw: serde_json::Map<String, serde_json::Value>,
}
