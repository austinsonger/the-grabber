use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InsightAlert {
    pub id: String,
    #[serde(alias = "type")]
    pub alert_type: String,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub first_occurred: Option<String>,
    #[serde(default)]
    pub last_occurred: Option<String>,
    #[serde(default)]
    pub occurrences: u64,
    #[serde(default)]
    pub organization: String,
    #[serde(default)]
    pub related_events: Option<Vec<String>>,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(flatten)]
    pub raw: serde_json::Map<String, serde_json::Value>,
}
