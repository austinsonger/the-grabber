use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Alert {
    pub id: String,
    #[serde(default)]
    pub composite_id: Option<String>,
    #[serde(default)]
    pub created_timestamp: Option<String>,
    #[serde(default)]
    pub updated_timestamp: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub severity: Option<i64>,
    #[serde(default)]
    pub severity_name: Option<String>,
    #[serde(default, rename = "type")]
    pub alert_type: Option<String>,
    #[serde(default)]
    pub product: Option<String>,
    #[serde(default)]
    pub tactic: Option<String>,
    #[serde(default)]
    pub technique: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
    /// Nested device summary — shape varies slightly by alert product, kept
    /// as raw JSON and read via `.get(...)` at the collector layer.
    #[serde(default)]
    pub device: serde_json::Value,
}
