use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct OktaPolicy {
    pub id: String,
    #[serde(default, rename = "type")]
    pub policy_type: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub priority: Option<i64>,
    #[serde(default)]
    pub system: Option<bool>,
    #[serde(default)]
    pub created: Option<String>,
    #[serde(default, rename = "lastUpdated")]
    pub last_updated: Option<String>,
    /// Settings shape varies per policy type — keep as raw JSON for the
    /// JsonCollector to write through unchanged.
    #[serde(default)]
    pub settings: serde_json::Value,
    #[serde(default)]
    pub conditions: serde_json::Value,
}
