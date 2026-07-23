use serde::Deserialize;

/// A single detection rule as returned by the Kibana Detection Engine API.
#[derive(Debug, Clone, Deserialize)]
pub struct DetectionRule {
    pub id: String,
    pub rule_id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub rule_type: String,
    pub enabled: bool,
    pub severity: String,
    pub risk_score: u64,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub author: Vec<String>,
    pub interval: String,
    #[serde(default)]
    pub index: Option<Vec<String>>,
    pub max_signals: Option<u64>,
    #[serde(default)]
    pub false_positives: Vec<String>,
    #[serde(default)]
    pub references: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct RulesFindResponse {
    pub data: Vec<DetectionRule>,
    pub total: u64,
}
