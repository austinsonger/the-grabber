use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InsightsEventsQuery {
    pub service: Vec<String>,
    pub start_time: String,
    pub end_time: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub search_after: Option<Vec<serde_json::Value>>,
    pub limit: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InsightsAlertsQuery {
    pub start_time: String,
    pub end_time: String,
    pub limit: u32,
}
