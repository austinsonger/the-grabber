use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub id: i64,
    pub uuid: Option<String>,
    pub name: String,
    /// Raw status string from the API (e.g. "completed", "running", "empty", "canceled").
    pub status: String,
    pub enabled: Option<bool>,
    pub creation_date: Option<i64>,
    pub last_modification_date: Option<i64>,
    pub owner: Option<String>,
    pub policy_id: Option<i64>,
    pub folder_id: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanDetails {
    #[serde(flatten)]
    pub summary: ScanSummary,
    pub hosts: Option<Vec<ScanHost>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanHost {
    pub host_id: i64,
    pub hostname: String,
    pub severity: Option<i64>,
    pub critical: Option<i64>,
    pub high: Option<i64>,
    pub medium: Option<i64>,
    pub low: Option<i64>,
    pub info: Option<i64>,
}
