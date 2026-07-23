use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct CaseUser {
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub full_name: Option<String>,
}

/// A single Security Solution case as returned by the Kibana Cases API.
#[derive(Debug, Clone, Deserialize)]
pub struct Case {
    pub id: String,
    pub title: String,
    pub status: String,
    pub severity: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default, rename = "totalAlerts")]
    pub total_alerts: i64,
    pub created_at: String,
    pub created_by: CaseUser,
    pub updated_at: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CasesFindResponse {
    pub cases: Vec<Case>,
    pub total: u64,
}
