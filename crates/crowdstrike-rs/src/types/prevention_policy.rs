use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct PreventionPolicy {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub platform_name: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub precedence: Option<i64>,
    #[serde(default)]
    pub created_timestamp: Option<String>,
    #[serde(default)]
    pub modified_timestamp: Option<String>,
    #[serde(default)]
    pub created_by: Option<String>,
    #[serde(default)]
    pub modified_by: Option<String>,
}
