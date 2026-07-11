use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct JiraProject {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub key: String,
    #[serde(default)]
    pub name: String,
    #[serde(rename = "projectTypeKey", default)]
    pub project_type_key: String,
    #[serde(default)]
    pub style: Option<String>,
    #[serde(default)]
    pub lead: Option<ProjectLead>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProjectLead {
    #[serde(rename = "accountId", default)]
    pub account_id: String,
    #[serde(rename = "displayName", default)]
    pub display_name: String,
}
