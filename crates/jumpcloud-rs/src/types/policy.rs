use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    #[serde(rename = "_id", alias = "id")]
    pub id: String,
    pub name: String,
    pub template: PolicyTemplate,
    #[serde(default)]
    pub values: Vec<PolicyValue>,
    #[serde(default)]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyTemplate {
    #[serde(rename = "_id", alias = "id")]
    pub id: String,
    pub name: String,
    #[serde(default, rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub template_type: Option<String>,
    #[serde(default)]
    pub os_meta_family: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyValue {
    #[serde(default)]
    pub config_field_id: Option<String>,
    pub name: String,
    #[serde(default)]
    pub value: serde_json::Value,
    #[serde(default)]
    pub sensitive: Option<bool>,
}
