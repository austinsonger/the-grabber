use serde::Deserialize;

/// A single exception list (a container of exception items).
#[derive(Debug, Clone, Deserialize)]
pub struct ExceptionList {
    pub list_id: String,
    pub namespace_type: String,
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ExceptionListsFindResponse {
    pub data: Vec<ExceptionList>,
    pub total: u64,
}

/// A single exception item (an entry within an exception list).
#[derive(Debug, Clone, Deserialize)]
pub struct ExceptionListItem {
    pub id: String,
    pub item_id: String,
    pub list_id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(rename = "type")]
    pub item_type: String,
    #[serde(default)]
    pub tags: Vec<String>,
    pub entries: Vec<serde_json::Value>,
    pub created_at: String,
    pub created_by: String,
    pub updated_at: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ExceptionItemsFindResponse {
    pub data: Vec<ExceptionListItem>,
    pub total: u64,
}
