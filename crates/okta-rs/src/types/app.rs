use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct OktaApp {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub status: String,
    #[serde(default, rename = "signOnMode")]
    pub sign_on_mode: Option<String>,
    #[serde(default)]
    pub created: Option<String>,
    #[serde(default, rename = "lastUpdated")]
    pub last_updated: Option<String>,
}
