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
    /// HAL links, e.g. `_links.accessPolicy.href` (the Identity Engine
    /// Authentication Policy assigned to this app). Shape varies per app
    /// type, so kept as raw JSON.
    #[serde(default, rename = "_links")]
    pub links: serde_json::Value,
}
