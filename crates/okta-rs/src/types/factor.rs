use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct OktaFactor {
    pub id: String,
    #[serde(default, rename = "factorType")]
    pub factor_type: String,
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default, rename = "vendorName")]
    pub vendor_name: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub created: Option<String>,
    #[serde(default, rename = "lastUpdated")]
    pub last_updated: Option<String>,
    #[serde(default)]
    pub profile: serde_json::Value,
}
