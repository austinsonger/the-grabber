use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct SensorUpdatePolicy {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub platform_name: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
    /// `{build, scheduler: {enabled, ...}, uninstall_protection, ...}` —
    /// kept as raw JSON since the shape varies by platform; read via
    /// `.get(...)` at the collector layer.
    #[serde(default)]
    pub settings: serde_json::Value,
    #[serde(default)]
    pub created_timestamp: Option<String>,
    #[serde(default)]
    pub modified_timestamp: Option<String>,
    #[serde(default)]
    pub created_by: Option<String>,
    #[serde(default)]
    pub modified_by: Option<String>,
}
