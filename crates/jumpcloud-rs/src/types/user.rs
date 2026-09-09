use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemUser {
    pub id: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub firstname: String,
    #[serde(default)]
    pub lastname: String,
    #[serde(default)]
    pub activated: bool,
    #[serde(default)]
    pub suspended: bool,
    #[serde(default)]
    pub account_locked: bool,
    #[serde(default)]
    pub mfa: SystemUserMfa,
    #[serde(default)]
    pub password_expired: bool,
    #[serde(default)]
    pub password_expiration_date: Option<String>,
    #[serde(default)]
    pub created: Option<String>,
    #[serde(default)]
    pub department: Option<String>,
    #[serde(default)]
    pub employee_identifier: Option<String>,
    #[serde(default)]
    pub employee_type: Option<String>,
    #[serde(default, rename = "jobTitle")]
    pub job_title: Option<String>,
    #[serde(default)]
    pub manager: Option<String>,
    #[serde(default)]
    pub external_dn: Option<String>,
    #[serde(default)]
    pub external_source_type: Option<String>,
    #[serde(default)]
    pub last_login_attempt: Option<String>,
    #[serde(default)]
    pub associated_tag_count: Option<u64>,
    /// Escape hatch for fields we do not model.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SystemUserMfa {
    #[serde(default)]
    pub configured: bool,
    #[serde(default)]
    pub exclusion: bool,
    #[serde(default)]
    pub configured_factors: Vec<String>,
    #[serde(default)]
    pub exclusion_days: Option<u32>,
}
