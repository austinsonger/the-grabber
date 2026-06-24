use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct OktaUser {
    pub id: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub created: Option<String>,
    #[serde(default)]
    pub activated: Option<String>,
    #[serde(default, rename = "statusChanged")]
    pub status_changed: Option<String>,
    #[serde(default, rename = "lastLogin")]
    pub last_login: Option<String>,
    #[serde(default, rename = "lastUpdated")]
    pub last_updated: Option<String>,
    #[serde(default, rename = "passwordChanged")]
    pub password_changed: Option<String>,
    pub profile: UserProfile,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct UserProfile {
    #[serde(default)]
    pub login: String,
    #[serde(default)]
    pub email: String,
    #[serde(default, rename = "secondEmail")]
    pub second_email: Option<String>,
    #[serde(default, rename = "firstName")]
    pub first_name: Option<String>,
    #[serde(default, rename = "lastName")]
    pub last_name: Option<String>,
    #[serde(default)]
    pub department: Option<String>,
    #[serde(default)]
    pub manager: Option<String>,
}
