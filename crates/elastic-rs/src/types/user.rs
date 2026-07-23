use serde::Deserialize;

/// One Elasticsearch security user (either a built-in system account like
/// `kibana_system`, or a custom user). `username` is not part of the raw
/// JSON body — the Elasticsearch `_security/user` response keys each user
/// object by username — so it's populated by the API layer from the map key.
#[derive(Debug, Clone)]
pub struct SecurityUser {
    pub username: String,
    pub roles: Vec<String>,
    pub full_name: Option<String>,
    pub email: Option<String>,
    pub enabled: bool,
}

#[derive(Debug, Deserialize)]
pub(crate) struct SecurityUserRaw {
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub full_name: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub enabled: bool,
}
