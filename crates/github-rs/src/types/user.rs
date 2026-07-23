use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct GithubUser {
    pub login: String,
    pub id: i64,
    #[serde(default, rename = "type")]
    pub user_type: String,
    #[serde(default)]
    pub site_admin: bool,
}
