use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct GithubOrg {
    pub login: String,
    #[serde(default)]
    pub two_factor_requirement_enabled: Option<bool>,
    #[serde(default)]
    pub default_repository_permission: Option<String>,
    #[serde(default)]
    pub members_can_create_repositories: Option<bool>,
    #[serde(default)]
    pub members_can_create_private_repositories: Option<bool>,
}
