use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct GithubRepo {
    pub id: i64,
    pub name: String,
    pub full_name: String,
    #[serde(default)]
    pub private: bool,
    #[serde(default)]
    pub visibility: String,
    #[serde(default)]
    pub default_branch: String,
    #[serde(default)]
    pub archived: bool,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub pushed_at: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct GithubBranchProtection {
    #[serde(default)]
    pub enforce_admins: Option<EnforceAdmins>,
    #[serde(default)]
    pub required_pull_request_reviews: Option<RequiredPullRequestReviews>,
    #[serde(default)]
    pub required_status_checks: Option<RequiredStatusChecks>,
    #[serde(default)]
    pub allow_force_pushes: Option<ToggleSetting>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EnforceAdmins {
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ToggleSetting {
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RequiredPullRequestReviews {
    #[serde(default)]
    pub required_approving_review_count: Option<i64>,
    #[serde(default)]
    pub require_code_owner_reviews: Option<bool>,
    #[serde(default)]
    pub dismiss_stale_reviews: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RequiredStatusChecks {
    #[serde(default)]
    pub strict: bool,
    #[serde(default)]
    pub contexts: Vec<String>,
}
