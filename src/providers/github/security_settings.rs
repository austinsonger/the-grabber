use anyhow::Result;
use async_trait::async_trait;
use github_rs::GithubClient;

use crate::evidence::CsvCollector;

pub struct GithubSecuritySettingsCollector {
    pub(crate) client: GithubClient,
}

impl GithubSecuritySettingsCollector {
    pub fn new(client: GithubClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for GithubSecuritySettingsCollector {
    fn name(&self) -> &str {
        "GitHub Org Security Settings"
    }
    fn filename_prefix(&self) -> &str {
        "Github_Org_Security_Settings"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Org Login",
            "Two-Factor Requirement Enabled",
            "Default Repository Permission",
            "Members Can Create Repositories",
            "Members Can Create Private Repositories",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let org = self.client.orgs().get().await?;
        Ok(vec![vec![
            org.login,
            org.two_factor_requirement_enabled
                .map(|b| b.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            org.default_repository_permission.unwrap_or_default(),
            org.members_can_create_repositories
                .map(|b| b.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            org.members_can_create_private_repositories
                .map(|b| b.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
        ]])
    }
}
