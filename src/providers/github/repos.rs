use anyhow::Result;
use async_trait::async_trait;
use github_rs::GithubClient;

use crate::evidence::CsvCollector;

pub struct GithubReposCollector {
    pub(crate) client: GithubClient,
}

impl GithubReposCollector {
    pub fn new(client: GithubClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for GithubReposCollector {
    fn name(&self) -> &str {
        "GitHub Repositories"
    }
    fn filename_prefix(&self) -> &str {
        "Github_Repositories"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Repo ID",
            "Name",
            "Full Name",
            "Visibility",
            "Private",
            "Default Branch",
            "Archived",
            "Created At",
            "Pushed At",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let repos = self.client.repos().list_all().await?;
        Ok(repos
            .into_iter()
            .map(|r| {
                vec![
                    r.id.to_string(),
                    r.name,
                    r.full_name,
                    r.visibility,
                    r.private.to_string(),
                    r.default_branch,
                    r.archived.to_string(),
                    r.created_at.unwrap_or_default(),
                    r.pushed_at.unwrap_or_default(),
                ]
            })
            .collect())
    }
}
