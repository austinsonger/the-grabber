use anyhow::Result;
use async_trait::async_trait;
use github_rs::GithubClient;

use crate::evidence::CsvCollector;

pub struct GithubTeamsCollector {
    pub(crate) client: GithubClient,
}

impl GithubTeamsCollector {
    pub fn new(client: GithubClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for GithubTeamsCollector {
    fn name(&self) -> &str {
        "GitHub Teams"
    }
    fn filename_prefix(&self) -> &str {
        "Github_Teams"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Team ID",
            "Slug",
            "Name",
            "Privacy",
            "Permission",
            "Description",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let teams = self.client.teams().list_all().await?;
        Ok(teams
            .into_iter()
            .map(|t| {
                vec![
                    t.id.to_string(),
                    t.slug,
                    t.name,
                    t.privacy,
                    t.permission,
                    t.description.unwrap_or_default(),
                ]
            })
            .collect())
    }
}

pub struct GithubTeamMembersCollector {
    pub(crate) client: GithubClient,
}

impl GithubTeamMembersCollector {
    pub fn new(client: GithubClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for GithubTeamMembersCollector {
    fn name(&self) -> &str {
        "GitHub Team Members"
    }
    fn filename_prefix(&self) -> &str {
        "Github_Team_Members"
    }
    fn headers(&self) -> &'static [&'static str] {
        &["Team Slug", "Team Name", "Member Login", "Member ID"]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let teams = self.client.teams().list_all().await?;
        let mut rows: Vec<Vec<String>> = Vec::new();
        for t in teams {
            let members = self.client.teams().list_members(&t.slug).await?;
            if members.is_empty() {
                rows.push(vec![
                    t.slug.clone(),
                    t.name.clone(),
                    String::new(),
                    String::new(),
                ]);
                continue;
            }
            for m in members {
                rows.push(vec![
                    t.slug.clone(),
                    t.name.clone(),
                    m.login,
                    m.id.to_string(),
                ]);
            }
        }
        Ok(rows)
    }
}
