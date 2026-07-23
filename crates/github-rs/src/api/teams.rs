use crate::client::{next_link, GithubClient};
use crate::error::GithubError;
use crate::types::team::GithubTeam;
use crate::types::user::GithubUser;

pub struct TeamsApi<'c>(pub(crate) &'c GithubClient);

impl<'c> TeamsApi<'c> {
    /// GET /orgs/{org}/teams — paginated.
    pub async fn list_all(&self) -> Result<Vec<GithubTeam>, GithubError> {
        let mut all = Vec::new();
        let mut next: Option<String> =
            Some(self.0.url(&format!("/orgs/{}/teams?per_page=100", self.0.org())));
        while let Some(url) = next {
            let resp = self.0.get_absolute(&url).await?;
            if !resp.status().is_success() {
                let status = resp.status().as_u16();
                let message = resp.text().await.unwrap_or_default();
                return Err(GithubError::Api { status, message });
            }
            let link = next_link(&resp);
            let page: Vec<GithubTeam> = resp.json().await?;
            all.extend(page);
            next = link;
        }
        Ok(all)
    }

    /// GET /orgs/{org}/teams/{team_slug}/members — paginated.
    pub async fn list_members(&self, team_slug: &str) -> Result<Vec<GithubUser>, GithubError> {
        let mut all = Vec::new();
        let mut next: Option<String> = Some(self.0.url(&format!(
            "/orgs/{}/teams/{}/members?per_page=100",
            self.0.org(),
            team_slug
        )));
        while let Some(url) = next {
            let resp = self.0.get_absolute(&url).await?;
            if !resp.status().is_success() {
                let status = resp.status().as_u16();
                let message = resp.text().await.unwrap_or_default();
                return Err(GithubError::Api { status, message });
            }
            let link = next_link(&resp);
            let page: Vec<GithubUser> = resp.json().await?;
            all.extend(page);
            next = link;
        }
        Ok(all)
    }
}
