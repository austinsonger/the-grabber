use crate::client::{next_link, GithubClient};
use crate::error::GithubError;
use crate::types::repo::{GithubBranchProtection, GithubRepo};

pub struct ReposApi<'c>(pub(crate) &'c GithubClient);

impl<'c> ReposApi<'c> {
    /// GET /orgs/{org}/repos?type=all — paginated.
    pub async fn list_all(&self) -> Result<Vec<GithubRepo>, GithubError> {
        let mut all = Vec::new();
        let mut next: Option<String> = Some(self.0.url(&format!(
            "/orgs/{}/repos?type=all&per_page=100",
            self.0.org()
        )));
        while let Some(url) = next {
            let resp = self.0.get_absolute(&url).await?;
            if !resp.status().is_success() {
                let status = resp.status().as_u16();
                let message = resp.text().await.unwrap_or_default();
                return Err(GithubError::Api { status, message });
            }
            let link = next_link(&resp);
            let page: Vec<GithubRepo> = resp.json().await?;
            all.extend(page);
            next = link;
        }
        Ok(all)
    }

    /// GET /repos/{org}/{repo_name}/branches/{branch}/protection.
    /// Returns `Err(GithubError::Api { status: 404, .. })` when the branch has
    /// no protection configured — callers decide how to represent that.
    pub async fn get_branch_protection(
        &self,
        repo_name: &str,
        branch: &str,
    ) -> Result<GithubBranchProtection, GithubError> {
        let path = format!(
            "/repos/{}/{}/branches/{}/protection",
            self.0.org(),
            repo_name,
            branch
        );
        let resp = self.0.get(&path).await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let message = resp.text().await.unwrap_or_default();
            return Err(GithubError::Api { status, message });
        }
        Ok(resp.json().await?)
    }
}
