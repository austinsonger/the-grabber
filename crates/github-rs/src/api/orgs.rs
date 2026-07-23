use crate::client::GithubClient;
use crate::error::GithubError;
use crate::types::org::GithubOrg;

pub struct OrgsApi<'c>(pub(crate) &'c GithubClient);

impl<'c> OrgsApi<'c> {
    /// GET /orgs/{org} — single-record org settings snapshot.
    pub async fn get(&self) -> Result<GithubOrg, GithubError> {
        let path = format!("/orgs/{}", self.0.org());
        let resp = self.0.get(&path).await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let message = resp.text().await.unwrap_or_default();
            return Err(GithubError::Api { status, message });
        }
        Ok(resp.json().await?)
    }
}
