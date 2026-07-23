use crate::client::{next_link, GithubClient};
use crate::error::GithubError;
use crate::types::user::GithubUser;

pub struct MembersApi<'c>(pub(crate) &'c GithubClient);

impl<'c> MembersApi<'c> {
    /// GET /orgs/{org}/members?role={role} — "admin" or "member". Paginated.
    pub async fn list_by_role(&self, role: &str) -> Result<Vec<GithubUser>, GithubError> {
        let first = self.0.url(&format!(
            "/orgs/{}/members?role={}&per_page=100",
            self.0.org(),
            role
        ));
        self.paginate(first).await
    }

    /// GET /orgs/{org}/members?filter=2fa_disabled — requires an org-owner
    /// token; callers should treat a 403 here as "unknown", not a hard error.
    pub async fn list_2fa_disabled(&self) -> Result<Vec<GithubUser>, GithubError> {
        let first = self.0.url(&format!(
            "/orgs/{}/members?filter=2fa_disabled&per_page=100",
            self.0.org()
        ));
        self.paginate(first).await
    }

    async fn paginate(&self, first_url: String) -> Result<Vec<GithubUser>, GithubError> {
        let mut all = Vec::new();
        let mut next: Option<String> = Some(first_url);
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
