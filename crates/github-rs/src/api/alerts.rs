use crate::client::{next_link, GithubClient};
use crate::error::GithubError;
use crate::types::alert::{
    GithubCodeScanningAlert, GithubDependabotAlert, GithubSecretScanningAlert,
};

pub struct AlertsApi<'c>(pub(crate) &'c GithubClient);

impl<'c> AlertsApi<'c> {
    /// GET /orgs/{org}/dependabot/alerts — paginated. Requires Dependabot
    /// alerts enabled for at least one repo in the org.
    pub async fn dependabot_alerts(&self) -> Result<Vec<GithubDependabotAlert>, GithubError> {
        self.paginate(self.0.url(&format!(
            "/orgs/{}/dependabot/alerts?per_page=100",
            self.0.org()
        )))
        .await
    }

    /// GET /orgs/{org}/secret-scanning/alerts — paginated. Requires secret
    /// scanning enabled for at least one repo in the org.
    pub async fn secret_scanning_alerts(
        &self,
    ) -> Result<Vec<GithubSecretScanningAlert>, GithubError> {
        self.paginate(self.0.url(&format!(
            "/orgs/{}/secret-scanning/alerts?per_page=100",
            self.0.org()
        )))
        .await
    }

    /// GET /orgs/{org}/code-scanning/alerts — paginated. Requires code
    /// scanning (e.g. CodeQL) configured for at least one repo in the org.
    pub async fn code_scanning_alerts(&self) -> Result<Vec<GithubCodeScanningAlert>, GithubError> {
        self.paginate(self.0.url(&format!(
            "/orgs/{}/code-scanning/alerts?per_page=100",
            self.0.org()
        )))
        .await
    }

    async fn paginate<T: serde::de::DeserializeOwned>(
        &self,
        first_url: String,
    ) -> Result<Vec<T>, GithubError> {
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
            let page: Vec<T> = resp.json().await?;
            all.extend(page);
            next = link;
        }
        Ok(all)
    }
}
