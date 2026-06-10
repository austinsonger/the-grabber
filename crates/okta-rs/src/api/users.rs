use crate::client::{next_link, OktaClient};
use crate::error::OktaError;
use crate::types::factor::OktaFactor;
use crate::types::user::OktaUser;

pub struct UsersApi<'c>(pub(crate) &'c OktaClient);

impl<'c> UsersApi<'c> {
    /// GET /api/v1/users — list every user, following Link pagination.
    pub async fn list_all(&self) -> Result<Vec<OktaUser>, OktaError> {
        let mut all = Vec::new();
        let mut next: Option<String> = Some(self.0.url("/api/v1/users?limit=200"));
        while let Some(url) = next {
            let resp = self.0.get_absolute(&url).await?;
            if !resp.status().is_success() {
                let status = resp.status().as_u16();
                let message = resp.text().await.unwrap_or_default();
                return Err(OktaError::Api { status, message });
            }
            let link = next_link(&resp);
            let page: Vec<OktaUser> = resp.json().await?;
            all.extend(page);
            next = link;
        }
        Ok(all)
    }

    /// GET /api/v1/users/{userId}/factors — MFA factors enrolled for one user.
    pub async fn list_factors(&self, user_id: &str) -> Result<Vec<OktaFactor>, OktaError> {
        let path = format!("/api/v1/users/{}/factors", user_id);
        let resp = self.0.get(&path).await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let message = resp.text().await.unwrap_or_default();
            return Err(OktaError::Api { status, message });
        }
        Ok(resp.json().await?)
    }
}
