//! Admin role assignments per user + role catalog.

use crate::client::OktaClient;
use crate::error::OktaError;

pub struct AdminRolesApi<'c>(pub(crate) &'c OktaClient);

impl<'c> AdminRolesApi<'c> {
    /// GET /api/v1/users/{user_id}/roles
    pub async fn roles_for(&self, user_id: &str) -> Result<serde_json::Value, OktaError> {
        let path = format!("/api/v1/users/{user_id}/roles");
        let resp = self.0.get(&path).await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let message = resp.text().await.unwrap_or_default();
            return Err(OktaError::Api { status, message });
        }
        Ok(resp.json().await?)
    }

    /// GET /api/v1/iam/roles
    pub async fn catalog(&self) -> Result<serde_json::Value, OktaError> {
        let resp = self.0.get("/api/v1/iam/roles").await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let message = resp.text().await.unwrap_or_default();
            return Err(OktaError::Api { status, message });
        }
        Ok(resp.json().await?)
    }
}
