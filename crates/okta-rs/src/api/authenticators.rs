//! Authenticator enrollment/configuration (password, Okta Verify, smart
//! card/PIV, security key, etc.). Per-authenticator `settings` shape varies
//! by `key`, so entries are returned as raw JSON.

use crate::client::OktaClient;
use crate::error::OktaError;

pub struct AuthenticatorsApi<'c>(pub(crate) &'c OktaClient);

impl<'c> AuthenticatorsApi<'c> {
    /// GET /api/v1/authenticators
    pub async fn list_all(&self) -> Result<Vec<serde_json::Value>, OktaError> {
        let resp = self.0.get("/api/v1/authenticators").await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let message = resp.text().await.unwrap_or_default();
            return Err(OktaError::Api { status, message });
        }
        Ok(resp.json().await?)
    }
}
