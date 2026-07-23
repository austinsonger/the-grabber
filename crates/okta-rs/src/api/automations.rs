//! Okta Automations (lightweight lifecycle automations, e.g. "suspend a
//! user after N days of inactivity"). Schema is the newest/least stable of
//! any endpoint this crate wraps, so entries are returned as raw JSON.

use crate::client::OktaClient;
use crate::error::OktaError;

pub struct AutomationsApi<'c>(pub(crate) &'c OktaClient);

impl<'c> AutomationsApi<'c> {
    /// GET /api/v1/automations
    pub async fn list_all(&self) -> Result<Vec<serde_json::Value>, OktaError> {
        let resp = self.0.get("/api/v1/automations").await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let message = resp.text().await.unwrap_or_default();
            return Err(OktaError::Api { status, message });
        }
        Ok(resp.json().await?)
    }
}
