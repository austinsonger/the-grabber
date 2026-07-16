//! Sign-in widget brand customization + OKTA_SIGN_ON policies.

use crate::client::OktaClient;
use crate::error::OktaError;

pub struct SignInWidgetApi<'c>(pub(crate) &'c OktaClient);

impl<'c> SignInWidgetApi<'c> {
    pub async fn brands(&self) -> Result<serde_json::Value, OktaError> {
        let resp = self.0.get("/api/v1/brands").await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let message = resp.text().await.unwrap_or_default();
            return Err(OktaError::Api { status, message });
        }
        Ok(resp.json().await?)
    }

    pub async fn customized_page(&self, brand_id: &str) -> Result<serde_json::Value, OktaError> {
        let path = format!("/api/v1/brands/{brand_id}/pages/sign-in/customized");
        let resp = self.0.get(&path).await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let message = resp.text().await.unwrap_or_default();
            return Err(OktaError::Api { status, message });
        }
        Ok(resp.json().await?)
    }

    pub async fn sign_on_policies(&self) -> Result<serde_json::Value, OktaError> {
        let resp = self.0.get("/api/v1/policies?type=OKTA_SIGN_ON").await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let message = resp.text().await.unwrap_or_default();
            return Err(OktaError::Api { status, message });
        }
        Ok(resp.json().await?)
    }
}
