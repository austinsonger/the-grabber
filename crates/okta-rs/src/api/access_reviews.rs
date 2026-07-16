//! Access certification campaigns (Okta Identity Governance).

use crate::client::OktaClient;
use crate::error::OktaError;

pub struct AccessReviewsApi<'c>(pub(crate) &'c OktaClient);

impl<'c> AccessReviewsApi<'c> {
    /// GET /governance/api/v1/campaigns (requires Identity Governance license)
    pub async fn campaigns(&self) -> Result<serde_json::Value, OktaError> {
        let resp = self.0.get("/governance/api/v1/campaigns").await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let message = resp.text().await.unwrap_or_default();
            return Err(OktaError::Api { status, message });
        }
        Ok(resp.json().await?)
    }
}
