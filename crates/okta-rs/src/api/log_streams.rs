//! Log Streaming (continuous export of the system log to an external SIEM,
//! e.g. AWS EventBridge or Splunk Cloud).

use crate::client::OktaClient;
use crate::error::OktaError;

pub struct LogStreamsApi<'c>(pub(crate) &'c OktaClient);

impl<'c> LogStreamsApi<'c> {
    /// GET /api/v1/logStreams
    pub async fn list_all(&self) -> Result<Vec<serde_json::Value>, OktaError> {
        let resp = self.0.get("/api/v1/logStreams").await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let message = resp.text().await.unwrap_or_default();
            return Err(OktaError::Api { status, message });
        }
        Ok(resp.json().await?)
    }
}
