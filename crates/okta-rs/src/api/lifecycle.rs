//! User lifecycle events (`user.lifecycle.deactivate`, `.suspend`, `.create`,
//! `.activate`) plus HRIS mapping + IdP config reads.

use crate::client::{next_link, OktaClient};
use crate::error::OktaError;
use crate::types::log_event::OktaLogEvent;
use reqwest::Response;

pub struct LifecycleApi<'c>(pub(crate) &'c OktaClient);

impl<'c> LifecycleApi<'c> {
    /// GET /api/v1/logs?filter=eventType eq "{event_type}"&since={since}
    /// Follows Link pagination.
    pub async fn events_all(
        &self,
        event_type: &str,
        since: &str,
    ) -> Result<Vec<OktaLogEvent>, OktaError> {
        let filter = format!("eventType eq \"{event_type}\"");
        let mut all: Vec<OktaLogEvent> = Vec::new();
        let path = format!(
            "/api/v1/logs?since={}&filter={}&limit=1000",
            urlencode(since),
            urlencode(&filter),
        );
        let mut next: Option<String> = Some(self.0.url(&path));
        while let Some(url) = next {
            let resp: Response = self.0.get_absolute(&url).await?;
            if !resp.status().is_success() {
                let status = resp.status().as_u16();
                let message = resp.text().await.unwrap_or_default();
                return Err(OktaError::Api { status, message });
            }
            let link = next_link(&resp);
            let page: Vec<OktaLogEvent> = resp.json().await?;
            all.extend(page);
            next = link;
        }
        Ok(all)
    }

    /// GET /api/v1/mappings
    pub async fn mappings(&self) -> Result<serde_json::Value, OktaError> {
        let resp = self.0.get("/api/v1/mappings").await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let message = resp.text().await.unwrap_or_default();
            return Err(OktaError::Api { status, message });
        }
        Ok(resp.json().await?)
    }

    /// GET /api/v1/idps
    pub async fn idps(&self) -> Result<serde_json::Value, OktaError> {
        let resp = self.0.get("/api/v1/idps").await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let message = resp.text().await.unwrap_or_default();
            return Err(OktaError::Api { status, message });
        }
        Ok(resp.json().await?)
    }
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}
