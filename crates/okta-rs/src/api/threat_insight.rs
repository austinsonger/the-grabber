//! ThreatInsight-derived System Log events (`security.threat.detected`).

use crate::client::{next_link, OktaClient};
use crate::error::OktaError;
use crate::types::log_event::OktaLogEvent;
use reqwest::Response;

pub struct ThreatInsightApi<'c>(pub(crate) &'c OktaClient);

impl<'c> ThreatInsightApi<'c> {
    pub async fn detections(&self, since: &str) -> Result<Vec<OktaLogEvent>, OktaError> {
        let path = format!(
            "/api/v1/logs?since={}&filter={}&limit=1000",
            urlencode(since),
            urlencode("eventType eq \"security.threat.detected\""),
        );
        let mut all: Vec<OktaLogEvent> = Vec::new();
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
