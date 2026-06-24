use crate::client::{next_link, OktaClient};
use crate::error::OktaError;
use crate::types::log_event::OktaLogEvent;

pub struct SystemLogApi<'c>(pub(crate) &'c OktaClient);

impl<'c> SystemLogApi<'c> {
    /// GET /api/v1/logs?since={ISO8601}&until={ISO8601}
    /// One page only. `filter` is an optional Okta SCIM filter expression.
    pub async fn events(
        &self,
        since: &str,
        until: &str,
        filter: Option<&str>,
    ) -> Result<Vec<OktaLogEvent>, OktaError> {
        let mut path = format!(
            "/api/v1/logs?since={}&until={}&limit=1000",
            urlencode(since),
            urlencode(until),
        );
        if let Some(f) = filter {
            path.push_str(&format!("&filter={}", urlencode(f)));
        }
        let resp = self.0.get(&path).await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let message = resp.text().await.unwrap_or_default();
            return Err(OktaError::Api { status, message });
        }
        Ok(resp.json().await?)
    }

    /// Follow Link-header pagination until exhausted.
    pub async fn events_all(
        &self,
        since: &str,
        until: &str,
        filter: Option<&str>,
    ) -> Result<Vec<OktaLogEvent>, OktaError> {
        let mut all = Vec::new();
        let mut first_path = format!(
            "/api/v1/logs?since={}&until={}&limit=1000",
            urlencode(since),
            urlencode(until),
        );
        if let Some(f) = filter {
            first_path.push_str(&format!("&filter={}", urlencode(f)));
        }
        let mut next: Option<String> = Some(self.0.url(&first_path));
        while let Some(url) = next {
            let resp = self.0.get_absolute(&url).await?;
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

/// Minimal RFC 3986 percent-encode for ISO 8601 timestamps and SCIM filters.
/// Encodes everything except unreserved characters.
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
