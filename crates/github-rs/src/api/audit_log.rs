use crate::client::{next_link, GithubClient};
use crate::error::GithubError;
use crate::types::audit_log::GithubAuditLogEvent;

pub struct AuditLogApi<'c>(pub(crate) &'c GithubClient);

impl<'c> AuditLogApi<'c> {
    /// GET /orgs/{org}/audit-log?phrase=created:{since}..{until} — paginated
    /// via Link headers. `since`/`until` are RFC 3339 timestamps.
    /// Requires GitHub Enterprise Cloud; on any other plan this 403s/404s.
    pub async fn events(
        &self,
        since: &str,
        until: &str,
    ) -> Result<Vec<GithubAuditLogEvent>, GithubError> {
        let phrase = format!("created:{}..{}", since, until);
        let first = self.0.url(&format!(
            "/orgs/{}/audit-log?phrase={}&per_page=100",
            self.0.org(),
            urlencode(&phrase)
        ));
        let mut all = Vec::new();
        let mut next: Option<String> = Some(first);
        while let Some(url) = next {
            let resp = self.0.get_absolute(&url).await?;
            if !resp.status().is_success() {
                let status = resp.status().as_u16();
                let message = resp.text().await.unwrap_or_default();
                return Err(GithubError::Api { status, message });
            }
            let link = next_link(&resp);
            let page: Vec<GithubAuditLogEvent> = resp.json().await?;
            all.extend(page);
            next = link;
        }
        Ok(all)
    }
}

/// Minimal RFC 3986 percent-encode for the `phrase` query parameter — the
/// only characters we need to escape are `:` and `Z` context punctuation from
/// RFC 3339 timestamps. Kept dependency-free rather than pulling in `url`.
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
