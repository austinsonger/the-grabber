use crate::client::TenableClient;
use crate::error::TenableError;
use crate::export::check_response;
use crate::types::audit::AuditEvent;

const DEFAULT_EVENT_LIMIT: u32 = 100;

pub struct AuditLogApi<'c>(pub(crate) &'c TenableClient);

/// Parameters for filtering and paginating audit log events.
#[derive(Default)]
pub struct EventsParams<'a> {
    /// Maximum records per page (default: 100).
    pub limit:  Option<u32>,
    /// Cursor token from a previous response to continue pagination.
    pub next:   Option<&'a str>,
    /// Filter expressions (e.g. `"action:user.login"`).
    pub filter: Option<&'a str>,
    /// Sort order (e.g. `"timestamp:asc"`).
    pub sort:   Option<&'a str>,
}

impl<'c> AuditLogApi<'c> {
    /// Fetch one page of audit log events.
    ///
    /// Returns the events and an optional cursor for the next page.
    /// Call again with `params.next = Some(cursor)` until `next_cursor` is `None`.
    pub async fn events(
        &self,
        params: EventsParams<'_>,
    ) -> Result<(Vec<AuditEvent>, Option<String>), TenableError> {
        let path = build_path(&params);
        let resp = self.0.get(&path).await?;
        let resp = check_response(resp).await?;

        #[derive(serde::Deserialize)]
        struct Response {
            events: Vec<AuditEvent>,
            #[serde(default)]
            pagination: Option<Pagination>,
        }
        #[derive(serde::Deserialize)]
        struct Pagination { next: Option<String> }

        let body: Response = resp.json().await?;
        let cursor = body.pagination.and_then(|p| p.next);
        Ok((body.events, cursor))
    }

    /// Collect all audit log events, following pagination cursors automatically.
    pub async fn events_all(&self, limit: Option<u32>) -> Result<Vec<AuditEvent>, TenableError> {
        let mut all = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let params = EventsParams {
                limit,
                next: cursor.as_deref(),
                ..Default::default()
            };
            let (page, next_cursor) = self.events(params).await?;
            all.extend(page);
            match next_cursor {
                Some(c) => cursor = Some(c),
                None    => break,
            }
        }
        Ok(all)
    }
}

fn build_path(params: &EventsParams<'_>) -> String {
    let limit = params.limit.unwrap_or(DEFAULT_EVENT_LIMIT);
    let mut qs = format!("?limit={}", limit);
    if let Some(next) = params.next   { qs.push_str(&format!("&next={}", next)); }
    if let Some(f)    = params.filter { qs.push_str(&format!("&f={}", f)); }
    if let Some(s)    = params.sort   { qs.push_str(&format!("&sort={}", s)); }
    format!("/audit-log/v1/events{}", qs)
}
