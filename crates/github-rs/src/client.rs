use reqwest::{header, Client, Response};
use tokio::time::{sleep, Duration};

use crate::api::{AlertsApi, AuditLogApi, MembersApi, OrgsApi, ReposApi, TeamsApi};
use crate::error::GithubError;

const MAX_RETRIES: u32 = 5;
const DEFAULT_RETRY_SECS: u64 = 60;

/// Async HTTP client for the GitHub REST API, scoped to one org.
///
/// Auth: `Authorization: Bearer <token>` is injected on every request, along
/// with `Accept: application/vnd.github+json` and
/// `X-GitHub-Api-Version: 2022-11-28`.
///
/// Retries only on rate-limit signals (429, or 403 carrying `Retry-After` or
/// `X-RateLimit-Remaining: 0`) — a bare 403 (missing scope, or the org's plan
/// doesn't have this feature) returns immediately instead of burning through
/// retries on a request that will never succeed.
///
/// `GithubClient` is cheaply cloneable — `reqwest::Client` is arc-pooled.
#[derive(Clone)]
pub struct GithubClient {
    pub(crate) http: Client,
    pub(crate) base_url: String,
    pub(crate) org: String,
}

impl GithubClient {
    /// Build a client for one org. `base_url` is the full REST API root —
    /// `https://api.github.com` for GitHub.com, or `https://HOST/api/v3` for
    /// GitHub Enterprise Server. The caller provides it verbatim; this client
    /// never rewrites or guesses a path suffix.
    pub fn new(base_url: &str, token: &str, org: &str) -> Result<Self, GithubError> {
        let trimmed = base_url.trim().trim_end_matches('/');
        if trimmed.is_empty() {
            return Err(GithubError::InvalidBaseUrl(base_url.to_string()));
        }
        let org_trimmed = org.trim();
        if org_trimmed.is_empty() {
            return Err(GithubError::InvalidBaseUrl(
                "org must not be empty".to_string(),
            ));
        }

        let auth = format!("Bearer {token}");
        let mut headers = header::HeaderMap::new();
        headers.insert(header::AUTHORIZATION, header::HeaderValue::from_str(&auth)?);
        headers.insert(
            header::ACCEPT,
            header::HeaderValue::from_static("application/vnd.github+json"),
        );
        headers.insert(
            header::HeaderName::from_static("x-github-api-version"),
            header::HeaderValue::from_static("2022-11-28"),
        );

        let http = Client::builder().default_headers(headers).build()?;
        Ok(Self {
            http,
            base_url: trimmed.to_string(),
            org: org_trimmed.to_string(),
        })
    }

    /// The org this client is scoped to.
    pub fn org(&self) -> &str {
        &self.org
    }

    /// Absolute URL for a path beginning with `/`.
    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    /// GET a relative path. Internal helper.
    pub(crate) async fn get(&self, path: &str) -> Result<Response, GithubError> {
        let url = self.url(path);
        self.send_with_retry(|| self.http.get(&url).send()).await
    }

    /// GET an absolute URL (used for Link-pagination follow-ups). Internal.
    pub(crate) async fn get_absolute(&self, url: &str) -> Result<Response, GithubError> {
        let owned = url.to_string();
        self.send_with_retry(|| self.http.get(&owned).send()).await
    }

    /// Public escape hatch used by integration tests.
    #[doc(hidden)]
    pub async fn raw_get(&self, path: &str) -> Result<Response, GithubError> {
        self.get(path).await
    }

    async fn send_with_retry<F, Fut>(&self, make_req: F) -> Result<Response, GithubError>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<Response, reqwest::Error>>,
    {
        let mut backoff = 1u64;
        for attempt in 0..=MAX_RETRIES {
            let resp = make_req().await?;
            if !is_rate_limited(&resp) || attempt == MAX_RETRIES {
                return Ok(resp);
            }
            let wait = retry_wait(&resp).max(backoff);
            sleep(Duration::from_secs(wait)).await;
            backoff = (backoff * 2).min(DEFAULT_RETRY_SECS);
        }
        unreachable!()
    }

    // API accessors -------------------------------------------------------
    pub fn members(&self) -> MembersApi<'_> {
        MembersApi(self)
    }
    pub fn teams(&self) -> TeamsApi<'_> {
        TeamsApi(self)
    }
    pub fn orgs(&self) -> OrgsApi<'_> {
        OrgsApi(self)
    }
    pub fn repos(&self) -> ReposApi<'_> {
        ReposApi(self)
    }
    pub fn audit_log(&self) -> AuditLogApi<'_> {
        AuditLogApi(self)
    }
    pub fn alerts(&self) -> AlertsApi<'_> {
        AlertsApi(self)
    }
}

/// A 429 is always a rate limit. A 403 only counts as one if it carries a
/// `Retry-After` header (secondary/abuse limit) or `X-RateLimit-Remaining: 0`
/// (primary limit exhausted) — a bare 403 is a permission/plan error that
/// will never succeed on retry.
fn is_rate_limited(resp: &Response) -> bool {
    if resp.status() == 429 {
        return true;
    }
    if resp.status() != 403 {
        return false;
    }
    if resp.headers().contains_key("retry-after") {
        return true;
    }
    resp.headers()
        .get("x-ratelimit-remaining")
        .and_then(|v| v.to_str().ok())
        == Some("0")
}

/// Seconds to wait before retrying. Prefers the explicit `Retry-After` header
/// (secondary/abuse limit — always short, capped defensively at
/// `DEFAULT_RETRY_SECS`), falling back to the primary limit's
/// `X-RateLimit-Reset` (Unix epoch seconds). That fallback is deliberately
/// NOT capped — a primary-limit reset can legitimately be up to an hour away,
/// and returning early would just draw another 403.
fn retry_wait(resp: &Response) -> u64 {
    if let Some(v) = resp.headers().get("retry-after") {
        if let Ok(s) = v.to_str() {
            if let Ok(secs) = s.parse::<u64>() {
                return secs.min(DEFAULT_RETRY_SECS);
            }
        }
    }
    if let Some(v) = resp.headers().get("x-ratelimit-reset") {
        if let Ok(s) = v.to_str() {
            if let Ok(reset_epoch) = s.parse::<i64>() {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                return (reset_epoch - now).max(1) as u64;
            }
        }
    }
    DEFAULT_RETRY_SECS
}

/// Parse RFC 5988 `Link` headers and return the URL with `rel="next"` if any.
///
/// Splits multi-link headers on `,` only when outside `<...>` brackets, so
/// URLs containing commas (e.g. `?phrase=a,b`) are preserved intact.
#[doc(hidden)]
pub fn next_link(resp: &Response) -> Option<String> {
    for v in resp.headers().get_all("link").iter() {
        let s = match v.to_str() {
            Ok(s) => s,
            Err(_) => continue,
        };
        for entry in split_link_entries(s) {
            let trimmed = entry.trim();
            let Some(open) = trimmed.find('<') else {
                continue;
            };
            let Some(close_rel) = trimmed[open + 1..].find('>') else {
                continue;
            };
            let close = open + 1 + close_rel;
            let url = &trimmed[open + 1..close];
            let rest = &trimmed[close + 1..];
            if rest.contains("rel=\"next\"") {
                return Some(url.to_string());
            }
        }
    }
    None
}

/// Split a Link header value into individual entries, treating `,` as a
/// separator only when outside `<...>` brackets.
fn split_link_entries(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut depth = 0;
    let mut start = 0;
    for (i, c) in s.char_indices() {
        match c {
            '<' => depth += 1,
            '>' => {
                if depth > 0 {
                    depth -= 1;
                }
            }
            ',' if depth == 0 => {
                out.push(&s[start..i]);
                start = i + c.len_utf8();
            }
            _ => {}
        }
    }
    out.push(&s[start..]);
    out
}
