use reqwest::{header, Client, Response};
use tokio::time::{sleep, Duration};

use crate::api::{
    AccessReviewsApi, AdminRolesApi, AppsApi, AuthenticatorsApi, AutomationsApi, GroupsApi,
    LifecycleApi, LogStreamsApi, PoliciesApi, SignInWidgetApi, SystemLogApi, ThreatInsightApi,
    UsersApi,
};
use crate::error::OktaError;

const MAX_RETRIES: u32 = 5;
const DEFAULT_RETRY_AFTER_SECS: u64 = 30;

/// Async HTTP client for the Okta REST API.
///
/// Auth: `Authorization: SSWS <api_token>` is injected on every request.
/// Retries 429 responses with exponential backoff, honouring `X-Rate-Limit-Reset`
/// (Unix epoch seconds) when present.
///
/// `OktaClient` is cheaply cloneable — `reqwest::Client` is arc-pooled.
#[derive(Clone)]
pub struct OktaClient {
    pub(crate) http: Client,
    pub(crate) base_url: String,
}

impl OktaClient {
    /// Build a client for a tenant URL (e.g. `https://acme.okta.com`).
    pub fn new(base_url: &str, api_token: &str) -> Result<Self, OktaError> {
        let trimmed = base_url.trim().trim_end_matches('/');
        if trimmed.is_empty() {
            return Err(OktaError::InvalidBaseUrl(base_url.to_string()));
        }
        let auth = format!("SSWS {api_token}");
        let mut headers = header::HeaderMap::new();
        headers.insert(header::AUTHORIZATION, header::HeaderValue::from_str(&auth)?);
        headers.insert(
            header::ACCEPT,
            header::HeaderValue::from_static("application/json"),
        );

        let http = Client::builder().default_headers(headers).build()?;
        Ok(Self {
            http,
            base_url: trimmed.to_string(),
        })
    }

    /// Absolute URL for a path beginning with `/`.
    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    /// GET a relative path. Internal helper.
    pub(crate) async fn get(&self, path: &str) -> Result<Response, OktaError> {
        let url = self.url(path);
        self.send_with_retry(|| self.http.get(&url).send()).await
    }

    /// GET an absolute URL (used for Link-pagination follow-ups). Internal.
    pub(crate) async fn get_absolute(&self, url: &str) -> Result<Response, OktaError> {
        let owned = url.to_string();
        self.send_with_retry(|| self.http.get(&owned).send()).await
    }

    /// Public escape hatch used by integration tests.
    #[doc(hidden)]
    pub async fn raw_get(&self, path: &str) -> Result<Response, OktaError> {
        self.get(path).await
    }

    async fn send_with_retry<F, Fut>(&self, make_req: F) -> Result<Response, OktaError>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<Response, reqwest::Error>>,
    {
        let mut backoff = 1u64;
        for attempt in 0..=MAX_RETRIES {
            let resp = make_req().await?;
            if resp.status() != 429 || attempt == MAX_RETRIES {
                return Ok(resp);
            }
            let wait = parse_retry_after(&resp).max(backoff);
            sleep(Duration::from_secs(wait)).await;
            backoff = (backoff * 2).min(DEFAULT_RETRY_AFTER_SECS);
        }
        unreachable!()
    }

    // API accessors -------------------------------------------------------
    pub fn users(&self) -> UsersApi<'_> {
        UsersApi(self)
    }
    pub fn groups(&self) -> GroupsApi<'_> {
        GroupsApi(self)
    }
    pub fn apps(&self) -> AppsApi<'_> {
        AppsApi(self)
    }
    pub fn policies(&self) -> PoliciesApi<'_> {
        PoliciesApi(self)
    }
    pub fn system_log(&self) -> SystemLogApi<'_> {
        SystemLogApi(self)
    }
    pub fn lifecycle(&self) -> LifecycleApi<'_> {
        LifecycleApi(self)
    }
    pub fn admin_roles(&self) -> AdminRolesApi<'_> {
        AdminRolesApi(self)
    }
    pub fn access_reviews(&self) -> AccessReviewsApi<'_> {
        AccessReviewsApi(self)
    }
    pub fn sign_in_widget(&self) -> SignInWidgetApi<'_> {
        SignInWidgetApi(self)
    }
    pub fn threat_insight(&self) -> ThreatInsightApi<'_> {
        ThreatInsightApi(self)
    }
    pub fn authenticators(&self) -> AuthenticatorsApi<'_> {
        AuthenticatorsApi(self)
    }
    pub fn automations(&self) -> AutomationsApi<'_> {
        AutomationsApi(self)
    }
    pub fn log_streams(&self) -> LogStreamsApi<'_> {
        LogStreamsApi(self)
    }
}

/// Honour `X-Rate-Limit-Reset` (epoch seconds) when present.
/// Returns the seconds-from-now to wait, or the default if the header
/// is missing or unparseable.
fn parse_retry_after(resp: &Response) -> u64 {
    if let Some(v) = resp.headers().get("X-Rate-Limit-Reset") {
        if let Ok(s) = v.to_str() {
            if let Ok(reset_epoch) = s.parse::<i64>() {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                let delta = (reset_epoch - now).max(1) as u64;
                return delta.min(DEFAULT_RETRY_AFTER_SECS);
            }
        }
    }
    DEFAULT_RETRY_AFTER_SECS
}

/// Parse RFC 5988 `Link` headers and return the URL with `rel="next"` if any.
///
/// Splits multi-link headers on `,` only when outside `<...>` brackets, so
/// URLs containing commas (e.g. `?filter=a,b`) are preserved intact.
#[doc(hidden)]
pub fn next_link(resp: &Response) -> Option<String> {
    for v in resp.headers().get_all("link").iter() {
        let s = match v.to_str() {
            Ok(s) => s,
            Err(_) => continue,
        };
        for entry in split_link_entries(s) {
            let trimmed = entry.trim();
            // Format: <https://...>; rel="next"
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
