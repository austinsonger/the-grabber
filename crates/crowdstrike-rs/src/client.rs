use std::sync::Arc;

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use reqwest::{Client, Response};
use serde::Deserialize;
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration};

use crate::api::{
    AlertsApi, HostsApi, PreventionPoliciesApi, SensorUpdatePoliciesApi, VulnerabilitiesApi,
};
use crate::error::CrowdStrikeError;

const MAX_RETRIES: u32 = 5;
const DEFAULT_RETRY_AFTER_SECS: u64 = 30;
/// Refresh the token this many seconds before its reported expiry.
const TOKEN_REFRESH_SKEW_SECS: i64 = 60;

/// Async HTTP client for the CrowdStrike Falcon REST API.
///
/// Auth: OAuth2 client-credentials grant (`POST /oauth2/token`). The bearer
/// token is cached and transparently refreshed ~60s before its reported
/// `expires_in` (Falcon tokens have a ~30 minute lifespan). Retries HTTP 429
/// with exponential backoff, and retries a 401 exactly once by forcing a
/// fresh token fetch (covers a token revoked or expired mid-flight).
///
/// `CrowdStrikeClient` is cheaply cloneable — the token cache is shared via
/// `Arc<Mutex<_>>` so every clone observes the same refreshed token.
#[derive(Clone)]
pub struct CrowdStrikeClient {
    http: Client,
    base_url: String,
    client_id: String,
    client_secret: String,
    token: Arc<Mutex<TokenState>>,
}

#[derive(Default)]
struct TokenState {
    access_token: String,
    expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: i64,
}

impl CrowdStrikeClient {
    /// Build a client for a Falcon cloud base URL (e.g. `https://api.crowdstrike.com`).
    /// No network call is made until the first request needs a token.
    pub fn new(
        base_url: &str,
        client_id: &str,
        client_secret: &str,
    ) -> Result<Self, CrowdStrikeError> {
        let trimmed = base_url.trim().trim_end_matches('/');
        if trimmed.is_empty() {
            return Err(CrowdStrikeError::InvalidBaseUrl(base_url.to_string()));
        }
        let http = Client::builder().build()?;
        Ok(Self {
            http,
            base_url: trimmed.to_string(),
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            token: Arc::new(Mutex::new(TokenState::default())),
        })
    }

    /// Absolute URL for a path beginning with `/`.
    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    /// Return a valid bearer token, fetching or refreshing it if necessary.
    async fn ensure_token(&self) -> Result<String, CrowdStrikeError> {
        let mut state = self.token.lock().await;
        let needs_refresh = match state.expires_at {
            Some(exp) => Utc::now() >= exp - ChronoDuration::seconds(TOKEN_REFRESH_SKEW_SECS),
            None => true,
        };
        if needs_refresh {
            let (token, expires_in) = self.fetch_token().await?;
            state.access_token = token;
            state.expires_at = Some(Utc::now() + ChronoDuration::seconds(expires_in));
        }
        Ok(state.access_token.clone())
    }

    /// Force the next `ensure_token()` call to fetch a fresh token regardless
    /// of the cached expiry. Called after a 401 response.
    async fn invalidate_token(&self) {
        let mut state = self.token.lock().await;
        state.expires_at = None;
    }

    async fn fetch_token(&self) -> Result<(String, i64), CrowdStrikeError> {
        let url = self.url("/oauth2/token");
        let params = [
            ("client_id", self.client_id.as_str()),
            ("client_secret", self.client_secret.as_str()),
        ];
        let resp = self.http.post(&url).form(&params).send().await?;
        let status = resp.status();
        if !status.is_success() {
            let message = resp.text().await.unwrap_or_default();
            return Err(CrowdStrikeError::Auth {
                status: status.as_u16(),
                message,
            });
        }
        let body: TokenResponse = resp.json().await?;
        Ok((body.access_token, body.expires_in))
    }

    async fn send_with_retry<F, Fut>(&self, make_req: F) -> Result<Response, CrowdStrikeError>
    where
        F: Fn(String) -> Fut,
        Fut: std::future::Future<Output = Result<Response, reqwest::Error>>,
    {
        let mut backoff = 1u64;
        let mut retried_auth = false;
        for attempt in 0..=MAX_RETRIES {
            let token = self.ensure_token().await?;
            let resp = make_req(token).await?;
            if resp.status().as_u16() == 401 && !retried_auth {
                retried_auth = true;
                self.invalidate_token().await;
                continue;
            }
            if resp.status() != 429 || attempt == MAX_RETRIES {
                return Ok(resp);
            }
            let wait = parse_retry_after(&resp).max(backoff);
            sleep(Duration::from_secs(wait)).await;
            backoff = (backoff * 2).min(DEFAULT_RETRY_AFTER_SECS);
        }
        unreachable!()
    }

    /// Execute a GET request, injecting the current bearer token.
    pub(crate) async fn get(&self, path: &str) -> Result<Response, CrowdStrikeError> {
        let url = self.url(path);
        self.send_with_retry(|token| self.http.get(&url).bearer_auth(token).send())
            .await
    }

    /// Execute a POST request with a JSON body, injecting the current bearer token.
    pub(crate) async fn post_json(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<Response, CrowdStrikeError> {
        let url = self.url(path);
        self.send_with_retry(|token| self.http.post(&url).bearer_auth(token).json(body).send())
            .await
    }

    /// Public escape hatch used by integration tests.
    #[doc(hidden)]
    pub async fn raw_get(&self, path: &str) -> Result<Response, CrowdStrikeError> {
        self.get(path).await
    }

    pub fn hosts(&self) -> HostsApi<'_> {
        HostsApi(self)
    }
    pub fn alerts(&self) -> AlertsApi<'_> {
        AlertsApi(self)
    }
    pub fn vulnerabilities(&self) -> VulnerabilitiesApi<'_> {
        VulnerabilitiesApi(self)
    }
    pub fn prevention_policies(&self) -> PreventionPoliciesApi<'_> {
        PreventionPoliciesApi(self)
    }
    pub fn sensor_update_policies(&self) -> SensorUpdatePoliciesApi<'_> {
        SensorUpdatePoliciesApi(self)
    }
}

fn parse_retry_after(resp: &Response) -> u64 {
    resp.headers()
        .get("X-RateLimit-RetryAfter")
        .or_else(|| resp.headers().get("Retry-After"))
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(DEFAULT_RETRY_AFTER_SECS)
}
