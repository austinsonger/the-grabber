use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use reqwest::{header, Client, Response};
use tokio::time::{sleep, Duration};

use crate::api::{IssuesApi, JqlSlaApi, ProjectsApi};
use crate::error::JiraError;

const MAX_RETRIES: u32 = 5;
const DEFAULT_RETRY_AFTER_SECS: u64 = 30;

/// Async HTTP client for the Jira Cloud REST API v3.
///
/// Auth: `Authorization: Basic base64(email:api_token)` is injected on every request.
/// Retries 429 responses with exponential backoff, honouring `Retry-After` when present.
///
/// `JiraClient` is cheaply cloneable — `reqwest::Client` is arc-pooled.
#[derive(Clone)]
pub struct JiraClient {
    pub(crate) http: Client,
    pub(crate) base_url: String,
}

impl JiraClient {
    /// Build a client for a tenant URL (e.g. `https://acme.atlassian.net`).
    pub fn new(base_url: &str, email: &str, api_token: &str) -> Result<Self, JiraError> {
        let trimmed = base_url.trim().trim_end_matches('/');
        if trimmed.is_empty() {
            return Err(JiraError::InvalidBaseUrl(base_url.to_string()));
        }
        let raw = format!("{email}:{api_token}");
        let encoded = B64.encode(raw.as_bytes());
        let auth = format!("Basic {encoded}");

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

    pub(crate) async fn get(&self, path: &str) -> Result<Response, JiraError> {
        let url = self.url(path);
        self.send_with_retry(|| self.http.get(&url).send()).await
    }

    pub(crate) async fn get_absolute(&self, url: &str) -> Result<Response, JiraError> {
        let owned = url.to_string();
        self.send_with_retry(|| self.http.get(&owned).send()).await
    }

    pub(crate) async fn post_json(
        &self,
        path: &str,
        body: serde_json::Value,
    ) -> Result<Response, JiraError> {
        let url = self.url(path);
        self.send_with_retry(|| self.http.post(&url).json(&body).send())
            .await
    }

    #[doc(hidden)]
    pub async fn raw_get(&self, path: &str) -> Result<Response, JiraError> {
        self.get(path).await
    }

    async fn send_with_retry<F, Fut>(&self, make_req: F) -> Result<Response, JiraError>
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
            backoff = (backoff * 2).min(60);
        }
        unreachable!("retry loop exits via return")
    }

    pub fn projects(&self) -> ProjectsApi<'_> {
        ProjectsApi(self)
    }
    pub fn issues(&self) -> IssuesApi<'_> {
        IssuesApi(self)
    }
    pub fn jql_sla(&self) -> JqlSlaApi<'_> {
        JqlSlaApi(self)
    }
}

fn parse_retry_after(resp: &Response) -> u64 {
    resp.headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(DEFAULT_RETRY_AFTER_SECS)
}
