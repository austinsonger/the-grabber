use futures::stream::{self, StreamExt};
use reqwest::{header, Client, Response};
use serde::{de::DeserializeOwned, Serialize};
use tokio::time::{sleep, Duration};

use crate::error::JumpCloudError;

const MAX_RETRIES: u32 = 5;
const DEFAULT_RETRY_AFTER_SECS: u64 = 30;
const V1_PAGE_LIMIT: u32 = 100;

/// Async HTTP client for the JumpCloud REST API.
///
/// Auth: `x-api-key: <api_key>` (and optional `x-org-id: <org_id>` for MTP/MSP)
/// injected on every request.
///
/// Retries 429 responses with exponential backoff up to `MAX_RETRIES` times.
///
/// `JumpCloudClient` is cheaply cloneable — `reqwest::Client` is arc-pooled.
#[derive(Clone)]
pub struct JumpCloudClient {
    pub(crate) http: Client,
    pub(crate) base_url: String,
}

impl JumpCloudClient {
    /// Build a client for a JumpCloud base URL (usually `https://console.jumpcloud.com`).
    pub fn new(base_url: &str, api_key: &str, org_id: Option<&str>) -> Result<Self, JumpCloudError> {
        let trimmed = base_url.trim().trim_end_matches('/');
        if trimmed.is_empty() {
            return Err(JumpCloudError::InvalidBaseUrl(base_url.to_string()));
        }
        let mut headers = header::HeaderMap::new();
        headers.insert(
            header::HeaderName::from_static("x-api-key"),
            header::HeaderValue::from_str(api_key)?,
        );
        if let Some(org) = org_id.filter(|s| !s.is_empty()) {
            headers.insert(
                header::HeaderName::from_static("x-org-id"),
                header::HeaderValue::from_str(org)?,
            );
        }
        headers.insert(
            header::ACCEPT,
            header::HeaderValue::from_static("application/json"),
        );
        headers.insert(
            header::CONTENT_TYPE,
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

    async fn get(&self, path: &str) -> Result<Response, JumpCloudError> {
        let url = self.url(path);
        self.send_with_retry(|| self.http.get(&url).send()).await
    }

    async fn get_absolute(&self, url: &str) -> Result<Response, JumpCloudError> {
        let owned = url.to_string();
        self.send_with_retry(|| self.http.get(&owned).send()).await
    }

    async fn send_with_retry<F, Fut>(&self, make_req: F) -> Result<Response, JumpCloudError>
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

    async fn expect_ok(resp: Response) -> Result<Response, JumpCloudError> {
        if resp.status().is_success() {
            return Ok(resp);
        }
        let status = resp.status().as_u16();
        let message = resp.text().await.unwrap_or_default();
        Err(JumpCloudError::Api { status, message })
    }

    /// v1 (`/api/*`) list endpoints return `{"results": [...], "totalCount": n}`.
    /// Walk pages by incrementing `skip` in chunks of `V1_PAGE_LIMIT`.
    pub async fn list_v1<T: DeserializeOwned>(&self, path: &str) -> Result<Vec<T>, JumpCloudError> {
        #[derive(serde::Deserialize)]
        struct V1Page<T> {
            #[serde(default = "Vec::new")]
            results: Vec<T>,
            #[serde(rename = "totalCount", default)]
            total_count: usize,
        }

        let mut out: Vec<T> = Vec::new();
        let mut skip: u32 = 0;
        loop {
            let sep = if path.contains('?') { '&' } else { '?' };
            let paged = format!("{path}{sep}limit={V1_PAGE_LIMIT}&skip={skip}");
            let resp = Self::expect_ok(self.get(&paged).await?).await?;
            let page: V1Page<T> = resp.json().await?;
            let got = page.results.len();
            out.extend(page.results);
            if got < V1_PAGE_LIMIT as usize || out.len() >= page.total_count {
                break;
            }
            skip += V1_PAGE_LIMIT;
        }
        Ok(out)
    }

    /// v2 (`/api/v2/*`) list endpoints return a bare JSON array. Some support
    /// `Link: <...>; rel="next"` headers for pagination; others use skip/limit
    /// mirroring v1. This helper handles both by falling through to skip/limit
    /// when no `Link: rel="next"` is present.
    pub async fn list_v2_cursor<T: DeserializeOwned>(
        &self,
        path: &str,
    ) -> Result<Vec<T>, JumpCloudError> {
        let mut out: Vec<T> = Vec::new();
        let mut skip: u32 = 0;
        let mut used_link = false;
        let mut next_url: Option<String> = None;
        loop {
            let resp = if let Some(url) = next_url.take() {
                Self::expect_ok(self.get_absolute(&url).await?).await?
            } else {
                let sep = if path.contains('?') { '&' } else { '?' };
                let paged = format!("{path}{sep}limit={V1_PAGE_LIMIT}&skip={skip}");
                Self::expect_ok(self.get(&paged).await?).await?
            };

            let next = extract_next_link(resp.headers());
            let page: Vec<T> = resp.json().await?;
            let got = page.len();
            out.extend(page);

            if let Some(url) = next {
                next_url = Some(url);
                used_link = true;
                continue;
            }
            if used_link || got < V1_PAGE_LIMIT as usize {
                break;
            }
            skip += V1_PAGE_LIMIT;
        }
        Ok(out)
    }

    /// POST a JSON body and decode the JSON response.
    pub async fn post_json<B: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, JumpCloudError> {
        let url = self.url(path);
        let owned_body = serde_json::to_vec(body)?;
        let resp = self
            .send_with_retry(|| {
                self.http
                    .post(&url)
                    .body(owned_body.clone())
                    .send()
            })
            .await?;
        let resp = Self::expect_ok(resp).await?;
        let value: T = resp.json().await?;
        Ok(value)
    }

    pub fn users(&self) -> crate::api::UsersApi<'_> {
        crate::api::UsersApi(self)
    }
    pub fn user_groups(&self) -> crate::api::UserGroupsApi<'_> {
        crate::api::UserGroupsApi(self)
    }
    pub fn systems(&self) -> crate::api::SystemsApi<'_> {
        crate::api::SystemsApi(self)
    }
    pub fn system_groups(&self) -> crate::api::SystemGroupsApi<'_> {
        crate::api::SystemGroupsApi(self)
    }
    pub fn applications(&self) -> crate::api::ApplicationsApi<'_> {
        crate::api::ApplicationsApi(self)
    }
    pub fn policies(&self) -> crate::api::PoliciesApi<'_> {
        crate::api::PoliciesApi(self)
    }
    pub fn administrators(&self) -> crate::api::AdministratorsApi<'_> {
        crate::api::AdministratorsApi(self)
    }
    pub fn organizations(&self) -> crate::api::OrganizationsApi<'_> {
        crate::api::OrganizationsApi(self)
    }
    pub fn insights(&self) -> crate::api::InsightsApi<'_> {
        crate::api::InsightsApi(self)
    }

    /// Concurrency helper used by member-listing collectors that fan out per
    /// group. Runs `fut_of(id)` for each id with `concurrency` in flight.
    pub async fn fan_out<T, F, Fut>(
        &self,
        ids: Vec<String>,
        concurrency: usize,
        fut_of: F,
    ) -> Vec<(String, Result<T, JumpCloudError>)>
    where
        F: Fn(String) -> Fut + Clone,
        Fut: std::future::Future<Output = Result<T, JumpCloudError>>,
    {
        stream::iter(ids)
            .map(|id| {
                let f = fut_of.clone();
                async move {
                    let out = f(id.clone()).await;
                    (id, out)
                }
            })
            .buffer_unordered(concurrency)
            .collect()
            .await
    }
}

fn parse_retry_after(resp: &Response) -> u64 {
    resp.headers()
        .get(header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(DEFAULT_RETRY_AFTER_SECS)
}

fn extract_next_link(headers: &header::HeaderMap) -> Option<String> {
    let link = headers.get(header::LINK)?.to_str().ok()?;
    for part in link.split(',') {
        let part = part.trim();
        if part.ends_with(r#"rel="next""#) || part.ends_with("rel=next") {
            let start = part.find('<')?;
            let end = part.find('>')?;
            if start < end {
                return Some(part[start + 1..end].to_string());
            }
        }
    }
    None
}
