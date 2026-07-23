use std::sync::Arc;
use std::time::{Duration, Instant};

use reqwest::{header, Client, Response};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use tokio::sync::Mutex;
use tokio::time::sleep;

use crate::error::JamfError;

const MAX_RETRIES: u32 = 5;
const DEFAULT_RETRY_AFTER_SECS: u64 = 30;
const PAGE_SIZE: u32 = 100;
/// Refresh 60s before Jamf's reported expiry to avoid a race with a slow request.
const TOKEN_REFRESH_SKEW_SECS: u64 = 60;

struct CachedToken {
    access_token: String,
    expires_at: Instant,
}

#[derive(Clone)]
pub struct JamfClient {
    http: Client,
    base_url: String,
    client_id: String,
    client_secret: String,
    token: Arc<Mutex<Option<CachedToken>>>,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PagedResponse<T> {
    #[serde(rename = "totalCount")]
    pub total_count: usize,
    pub results: Vec<T>,
}

impl JamfClient {
    pub fn computers(&self) -> crate::api::computers::ComputersApi<'_> {
        crate::api::computers::ComputersApi(self)
    }
    pub fn mobile_devices(&self) -> crate::api::mobile_devices::MobileDevicesApi<'_> {
        crate::api::mobile_devices::MobileDevicesApi(self)
    }
    pub fn computer_config_profiles(
        &self,
    ) -> crate::api::config_profiles::ComputerConfigProfilesApi<'_> {
        crate::api::config_profiles::ComputerConfigProfilesApi(self)
    }
    pub fn mobile_config_profiles(
        &self,
    ) -> crate::api::config_profiles::MobileConfigProfilesApi<'_> {
        crate::api::config_profiles::MobileConfigProfilesApi(self)
    }
    pub fn computer_groups(&self) -> crate::api::groups::ComputerGroupsApi<'_> {
        crate::api::groups::ComputerGroupsApi(self)
    }
    pub fn mobile_device_groups(&self) -> crate::api::groups::MobileDeviceGroupsApi<'_> {
        crate::api::groups::MobileDeviceGroupsApi(self)
    }
    pub fn policies(&self) -> crate::api::policies::PoliciesApi<'_> {
        crate::api::policies::PoliciesApi(self)
    }
    pub fn patch(&self) -> crate::api::patch::PatchApi<'_> {
        crate::api::patch::PatchApi(self)
    }

    /// Build a client for a Jamf Pro server URL (e.g. `https://acme.jamfcloud.com`).
    /// Works identically for Jamf Cloud and self-hosted/on-prem servers.
    pub fn new(base_url: &str, client_id: &str, client_secret: &str) -> Result<Self, JamfError> {
        let trimmed = base_url.trim().trim_end_matches('/');
        if trimmed.is_empty() {
            return Err(JamfError::InvalidBaseUrl(base_url.to_string()));
        }
        let mut headers = header::HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            header::HeaderValue::from_static("application/json"),
        );
        let http = Client::builder().default_headers(headers).build()?;
        Ok(Self {
            http,
            base_url: trimmed.to_string(),
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            token: Arc::new(Mutex::new(None)),
        })
    }

    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    /// Fetch (or return a cached) Bearer token via OAuth2 client-credentials.
    async fn ensure_token(&self, force: bool) -> Result<String, JamfError> {
        {
            let guard = self.token.lock().await;
            if !force {
                if let Some(cached) = guard.as_ref() {
                    if Instant::now() < cached.expires_at {
                        return Ok(cached.access_token.clone());
                    }
                }
            }
        }
        let url = self.url("/api/oauth/token");
        let form = [
            ("client_id", self.client_id.as_str()),
            ("client_secret", self.client_secret.as_str()),
            ("grant_type", "client_credentials"),
        ];
        let resp = self
            .http
            .post(&url)
            .form(&form)
            .send()
            .await
            .map_err(JamfError::Http)?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let message = resp.text().await.unwrap_or_default();
            return Err(JamfError::Auth(format!("HTTP {status} — {message}")));
        }
        let parsed: TokenResponse = resp.json().await?;
        let expires_at = Instant::now()
            + Duration::from_secs(parsed.expires_in.saturating_sub(TOKEN_REFRESH_SKEW_SECS));
        let token = parsed.access_token.clone();
        let mut guard = self.token.lock().await;
        *guard = Some(CachedToken {
            access_token: parsed.access_token,
            expires_at,
        });
        Ok(token)
    }

    /// GET a relative path (e.g. `/api/v1/computers-inventory?page=0`).
    /// Refreshes the token once on a 401, then retries the request exactly once.
    pub async fn get(&self, path: &str) -> Result<Response, JamfError> {
        let url = self.url(path);
        let token = self.ensure_token(false).await?;
        let resp = self.send_with_retry(&url, &token).await?;
        if resp.status().as_u16() == 401 {
            let fresh = self.ensure_token(true).await?;
            return self.send_with_retry(&url, &fresh).await;
        }
        Ok(resp)
    }

    async fn send_with_retry(&self, url: &str, token: &str) -> Result<Response, JamfError> {
        let mut backoff = 1u64;
        for attempt in 0..=MAX_RETRIES {
            let resp = self
                .http
                .get(url)
                .bearer_auth(token)
                .send()
                .await
                .map_err(JamfError::Http)?;
            if resp.status().as_u16() != 429 || attempt == MAX_RETRIES {
                return Ok(resp);
            }
            let wait = parse_retry_after(&resp).max(backoff);
            sleep(Duration::from_secs(wait)).await;
            backoff = (backoff * 2).min(DEFAULT_RETRY_AFTER_SECS);
        }
        unreachable!()
    }

    /// Modern JSON API pagination: loops `page`/`page-size` until fewer than
    /// a full page is returned or `totalCount` is reached.
    pub async fn get_all_paged<T: DeserializeOwned>(
        &self,
        base_path: &str,
    ) -> Result<Vec<T>, JamfError> {
        let mut all = Vec::new();
        let mut page = 0u32;
        loop {
            let sep = if base_path.contains('?') { '&' } else { '?' };
            let path = format!("{base_path}{sep}page={page}&page-size={PAGE_SIZE}");
            let resp = self.get(&path).await?;
            if !resp.status().is_success() {
                let status = resp.status().as_u16();
                let message = resp.text().await.unwrap_or_default();
                return Err(JamfError::Api { status, message });
            }
            let parsed: PagedResponse<T> = resp.json().await?;
            let got = parsed.results.len();
            all.extend(parsed.results);
            if got < PAGE_SIZE as usize || all.len() >= parsed.total_count {
                break;
            }
            page += 1;
        }
        Ok(all)
    }
}

/// Honour a standard `Retry-After` header (seconds form) when present.
fn parse_retry_after(resp: &Response) -> u64 {
    resp.headers()
        .get("Retry-After")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(DEFAULT_RETRY_AFTER_SECS)
        .min(DEFAULT_RETRY_AFTER_SECS)
}
