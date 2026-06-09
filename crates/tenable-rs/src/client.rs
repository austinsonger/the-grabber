use reqwest::{header, Client};
use serde::de::DeserializeOwned;
use tokio::time::{sleep, Duration};

use crate::api::{AssetsApi, AuditLogApi, ComplianceApi, ScansApi, UsersApi, VulnsApi, WasApi};
use crate::error::TenableError;
use crate::export::{check_response, ExportJob, ExportStarted};

const DEFAULT_RETRY_AFTER_SECS: u64 = 60;
const MAX_RETRIES: u32 = 5;

/// Thin async HTTP client for the Tenable REST API.
///
/// Injects `X-ApiKeys` auth headers on every request and transparently retries
/// 429 rate-limit responses with exponential backoff (up to 5 retries, honouring `Retry-After`).
///
/// `TenableClient` is cheaply cloneable — `reqwest::Client` wraps an arc-pooled
/// connection pool. Build one instance and clone into each collector.
#[derive(Clone)]
pub struct TenableClient {
    pub(crate) http: Client,
    pub(crate) base_url: String,
}

/// Which Tenable deployment a given base URL maps to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TenableFlavor {
    /// Commercial Tenable.io — `https://cloud.tenable.com`.
    TenableIoCommercial,
    /// FedRAMP-hosted Tenable.io — `https://fedcloud.tenable.com`.
    TenableIoFedramp,
    /// Self-hosted Tenable.sc / Security Center.
    TenableSc,
}

impl TenableFlavor {
    /// Classify a base URL into a Tenable deployment flavor.
    /// The check is case-insensitive on the host and ignores trailing slashes.
    pub fn for_url(url: &str) -> Self {
        let u = url.trim().trim_end_matches('/').to_lowercase();
        if u == "https://cloud.tenable.com" || u == "http://cloud.tenable.com" {
            Self::TenableIoCommercial
        } else if u == "https://fedcloud.tenable.com" || u == "http://fedcloud.tenable.com" {
            Self::TenableIoFedramp
        } else {
            Self::TenableSc
        }
    }

    /// Human label for logs and TUI messages.
    pub fn label(self) -> &'static str {
        match self {
            Self::TenableIoCommercial => "Tenable.io (commercial)",
            Self::TenableIoFedramp => "Tenable.io (FedRAMP)",
            Self::TenableSc => "Tenable.sc (on-prem)",
        }
    }

    /// Where to generate API keys for this deployment.
    pub fn api_keys_hint(self) -> &'static str {
        match self {
            Self::TenableIoCommercial => {
                "Generate keys at https://cloud.tenable.com → Settings → My Account → API Keys"
            }
            Self::TenableIoFedramp => {
                "Generate keys at https://fedcloud.tenable.com → Settings → My Account → API Keys"
            }
            Self::TenableSc => {
                "Generate keys in Tenable.sc → Username → API Keys (admin enables under Users → Edit)"
            }
        }
    }
}

impl TenableClient {
    /// Connect to Tenable.io (cloud-hosted, `https://cloud.tenable.com`).
    pub fn tenable_io(access_key: &str, secret_key: &str) -> Result<Self, TenableError> {
        Self::build("https://cloud.tenable.com", access_key, secret_key)
    }

    /// Connect to Tenable.io FedRAMP (`https://fedcloud.tenable.com`).
    pub fn tenable_io_fedramp(access_key: &str, secret_key: &str) -> Result<Self, TenableError> {
        Self::build("https://fedcloud.tenable.com", access_key, secret_key)
    }

    /// Connect to Tenable.sc (on-premises Security Center).
    pub fn tenable_sc(
        base_url: &str,
        access_key: &str,
        secret_key: &str,
    ) -> Result<Self, TenableError> {
        Self::build(base_url, access_key, secret_key)
    }

    /// Build a client by inferring the deployment flavor from `base_url`.
    /// Recognizes `cloud.tenable.com` (commercial) and `fedcloud.tenable.com`
    /// (FedRAMP); anything else is treated as Tenable.sc.
    pub fn from_url(
        base_url: &str,
        access_key: &str,
        secret_key: &str,
    ) -> Result<(Self, TenableFlavor), TenableError> {
        let flavor = TenableFlavor::for_url(base_url);
        let client = match flavor {
            TenableFlavor::TenableIoCommercial => Self::tenable_io(access_key, secret_key)?,
            TenableFlavor::TenableIoFedramp => Self::tenable_io_fedramp(access_key, secret_key)?,
            TenableFlavor::TenableSc => Self::tenable_sc(base_url, access_key, secret_key)?,
        };
        Ok((client, flavor))
    }

    fn build(base_url: &str, access_key: &str, secret_key: &str) -> Result<Self, TenableError> {
        let auth_value = format!("accessKey={access_key}; secretKey={secret_key}");
        let mut headers = header::HeaderMap::new();
        headers.insert("X-ApiKeys", header::HeaderValue::from_str(&auth_value)?);

        let http = Client::builder().default_headers(headers).build()?;

        Ok(Self {
            http,
            base_url: base_url.trim_end_matches('/').to_string(),
        })
    }

    /// Build a full URL by appending `path` (which must start with `/`).
    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    async fn send_with_retry<F, Fut>(&self, make_req: F) -> Result<reqwest::Response, TenableError>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<reqwest::Response, reqwest::Error>>,
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

    /// Execute a GET request, retrying up to 5 times on 429 with exponential backoff.
    pub(crate) async fn get(&self, path: &str) -> Result<reqwest::Response, TenableError> {
        let url = self.url(path);
        self.send_with_retry(|| self.http.get(&url).send()).await
    }

    /// Execute a POST request with a JSON body, retrying up to 5 times on 429 with exponential backoff.
    pub(crate) async fn post(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<reqwest::Response, TenableError> {
        let url = self.url(path);
        self.send_with_retry(|| self.http.post(&url).json(body).send())
            .await
    }

    pub fn vulns(&self) -> VulnsApi<'_> {
        VulnsApi(self)
    }
    pub fn assets(&self) -> AssetsApi<'_> {
        AssetsApi(self)
    }
    pub fn scans(&self) -> ScansApi<'_> {
        ScansApi(self)
    }
    pub fn audit_log(&self) -> AuditLogApi<'_> {
        AuditLogApi(self)
    }
    pub fn compliance(&self) -> ComplianceApi<'_> {
        ComplianceApi(self)
    }
    pub fn was(&self) -> WasApi<'_> {
        WasApi(self)
    }
    pub fn users(&self) -> UsersApi<'_> {
        UsersApi(self)
    }

    /// POST to `post_path` to start an export, then build poll/download paths
    /// rooted at `resource_base`.
    ///
    /// `post_path` and `resource_base` differ for assets: the POST goes to
    /// `/assets/v2/export`, but status and chunk downloads use `/assets/export`.
    /// For vulns and compliance they are the same value.
    pub(crate) async fn start_export<T: DeserializeOwned>(
        &self,
        post_path: &str,
        resource_base: &str,
        body: &serde_json::Value,
    ) -> Result<ExportJob<T>, TenableError> {
        let resp = self.post(post_path, body).await?;
        let resp = check_response(resp).await?;
        let started: ExportStarted = resp.json().await?;
        Ok(ExportJob::new(
            self.clone(),
            format!("{}/{}", resource_base, started.export_uuid),
        ))
    }
}

fn parse_retry_after(resp: &reqwest::Response) -> u64 {
    resp.headers()
        .get("Retry-After")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(DEFAULT_RETRY_AFTER_SECS)
}
