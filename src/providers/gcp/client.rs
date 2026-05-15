//! Thin HTTP client for GCP REST APIs.
//!
//! Authentication is handled by `google-cloud-auth` (Application Default
//! Credentials). In production this picks up:
//!   - `GOOGLE_APPLICATION_CREDENTIALS` env → service-account JSON key
//!   - GCE/GKE metadata server → attached service account / Workload Identity
//!   - `gcloud auth application-default login` → user credentials
//!
//! All methods return `anyhow::Result` so callers can use `?` freely.

use std::sync::Arc;

use anyhow::{Context, Result};
use google_cloud_auth::project::Config as AuthConfig;
use google_cloud_auth::token::DefaultTokenSourceProvider;
use google_cloud_token::{TokenSource, TokenSourceProvider};
use reqwest::{Client as HttpClient, Response, StatusCode};
use serde::Serialize;
use serde_json::Value;
use tokio::sync::RwLock;

// ---------------------------------------------------------------------------
// Inner state (shared via Arc so GcpClient is cheaply cloneable)
// ---------------------------------------------------------------------------

struct GcpClientInner {
    http:         HttpClient,
    /// Token source obtained from ADC.
    token_source: Option<Arc<dyn TokenSource>>,
    /// Non-`None` only in unit tests — bypasses ADC entirely.
    static_token: Option<String>,
    /// When set (tests only), prepended to every path.
    base_url:     Option<String>,
}

// ---------------------------------------------------------------------------
// Public handle
// ---------------------------------------------------------------------------

/// Cloneable, async-safe GCP REST client.
#[derive(Clone)]
pub struct GcpClient {
    inner: Arc<RwLock<GcpClientInner>>,
}

impl GcpClient {
    /// Build a client using Application Default Credentials.
    ///
    /// Scopes requested: `https://www.googleapis.com/auth/cloud-platform`
    /// (covers every GCP REST API used by the grabber's collectors).
    pub async fn from_adc() -> Result<Self> {
        let scopes = ["https://www.googleapis.com/auth/cloud-platform"];
        let cfg = AuthConfig::default().with_scopes(&scopes);
        let provider = DefaultTokenSourceProvider::new(cfg)
            .await
            .context("Failed to initialize GCP Application Default Credentials")?;
        let token_source: Arc<dyn TokenSource> = provider.token_source();
        let http = HttpClient::builder()
            .user_agent(concat!("the-grabber/", env!("CARGO_PKG_VERSION")))
            .build()
            .context("Failed to build HTTP client")?;
        Ok(Self {
            inner: Arc::new(RwLock::new(GcpClientInner {
                http,
                token_source: Some(token_source),
                static_token: None,
                base_url: None,
            })),
        })
    }

    /// Test-only constructor: fixed bearer token + mock server base URL.
    #[cfg(test)]
    pub fn from_static_token(token: impl Into<String>, base_url: &str) -> Self {
        let http = HttpClient::builder()
            .user_agent("the-grabber-test")
            .build()
            .expect("test HTTP client");
        Self {
            inner: Arc::new(RwLock::new(GcpClientInner {
                http,
                token_source: None,
                static_token: Some(token.into()),
                base_url: Some(base_url.trim_end_matches('/').to_owned()),
            })),
        }
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Returns the raw bearer token string (no "Bearer " prefix for reqwest
    /// `.bearer_auth()`). The `google_cloud_token::TokenSource::token()` method
    /// returns a "Bearer <tok>" string, so we strip the prefix here.
    async fn bearer_token(&self) -> Result<String> {
        let inner = self.inner.read().await;
        if let Some(ref tok) = inner.static_token {
            return Ok(tok.clone());
        }
        if let Some(ref src) = inner.token_source {
            let raw = src
                .token()
                .await
                .map_err(|e| anyhow::anyhow!("Failed to obtain GCP bearer token: {e}"))?;
            // Strip "Bearer " prefix so reqwest can add it back
            let tok = raw.trim_start_matches("Bearer ").to_owned();
            return Ok(tok);
        }
        anyhow::bail!("No token source configured for GcpClient")
    }

    fn resolve_url(&self, url: &str) -> String {
        // Synchronously inspect base_url; fine since this is only set in tests
        // where inner is not being written.
        if let Ok(inner) = self.inner.try_read() {
            if let Some(ref base) = inner.base_url {
                // In tests the mock server mounts routes at absolute paths.
                // Strip the protocol+host from the collector's URL.
                if let Some(path) = url
                    .split("//")
                    .nth(1)
                    .and_then(|s| s.find('/').map(|i| &s[i..]))
                {
                    return format!("{}{}", base, path);
                }
            }
        }
        url.to_owned()
    }

    // -----------------------------------------------------------------------
    // Public HTTP methods
    // -----------------------------------------------------------------------

    /// HTTP GET; returns the raw `reqwest::Response`.
    pub async fn get(&self, url: &str) -> Result<Response> {
        let token = self.bearer_token().await?;
        let resolved = self.resolve_url(url);
        let inner = self.inner.read().await;
        inner
            .http
            .get(&resolved)
            .bearer_auth(&token)
            .send()
            .await
            .with_context(|| format!("GET {resolved}"))
    }

    /// HTTP POST with a JSON body; returns the raw `reqwest::Response`.
    pub async fn post<B: Serialize + ?Sized>(&self, url: &str, body: &B) -> Result<Response> {
        let token = self.bearer_token().await?;
        let resolved = self.resolve_url(url);
        let inner = self.inner.read().await;
        inner
            .http
            .post(&resolved)
            .bearer_auth(&token)
            .json(body)
            .send()
            .await
            .with_context(|| format!("POST {resolved}"))
    }

    // -----------------------------------------------------------------------
    // Pagination helper
    // -----------------------------------------------------------------------

    /// Page through a GCP LIST endpoint that uses `pageToken` / `nextPageToken`,
    /// collecting all items under the given `items_key` JSON field.
    ///
    /// Callers must pass the *full* initial URL including any query parameters.
    /// The helper appends `&pageToken=<tok>` on subsequent pages.
    pub async fn paginate(&self, url: &str, items_key: &str) -> Result<Vec<Value>> {
        let mut all: Vec<Value> = Vec::new();
        let mut page_token: Option<String> = None;

        loop {
            let paged_url = match &page_token {
                Some(tok) => {
                    let sep = if url.contains('?') { "&" } else { "?" };
                    format!("{url}{sep}pageToken={tok}")
                }
                None => url.to_owned(),
            };

            let resp = self.get(&paged_url).await?;
            let status = resp.status();
            let body: Value = resp
                .json()
                .await
                .with_context(|| format!("Failed to parse JSON from GET {paged_url}"))?;

            if !status.is_success() {
                let msg = body
                    .get("error")
                    .and_then(|e| e.get("message"))
                    .and_then(|m| m.as_str())
                    .unwrap_or("unknown error");
                anyhow::bail!("GCP API {status} from {paged_url}: {msg}");
            }

            if let Some(items) = body.get(items_key).and_then(|v| v.as_array()) {
                all.extend(items.iter().cloned());
            }

            match body.get("nextPageToken").and_then(|t| t.as_str()) {
                Some(tok) => page_token = Some(tok.to_owned()),
                None => break,
            }
        }

        Ok(all)
    }

    /// POST-based pagination (used by Security Command Center's `findings:list`).
    pub async fn paginate_post(
        &self,
        url: &str,
        body: &serde_json::Value,
        items_key: &str,
    ) -> Result<Vec<Value>> {
        let mut all: Vec<Value> = Vec::new();
        let mut page_token: Option<String> = None;

        loop {
            let mut req = body.clone();
            if let Some(tok) = &page_token {
                req["pageToken"] = Value::String(tok.clone());
            }

            let resp = self.post(url, &req).await?;
            let status: StatusCode = resp.status();
            let resp_body: Value = resp
                .json()
                .await
                .with_context(|| format!("Failed to parse JSON from POST {url}"))?;

            if !status.is_success() {
                let msg = resp_body
                    .get("error")
                    .and_then(|e| e.get("message"))
                    .and_then(|m| m.as_str())
                    .unwrap_or("unknown error");
                anyhow::bail!("GCP API {status} from {url}: {msg}");
            }

            if let Some(items) = resp_body.get(items_key).and_then(|v| v.as_array()) {
                all.extend(items.iter().cloned());
            }

            match resp_body.get("nextPageToken").and_then(|t| t.as_str()) {
                Some(tok) => page_token = Some(tok.to_owned()),
                None => break,
            }
        }

        Ok(all)
    }
}
