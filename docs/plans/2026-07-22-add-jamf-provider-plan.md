# Add Jamf Provider Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a first-class Jamf Pro provider to Grabber — a new `crates/jamf-rs` API client, a `src/providers/jamf/` collector set (9 P0 collectors), config/TUI/runner wiring, FedRAMP mapping, and documentation — following the exact architecture already used by the Okta provider.

**Architecture:** One new workspace crate (`jamf-rs`) wraps the Jamf Pro REST API: OAuth2 client-credentials auth against `/api/oauth/token`, a shared `Bearer` token cached and refreshed on expiry, a generic page-based pagination helper for the modern JSON API (`/api/v1`, `/api/v2`), and `Accept: application/json` content negotiation against the Classic API (`/JSSResource/*`) so Classic endpoints return JSON too — no XML parser needed. `src/providers/jamf/` then implements one `CsvCollector`/`JsonCollector` struct per evidence type, registered in a `JamfProviderFactory`, wired into config (`jamf-config.toml`), the TUI (provider-scoped menu, no bespoke screens), and the TUI runner's account-prep loop — mirroring the Okta provider at every layer.

**Tech Stack:** Rust (edition 2021), `reqwest` (rustls-tls), `serde`/`serde_json`, `tokio`, `thiserror`, `async-trait`, `wiremock` (crate tests only), `ratatui`/`crossterm` (TUI).

## Global Constraints

- Read-only: no Jamf API calls in this plan ever create/update/delete a Jamf resource (spec Non-Goal 1).
- No Jamf Connect collector; no Jamf Protect collector — both explicitly out of scope for this plan (spec Non-Goals 2–3; Protect is deferred to a future follow-on plan).
- Never collect FileVault recovery keys or any other escrowed secret — only status/compliance flags (spec Non-Goal 6).
- New Cargo feature `jamf` is added to the `default` feature list in the workspace `Cargo.toml`, matching `tenable`/`okta`/`jira`/`elastic`.
- Per project convention ([[feedback_no_tests_just_implementation]]), only the new `crates/jamf-rs` API-client crate gets dedicated tests (mirroring `crates/okta-rs`'s existing wiremock tests) — the `src/providers/jamf/*`, TUI, config, and docs layers follow the Okta precedent of no dedicated test files; each of those steps instead ends with a `cargo check`/`cargo clippy` verification.
- Every new/changed Rust file must leave the tree compilable — run `cargo check --features jamf` after each step that touches `.rs` files, not just at the end of a task.
- Exact Jamf Pro endpoint/field names are verified against a live tenant's Swagger docs (`https://<server>/api/doc/`) and Classic API (`https://<server>/JSSResource/...` with `Accept: application/json`) as part of each collector task's acceptance step — the shapes below are the implementation target; adjust field renames only if a specific tenant's Jamf Pro version differs, per the spec's Open Questions.

---

## Task 1: `crates/jamf-rs` — OAuth2 client, pagination, and error types

**Files:**
- Create: `crates/jamf-rs/Cargo.toml`
- Create: `crates/jamf-rs/src/lib.rs`
- Create: `crates/jamf-rs/src/error.rs`
- Create: `crates/jamf-rs/src/client.rs`
- Test: `crates/jamf-rs/tests/client_test.rs`
- Modify: `Cargo.toml:2` (workspace members)
- Modify: `Cargo.toml:100-101` (add `jamf-rs` path dependency, alongside the existing Okta stanza)
- Modify: `Cargo.toml:109-116` (add `jamf` to `default` and declare the `jamf` feature)

**Interfaces:**
- Produces: `jamf_rs::JamfClient::new(base_url: &str, client_id: &str, client_secret: &str) -> Result<JamfClient, JamfError>`, `JamfClient` is `Clone`. `pub(crate) async fn get(&self, path: &str) -> Result<reqwest::Response, JamfError>` (Bearer-authed, single 401-refresh retry, 429 backoff). `pub(crate) async fn get_all_paged<T: DeserializeOwned>(&self, base_path: &str) -> Result<Vec<T>, JamfError>` (modern JSON API page/page-size pagination). `JamfError` enum with `Api { status: u16, message: String }` variant.

- [ ] **Step 1: Create the crate skeleton**

`crates/jamf-rs/Cargo.toml`:
```toml
[package]
name        = "jamf-rs"
version     = "0.1.0"
edition     = "2021"
description = "Async Rust client for the Jamf Pro API"
license     = "MIT OR Apache-2.0"

[dependencies]
reqwest    = { version = "0.12", features = ["json", "rustls-tls"], default-features = false }
serde      = { version = "1", features = ["derive"] }
serde_json = "1"
tokio      = { version = "1", features = ["time"] }
thiserror  = "2"

[dev-dependencies]
tokio    = { version = "1", features = ["full"] }
wiremock = "0.6"
```

- [ ] **Step 2: Write the error type**

`crates/jamf-rs/src/error.rs`:
```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum JamfError {
    #[error("HTTP transport error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("invalid header value: {0}")]
    Header(#[from] reqwest::header::InvalidHeaderValue),

    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Jamf API error: HTTP {status} — {message}")]
    Api { status: u16, message: String },

    #[error("invalid base URL: {0}")]
    InvalidBaseUrl(String),

    #[error("OAuth token request failed: {0}")]
    Auth(String),
}
```

- [ ] **Step 3: Write the client — construction, token cache, GET helper, backoff**

`crates/jamf-rs/src/client.rs`:
```rust
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
    pub(crate) async fn get(&self, path: &str) -> Result<Response, JamfError> {
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
    pub(crate) async fn get_all_paged<T: DeserializeOwned>(
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
```

- [ ] **Step 4: Write `lib.rs` re-exporting the public surface**

`crates/jamf-rs/src/lib.rs`:
```rust
mod client;
mod error;

pub mod api;

pub use client::JamfClient;
pub use error::JamfError;
```

Create an empty `crates/jamf-rs/src/api/mod.rs` for now (filled in by later tasks):
```rust
// Per-resource API namespaces are added here as they're implemented
// (computers, mobile_devices, config_profiles, groups, policies, patch).
```
Add `pub mod api;` is already in `lib.rs` above; add nothing else yet.

- [ ] **Step 5: Register the crate in the workspace**

Edit `Cargo.toml:2`:
```toml
members  = [".", "crates/tenable-rs", "crates/okta-rs", "crates/jira-rs", "crates/elastic-rs", "crates/jamf-rs"]
```

Edit `Cargo.toml` after line 107 (the Elastic stanza), adding:
```toml
# Jamf — only compiled with `--features jamf`
jamf-rs = { path = "crates/jamf-rs", optional = true }
```

Edit `Cargo.toml:109-116`:
```toml
[features]
default = ["tenable", "okta", "jira", "elastic", "jamf"]
azure   = ["dep:azure_identity", "dep:azure_mgmt_monitor", "dep:azure_mgmt_resources"]
gcp     = ["dep:google-cloud-auth"]
tenable = ["dep:tenable-rs"]
okta    = ["dep:okta-rs"]
jira    = ["dep:jira-rs"]
elastic = ["dep:elastic-rs"]
jamf    = ["dep:jamf-rs"]
```

- [ ] **Step 6: Write the client test**

`crates/jamf-rs/tests/client_test.rs`:
```rust
use jamf_rs::JamfClient;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn fetches_token_and_attaches_bearer_auth() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "test-token",
            "expires_in": 3600
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v1/ping"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
        .mount(&server)
        .await;

    let client = JamfClient::new(&server.uri(), "id", "secret").expect("client builds");
    let resp = client
        .get("/api/v1/ping")
        .await
        .expect("request succeeds");
    assert!(resp.status().is_success());
}
```

- [ ] **Step 7: Verify it builds and the test passes**

Run:
```bash
cargo test -p jamf-rs
```
Expected: `fetches_token_and_attaches_bearer_auth ... ok`.

- [ ] **Step 8: Commit**

```bash
git add Cargo.toml Cargo.lock crates/jamf-rs
git commit -m "feat: scaffold jamf-rs API client crate"
```

---

## Task 2: `CloudProvider::Jamf` + `src/providers/jamf/` scaffold + empty factory

**Files:**
- Modify: `src/providers/mod.rs` (add `Jamf` variant, `Display` arm, feature-gated module)
- Create: `src/providers/jamf/mod.rs`
- Create: `src/providers/jamf/factory.rs`

**Interfaces:**
- Consumes: `jamf_rs::JamfClient` (Task 1).
- Produces: `crate::providers::CloudProvider::Jamf`; `crate::providers::jamf::factory::JamfProviderFactory::new(client: JamfClient, tenant_name: String, selected: Vec<String>) -> Self`, implementing `ProviderFactory` (empty `csv_collectors()`/`json_collectors()` until later tasks populate them).

- [ ] **Step 1: Add the `Jamf` variant to `CloudProvider`**

Edit `src/providers/mod.rs` (the enum currently at lines 31-43 and the `Display` impl at lines 45-57):
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum CloudProvider {
    #[default]
    Aws,
    Azure,
    Gcp,
    Tenable,
    Okta,
    Jira,
    Elastic,
    Jamf,
}

impl fmt::Display for CloudProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CloudProvider::Aws => write!(f, "AWS"),
            CloudProvider::Azure => write!(f, "Azure"),
            CloudProvider::Gcp => write!(f, "GCP"),
            CloudProvider::Tenable => write!(f, "Tenable"),
            CloudProvider::Okta => write!(f, "Okta"),
            CloudProvider::Jira => write!(f, "Jira"),
            CloudProvider::Elastic => write!(f, "Elastic"),
            CloudProvider::Jamf => write!(f, "Jamf"),
        }
    }
}
```

Edit the module-gate block at the top of the same file (after the existing `elastic` gate):
```rust
#[cfg(feature = "jamf")]
pub mod jamf;
```

- [ ] **Step 2: Create the module file with the auth doc comment**

`src/providers/jamf/mod.rs`:
```rust
pub mod factory;

// Authentication:
//   POST {base_url}/api/oauth/token  (client_id + client_secret, grant_type=client_credentials)
//   -> Authorization: Bearer <access_token> on every subsequent request.
//
// Base URL: per-tenant Jamf Pro server (e.g. https://acme.jamfcloud.com, or a
// self-hosted URL). Supplied via the `jamf_base_url` config field or the
// `JAMF_BASE_URL` env var.
```

- [ ] **Step 3: Write the empty factory**

`src/providers/jamf/factory.rs`:
```rust
use jamf_rs::JamfClient;

use crate::evidence::{CsvCollector, EvidenceCollector, JsonCollector};
use crate::providers::{CloudProvider, ProviderFactory};

pub struct JamfProviderFactory {
    client: JamfClient,
    tenant_name: String,
    selected: Vec<String>,
}

impl JamfProviderFactory {
    pub fn new(client: JamfClient, tenant_name: String, selected: Vec<String>) -> Self {
        Self {
            client,
            tenant_name,
            selected,
        }
    }
}

impl ProviderFactory for JamfProviderFactory {
    fn provider(&self) -> CloudProvider {
        CloudProvider::Jamf
    }
    fn account_id(&self) -> &str {
        &self.tenant_name
    }
    fn region(&self) -> &str {
        ""
    }

    fn csv_collectors(&self) -> Vec<Box<dyn CsvCollector>> {
        Vec::new()
    }
    fn json_collectors(&self) -> Vec<Box<dyn JsonCollector>> {
        Vec::new()
    }
    fn evidence_collectors(&self) -> Vec<Box<dyn EvidenceCollector>> {
        Vec::new()
    }
}
```

- [ ] **Step 4: Verify it builds**

Run:
```bash
cargo check --features jamf
```
Expected: no errors (an unused-import warning on `CsvCollector`/`JsonCollector` in `factory.rs` is expected and harmless until Task 3+ populate the vectors — `cargo check` still passes).

- [ ] **Step 5: Commit**

```bash
git add src/providers/mod.rs src/providers/jamf
git commit -m "feat: scaffold Jamf provider factory and CloudProvider variant"
```

---

## Task 3: Computers + Mobile Devices collectors

**Files:**
- Create: `crates/jamf-rs/src/api/computers.rs`
- Create: `crates/jamf-rs/src/api/mobile_devices.rs`
- Modify: `crates/jamf-rs/src/api/mod.rs`
- Modify: `crates/jamf-rs/src/client.rs` (add accessor methods)
- Create: `src/providers/jamf/computers.rs`
- Create: `src/providers/jamf/mobile_devices.rs`
- Modify: `src/providers/jamf/mod.rs` (register modules)
- Modify: `src/providers/jamf/factory.rs` (register both collectors)

**Interfaces:**
- Consumes: `JamfClient::get_all_paged` (Task 1).
- Produces: `client.computers().list_all() -> Result<Vec<JamfComputer>, JamfError>`, `client.mobile_devices().list_all() -> Result<Vec<JamfMobileDevice>, JamfError>`; `JamfComputersCollector::new(client: JamfClient)`, `JamfMobileDevicesCollector::new(client: JamfClient)`, both implementing `CsvCollector`.

- [ ] **Step 1: Add the computers API model + accessor**

`crates/jamf-rs/src/api/computers.rs`:
```rust
use serde::Deserialize;

use crate::client::JamfClient;
use crate::error::JamfError;

#[derive(Debug, Clone, Deserialize)]
pub struct JamfComputer {
    pub id: String,
    pub general: ComputerGeneral,
    pub hardware: ComputerHardware,
    #[serde(rename = "operatingSystem")]
    pub operating_system: ComputerOperatingSystem,
    pub security: ComputerSecurity,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ComputerGeneral {
    #[serde(default)]
    pub name: String,
    #[serde(default, rename = "lastContactTime")]
    pub last_contact_time: Option<String>,
    #[serde(default, rename = "remoteManagement")]
    pub remote_management: RemoteManagement,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RemoteManagement {
    #[serde(default)]
    pub managed: bool,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ComputerHardware {
    #[serde(default)]
    pub model: String,
    #[serde(default, rename = "serialNumber")]
    pub serial_number: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ComputerOperatingSystem {
    #[serde(default)]
    pub version: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ComputerSecurity {
    #[serde(default, rename = "fileVault2Status")]
    pub filevault2_status: String,
}

pub struct ComputersApi<'c>(pub(crate) &'c JamfClient);

impl<'c> ComputersApi<'c> {
    /// GET /api/v1/computers-inventory — full inventory, all sections.
    pub async fn list_all(&self) -> Result<Vec<JamfComputer>, JamfError> {
        self.0
            .get_all_paged("/api/v1/computers-inventory?section=GENERAL&section=HARDWARE&section=OPERATING_SYSTEM&section=SECURITY")
            .await
    }
}
```

- [ ] **Step 2: Add the mobile devices API model + accessor**

`crates/jamf-rs/src/api/mobile_devices.rs`:
```rust
use serde::Deserialize;

use crate::client::JamfClient;
use crate::error::JamfError;

#[derive(Debug, Clone, Deserialize)]
pub struct JamfMobileDevice {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default, rename = "serialNumber")]
    pub serial_number: String,
    #[serde(default)]
    pub model: String,
    #[serde(default, rename = "osVersion")]
    pub os_version: String,
    #[serde(default, rename = "lastEnrolledDate")]
    pub last_enrolled_date: Option<String>,
    #[serde(default)]
    pub managed: bool,
    #[serde(default)]
    pub supervised: bool,
}

pub struct MobileDevicesApi<'c>(pub(crate) &'c JamfClient);

impl<'c> MobileDevicesApi<'c> {
    /// GET /api/v2/mobile-devices/detail — full inventory.
    pub async fn list_all(&self) -> Result<Vec<JamfMobileDevice>, JamfError> {
        self.0.get_all_paged("/api/v2/mobile-devices/detail").await
    }
}
```

- [ ] **Step 3: Wire accessor methods on `JamfClient` and re-export from `api/mod.rs`**

Append to `crates/jamf-rs/src/client.rs` (new `impl JamfClient` block, or add methods to the existing one):
```rust
impl JamfClient {
    pub fn computers(&self) -> crate::api::computers::ComputersApi<'_> {
        crate::api::computers::ComputersApi(self)
    }
    pub fn mobile_devices(&self) -> crate::api::mobile_devices::MobileDevicesApi<'_> {
        crate::api::mobile_devices::MobileDevicesApi(self)
    }
}
```

`crates/jamf-rs/src/api/mod.rs`:
```rust
pub mod computers;
pub mod mobile_devices;
```

- [ ] **Step 4: Write the Grabber `CsvCollector` for computers**

`src/providers/jamf/computers.rs`:
```rust
use anyhow::Result;
use async_trait::async_trait;
use jamf_rs::JamfClient;

use crate::evidence::CsvCollector;

pub struct JamfComputersCollector {
    client: JamfClient,
}

impl JamfComputersCollector {
    pub fn new(client: JamfClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for JamfComputersCollector {
    fn name(&self) -> &str {
        "Jamf Computers"
    }
    fn filename_prefix(&self) -> &str {
        "Jamf_Computers"
    }

    fn headers(&self) -> &'static [&'static str] {
        &[
            "Computer ID",
            "Name",
            "Serial Number",
            "Model",
            "OS Version",
            "Last Contact Time",
            "Managed",
            "FileVault Status",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let computers = match self.client.computers().list_all().await {
            Ok(c) => c,
            Err(jamf_rs::JamfError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };
        let rows = computers
            .into_iter()
            .map(|c| {
                vec![
                    c.id,
                    c.general.name,
                    c.hardware.serial_number,
                    c.hardware.model,
                    c.operating_system.version,
                    c.general.last_contact_time.unwrap_or_default(),
                    c.general.remote_management.managed.to_string(),
                    c.security.filevault2_status,
                ]
            })
            .collect();
        Ok(rows)
    }
}
```

- [ ] **Step 5: Write the Grabber `CsvCollector` for mobile devices**

`src/providers/jamf/mobile_devices.rs`:
```rust
use anyhow::Result;
use async_trait::async_trait;
use jamf_rs::JamfClient;

use crate::evidence::CsvCollector;

pub struct JamfMobileDevicesCollector {
    client: JamfClient,
}

impl JamfMobileDevicesCollector {
    pub fn new(client: JamfClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for JamfMobileDevicesCollector {
    fn name(&self) -> &str {
        "Jamf Mobile Devices"
    }
    fn filename_prefix(&self) -> &str {
        "Jamf_Mobile_Devices"
    }

    fn headers(&self) -> &'static [&'static str] {
        &[
            "Device ID",
            "Name",
            "Serial Number",
            "Model",
            "OS Version",
            "Last Enrolled",
            "Managed",
            "Supervised",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let devices = match self.client.mobile_devices().list_all().await {
            Ok(d) => d,
            Err(jamf_rs::JamfError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };
        let rows = devices
            .into_iter()
            .map(|d| {
                vec![
                    d.id,
                    d.name,
                    d.serial_number,
                    d.model,
                    d.os_version,
                    d.last_enrolled_date.unwrap_or_default(),
                    d.managed.to_string(),
                    d.supervised.to_string(),
                ]
            })
            .collect();
        Ok(rows)
    }
}
```

- [ ] **Step 6: Register both modules and both collectors**

`src/providers/jamf/mod.rs` — add after `pub mod factory;`:
```rust
pub mod computers;
pub mod mobile_devices;
```

`src/providers/jamf/factory.rs` — replace the empty `csv_collectors()` body:
```rust
fn csv_collectors(&self) -> Vec<Box<dyn CsvCollector>> {
    let mut v: Vec<Box<dyn CsvCollector>> = Vec::new();
    if self.selected.iter().any(|s| s == "jamf-computers") {
        v.push(Box::new(super::computers::JamfComputersCollector::new(
            self.client.clone(),
        )));
    }
    if self.selected.iter().any(|s| s == "jamf-mobile-devices") {
        v.push(Box::new(
            super::mobile_devices::JamfMobileDevicesCollector::new(self.client.clone()),
        ));
    }
    v
}
```

- [ ] **Step 7: Verify it builds**

Run:
```bash
cargo check --features jamf
```
Expected: no errors.

- [ ] **Step 8: Verify against a live Jamf Pro tenant (acceptance)**

Against a real tenant's `/api/doc/` Swagger UI, confirm the `/api/v1/computers-inventory` and `/api/v2/mobile-devices/detail` field names (`general.remoteManagement.managed`, `security.fileVault2Status`, etc.) match this tenant's Jamf Pro version; adjust `#[serde(rename = "...")]` attributes only if they differ. This does not change the collector's headers or shape.

- [ ] **Step 9: Commit**

```bash
git add crates/jamf-rs src/providers/jamf
git commit -m "feat: add Jamf computers and mobile devices collectors"
```

---

## Task 4: Computer + Mobile Config Profiles collectors (Classic API)

**Files:**
- Create: `crates/jamf-rs/src/api/config_profiles.rs`
- Modify: `crates/jamf-rs/src/api/mod.rs`
- Modify: `crates/jamf-rs/src/client.rs`
- Create: `src/providers/jamf/computer_config_profiles.rs`
- Create: `src/providers/jamf/mobile_config_profiles.rs`
- Modify: `src/providers/jamf/mod.rs`
- Modify: `src/providers/jamf/factory.rs`

**Interfaces:**
- Consumes: `JamfClient::get` (Task 1) for non-paginated Classic API list+detail calls.
- Produces: `client.computer_config_profiles().list_all() -> Result<Vec<ConfigProfile>, JamfError>`, `client.mobile_config_profiles().list_all() -> Result<Vec<ConfigProfile>, JamfError>`; `JamfComputerConfigProfilesCollector`, `JamfMobileConfigProfilesCollector` (both `CsvCollector`).

- [ ] **Step 1: Add the shared config-profile model + both accessors**

Classic API (`/JSSResource/...`) honors `Accept: application/json` (set globally in `JamfClient::new`, Task 1 Step 3), so list/detail responses parse as JSON, not XML.

`crates/jamf-rs/src/api/config_profiles.rs`:
```rust
use serde::Deserialize;

use crate::client::JamfClient;
use crate::error::JamfError;

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ConfigProfile {
    pub id: i64,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub category: NamedRef,
    #[serde(default, rename = "distribution_method")]
    pub distribution_method: String,
    #[serde(default)]
    pub scope: ProfileScope,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct NamedRef {
    #[serde(default)]
    pub name: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ProfileScope {
    #[serde(default)]
    pub all_computers: bool,
    #[serde(default)]
    pub all_mobile_devices: bool,
    #[serde(default)]
    pub computer_groups: Vec<NamedRef>,
    #[serde(default)]
    pub mobile_device_groups: Vec<NamedRef>,
}

#[derive(Debug, Deserialize)]
struct ListEnvelope<T> {
    #[serde(alias = "os_x_configuration_profiles", alias = "mobile_device_configuration_profiles")]
    items: Vec<T>,
}

#[derive(Debug, Deserialize)]
struct ListItem {
    id: i64,
}

#[derive(Debug, Deserialize)]
struct DetailEnvelope {
    #[serde(alias = "os_x_configuration_profile", alias = "mobile_device_configuration_profile")]
    general: DetailGeneral,
}

#[derive(Debug, Deserialize)]
struct DetailGeneral {
    general: ProfileGeneralFields,
    #[serde(default)]
    scope: ProfileScope,
}

#[derive(Debug, Deserialize, Default)]
struct ProfileGeneralFields {
    #[serde(default)]
    name: String,
    #[serde(default)]
    category: NamedRef,
    #[serde(default)]
    distribution_method: String,
}

async fn list_and_fetch(
    client: &JamfClient,
    list_path: &str,
    detail_path_prefix: &str,
) -> Result<Vec<ConfigProfile>, JamfError> {
    let resp = client.get(list_path).await?;
    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let message = resp.text().await.unwrap_or_default();
        return Err(JamfError::Api { status, message });
    }
    let list: ListEnvelope<ListItem> = resp.json().await?;

    let mut out = Vec::with_capacity(list.items.len());
    for item in list.items {
        let detail_resp = client
            .get(&format!("{detail_path_prefix}/id/{}", item.id))
            .await?;
        if !detail_resp.status().is_success() {
            continue;
        }
        let detail: DetailEnvelope = detail_resp.json().await?;
        out.push(ConfigProfile {
            id: item.id,
            name: detail.general.general.name,
            category: detail.general.general.category,
            distribution_method: detail.general.general.distribution_method,
            scope: detail.general.scope,
        });
    }
    Ok(out)
}

pub struct ComputerConfigProfilesApi<'c>(pub(crate) &'c JamfClient);

impl<'c> ComputerConfigProfilesApi<'c> {
    pub async fn list_all(&self) -> Result<Vec<ConfigProfile>, JamfError> {
        list_and_fetch(
            self.0,
            "/JSSResource/osxconfigurationprofiles",
            "/JSSResource/osxconfigurationprofiles",
        )
        .await
    }
}

pub struct MobileConfigProfilesApi<'c>(pub(crate) &'c JamfClient);

impl<'c> MobileConfigProfilesApi<'c> {
    pub async fn list_all(&self) -> Result<Vec<ConfigProfile>, JamfError> {
        list_and_fetch(
            self.0,
            "/JSSResource/mobiledeviceconfigurationprofiles",
            "/JSSResource/mobiledeviceconfigurationprofiles",
        )
        .await
    }
}
```

- [ ] **Step 2: Wire accessors and re-export**

`crates/jamf-rs/src/client.rs` — add to the `impl JamfClient` block from Task 3:
```rust
pub fn computer_config_profiles(&self) -> crate::api::config_profiles::ComputerConfigProfilesApi<'_> {
    crate::api::config_profiles::ComputerConfigProfilesApi(self)
}
pub fn mobile_config_profiles(&self) -> crate::api::config_profiles::MobileConfigProfilesApi<'_> {
    crate::api::config_profiles::MobileConfigProfilesApi(self)
}
```

`crates/jamf-rs/src/api/mod.rs` — add:
```rust
pub mod config_profiles;
```

- [ ] **Step 3: Write the two Grabber collectors**

`src/providers/jamf/computer_config_profiles.rs`:
```rust
use anyhow::Result;
use async_trait::async_trait;
use jamf_rs::JamfClient;

use crate::evidence::CsvCollector;

fn scope_summary(scope: &jamf_rs::api::config_profiles::ProfileScope) -> String {
    if scope.all_computers || scope.all_mobile_devices {
        return "All".to_string();
    }
    let groups: Vec<&str> = scope
        .computer_groups
        .iter()
        .chain(scope.mobile_device_groups.iter())
        .map(|g| g.name.as_str())
        .collect();
    if groups.is_empty() {
        "None".to_string()
    } else {
        groups.join("; ")
    }
}

pub struct JamfComputerConfigProfilesCollector {
    client: JamfClient,
}

impl JamfComputerConfigProfilesCollector {
    pub fn new(client: JamfClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for JamfComputerConfigProfilesCollector {
    fn name(&self) -> &str {
        "Jamf Computer Configuration Profiles"
    }
    fn filename_prefix(&self) -> &str {
        "Jamf_Computer_Config_Profiles"
    }

    fn headers(&self) -> &'static [&'static str] {
        &["Profile ID", "Name", "Category", "Distribution Method", "Scope"]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let profiles = match self.client.computer_config_profiles().list_all().await {
            Ok(p) => p,
            Err(jamf_rs::JamfError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };
        let rows = profiles
            .into_iter()
            .map(|p| {
                vec![
                    p.id.to_string(),
                    p.name,
                    p.category.name,
                    p.distribution_method,
                    scope_summary(&p.scope),
                ]
            })
            .collect();
        Ok(rows)
    }
}
```

`src/providers/jamf/mobile_config_profiles.rs` (identical shape, swap the client accessor and filename prefix):
```rust
use anyhow::Result;
use async_trait::async_trait;
use jamf_rs::JamfClient;

use crate::evidence::CsvCollector;

fn scope_summary(scope: &jamf_rs::api::config_profiles::ProfileScope) -> String {
    if scope.all_computers || scope.all_mobile_devices {
        return "All".to_string();
    }
    let groups: Vec<&str> = scope
        .computer_groups
        .iter()
        .chain(scope.mobile_device_groups.iter())
        .map(|g| g.name.as_str())
        .collect();
    if groups.is_empty() {
        "None".to_string()
    } else {
        groups.join("; ")
    }
}

pub struct JamfMobileConfigProfilesCollector {
    client: JamfClient,
}

impl JamfMobileConfigProfilesCollector {
    pub fn new(client: JamfClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for JamfMobileConfigProfilesCollector {
    fn name(&self) -> &str {
        "Jamf Mobile Configuration Profiles"
    }
    fn filename_prefix(&self) -> &str {
        "Jamf_Mobile_Config_Profiles"
    }

    fn headers(&self) -> &'static [&'static str] {
        &["Profile ID", "Name", "Category", "Distribution Method", "Scope"]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let profiles = match self.client.mobile_config_profiles().list_all().await {
            Ok(p) => p,
            Err(jamf_rs::JamfError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };
        let rows = profiles
            .into_iter()
            .map(|p| {
                vec![
                    p.id.to_string(),
                    p.name,
                    p.category.name,
                    p.distribution_method,
                    scope_summary(&p.scope),
                ]
            })
            .collect();
        Ok(rows)
    }
}
```

- [ ] **Step 4: Register modules and collectors**

`src/providers/jamf/mod.rs` — add:
```rust
pub mod computer_config_profiles;
pub mod mobile_config_profiles;
```

`src/providers/jamf/factory.rs` — add inside `csv_collectors()`, before the final `v`:
```rust
if self.selected.iter().any(|s| s == "jamf-computer-config-profiles") {
    v.push(Box::new(
        super::computer_config_profiles::JamfComputerConfigProfilesCollector::new(
            self.client.clone(),
        ),
    ));
}
if self.selected.iter().any(|s| s == "jamf-mobile-config-profiles") {
    v.push(Box::new(
        super::mobile_config_profiles::JamfMobileConfigProfilesCollector::new(
            self.client.clone(),
        ),
    ));
}
```

- [ ] **Step 5: Verify it builds**

Run:
```bash
cargo check --features jamf
```
Expected: no errors.

- [ ] **Step 6: Verify against a live tenant (acceptance)**

Confirm the Classic API JSON envelope key names (`os_x_configuration_profiles` vs. a differently-cased variant, `distribution_method`, `all_computers`) against a live tenant with `curl -H "Accept: application/json" -H "Authorization: Bearer <token>" https://<server>/JSSResource/osxconfigurationprofiles`; adjust the `#[serde(alias = "...")]`/`rename` attributes only if they differ.

- [ ] **Step 7: Commit**

```bash
git add crates/jamf-rs src/providers/jamf
git commit -m "feat: add Jamf computer and mobile configuration profile collectors"
```

---

## Task 5: Computer + Mobile Device Groups collectors (Classic API)

**Files:**
- Create: `crates/jamf-rs/src/api/groups.rs`
- Modify: `crates/jamf-rs/src/api/mod.rs`
- Modify: `crates/jamf-rs/src/client.rs`
- Create: `src/providers/jamf/computer_groups.rs`
- Create: `src/providers/jamf/mobile_device_groups.rs`
- Modify: `src/providers/jamf/mod.rs`
- Modify: `src/providers/jamf/factory.rs`

**Interfaces:**
- Consumes: `JamfClient::get` (Task 1).
- Produces: `client.computer_groups().list_all() -> Result<Vec<DeviceGroup>, JamfError>`, `client.mobile_device_groups().list_all() -> Result<Vec<DeviceGroup>, JamfError>`; `JamfComputerGroupsCollector`, `JamfMobileDeviceGroupsCollector` (both `CsvCollector`).

- [ ] **Step 1: Add the shared group model + both accessors**

`crates/jamf-rs/src/api/groups.rs`:
```rust
use serde::Deserialize;

use crate::client::JamfClient;
use crate::error::JamfError;

#[derive(Debug, Clone, Deserialize, Default)]
pub struct DeviceGroup {
    pub id: i64,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub is_smart: bool,
    #[serde(default)]
    pub criteria: Vec<Criterion>,
    #[serde(default)]
    pub member_count: usize,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Criterion {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub operator: String,
    #[serde(default)]
    pub value: String,
}

#[derive(Debug, Deserialize)]
struct ListEnvelope {
    #[serde(alias = "computer_groups", alias = "mobile_device_groups")]
    items: Vec<ListItem>,
}

#[derive(Debug, Deserialize)]
struct ListItem {
    id: i64,
}

#[derive(Debug, Deserialize)]
struct DetailEnvelope {
    #[serde(alias = "computer_group", alias = "mobile_device_group")]
    detail: GroupDetail,
}

#[derive(Debug, Deserialize, Default)]
struct GroupDetail {
    #[serde(default)]
    name: String,
    #[serde(default)]
    is_smart: bool,
    #[serde(default)]
    criteria: CriteriaEnvelope,
    #[serde(default, alias = "computers", alias = "mobile_devices")]
    members: MembersEnvelope,
}

#[derive(Debug, Deserialize, Default)]
struct CriteriaEnvelope {
    #[serde(default)]
    criterion: Vec<Criterion>,
}

#[derive(Debug, Deserialize, Default)]
struct MembersEnvelope {
    #[serde(default, alias = "computer", alias = "mobile_device")]
    member: Vec<serde_json::Value>,
}

async fn list_and_fetch(
    client: &JamfClient,
    list_path: &str,
    detail_path_prefix: &str,
) -> Result<Vec<DeviceGroup>, JamfError> {
    let resp = client.get(list_path).await?;
    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let message = resp.text().await.unwrap_or_default();
        return Err(JamfError::Api { status, message });
    }
    let list: ListEnvelope = resp.json().await?;

    let mut out = Vec::with_capacity(list.items.len());
    for item in list.items {
        let detail_resp = client
            .get(&format!("{detail_path_prefix}/id/{}", item.id))
            .await?;
        if !detail_resp.status().is_success() {
            continue;
        }
        let detail: DetailEnvelope = detail_resp.json().await?;
        out.push(DeviceGroup {
            id: item.id,
            name: detail.detail.name,
            is_smart: detail.detail.is_smart,
            criteria: detail.detail.criteria.criterion,
            member_count: detail.detail.members.member.len(),
        });
    }
    Ok(out)
}

pub struct ComputerGroupsApi<'c>(pub(crate) &'c JamfClient);

impl<'c> ComputerGroupsApi<'c> {
    pub async fn list_all(&self) -> Result<Vec<DeviceGroup>, JamfError> {
        list_and_fetch(
            self.0,
            "/JSSResource/computergroups",
            "/JSSResource/computergroups",
        )
        .await
    }
}

pub struct MobileDeviceGroupsApi<'c>(pub(crate) &'c JamfClient);

impl<'c> MobileDeviceGroupsApi<'c> {
    pub async fn list_all(&self) -> Result<Vec<DeviceGroup>, JamfError> {
        list_and_fetch(
            self.0,
            "/JSSResource/mobiledevicegroups",
            "/JSSResource/mobiledevicegroups",
        )
        .await
    }
}
```

- [ ] **Step 2: Wire accessors and re-export**

`crates/jamf-rs/src/client.rs` — add to the `impl JamfClient` block:
```rust
pub fn computer_groups(&self) -> crate::api::groups::ComputerGroupsApi<'_> {
    crate::api::groups::ComputerGroupsApi(self)
}
pub fn mobile_device_groups(&self) -> crate::api::groups::MobileDeviceGroupsApi<'_> {
    crate::api::groups::MobileDeviceGroupsApi(self)
}
```

`crates/jamf-rs/src/api/mod.rs` — add:
```rust
pub mod groups;
```

- [ ] **Step 3: Write the two Grabber collectors**

`src/providers/jamf/computer_groups.rs`:
```rust
use anyhow::Result;
use async_trait::async_trait;
use jamf_rs::JamfClient;

use crate::evidence::CsvCollector;

fn criteria_summary(criteria: &[jamf_rs::api::groups::Criterion]) -> String {
    if criteria.is_empty() {
        return "static".to_string();
    }
    criteria
        .iter()
        .map(|c| format!("{} {} {}", c.name, c.operator, c.value))
        .collect::<Vec<_>>()
        .join(" AND ")
}

pub struct JamfComputerGroupsCollector {
    client: JamfClient,
}

impl JamfComputerGroupsCollector {
    pub fn new(client: JamfClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for JamfComputerGroupsCollector {
    fn name(&self) -> &str {
        "Jamf Computer Groups"
    }
    fn filename_prefix(&self) -> &str {
        "Jamf_Computer_Groups"
    }

    fn headers(&self) -> &'static [&'static str] {
        &["Group ID", "Name", "Type", "Criteria", "Member Count"]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let groups = match self.client.computer_groups().list_all().await {
            Ok(g) => g,
            Err(jamf_rs::JamfError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };
        let rows = groups
            .into_iter()
            .map(|g| {
                vec![
                    g.id.to_string(),
                    g.name,
                    if g.is_smart { "Smart".to_string() } else { "Static".to_string() },
                    criteria_summary(&g.criteria),
                    g.member_count.to_string(),
                ]
            })
            .collect();
        Ok(rows)
    }
}
```

`src/providers/jamf/mobile_device_groups.rs` (identical shape):
```rust
use anyhow::Result;
use async_trait::async_trait;
use jamf_rs::JamfClient;

use crate::evidence::CsvCollector;

fn criteria_summary(criteria: &[jamf_rs::api::groups::Criterion]) -> String {
    if criteria.is_empty() {
        return "static".to_string();
    }
    criteria
        .iter()
        .map(|c| format!("{} {} {}", c.name, c.operator, c.value))
        .collect::<Vec<_>>()
        .join(" AND ")
}

pub struct JamfMobileDeviceGroupsCollector {
    client: JamfClient,
}

impl JamfMobileDeviceGroupsCollector {
    pub fn new(client: JamfClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for JamfMobileDeviceGroupsCollector {
    fn name(&self) -> &str {
        "Jamf Mobile Device Groups"
    }
    fn filename_prefix(&self) -> &str {
        "Jamf_Mobile_Device_Groups"
    }

    fn headers(&self) -> &'static [&'static str] {
        &["Group ID", "Name", "Type", "Criteria", "Member Count"]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let groups = match self.client.mobile_device_groups().list_all().await {
            Ok(g) => g,
            Err(jamf_rs::JamfError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };
        let rows = groups
            .into_iter()
            .map(|g| {
                vec![
                    g.id.to_string(),
                    g.name,
                    if g.is_smart { "Smart".to_string() } else { "Static".to_string() },
                    criteria_summary(&g.criteria),
                    g.member_count.to_string(),
                ]
            })
            .collect();
        Ok(rows)
    }
}
```

- [ ] **Step 4: Register modules and collectors**

`src/providers/jamf/mod.rs` — add:
```rust
pub mod computer_groups;
pub mod mobile_device_groups;
```

`src/providers/jamf/factory.rs` — add inside `csv_collectors()`:
```rust
if self.selected.iter().any(|s| s == "jamf-computer-groups") {
    v.push(Box::new(super::computer_groups::JamfComputerGroupsCollector::new(
        self.client.clone(),
    )));
}
if self.selected.iter().any(|s| s == "jamf-mobile-device-groups") {
    v.push(Box::new(
        super::mobile_device_groups::JamfMobileDeviceGroupsCollector::new(self.client.clone()),
    ));
}
```

- [ ] **Step 5: Verify it builds**

Run:
```bash
cargo check --features jamf
```
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add crates/jamf-rs src/providers/jamf
git commit -m "feat: add Jamf computer and mobile device group collectors"
```

---

## Task 6: Policies collector (Classic API, `JsonCollector`)

**Files:**
- Create: `crates/jamf-rs/src/api/policies.rs`
- Modify: `crates/jamf-rs/src/api/mod.rs`
- Modify: `crates/jamf-rs/src/client.rs`
- Create: `src/providers/jamf/policies.rs`
- Modify: `src/providers/jamf/mod.rs`
- Modify: `src/providers/jamf/factory.rs`

**Interfaces:**
- Consumes: `JamfClient::get` (Task 1).
- Produces: `client.policies().list_all() -> Result<Vec<Policy>, JamfError>`; `JamfPoliciesCollector` implementing `JsonCollector` (per the spec, `jamf-policies` is the one JSON-typed P0 collector).

- [ ] **Step 1: Add the policy model + list+detail accessor**

`crates/jamf-rs/src/api/policies.rs`:
```rust
use serde::{Deserialize, Serialize};

use crate::client::JamfClient;
use crate::error::JamfError;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Policy {
    pub id: i64,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub frequency: String,
    #[serde(default)]
    pub scope: String,
}

#[derive(Debug, Deserialize)]
struct ListEnvelope {
    policies: Vec<ListItem>,
}

#[derive(Debug, Deserialize)]
struct ListItem {
    id: i64,
}

#[derive(Debug, Deserialize)]
struct DetailEnvelope {
    policy: PolicyDetail,
}

#[derive(Debug, Deserialize, Default)]
struct PolicyDetail {
    #[serde(default)]
    general: PolicyGeneral,
    #[serde(default)]
    scope: PolicyScopeDetail,
}

#[derive(Debug, Deserialize, Default)]
struct PolicyGeneral {
    #[serde(default)]
    name: String,
    #[serde(default)]
    category: NamedRef,
    #[serde(default)]
    frequency: String,
}

#[derive(Debug, Deserialize, Default)]
struct NamedRef {
    #[serde(default)]
    name: String,
}

#[derive(Debug, Deserialize, Default)]
struct PolicyScopeDetail {
    #[serde(default)]
    all_computers: bool,
    #[serde(default)]
    computer_groups: Vec<NamedRef>,
}

pub struct PoliciesApi<'c>(pub(crate) &'c JamfClient);

impl<'c> PoliciesApi<'c> {
    /// GET /JSSResource/policies (list) + /JSSResource/policies/id/{id} (detail per policy) —
    /// the Classic API's list endpoint only returns id+name, so full policy detail requires
    /// one detail fetch per policy.
    pub async fn list_all(&self) -> Result<Vec<Policy>, JamfError> {
        let resp = self.0.get("/JSSResource/policies").await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let message = resp.text().await.unwrap_or_default();
            return Err(JamfError::Api { status, message });
        }
        let list: ListEnvelope = resp.json().await?;

        let mut out = Vec::with_capacity(list.policies.len());
        for item in list.policies {
            let detail_resp = self
                .0
                .get(&format!("/JSSResource/policies/id/{}", item.id))
                .await?;
            if !detail_resp.status().is_success() {
                continue;
            }
            let detail: DetailEnvelope = detail_resp.json().await?;
            let scope = if detail.policy.scope.all_computers {
                "All".to_string()
            } else {
                let names: Vec<&str> = detail
                    .policy
                    .scope
                    .computer_groups
                    .iter()
                    .map(|g| g.name.as_str())
                    .collect();
                if names.is_empty() {
                    "None".to_string()
                } else {
                    names.join("; ")
                }
            };
            out.push(Policy {
                id: item.id,
                name: detail.policy.general.name,
                category: detail.policy.general.category.name,
                frequency: detail.policy.general.frequency,
                scope,
            });
        }
        Ok(out)
    }
}
```

- [ ] **Step 2: Wire the accessor and re-export**

`crates/jamf-rs/src/client.rs` — add to the `impl JamfClient` block:
```rust
pub fn policies(&self) -> crate::api::policies::PoliciesApi<'_> {
    crate::api::policies::PoliciesApi(self)
}
```

`crates/jamf-rs/src/api/mod.rs` — add:
```rust
pub mod policies;
```

- [ ] **Step 3: Write the Grabber `JsonCollector`**

`src/providers/jamf/policies.rs`:
```rust
use anyhow::Result;
use async_trait::async_trait;
use jamf_rs::JamfClient;

use crate::evidence::JsonCollector;

pub struct JamfPoliciesCollector {
    client: JamfClient,
}

impl JamfPoliciesCollector {
    pub fn new(client: JamfClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl JsonCollector for JamfPoliciesCollector {
    fn name(&self) -> &str {
        "Jamf Policies"
    }
    fn filename_prefix(&self) -> &str {
        "Jamf_Policies"
    }

    async fn collect_records(
        &self,
        _account_id: &str,
        _region: &str,
    ) -> Result<Vec<serde_json::Value>> {
        let policies = match self.client.policies().list_all().await {
            Ok(p) => p,
            Err(jamf_rs::JamfError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };
        Ok(policies
            .into_iter()
            .map(|p| serde_json::to_value(p).unwrap_or(serde_json::Value::Null))
            .collect())
    }
}
```

- [ ] **Step 4: Register the module and the collector**

`src/providers/jamf/mod.rs` — add:
```rust
pub mod policies;
```

`src/providers/jamf/factory.rs` — replace the empty `json_collectors()` body:
```rust
fn json_collectors(&self) -> Vec<Box<dyn JsonCollector>> {
    let mut v: Vec<Box<dyn JsonCollector>> = Vec::new();
    if self.selected.iter().any(|s| s == "jamf-policies") {
        v.push(Box::new(super::policies::JamfPoliciesCollector::new(
            self.client.clone(),
        )));
    }
    v
}
```

- [ ] **Step 5: Verify it builds**

Run:
```bash
cargo check --features jamf
```
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add crates/jamf-rs src/providers/jamf
git commit -m "feat: add Jamf policies collector"
```

---

## Task 7: Patch Titles + Patch Compliance collectors

**Files:**
- Create: `crates/jamf-rs/src/api/patch.rs`
- Modify: `crates/jamf-rs/src/api/mod.rs`
- Modify: `crates/jamf-rs/src/client.rs`
- Create: `src/providers/jamf/patch_titles.rs`
- Create: `src/providers/jamf/patch_compliance.rs`
- Modify: `src/providers/jamf/mod.rs`
- Modify: `src/providers/jamf/factory.rs`

**Interfaces:**
- Consumes: `JamfClient::get` (Task 1).
- Produces: `client.patch().list_titles() -> Result<Vec<PatchTitle>, JamfError>`, `client.patch().summary(title_id: &str) -> Result<PatchSummary, JamfError>`; `JamfPatchTitlesCollector`, `JamfPatchComplianceCollector` (both `CsvCollector`).

- [ ] **Step 1: Add the patch models + accessor**

`crates/jamf-rs/src/api/patch.rs`:
```rust
use serde::Deserialize;

use crate::client::JamfClient;
use crate::error::JamfError;

#[derive(Debug, Clone, Deserialize)]
pub struct PatchTitle {
    pub id: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct PatchSummary {
    #[serde(default, rename = "latestVersion")]
    pub latest_version: String,
    #[serde(default)]
    pub versions: Vec<PatchVersionCount>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct PatchVersionCount {
    #[serde(default)]
    pub version: String,
    #[serde(default, rename = "hostIds")]
    pub host_ids: Vec<String>,
}

impl PatchSummary {
    /// Devices currently on `latest_version`.
    pub fn compliant_count(&self) -> usize {
        self.versions
            .iter()
            .find(|v| v.version == self.latest_version)
            .map(|v| v.host_ids.len())
            .unwrap_or(0)
    }

    /// Devices on any other reported version.
    pub fn out_of_date_count(&self) -> usize {
        self.versions
            .iter()
            .filter(|v| v.version != self.latest_version)
            .map(|v| v.host_ids.len())
            .sum()
    }
}

pub struct PatchApi<'c>(pub(crate) &'c JamfClient);

impl<'c> PatchApi<'c> {
    /// GET /api/v2/patch-software-title-configurations — configured patch titles.
    /// Org-scale title counts are small (tens, not thousands), so this call is
    /// not paginated.
    pub async fn list_titles(&self) -> Result<Vec<PatchTitle>, JamfError> {
        let resp = self
            .0
            .get("/api/v2/patch-software-title-configurations")
            .await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let message = resp.text().await.unwrap_or_default();
            return Err(JamfError::Api { status, message });
        }
        Ok(resp.json().await?)
    }

    /// GET /api/v2/patch-software-title-configurations/{id}/patch-summary
    pub async fn summary(&self, title_id: &str) -> Result<PatchSummary, JamfError> {
        let resp = self
            .0
            .get(&format!(
                "/api/v2/patch-software-title-configurations/{title_id}/patch-summary"
            ))
            .await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let message = resp.text().await.unwrap_or_default();
            return Err(JamfError::Api { status, message });
        }
        Ok(resp.json().await?)
    }
}
```

- [ ] **Step 2: Wire the accessor and re-export**

`crates/jamf-rs/src/client.rs` — add to the `impl JamfClient` block:
```rust
pub fn patch(&self) -> crate::api::patch::PatchApi<'_> {
    crate::api::patch::PatchApi(self)
}
```

`crates/jamf-rs/src/api/mod.rs` — add:
```rust
pub mod patch;
```

- [ ] **Step 3: Write the patch-titles collector (no minimum-OS field on this endpoint — omit it from headers rather than fabricate a value)**

`src/providers/jamf/patch_titles.rs`:
```rust
use anyhow::Result;
use async_trait::async_trait;
use jamf_rs::JamfClient;

use crate::evidence::CsvCollector;

pub struct JamfPatchTitlesCollector {
    client: JamfClient,
}

impl JamfPatchTitlesCollector {
    pub fn new(client: JamfClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for JamfPatchTitlesCollector {
    fn name(&self) -> &str {
        "Jamf Patch Titles"
    }
    fn filename_prefix(&self) -> &str {
        "Jamf_Patch_Titles"
    }

    fn headers(&self) -> &'static [&'static str] {
        &["Title ID", "Display Name"]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let titles = match self.client.patch().list_titles().await {
            Ok(t) => t,
            Err(jamf_rs::JamfError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };
        let rows = titles.into_iter().map(|t| vec![t.id, t.display_name]).collect();
        Ok(rows)
    }
}
```

- [ ] **Step 4: Write the patch-compliance collector**

`src/providers/jamf/patch_compliance.rs`:
```rust
use anyhow::Result;
use async_trait::async_trait;
use jamf_rs::JamfClient;

use crate::evidence::CsvCollector;

pub struct JamfPatchComplianceCollector {
    client: JamfClient,
}

impl JamfPatchComplianceCollector {
    pub fn new(client: JamfClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for JamfPatchComplianceCollector {
    fn name(&self) -> &str {
        "Jamf Patch Compliance"
    }
    fn filename_prefix(&self) -> &str {
        "Jamf_Patch_Compliance"
    }

    fn headers(&self) -> &'static [&'static str] {
        &["Title ID", "Display Name", "Latest Version", "Compliant Devices", "Out Of Date Devices"]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let titles = match self.client.patch().list_titles().await {
            Ok(t) => t,
            Err(jamf_rs::JamfError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };
        let mut rows = Vec::with_capacity(titles.len());
        for title in titles {
            let summary = match self.client.patch().summary(&title.id).await {
                Ok(s) => s,
                Err(jamf_rs::JamfError::Api { status: 404, .. }) => continue,
                Err(e) => return Err(e.into()),
            };
            rows.push(vec![
                title.id,
                title.display_name,
                summary.latest_version.clone(),
                summary.compliant_count().to_string(),
                summary.out_of_date_count().to_string(),
            ]);
        }
        Ok(rows)
    }
}
```

- [ ] **Step 5: Register modules and collectors**

`src/providers/jamf/mod.rs` — add:
```rust
pub mod patch_titles;
pub mod patch_compliance;
```

`src/providers/jamf/factory.rs` — add inside `csv_collectors()`:
```rust
if self.selected.iter().any(|s| s == "jamf-patch-titles") {
    v.push(Box::new(super::patch_titles::JamfPatchTitlesCollector::new(
        self.client.clone(),
    )));
}
if self.selected.iter().any(|s| s == "jamf-patch-compliance") {
    v.push(Box::new(
        super::patch_compliance::JamfPatchComplianceCollector::new(self.client.clone()),
    ));
}
```

- [ ] **Step 6: Verify it builds**

Run:
```bash
cargo check --features jamf && cargo clippy --features jamf -- -D warnings
```
Expected: no errors, no warnings. This is the last of the 9 P0 collectors — confirm `cargo check --features jamf` compiles cleanly with all nine registered.

- [ ] **Step 7: Commit**

```bash
git add crates/jamf-rs src/providers/jamf
git commit -m "feat: add Jamf patch titles and patch compliance collectors"
```

---

## Task 8: Config wiring — `jamf-config.toml`, `Account` fields, `.gitignore`

**Files:**
- Modify: `src/app_config.rs`
- Create: `jamf-config.example.toml`
- Modify: `.gitignore`

**Interfaces:**
- Produces: `Account::jamf_base_url_resolved(&self) -> Option<String>`, `Account::jamf_client_id_resolved(&self) -> Option<String>`, `Account::jamf_client_secret_resolved(&self) -> Option<String>`.

- [ ] **Step 1: Add the Jamf fields to `Account`**

Edit `src/app_config.rs`, adding a new field block right after the Elastic fields (after line 219, before the "Collector filtering" comment at line 221):
```rust
    // ------------------------------------------------------------------
    // Jamf fields
    // ------------------------------------------------------------------
    /// Jamf Pro server base URL (e.g. `https://acme.jamfcloud.com`, or a
    /// self-hosted URL — the API is identical either way).
    pub jamf_base_url: Option<String>,

    /// Jamf Pro API OAuth2 client ID (client-credentials flow).
    /// Can also be supplied via `JAMF_CLIENT_ID` env var (env wins over TOML).
    pub jamf_client_id: Option<String>,

    /// Jamf Pro API OAuth2 client secret.
    /// Can also be supplied via `JAMF_CLIENT_SECRET` env var (env wins over TOML).
    pub jamf_client_secret: Option<String>,
```

- [ ] **Step 2: Add the resolver methods**

Edit `src/app_config.rs`, adding to `impl Account` right after `elastic_api_key_resolved` (after line 313, before the closing `}` of the impl block at line 314):
```rust

    /// Resolve Jamf base URL, trimming any trailing slash. Returns None if unset.
    pub fn jamf_base_url_resolved(&self) -> Option<String> {
        std::env::var("JAMF_BASE_URL")
            .ok()
            .or_else(|| self.jamf_base_url.clone())
            .map(|s| s.trim().trim_end_matches('/').to_string())
            .filter(|s| !s.is_empty())
    }

    /// Resolve Jamf OAuth2 client ID: env var takes precedence over TOML.
    pub fn jamf_client_id_resolved(&self) -> Option<String> {
        std::env::var("JAMF_CLIENT_ID")
            .ok()
            .or_else(|| self.jamf_client_id.clone())
    }

    /// Resolve Jamf OAuth2 client secret: env var takes precedence over TOML.
    pub fn jamf_client_secret_resolved(&self) -> Option<String> {
        std::env::var("JAMF_CLIENT_SECRET")
            .ok()
            .or_else(|| self.jamf_client_secret.clone())
    }
```

- [ ] **Step 3: Add the `jamf-config.toml` merge block in `load_config()`**

Edit `src/app_config.rs`, adding after the Elastic merge block (after line 381, before `Some(cfg)` at line 383):
```rust

    // Merge jamf-config.toml accounts if present
    let jamf_path = PathBuf::from("jamf-config.toml");
    if jamf_path.exists() {
        if let Ok(contents) = fs::read_to_string(&jamf_path) {
            if let Ok(jamf_cfg) = toml::from_str::<AppConfig>(&contents) {
                cfg.account.extend(jamf_cfg.account);
            }
        }
    }
```

Also update the doc comment above `load_config()` (lines 316-322) to mention `jamf-config.toml`:
```rust
/// Best-effort load of config, checking in order:
///   1. `./config.toml`  (project-local)
///   2. `~/.config/evidence/config.toml`  (user-global)
///
/// After loading the primary config, `./tenable-config.toml`, `./okta-config.toml`,
/// `./jira-config.toml`, `./elastic-config.toml`, and `./jamf-config.toml` are merged
/// in (accounts only) if those files exist.
```

- [ ] **Step 4: Write `jamf-config.example.toml`**

`jamf-config.example.toml`:
```toml
# Jamf credentials — keep this file out of version control
# Add to .gitignore: jamf-config.toml
#
# Merged automatically into config.toml at startup when present.
# Env vars override TOML values: JAMF_BASE_URL, JAMF_CLIENT_ID, JAMF_CLIENT_SECRET

[[account]]
name               = "Jamf"
provider           = "jamf"
description        = "Jamf Pro production tenant"
output_dir         = "./evidence-output/jamf"
jamf_base_url      = "https://acme.jamfcloud.com"
jamf_client_id     = ""
jamf_client_secret = ""
```

- [ ] **Step 5: Update `.gitignore`**

Edit `.gitignore`, adding after the Okta stanza (after line 52, `okta-config.toml`):
```
# Jamf credentials — never commit
jamf-config.toml
```

- [ ] **Step 6: Verify it builds**

Run:
```bash
cargo check --features jamf
```
Expected: no errors.

- [ ] **Step 7: Commit**

```bash
git add src/app_config.rs jamf-config.example.toml .gitignore
git commit -m "feat: add Jamf account config fields and jamf-config.toml merge"
```

---

## Task 9: TUI wiring — provider selection, collector menu

**Files:**
- Modify: `src/tui/app/nav.rs`
- Modify: `src/tui/events.rs`
- Modify: `src/tui/ui/account_screens.rs`
- Create: `src/tui/menus/jamf.rs`
- Modify: `src/tui/menus/mod.rs`

Per the six-touchpoint checklist in CLAUDE.md: Jamf is a plain collector-menu provider like Okta (no bespoke `Screen` variant), so `src/tui/state.rs`, `src/tui/ui/mod.rs`, `src/tui/ui/frame.rs`, and `src/tui/collector_data.rs` need **no changes** — confirmed by the fact Okta touches none of them either.

**Interfaces:**
- Produces: `crate::tui::menus::jamf::JAMF_CATEGORIES: &[ProviderCategory]`, registered in `PROVIDER_MENUS`.

- [ ] **Step 1: Add `CloudProvider::Jamf` to the two `nav.rs` transition arms**

Edit `src/tui/app/nav.rs:107-110` (the `next_screen()` `ProviderSelection` arm):
```rust
                } else if self.selected_provider == CloudProvider::Okta
                    || self.selected_provider == CloudProvider::Jira
                    || self.selected_provider == CloudProvider::Elastic
                    || self.selected_provider == CloudProvider::Jamf
                {
```

Edit `src/tui/app/nav.rs:160-163` (the `prev_screen()` `SelectCollectors` arm):
```rust
                } else if self.selected_provider == CloudProvider::Okta
                    || self.selected_provider == CloudProvider::Jira
                    || self.selected_provider == CloudProvider::Elastic
                    || self.selected_provider == CloudProvider::Jamf
                {
```

- [ ] **Step 2: Add the `validate_current()` no-accounts-configured check**

Edit `src/tui/app/nav.rs`, adding a new block after the Elastic block that follows the Okta block shown at lines 238-249 (i.e. immediately after the existing `#[cfg(feature = "elastic")]` block that mirrors it):
```rust
                #[cfg(feature = "jamf")]
                if self.selected_provider == CloudProvider::Jamf {
                    let has_jamf = self
                        .accounts
                        .iter()
                        .any(|a| a.provider == CloudProvider::Jamf);
                    if !has_jamf {
                        self.error_msg =
                            Some("No Jamf accounts configured in jamf-config.toml".into());
                        return false;
                    }
                }
```

- [ ] **Step 3: Register the provider in `events.rs`'s provider list**

Edit `src/tui/events.rs:872-873` (immediately after the `#[cfg(feature = "elastic")] v.push(CloudProvider::Elastic);` line, inside `handle_provider_selection`):
```rust
        #[cfg(feature = "jamf")]
        v.push(CloudProvider::Jamf);
```

- [ ] **Step 4: Add the matching tile in `account_screens.rs`**

Edit `src/tui/ui/account_screens.rs`, immediately after the Elastic tile (the block starting at line 56):
```rust
        #[cfg(feature = "jamf")]
        v.push((
            CloudProvider::Jamf,
            "◆  Jamf",
            "Collect computer/mobile device inventory, configuration profiles, policies, and patch compliance from Jamf Pro",
        ));
```

- [ ] **Step 5: Write the Jamf collector menu**

`src/tui/menus/jamf.rs`:
```rust
//! Jamf collector menu. 9 collectors across 3 categories.

use super::ProviderCategory;

pub const JAMF_CATEGORIES: &[ProviderCategory] = &[
    ProviderCategory {
        name: "Device Inventory",
        items: &[
            ("jamf-computers", "Computers                "),
            ("jamf-mobile-devices", "Mobile Devices           "),
            ("jamf-computer-groups", "Computer Groups          "),
            ("jamf-mobile-device-groups", "Mobile Device Groups     "),
        ],
    },
    ProviderCategory {
        name: "Configuration & Policy",
        items: &[
            ("jamf-computer-config-profiles", "Computer Config Profiles "),
            ("jamf-mobile-config-profiles", "Mobile Config Profiles   "),
            ("jamf-policies", "Policies                 "),
        ],
    },
    ProviderCategory {
        name: "Patch Management",
        items: &[
            ("jamf-patch-titles", "Patch Titles             "),
            ("jamf-patch-compliance", "Patch Compliance         "),
        ],
    },
];
```

- [ ] **Step 6: Register the menu**

Edit `src/tui/menus/mod.rs:5-9` (module declarations):
```rust
pub mod aws;
pub mod elastic;
pub mod jamf;
pub mod jira;
pub mod okta;
pub mod tenable;
```

Edit `src/tui/menus/mod.rs:25-46` (`PROVIDER_MENUS`), adding after the Elastic entry:
```rust
    ProviderMenu {
        provider: CloudProvider::Jamf,
        categories: jamf::JAMF_CATEGORIES,
    },
```

- [ ] **Step 7: Verify it builds**

Run:
```bash
cargo check --features jamf
```
Expected: no errors.

- [ ] **Step 8: Commit**

```bash
git add src/tui
git commit -m "feat: wire Jamf into TUI provider selection and collector menu"
```

---

## Task 10: Runner wiring — Jamf account-prep block in `tui_session.rs`

**Files:**
- Modify: `src/runner/tui_session.rs`

**Interfaces:**
- Consumes: `Account::jamf_base_url_resolved`/`jamf_client_id_resolved`/`jamf_client_secret_resolved` (Task 8), `jamf_rs::JamfClient::new` (Task 1), `JamfProviderFactory::new` (Task 2).

- [ ] **Step 1: Add the Jamf account-prep block**

Edit `src/runner/tui_session.rs`, inserting a new block immediately after the Jira block (which itself follows the Okta block at lines 728-836) — i.e. after whichever provider block is last before this insertion; place it directly after the Okta block at line 836, before the `// ── Jira accounts ──` comment at line 838, mirroring the Okta block exactly:
```rust
            // ── Jamf accounts ────────────────────────────────────────────────────
            #[cfg(feature = "jamf")]
            if !app.selected_accounts.is_empty() {
                use crate::providers::ProviderFactory as _;

                let sorted_all: Vec<usize> = {
                    let mut v: Vec<usize> = app.selected_accounts.iter().copied().collect();
                    v.sort();
                    v
                };
                for &idx in &sorted_all {
                    if app.accounts[idx].provider != crate::providers::CloudProvider::Jamf {
                        continue;
                    }
                    let acct = &app.accounts[idx];
                    let tenant_name = acct.name.clone();

                    let base_url = match acct.jamf_base_url_resolved() {
                        Some(u) => u,
                        None => {
                            app.prep_log.push(format!(
                                "  ✗ Jamf '{}' — missing jamf_base_url (or JAMF_BASE_URL env)",
                                tenant_name,
                            ));
                            terminal.draw(|f| crate::tui::ui::draw(f, &app))?;
                            continue;
                        }
                    };
                    let client_id = match acct.jamf_client_id_resolved() {
                        Some(c) => c,
                        None => {
                            app.prep_log.push(format!(
                                "  ✗ Jamf '{}' — missing jamf_client_id (or JAMF_CLIENT_ID env)",
                                tenant_name,
                            ));
                            terminal.draw(|f| crate::tui::ui::draw(f, &app))?;
                            continue;
                        }
                    };
                    let client_secret = match acct.jamf_client_secret_resolved() {
                        Some(s) => s,
                        None => {
                            app.prep_log.push(format!(
                                "  ✗ Jamf '{}' — missing jamf_client_secret (or JAMF_CLIENT_SECRET env)",
                                tenant_name,
                            ));
                            terminal.draw(|f| crate::tui::ui::draw(f, &app))?;
                            continue;
                        }
                    };

                    app.prep_log
                        .push(format!("  Jamf '{}' → {}", tenant_name, base_url));
                    terminal.draw(|f| crate::tui::ui::draw(f, &app))?;

                    let client = match jamf_rs::JamfClient::new(&base_url, &client_id, &client_secret) {
                        Ok(c) => c,
                        Err(e) => {
                            app.prep_log.push(format!(
                                "  ✗ Jamf '{}' — client build failed: {e}",
                                tenant_name,
                            ));
                            terminal.draw(|f| crate::tui::ui::draw(f, &app))?;
                            continue;
                        }
                    };

                    let selected_keys: Vec<String> = app
                        .selected_collectors()
                        .into_iter()
                        .filter(|k| k.starts_with("jamf-"))
                        .collect();

                    let factory = crate::providers::jamf::factory::JamfProviderFactory::new(
                        client,
                        tenant_name.clone(),
                        selected_keys.clone(),
                    );
                    let csv_cols = factory.csv_collectors();
                    let json_inv_cols = factory.json_collectors();
                    let evidence_cols = factory.evidence_collectors();
                    let display_names: Vec<String> = csv_cols
                        .iter()
                        .map(|c| c.name().to_string())
                        .chain(json_inv_cols.iter().map(|c| c.name().to_string()))
                        .chain(evidence_cols.iter().map(|c| c.name().to_string()))
                        .collect();

                    let output_path = Some(
                        base_output_path
                            .clone()
                            .unwrap_or_else(|| PathBuf::from("."))
                            .join(&tenant_name),
                    );

                    prepared.push(crate::runner::multi_account::AccountCollectors {
                        account_id: tenant_name.clone(),
                        aws_caller_arn: String::new(),
                        aws_user_id: String::new(),
                        profile: String::new(),
                        region: String::new(),
                        output_path,
                        collector_keys: selected_keys,
                        json_collectors: evidence_cols,
                        json_inv_collectors: json_inv_cols,
                        csv_collectors: csv_cols,
                        display_names,
                        discovered_regions: Vec::new(),
                        regional_collectors: Vec::new(),
                        inventory_multi_region: Vec::new(),
                        endpoint_label: Some(format!("Jamf — {}", base_url)),
                    });

                    app.prep_log
                        .push(format!("  ✓ Jamf '{}' ready.", tenant_name));
                    terminal.draw(|f| crate::tui::ui::draw(f, &app))?;
                }
            }

```

- [ ] **Step 2: Verify it builds**

Run:
```bash
cargo check --features jamf
```
Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add src/runner/tui_session.rs
git commit -m "feat: wire Jamf account preparation into the TUI runner"
```

---

## Task 11: FedRAMP mapping — `assets/fedramp-map.json`

**Files:**
- Modify: `assets/fedramp-map.json`

**Interfaces:**
- Consumes: existing `requirements` entries `NIST-1098`, `NIST-1099`, `NIST-1100` (AC-19 mobile device management), `NIST-1235`–`NIST-1237` (CM-06 configuration baseline), `NIST-1688`, `NIST-1689` (SI-02 patch management) — all already present in `assets/fedramp-map.json`, no new requirement rows needed.
- Produces: `collectors` entries for the 7 P0 collectors that map to real compliance requirements. Following the Okta precedent (pure inventory/scoping collectors — `Okta_Users`, `Okta_Groups` — carry no explicit mapping and fall back to the trait default), `Jamf_Computer_Groups` and `Jamf_Mobile_Device_Groups` intentionally get no entry here.

- [ ] **Step 1: Add the 7 mapped collector entries**

Edit `assets/fedramp-map.json`, adding these keys to the `collectors` object (anywhere in the object — it's a `BTreeMap`, so insertion order doesn't matter):
```json
"Jamf_Computers": {
  "req_ids": ["NIST-1098", "NIST-1099", "NIST-1100"],
  "control_ids": ["AC-19a.", "AC-19b.", "AC-19(05)"]
},
"Jamf_Mobile_Devices": {
  "req_ids": ["NIST-1098", "NIST-1099", "NIST-1100"],
  "control_ids": ["AC-19a.", "AC-19b.", "AC-19(05)"]
},
"Jamf_Computer_Config_Profiles": {
  "req_ids": ["NIST-1235", "NIST-1236", "NIST-1237"],
  "control_ids": ["CM-06a., CM-06b.", "CM-06c.", "CM-06d."]
},
"Jamf_Mobile_Config_Profiles": {
  "req_ids": ["NIST-1235", "NIST-1236", "NIST-1237"],
  "control_ids": ["CM-06a., CM-06b.", "CM-06c.", "CM-06d."]
},
"Jamf_Policies": {
  "req_ids": ["NIST-1237"],
  "control_ids": ["CM-06d."]
},
"Jamf_Patch_Titles": {
  "req_ids": ["NIST-1688"],
  "control_ids": ["SI-02b."]
},
"Jamf_Patch_Compliance": {
  "req_ids": ["NIST-1689"],
  "control_ids": ["SI-02c."]
}
```

- [ ] **Step 2: Verify the JSON parses and the bundled map still loads**

Run:
```bash
cargo test --features jamf fedramp_map
```
Expected: existing `fedramp_map` tests pass (the `Lazy` bundled-map loader in `src/fedramp_map.rs` panics at first use if the JSON fails to parse, so a passing test run here proves the edit is well-formed).

- [ ] **Step 3: Commit**

```bash
git add assets/fedramp-map.json
git commit -m "docs: map Jamf collectors to FedRAMP AC-19/CM-06/SI-02 requirements"
```

---

## Task 12: Documentation — README, cli-examples, evidence-list

**Files:**
- Modify: `README.md`
- Modify: `cli-examples.md`
- Modify: `evidence-list.md`

**Interfaces:** None (docs only).

- [ ] **Step 1: Add the README Jamf section**

Edit `README.md`, inserting a new `## Jamf` section immediately after the Elastic section ends (after line 898, before `## Azure / GCP` at line 899):
```markdown
## Jamf

Optional feature — build with `--features jamf` (enabled by default).

### Configuration

Create `jamf-config.toml` in the repo root (gitignored):

```toml
[[account]]
name               = "Jamf"
provider           = "jamf"
description        = "Jamf Pro production tenant"
output_dir         = "./evidence-output/jamf"
jamf_base_url      = "https://acme.jamfcloud.com"
jamf_client_id     = ""
jamf_client_secret = ""
```

Or set the values via environment variables (env wins over TOML):

- `JAMF_BASE_URL` — e.g. `https://acme.jamfcloud.com` (works identically for Jamf Cloud and self-hosted servers)
- `JAMF_CLIENT_ID` — OAuth2 API client ID
- `JAMF_CLIENT_SECRET` — OAuth2 API client secret

Create an API client in the Jamf Pro console: **Settings → System → API Roles and Clients → New**. Grant it a read-only API role scoped to Computers, Mobile Devices, Configuration Profiles, Policies, Groups, and Patch Management.

### Collectors

| Key | Output | Description |
|-----|--------|-------------|
| `jamf-computers` | CSV | Computer inventory: serial, model, OS version, last check-in, FileVault status |
| `jamf-mobile-devices` | CSV | Mobile device inventory: serial, model, OS version, supervised state |
| `jamf-computer-config-profiles` | CSV | Computer configuration profiles with scope |
| `jamf-mobile-config-profiles` | CSV | Mobile device configuration profiles with scope |
| `jamf-computer-groups` | CSV | Smart and static computer groups with criteria and member counts |
| `jamf-mobile-device-groups` | CSV | Smart and static mobile device groups with criteria and member counts |
| `jamf-policies` | JSON | Policies with category, scope, and frequency |
| `jamf-patch-titles` | CSV | Configured patch software titles |
| `jamf-patch-compliance` | CSV | Per-title compliant vs. out-of-date device counts |

### Security note

Only FileVault **status** (enabled/disabled) is collected — recovery keys are never retrieved.
```

Also update the summary bullet at `README.md:13`:
```markdown
- **200+ collectors across five providers** — 144 AWS, 24 Okta, 28 Jira, 5 Tenable, 9 Jamf (see `evidence-list.md` for the current catalog)
```

And the non-AWS-providers sentence at `README.md:178`:
```markdown
Non-AWS providers (Okta, Jira, Tenable, Jamf) surface their own per-provider collector menus with only the keys relevant to that provider.
```

- [ ] **Step 2: Add the cli-examples.md Jamf section**

Edit `cli-examples.md`, inserting after the Tenable section (at the end of the file, or immediately after `## Tenable` at line 361 — check the file's actual end and append there so section ordering matches README's Okta→Jira→Tenable→Elastic→Jamf progression):
```markdown
## Jamf

### Jamf — core device inventory

```bash
./target/release/grabber \
  --collectors jamf-computers,jamf-mobile-devices,jamf-computer-groups,jamf-mobile-device-groups
```

### Jamf — configuration and patch compliance

```bash
./target/release/grabber \
  --collectors jamf-computer-config-profiles,jamf-mobile-config-profiles,jamf-policies,jamf-patch-titles,jamf-patch-compliance
```

The Jamf Pro server URL and OAuth client credentials come from `jamf-config.toml` (or `JAMF_BASE_URL` / `JAMF_CLIENT_ID` / `JAMF_CLIENT_SECRET`). Jamf is a TUI/config-driven provider today (like Okta/Jira/Elastic) — run the interactive wizard to select a Jamf account and these collector keys.
```

- [ ] **Step 3: Add the evidence-list.md Jamf section and update the summary count**

Edit `evidence-list.md`, adding a new `### Device Management — Jamf` section after the existing `### Identity — Okta` section (after line 79, before whatever section follows it):
```markdown
### Device Management — Jamf

| # | Name | Filename Prefix | Columns |
|---|------|----------------|---------|
| EV196 | Jamf Computers | `Jamf_Computers` | Computer ID, Name, Serial Number, Model, OS Version, Last Contact Time, Managed, FileVault Status |
| EV197 | Jamf Mobile Devices | `Jamf_Mobile_Devices` | Device ID, Name, Serial Number, Model, OS Version, Last Enrolled, Managed, Supervised |
| EV198 | Jamf Computer Configuration Profiles | `Jamf_Computer_Config_Profiles` | Profile ID, Name, Category, Distribution Method, Scope |
| EV199 | Jamf Mobile Configuration Profiles | `Jamf_Mobile_Config_Profiles` | Profile ID, Name, Category, Distribution Method, Scope |
| EV200 | Jamf Computer Groups | `Jamf_Computer_Groups` | Group ID, Name, Type, Criteria, Member Count |
| EV201 | Jamf Mobile Device Groups | `Jamf_Mobile_Device_Groups` | Group ID, Name, Type, Criteria, Member Count |
| EV202 | Jamf Policies | `Jamf_Policies` | Policy ID, Name, Category, Frequency, Scope |
| EV203 | Jamf Patch Titles | `Jamf_Patch_Titles` | Title ID, Display Name |
| EV204 | Jamf Patch Compliance | `Jamf_Patch_Compliance` | Title ID, Display Name, Latest Version, Compliant Devices, Out Of Date Devices |
```

Note the existing numbering (`EV189`–`EV195` for Okta per the earlier scan) means the next free number is `EV196`; if other plans landed collectors in between, renumber this block to start at whatever the actual next free `EV` number is at implementation time — do not reuse an existing number.

Edit the summary table at `evidence-list.md:401-410`:
```markdown
| Category | Count |
|----------|-------|
| AWS collectors | 144 |
| Okta collectors | 24 |
| Jira collectors | 28 |
| Tenable collectors | 5 |
| Jamf collectors | 9 |
| **Total evidence collectors** | **210** |
| Asset Inventory asset types (Inventory feature) | 8 |
```

- [ ] **Step 4: Commit**

```bash
git add README.md cli-examples.md evidence-list.md
git commit -m "docs: document the Jamf provider in README, cli-examples, and evidence-list"
```

---

## Task 13: Final verification

**Files:** None (verification only).

**Interfaces:** None.

- [ ] **Step 1: Full workspace build with the feature on**

Run:
```bash
cargo build --features jamf
```
Expected: succeeds with no errors.

- [ ] **Step 2: Full workspace build with default features (Jamf included, per Task 1 Step 5)**

Run:
```bash
cargo build
```
Expected: succeeds — `jamf` is now part of `default`, so this is equivalent to the previous step, but confirms nothing else in the workspace assumed `jamf` would stay opt-in.

- [ ] **Step 3: Confirm the tree still builds with Jamf disabled**

Run:
```bash
cargo build --no-default-features --features tenable,okta,jira,elastic
```
Expected: succeeds — proves the `#[cfg(feature = "jamf")]` gates in `src/providers/mod.rs`, `src/tui/app/nav.rs`, `src/tui/events.rs`, `src/tui/ui/account_screens.rs`, and `src/runner/tui_session.rs` are complete and the crate compiles with Jamf fully absent.

- [ ] **Step 4: Lint and format**

Run:
```bash
cargo clippy --features jamf -- -D warnings
cargo fmt --check
```
Expected: clean on both. If `cargo fmt --check` fails, run `cargo fmt` (no `--check`) and re-verify.

- [ ] **Step 5: Run the jamf-rs crate test**

Run:
```bash
cargo test -p jamf-rs
```
Expected: `fetches_token_and_attaches_bearer_auth ... ok`.

- [ ] **Step 6: Manual smoke test against a live Jamf Pro tenant (if available)**

Populate `jamf-config.toml` from `jamf-config.example.toml` with real credentials, then run:
```bash
cargo run --features jamf
```
Walk the TUI: **Provider → Jamf → (account) → Collectors → Confirm → Run**. Expected: all 9 `jamf-*` collectors report `success` or `empty` (never `error`/`timeout`) in the resulting `RUN-MANIFEST-*.json`, and each produces a non-empty output file when the tenant has corresponding data. If a tenant is unavailable, skip this step and note it explicitly rather than claiming it was verified.

- [ ] **Step 7: Commit (only if Step 4's `cargo fmt` made changes)**

```bash
git add -A
git commit -m "chore: cargo fmt Jamf provider files"
```
