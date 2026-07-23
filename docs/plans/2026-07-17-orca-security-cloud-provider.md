# Orca Security Cloud Provider Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Orca Security (a CNAPP/cloud security posture platform) as a fifth optional provider in the-grabber, following the exact architectural pattern already used for Tenable, Okta, and Jira — a feature-gated Rust API client crate, a `ProviderFactory`/`CsvCollector` implementation under `src/providers/orca/`, and full TUI wizard wiring so a user can pick "Orca Security" on the Provider Selection screen and run its collectors end to end.

**Architecture:** A new workspace-member crate `orca-rs` (mirroring `okta-rs`'s single-API-token, no-region-flavor client shape — Orca has one auth scheme and no async-export job pattern, unlike Tenable) exposes `OrcaClient` with `alerts()`, `assets()`, and `compliance()` accessors. `src/providers/orca/` implements three `CsvCollector`s and one `OrcaProviderFactory` (`ProviderFactory` impl, `region()` returns `""` — Orca has no region concept, same as Tenable/Okta/Jira). The TUI gets a new `CloudProvider::Orca` variant threaded through every `#[cfg(feature = "orca")]` match/list already used for the other three regionless providers (provider tile, provider-selection key list, nav screen transitions, account-build block in `tui_session.rs`), following the file-by-file pattern documented in `AGENTS.md`.

**Tech Stack:** Rust 2021, `reqwest` (rustls-tls, JSON), `serde`/`serde_json`, `tokio`, `thiserror`, `ratatui` (existing TUI, unchanged framework), Cargo workspace + feature flags.

## Global Constraints

- Provider identifier (TOML `provider = "..."` value, `CloudProvider` variant, feature flag, collector-key prefix): **`orca`** — `CloudProvider::Orca`, `--features orca`, collector keys `orca-alerts` / `orca-assets` / `orca-compliance`.
- New crate name and path: **`orca-rs`** at **`crates/orca-rs`**, added as a workspace member exactly like `tenable-rs`/`okta-rs`/`jira-rs`.
- Orca REST API authentication: `Authorization: Token <api_token>` header (per Orca Security's published API docs — distinct from Tenable's dual `X-ApiKeys` header and from Okta's `Authorization: SSWS <token>` scheme). Source: [Orca Security API Overview / region-selection docs](https://docs.orcasecurity.io/), corroborated by third-party integration docs ([Stitchflow](https://www.stitchflow.com/user-management/orca-security/api), [apitracker.io](https://apitracker.io/a/orca-security)).
- Base URL is region-specific: `https://app.us.orcasecurity.io` (US, default) or `https://app.eu.orcasecurity.io` (EU) — configurable via `orca_base_url` / `ORCA_BASE_URL`, mirroring how Tenable's `tenable_url` / `TENABLE_URL` and Okta's `okta_domain` / `OKTA_DOMAIN` work today.
- Pagination: Orca's REST endpoints use offset-based pagination (`limit` / `offset` query params, default page size documented at 100–1000) — simpler than Tenable's async-export-job machinery and Okta's `Link`-header pagination. Do not port `TenableClient`'s `ExportJob`/`start_export` machinery; it does not apply here.
- **Field-name caveat (must be preserved as a code comment, not fixed as a blocking TODO):** Orca's public reference docs sit behind a region-selection gate and this plan was written without access to a live tenant's OpenAPI spec. The `types::*` structs in Task 2 use field names based on Orca's documented "Unified Data Model" concepts (alert/finding, asset, compliance-framework-result) and third-party integration docs. Every field is `#[serde(default)]` so unexpected/missing fields deserialize to empty/zero rather than erroring. Before relying on this in production, an engineer with tenant access should hit each endpoint once, diff the real response against `types::*`, and adjust field names (this is a one-file, low-risk fixup — it does not change the architecture below).
- Per `AGENTS.md`: use `anyhow::Result`/`.context()` in application code, never `unwrap()`/`expect()` in production code (crate-internal `orca-rs` uses `thiserror`, matching `tenable-rs`/`okta-rs`), run `cargo fmt` and keep `cargo clippy -- -D warnings` clean.
- Per project convention observed in every existing provider (`src/providers/{tenable,okta,jira}/*.rs` have no `#[cfg(test)]` modules): this plan does **not** include test-writing steps. Each task's deliverable is verified by `cargo check`/`cargo build` compiling cleanly, matching how Tenable/Okta/Jira collectors were built. The one pre-existing test suite that must keep passing is `src/tui/app/mod.rs`'s `#[cfg(test)] mod tests` (per-provider menu selection tests) — Task 9 must not break it.
- Do not touch `main.rs` — per `AGENTS.md`, new provider modules are self-registering via `src/providers/mod.rs` and do not need declaring in `main.rs`.
- Non-AWS providers (Tenable/Okta/Jira) are **TUI-only** today — `src/runner/cli_runners.rs`'s `run_standard_cli`/`run_inventory_cli` build an `AwsProviderFactory` unconditionally and never reference `CloudProvider::Tenable/Okta/Jira`. Orca follows the same scope: no CLI-runner changes, TUI wizard only.

---

### Task 1: Scaffold the `orca-rs` crate (client, error, pagination helper)

**Files:**
- Create: `crates/orca-rs/Cargo.toml`
- Create: `crates/orca-rs/src/lib.rs`
- Create: `crates/orca-rs/src/error.rs`
- Create: `crates/orca-rs/src/client.rs`

**Interfaces:**
- Produces: `pub struct OrcaClient` with `pub fn new(base_url: &str, api_token: &str) -> Result<Self, OrcaError>`, `pub(crate) async fn get(&self, path: &str) -> Result<reqwest::Response, OrcaError>`, `pub(crate) async fn get_paginated<T: DeserializeOwned>(&self, path: &str) -> Result<Vec<T>, OrcaError>`, and accessor stubs `alerts()`/`assets()`/`compliance()` (added once their `Api` types exist in Task 2 — for this task, omit the three accessor methods and leave the crate building with just the client/error/pagination plumbing).
- Produces: `pub enum OrcaError` (via `thiserror`) with variants `Http`, `Header`, `Json`, `Api { status: u16, message: String }`, `Auth`, `Forbidden`, `InvalidBaseUrl(String)`.
- Consumes: nothing (leaf crate, no dependency on `the-grabber`'s own code).

- [ ] **Step 1: Create the crate's `Cargo.toml`**

```toml
[package]
name        = "orca-rs"
version     = "0.1.0"
edition     = "2021"
description = "Async Rust client for the Orca Security REST API"
license     = "MIT OR Apache-2.0"

[dependencies]
reqwest    = { version = "0.12", features = ["json", "rustls-tls"], default-features = false }
serde      = { version = "1", features = ["derive"] }
serde_json = "1"
tokio      = { version = "1", features = ["time"] }
thiserror  = "2"
```

- [ ] **Step 2: Create `crates/orca-rs/src/error.rs`**

```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum OrcaError {
    #[error("HTTP transport error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("invalid header value: {0}")]
    Header(#[from] reqwest::header::InvalidHeaderValue),

    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Orca API error: HTTP {status} — {message}")]
    Api { status: u16, message: String },

    #[error("authentication failed — check the Orca API token")]
    Auth,

    #[error("permission denied — the Orca API token lacks the required role")]
    Forbidden,

    #[error("invalid base URL: {0}")]
    InvalidBaseUrl(String),
}
```

- [ ] **Step 3: Create `crates/orca-rs/src/client.rs`**

```rust
use reqwest::{header, Client, Response};
use serde::de::DeserializeOwned;
use tokio::time::{sleep, Duration};

use crate::error::OrcaError;

const MAX_RETRIES: u32 = 5;
const DEFAULT_RETRY_AFTER_SECS: u64 = 30;
const PAGE_LIMIT: u32 = 100;

/// Async HTTP client for the Orca Security REST API.
///
/// Auth: `Authorization: Token <api_token>` is injected on every request.
/// Retries 429 responses with exponential backoff.
///
/// Field names in `crate::types` are based on Orca's documented data model
/// as of 2026-07 and were not verified against a live tenant response —
/// confirm against your tenant's OpenAPI spec (Settings → API) and adjust
/// `types::*` if a field is renamed or absent in your payloads.
///
/// `OrcaClient` is cheaply cloneable — `reqwest::Client` is arc-pooled.
#[derive(Clone)]
pub struct OrcaClient {
    pub(crate) http: Client,
    pub(crate) base_url: String,
}

impl OrcaClient {
    /// Build a client for a tenant base URL (e.g. `https://app.us.orcasecurity.io`).
    pub fn new(base_url: &str, api_token: &str) -> Result<Self, OrcaError> {
        let trimmed = base_url.trim().trim_end_matches('/');
        if trimmed.is_empty() {
            return Err(OrcaError::InvalidBaseUrl(base_url.to_string()));
        }
        let auth = format!("Token {api_token}");
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

    async fn send_with_retry<F, Fut>(&self, make_req: F) -> Result<Response, OrcaError>
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
            sleep(Duration::from_secs(backoff)).await;
            backoff = (backoff * 2).min(DEFAULT_RETRY_AFTER_SECS);
        }
        unreachable!()
    }

    /// GET a relative path. Internal helper for single-page endpoints.
    pub(crate) async fn get(&self, path: &str) -> Result<Response, OrcaError> {
        let url = self.url(path);
        self.send_with_retry(|| self.http.get(&url).send()).await
    }

    /// GET `path`, following offset-based pagination (`limit`/`offset` query
    /// params) until a page returns fewer than `PAGE_LIMIT` items. `path`
    /// must not already contain a `?` — query params are appended here.
    /// Expects each page to be a JSON object shaped `{"data": [...]}`.
    pub(crate) async fn get_paginated<T: DeserializeOwned>(
        &self,
        path: &str,
    ) -> Result<Vec<T>, OrcaError> {
        let mut all = Vec::new();
        let mut offset = 0u32;
        loop {
            let url = format!("{}?limit={}&offset={}", self.url(path), PAGE_LIMIT, offset);
            let resp = self.send_with_retry(|| self.http.get(&url).send()).await?;
            if !resp.status().is_success() {
                let status = resp.status().as_u16();
                let message = resp.text().await.unwrap_or_default();
                return Err(map_status(status, message));
            }
            let page: OrcaListResponse<T> = resp.json().await?;
            let count = page.data.len();
            all.extend(page.data);
            if count < PAGE_LIMIT as usize {
                break;
            }
            offset += PAGE_LIMIT;
        }
        Ok(all)
    }
}

fn map_status(status: u16, message: String) -> OrcaError {
    match status {
        401 => OrcaError::Auth,
        403 => OrcaError::Forbidden,
        _ => OrcaError::Api { status, message },
    }
}

#[derive(serde::Deserialize)]
struct OrcaListResponse<T> {
    #[serde(default)]
    data: Vec<T>,
}
```

- [ ] **Step 4: Create `crates/orca-rs/src/lib.rs`**

```rust
//! Async Rust client for the Orca Security REST API.
//!
//! # Quick start
//!
//! ```no_run
//! use orca_rs::OrcaClient;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let client = OrcaClient::new("https://app.us.orcasecurity.io", "api_token")?;
//!     let alerts = client.alerts().list_all().await?;
//!     println!("{} alerts", alerts.len());
//!     Ok(())
//! }
//! ```

mod client;
mod error;

pub mod api;
pub mod types;

pub use client::OrcaClient;
pub use error::OrcaError;
```

Note: `lib.rs` references `pub mod api;` and `pub mod types;`, which don't exist until Task 2. This is harmless for the root package's `cargo check`: `crates/orca-rs` is not yet listed in the root `Cargo.toml`'s workspace `members` (that happens in Task 3), and a bare `cargo check` run from the workspace root only checks the root package by default (it is both a workspace root and a normal package, so `--workspace` would be needed to reach member crates at all) — so an incomplete `orca-rs` crate at this point cannot break the main build.

- [ ] **Step 5: Commit**

```bash
git add crates/orca-rs/Cargo.toml crates/orca-rs/src/lib.rs crates/orca-rs/src/error.rs crates/orca-rs/src/client.rs
git commit -m "feat(orca): scaffold orca-rs client crate (auth, pagination, error type)"
```

---

### Task 2: Orca API modules and response types (alerts, assets, compliance)

**Files:**
- Create: `crates/orca-rs/src/api/mod.rs`
- Create: `crates/orca-rs/src/api/alerts.rs`
- Create: `crates/orca-rs/src/api/assets.rs`
- Create: `crates/orca-rs/src/api/compliance.rs`
- Create: `crates/orca-rs/src/types/mod.rs`
- Create: `crates/orca-rs/src/types/alert.rs`
- Create: `crates/orca-rs/src/types/asset.rs`
- Create: `crates/orca-rs/src/types/compliance.rs`
- Modify: `crates/orca-rs/src/client.rs:` (add `alerts()`/`assets()`/`compliance()` accessor methods to the end of `impl OrcaClient`, just before the closing brace)

**Interfaces:**
- Consumes: `OrcaClient::get_paginated<T>()` from Task 1 (`crates/orca-rs/src/client.rs`).
- Produces: `pub struct OrcaAlert`, `pub struct OrcaAsset`, `pub struct OrcaComplianceResult` (all `#[derive(Debug, Clone, Default, Deserialize)]`), `pub struct AlertsApi<'c>` / `AssetsApi<'c>` / `ComplianceApi<'c>` each with an `async fn list_all(&self) -> Result<Vec<T>, OrcaError>`. These are consumed directly by `src/providers/orca/*.rs` collectors in Task 6.

- [ ] **Step 1: Create `crates/orca-rs/src/types/alert.rs`**

```rust
use serde::Deserialize;

#[derive(Debug, Clone, Default, Deserialize)]
pub struct OrcaAlert {
    #[serde(default)]
    pub id: String,
    #[serde(default, rename = "type")]
    pub alert_type: String,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub risk_level: String,
    #[serde(default)]
    pub score: Option<f64>,
    #[serde(default)]
    pub rule_name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub cloud_provider: String,
    #[serde(default)]
    pub cloud_account_id: String,
    #[serde(default)]
    pub region: String,
    #[serde(default)]
    pub asset_name: String,
    #[serde(default)]
    pub asset_unique_id: String,
    #[serde(default)]
    pub create_time: String,
    #[serde(default)]
    pub update_time: String,
}
```

- [ ] **Step 2: Create `crates/orca-rs/src/types/asset.rs`**

```rust
use serde::Deserialize;

#[derive(Debug, Clone, Default, Deserialize)]
pub struct OrcaAsset {
    #[serde(default)]
    pub asset_unique_id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default, rename = "type")]
    pub asset_type: String,
    #[serde(default)]
    pub cloud_provider: String,
    #[serde(default)]
    pub cloud_account_id: String,
    #[serde(default)]
    pub region: String,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub organization: String,
    #[serde(default)]
    pub first_seen: String,
    #[serde(default)]
    pub last_seen: String,
}
```

- [ ] **Step 3: Create `crates/orca-rs/src/types/compliance.rs`**

```rust
use serde::Deserialize;

#[derive(Debug, Clone, Default, Deserialize)]
pub struct OrcaComplianceResult {
    #[serde(default)]
    pub framework: String,
    #[serde(default)]
    pub requirement_id: String,
    #[serde(default)]
    pub requirement_name: String,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub score: Option<f64>,
    #[serde(default)]
    pub cloud_account_id: String,
    #[serde(default)]
    pub cloud_provider: String,
    #[serde(default)]
    pub last_evaluated: String,
}
```

- [ ] **Step 4: Create `crates/orca-rs/src/types/mod.rs`**

```rust
pub mod alert;
pub mod asset;
pub mod compliance;
```

- [ ] **Step 5: Create `crates/orca-rs/src/api/alerts.rs`**

```rust
use crate::client::OrcaClient;
use crate::error::OrcaError;
use crate::types::alert::OrcaAlert;

pub struct AlertsApi<'c>(pub(crate) &'c OrcaClient);

impl<'c> AlertsApi<'c> {
    /// GET /api/alerts — every open security alert (finding), paginated.
    pub async fn list_all(&self) -> Result<Vec<OrcaAlert>, OrcaError> {
        self.0.get_paginated("/api/alerts").await
    }
}
```

- [ ] **Step 6: Create `crates/orca-rs/src/api/assets.rs`**

```rust
use crate::client::OrcaClient;
use crate::error::OrcaError;
use crate::types::asset::OrcaAsset;

pub struct AssetsApi<'c>(pub(crate) &'c OrcaClient);

impl<'c> AssetsApi<'c> {
    /// GET /api/assets — full cloud asset inventory, paginated.
    pub async fn list_all(&self) -> Result<Vec<OrcaAsset>, OrcaError> {
        self.0.get_paginated("/api/assets").await
    }
}
```

- [ ] **Step 7: Create `crates/orca-rs/src/api/compliance.rs`**

```rust
use crate::client::OrcaClient;
use crate::error::OrcaError;
use crate::types::compliance::OrcaComplianceResult;

pub struct ComplianceApi<'c>(pub(crate) &'c OrcaClient);

impl<'c> ComplianceApi<'c> {
    /// GET /api/compliance — compliance framework requirement results, paginated.
    /// Verify this path against your tenant's OpenAPI spec — Orca's compliance
    /// surface has moved between `/api/compliance` and query-DSL endpoints
    /// across API versions; adjust here if your tenant uses a different path.
    pub async fn list_all(&self) -> Result<Vec<OrcaComplianceResult>, OrcaError> {
        self.0.get_paginated("/api/compliance").await
    }
}
```

- [ ] **Step 8: Create `crates/orca-rs/src/api/mod.rs`**

```rust
pub mod alerts;
pub mod assets;
pub mod compliance;

pub use alerts::AlertsApi;
pub use assets::AssetsApi;
pub use compliance::ComplianceApi;
```

- [ ] **Step 9: Add API accessors to `OrcaClient`**

Edit `crates/orca-rs/src/client.rs`. Add this import at the top of the file, alongside the existing `use` lines:

```rust
use crate::api::{AlertsApi, AssetsApi, ComplianceApi};
```

Then add these three methods inside `impl OrcaClient { ... }`, right after the closing brace of `get_paginated` (before the impl block's own closing brace):

```rust

    pub fn alerts(&self) -> AlertsApi<'_> {
        AlertsApi(self)
    }
    pub fn assets(&self) -> AssetsApi<'_> {
        AssetsApi(self)
    }
    pub fn compliance(&self) -> ComplianceApi<'_> {
        ComplianceApi(self)
    }
```

- [ ] **Step 10: Note on verification**

`crates/orca-rs` is not yet a workspace member (that's Task 3), so there is no `-p orca-rs` or `cd crates/orca-rs && cargo check` available to target it in isolation yet — attempting either now raises a "current package believes it's in a workspace when it's not" error, since the parent workspace's `members` list is explicit and doesn't include this path. That's expected; skip standalone verification for this crate and rely on Task 3's `cargo check -p orca-rs` (once it's a member) to confirm the crate itself compiles.

- [ ] **Step 11: Commit**

```bash
git add crates/orca-rs/src/api crates/orca-rs/src/types crates/orca-rs/src/client.rs
git commit -m "feat(orca): add alerts/assets/compliance API modules and response types"
```

---

### Task 3: Wire `orca-rs` into the workspace and root `Cargo.toml`

**Files:**
- Modify: `Cargo.toml:2` (workspace `members`)
- Modify: `Cargo.toml:89-104` (dependency + `[features]`)

**Interfaces:**
- Consumes: `crates/orca-rs` (Task 1–2).
- Produces: Cargo feature `orca` (default-enabled), gating `crate::providers::orca` module usage in every later task.

- [ ] **Step 1: Add the crate to the workspace members list**

In `Cargo.toml`, change:

```toml
members  = [".", "crates/tenable-rs", "crates/okta-rs", "crates/jira-rs"]
```

to:

```toml
members  = [".", "crates/tenable-rs", "crates/okta-rs", "crates/jira-rs", "crates/orca-rs"]
```

- [ ] **Step 2: Add the optional dependency**

In `Cargo.toml`, immediately after the existing block:

```toml
# Jira — only compiled with `--features jira`
jira-rs = { path = "crates/jira-rs", optional = true }
```

add:

```toml

# Orca Security — only compiled with `--features orca`
orca-rs = { path = "crates/orca-rs", optional = true }
```

- [ ] **Step 3: Register the feature flag**

In `Cargo.toml`, change:

```toml
[features]
default = ["tenable", "okta", "jira"]
azure   = ["dep:azure_identity", "dep:azure_mgmt_monitor", "dep:azure_mgmt_resources"]
gcp     = ["dep:google-cloud-auth"]
tenable = ["dep:tenable-rs"]
okta    = ["dep:okta-rs"]
jira    = ["dep:jira-rs"]
```

to:

```toml
[features]
default = ["tenable", "okta", "jira", "orca"]
azure   = ["dep:azure_identity", "dep:azure_mgmt_monitor", "dep:azure_mgmt_resources"]
gcp     = ["dep:google-cloud-auth"]
tenable = ["dep:tenable-rs"]
okta    = ["dep:okta-rs"]
jira    = ["dep:jira-rs"]
orca    = ["dep:orca-rs"]
```

- [ ] **Step 4: Verify the workspace resolves the new member**

Run: `cargo check -p orca-rs`
Expected: succeeds (the crate is now a workspace member reachable independently of the root package's own features).

Run: `cargo metadata --no-deps --format-version 1 | grep -c '"name":"orca-rs"'` (or open `Cargo.lock` and confirm an `orca-rs` entry was added)
Expected: `Cargo.lock` now contains an `orca-rs` package entry (root `cargo check` in Task 4+ will regenerate it if this exact command isn't available in your shell).

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock
git commit -m "build: add orca-rs as a workspace member and Cargo feature"
```

---

### Task 4: `CloudProvider::Orca` variant

**Files:**
- Modify: `src/providers/mod.rs`

**Interfaces:**
- Produces: `CloudProvider::Orca` (usable by every later task).
- Note: this task deliberately does **not** add `#[cfg(feature = "orca")] pub mod orca;` yet. That module declaration is the one edit that pulls `src/providers/orca/` into the compiled tree, and since `orca` is a default-on feature (Task 3), adding it before `src/providers/orca/{alerts,assets,compliance,factory}.rs` all exist would break `cargo check` on every Write in between (violating the project's "tree stays compilable after every Write" convention). It is added as the final step of Task 7 instead, once every file it needs to resolve already exists.

- [ ] **Step 1: Add the enum variant**

Change:

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
}
```

to:

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
    Orca,
}
```

- [ ] **Step 2: Add the `Display` arm**

Change:

```rust
impl fmt::Display for CloudProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CloudProvider::Aws => write!(f, "AWS"),
            CloudProvider::Azure => write!(f, "Azure"),
            CloudProvider::Gcp => write!(f, "GCP"),
            CloudProvider::Tenable => write!(f, "Tenable"),
            CloudProvider::Okta => write!(f, "Okta"),
            CloudProvider::Jira => write!(f, "Jira"),
        }
    }
}
```

to:

```rust
impl fmt::Display for CloudProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CloudProvider::Aws => write!(f, "AWS"),
            CloudProvider::Azure => write!(f, "Azure"),
            CloudProvider::Gcp => write!(f, "GCP"),
            CloudProvider::Tenable => write!(f, "Tenable"),
            CloudProvider::Okta => write!(f, "Okta"),
            CloudProvider::Jira => write!(f, "Jira"),
            CloudProvider::Orca => write!(f, "Orca Security"),
        }
    }
}
```

This `Display` match is exhaustive (no wildcard arm), so the compiler now forces every future new variant to be handled here — this is by design (per the codebase-mapping research, this is the one true compile-time safety net for new providers).

- [ ] **Step 3: Verify**

Run: `cargo check`
Expected: `Finished` with no errors. The new variant and `Display` arm are self-contained — nothing yet references `crate::providers::orca` (that module doesn't exist until Task 6, and it isn't declared as a submodule of `src/providers/mod.rs` until the final step of Task 7), so this compiles cleanly on its own.

- [ ] **Step 4: Commit**

```bash
git add src/providers/mod.rs
git commit -m "feat(orca): add CloudProvider::Orca variant"
```

---

### Task 5: Account config fields, resolvers, config-file merge, example TOML, gitignore

**Files:**
- Modify: `src/app_config.rs`
- Create: `orca-config.example.toml`
- Modify: `.gitignore`

**Interfaces:**
- Consumes: `CloudProvider::Orca` (Task 4).
- Produces: `Account::orca_api_token_resolved(&self) -> Option<String>`, `Account::orca_base_url_resolved(&self) -> String` — consumed by `src/runner/tui_session.rs` in Task 10.

- [ ] **Step 1: Add Orca fields to `Account`**

In `src/app_config.rs`, after the Jira fields block and before the "Collector filtering" block, change:

```rust
    /// Jira API token.
    /// Can also be supplied via `JIRA_API_TOKEN` env var (env wins over TOML).
    pub jira_api_token: Option<String>,

    // ------------------------------------------------------------------
    // Collector filtering (all providers)
    // ------------------------------------------------------------------
```

to:

```rust
    /// Jira API token.
    /// Can also be supplied via `JIRA_API_TOKEN` env var (env wins over TOML).
    pub jira_api_token: Option<String>,

    // ------------------------------------------------------------------
    // Orca Security fields
    // ------------------------------------------------------------------
    /// Orca Security API token (Settings → Users & Permissions → API → API Tokens).
    /// Can also be supplied via `ORCA_API_TOKEN` env var (env wins over TOML).
    pub orca_api_token: Option<String>,

    /// Orca Security tenant base URL.
    /// Omit for the US tenant (defaults to `https://app.us.orcasecurity.io`).
    /// Set to `https://app.eu.orcasecurity.io` for an EU tenant.
    pub orca_base_url: Option<String>,

    // ------------------------------------------------------------------
    // Collector filtering (all providers)
    // ------------------------------------------------------------------
```

- [ ] **Step 2: Add resolver methods**

In `src/app_config.rs`, at the end of `impl Account { ... }` (right after `jira_domain_resolved`, before the closing `}` of the `impl` block), add:

```rust

    /// Resolve Orca API token: env var takes precedence over TOML.
    pub fn orca_api_token_resolved(&self) -> Option<String> {
        std::env::var("ORCA_API_TOKEN")
            .ok()
            .or_else(|| self.orca_api_token.clone())
    }

    /// Resolve Orca base URL, defaulting to the US tenant endpoint.
    pub fn orca_base_url_resolved(&self) -> String {
        std::env::var("ORCA_BASE_URL")
            .ok()
            .or_else(|| self.orca_base_url.clone())
            .map(|s| s.trim().trim_end_matches('/').to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "https://app.us.orcasecurity.io".to_string())
    }
```

- [ ] **Step 3: Merge `orca-config.toml` in `load_config()`**

In `src/app_config.rs`, change:

```rust
    // Merge jira-config.toml accounts if present
    let jira_path = PathBuf::from("jira-config.toml");
    if jira_path.exists() {
        if let Ok(contents) = fs::read_to_string(&jira_path) {
            if let Ok(jira_cfg) = toml::from_str::<AppConfig>(&contents) {
                cfg.account.extend(jira_cfg.account);
            }
        }
    }

    Some(cfg)
}
```

to:

```rust
    // Merge jira-config.toml accounts if present
    let jira_path = PathBuf::from("jira-config.toml");
    if jira_path.exists() {
        if let Ok(contents) = fs::read_to_string(&jira_path) {
            if let Ok(jira_cfg) = toml::from_str::<AppConfig>(&contents) {
                cfg.account.extend(jira_cfg.account);
            }
        }
    }

    // Merge orca-config.toml accounts if present
    let orca_path = PathBuf::from("orca-config.toml");
    if orca_path.exists() {
        if let Ok(contents) = fs::read_to_string(&orca_path) {
            if let Ok(orca_cfg) = toml::from_str::<AppConfig>(&contents) {
                cfg.account.extend(orca_cfg.account);
            }
        }
    }

    Some(cfg)
}
```

Also update the doc comment directly above `pub fn load_config()` — change:

```rust
/// After loading the primary config, `./tenable-config.toml`, `./okta-config.toml`,
/// and `./jira-config.toml` are merged in (accounts only) if those files exist.
```

to:

```rust
/// After loading the primary config, `./tenable-config.toml`, `./okta-config.toml`,
/// `./jira-config.toml`, and `./orca-config.toml` are merged in (accounts only)
/// if those files exist.
```

- [ ] **Step 4: Create `orca-config.example.toml`**

```toml
# Orca Security credentials — keep this file out of version control
# Add to .gitignore: orca-config.toml
#
# Merged automatically into config.toml at startup when present.
# Env vars override TOML values: ORCA_API_TOKEN, ORCA_BASE_URL

[[account]]
name            = "Orca Security"
provider        = "orca"
description     = "Orca Security cloud posture and vulnerability findings"
output_dir      = "./evidence-output/orca"
orca_api_token  = ""
# orca_base_url = ""   # omit for the US tenant; set to https://app.eu.orcasecurity.io for EU
```

- [ ] **Step 5: Add the gitignore entry**

In `.gitignore`, after:

```
# Jira credentials — never commit
jira-config.toml
```

add:

```

# Orca Security credentials — never commit
orca-config.toml
```

- [ ] **Step 6: Verify**

Run: `cargo check`
Expected: `Finished` with no errors. `app_config.rs` has no dependency on `src/providers/orca` (that module isn't declared in `src/providers/mod.rs` until the final step of Task 7), so this compiles cleanly on its own.

- [ ] **Step 7: Commit**

```bash
git add src/app_config.rs orca-config.example.toml .gitignore
git commit -m "feat(orca): add Orca account config fields, resolvers, and config-file merge"
```

---

### Task 6: `src/providers/orca/` — CSV collectors and module registration

**Files:**
- Create: `src/providers/orca/mod.rs`
- Create: `src/providers/orca/alerts.rs`
- Create: `src/providers/orca/assets.rs`
- Create: `src/providers/orca/compliance.rs`

**Interfaces:**
- Consumes: `orca_rs::OrcaClient` (Task 1–2), `crate::evidence::CsvCollector` trait (`src/evidence.rs`, pre-existing, unchanged).
- Produces: `OrcaAlertsCollector`, `OrcaAssetsCollector`, `OrcaComplianceCollector` (each `pub fn new(client: OrcaClient) -> Self` + `impl CsvCollector`) — consumed by `src/providers/orca/factory.rs` in Task 7.

- [ ] **Step 1: Create `src/providers/orca/alerts.rs`**

```rust
use anyhow::Result;
use async_trait::async_trait;
use orca_rs::OrcaClient;

use crate::evidence::CsvCollector;

pub struct OrcaAlertsCollector {
    client: OrcaClient,
}

impl OrcaAlertsCollector {
    pub fn new(client: OrcaClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for OrcaAlertsCollector {
    fn name(&self) -> &str {
        "Orca Security Alerts"
    }
    fn filename_prefix(&self) -> &str {
        "Orca_Security_Alerts"
    }

    fn headers(&self) -> &'static [&'static str] {
        &[
            "Alert ID",
            "Type",
            "State",
            "Status",
            "Risk Level",
            "Score",
            "Rule Name",
            "Description",
            "Cloud Provider",
            "Cloud Account ID",
            "Region",
            "Asset Name",
            "Asset ID",
            "Created",
            "Last Updated",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let alerts = match self.client.alerts().list_all().await {
            Ok(a) => a,
            Err(orca_rs::OrcaError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };
        let rows = alerts
            .into_iter()
            .map(|a| {
                vec![
                    a.id,
                    a.alert_type,
                    a.state,
                    a.status,
                    a.risk_level,
                    a.score.map(|s| s.to_string()).unwrap_or_default(),
                    a.rule_name,
                    a.description,
                    a.cloud_provider,
                    a.cloud_account_id,
                    a.region,
                    a.asset_name,
                    a.asset_unique_id,
                    a.create_time,
                    a.update_time,
                ]
            })
            .collect();
        Ok(rows)
    }
}
```

- [ ] **Step 2: Create `src/providers/orca/assets.rs`**

```rust
use anyhow::Result;
use async_trait::async_trait;
use orca_rs::OrcaClient;

use crate::evidence::CsvCollector;

pub struct OrcaAssetsCollector {
    client: OrcaClient,
}

impl OrcaAssetsCollector {
    pub fn new(client: OrcaClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for OrcaAssetsCollector {
    fn name(&self) -> &str {
        "Orca Cloud Asset Inventory"
    }
    fn filename_prefix(&self) -> &str {
        "Orca_Cloud_Asset_Inventory"
    }

    fn headers(&self) -> &'static [&'static str] {
        &[
            "Asset ID",
            "Name",
            "Type",
            "Cloud Provider",
            "Cloud Account ID",
            "Region",
            "State",
            "Organization",
            "First Seen",
            "Last Seen",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let assets = match self.client.assets().list_all().await {
            Ok(a) => a,
            Err(orca_rs::OrcaError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };
        let rows = assets
            .into_iter()
            .map(|a| {
                vec![
                    a.asset_unique_id,
                    a.name,
                    a.asset_type,
                    a.cloud_provider,
                    a.cloud_account_id,
                    a.region,
                    a.state,
                    a.organization,
                    a.first_seen,
                    a.last_seen,
                ]
            })
            .collect();
        Ok(rows)
    }
}
```

- [ ] **Step 3: Create `src/providers/orca/compliance.rs`**

```rust
use anyhow::Result;
use async_trait::async_trait;
use orca_rs::OrcaClient;

use crate::evidence::CsvCollector;

pub struct OrcaComplianceCollector {
    client: OrcaClient,
}

impl OrcaComplianceCollector {
    pub fn new(client: OrcaClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for OrcaComplianceCollector {
    fn name(&self) -> &str {
        "Orca Compliance Framework Results"
    }
    fn filename_prefix(&self) -> &str {
        "Orca_Compliance_Framework_Results"
    }

    fn headers(&self) -> &'static [&'static str] {
        &[
            "Framework",
            "Requirement ID",
            "Requirement Name",
            "Category",
            "Status",
            "Score",
            "Cloud Account ID",
            "Cloud Provider",
            "Last Evaluated",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let results = match self.client.compliance().list_all().await {
            Ok(r) => r,
            Err(orca_rs::OrcaError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };
        let rows = results
            .into_iter()
            .map(|r| {
                vec![
                    r.framework,
                    r.requirement_id,
                    r.requirement_name,
                    r.category,
                    r.status,
                    r.score.map(|s| s.to_string()).unwrap_or_default(),
                    r.cloud_account_id,
                    r.cloud_provider,
                    r.last_evaluated,
                ]
            })
            .collect();
        Ok(rows)
    }
}
```

- [ ] **Step 4: Create `src/providers/orca/mod.rs`**

```rust
pub mod alerts;
pub mod assets;
pub mod compliance;
pub mod factory;

// Authentication:
//   Authorization: Token <api_token>
//
// Base URL: region-specific — https://app.us.orcasecurity.io (US, default) or
// https://app.eu.orcasecurity.io (EU). Supplied via the `orca_base_url` config
// field or the `ORCA_BASE_URL` env var.
```

Note: this declares `pub mod factory;`, which is created in Task 7. This is harmless right now: `src/providers/orca/` (this whole directory) is not yet reachable from the compiled tree — `src/providers/mod.rs` doesn't declare `pub mod orca;` until the final step of Task 7 — so an as-yet-nonexistent `factory` submodule inside an unreached directory does not affect `cargo check`.

- [ ] **Step 5: Verify**

Run: `cargo check`
Expected: `Finished` with no errors, for the same reason as Step 4's note above.

- [ ] **Step 6: Commit**

```bash
git add src/providers/orca/mod.rs src/providers/orca/alerts.rs src/providers/orca/assets.rs src/providers/orca/compliance.rs
git commit -m "feat(orca): add Orca alerts/assets/compliance CSV collectors"
```

---

### Task 7: `OrcaProviderFactory`

**Files:**
- Create: `src/providers/orca/factory.rs`
- Modify: `src/providers/mod.rs`

**Interfaces:**
- Consumes: `orca_rs::OrcaClient`, `crate::evidence::{CsvCollector, EvidenceCollector, JsonCollector}`, `crate::providers::{CloudProvider, ProviderFactory}`, the three collectors from Task 6.
- Produces: `pub struct OrcaProviderFactory` with `pub fn new(client: OrcaClient, tenant_name: String, selected: Vec<String>) -> Self` and a full `impl ProviderFactory` — consumed by `src/runner/tui_session.rs` in Task 10. Also produces the `#[cfg(feature = "orca")] pub mod orca;` declaration deferred from Task 4 — this is the single edit that makes `src/providers/orca/` part of the compiled tree for the first time, so it lands last, in Step 2, after `factory.rs` already exists.

- [ ] **Step 1: Create `src/providers/orca/factory.rs`**

```rust
use orca_rs::OrcaClient;

use crate::evidence::{CsvCollector, EvidenceCollector, JsonCollector};
use crate::providers::{CloudProvider, ProviderFactory};

pub struct OrcaProviderFactory {
    client: OrcaClient,
    tenant_name: String,
    selected: Vec<String>,
}

impl OrcaProviderFactory {
    pub fn new(client: OrcaClient, tenant_name: String, selected: Vec<String>) -> Self {
        Self {
            client,
            tenant_name,
            selected,
        }
    }
}

impl ProviderFactory for OrcaProviderFactory {
    fn provider(&self) -> CloudProvider {
        CloudProvider::Orca
    }
    fn account_id(&self) -> &str {
        &self.tenant_name
    }
    fn region(&self) -> &str {
        ""
    } // Orca has no region concept

    fn csv_collectors(&self) -> Vec<Box<dyn CsvCollector>> {
        let mut v: Vec<Box<dyn CsvCollector>> = Vec::new();
        if self.selected.iter().any(|s| s == "orca-alerts") {
            v.push(Box::new(super::alerts::OrcaAlertsCollector::new(
                self.client.clone(),
            )));
        }
        if self.selected.iter().any(|s| s == "orca-assets") {
            v.push(Box::new(super::assets::OrcaAssetsCollector::new(
                self.client.clone(),
            )));
        }
        if self.selected.iter().any(|s| s == "orca-compliance") {
            v.push(Box::new(super::compliance::OrcaComplianceCollector::new(
                self.client.clone(),
            )));
        }
        v
    }
    fn json_collectors(&self) -> Vec<Box<dyn JsonCollector>> {
        Vec::new()
    }
    fn evidence_collectors(&self) -> Vec<Box<dyn EvidenceCollector>> {
        Vec::new()
    }
}
```

- [ ] **Step 2: Declare the `orca` provider module**

Now that `src/providers/orca/{alerts,assets,compliance,factory}.rs` and `mod.rs` all exist, add the deferred declaration. In `src/providers/mod.rs`, change:

```rust
#[cfg(feature = "jira")]
pub mod jira;
```

to:

```rust
#[cfg(feature = "jira")]
pub mod jira;

#[cfg(feature = "orca")]
pub mod orca;
```

- [ ] **Step 3: Verify the whole workspace compiles**

Run: `cargo check`
Expected: `Finished` with no errors. This is the first point where `src/providers/orca/` is actually part of the compiled tree (default features include `orca` since Task 3), and everything it needs already exists.

Run: `cargo check --all-features`
Expected: `Finished` with no errors (covers `azure`/`gcp` stub features too).

Run: `cargo check --no-default-features`
Expected: `Finished` with no errors (confirms `orca`, like `tenable`/`okta`/`jira`, is fully optional and the crate compiles with it off).

- [ ] **Step 4: Commit**

```bash
git add src/providers/orca/factory.rs src/providers/mod.rs
git commit -m "feat(orca): add OrcaProviderFactory and register the orca provider module"
```

---

### Task 8: TUI collector menu

**Files:**
- Create: `src/tui/menus/orca.rs`
- Modify: `src/tui/menus/mod.rs`

**Interfaces:**
- Consumes: `CloudProvider::Orca` (Task 4), `super::ProviderCategory` (pre-existing type in `src/tui/menus/mod.rs`).
- Produces: `pub const ORCA_CATEGORIES: &[ProviderCategory]`, registered in `PROVIDER_MENUS` — consumed by `menu_for(CloudProvider::Orca)` wherever the TUI builds the Collectors screen (`src/tui/app/mod.rs`, unchanged in this task — it calls `menu_for(default_provider)` and `menu_for(self.selected_provider)` generically already).

- [ ] **Step 1: Create `src/tui/menus/orca.rs`**

```rust
//! Orca Security collector menu. 3 collectors, one category.

use super::ProviderCategory;

pub const ORCA_CATEGORIES: &[ProviderCategory] = &[
    ProviderCategory {
        name: "Cloud Security Findings",
        items: &[
            ("orca-alerts", "Security Alerts             "),
            ("orca-assets", "Cloud Asset Inventory       "),
            ("orca-compliance", "Compliance Framework Results"),
        ],
    },
];
```

- [ ] **Step 2: Register the menu**

In `src/tui/menus/mod.rs`, change:

```rust
pub mod aws;
pub mod jira;
pub mod okta;
pub mod tenable;
```

to:

```rust
pub mod aws;
pub mod jira;
pub mod okta;
pub mod orca;
pub mod tenable;
```

Then change:

```rust
pub const PROVIDER_MENUS: &[ProviderMenu] = &[
    ProviderMenu { provider: CloudProvider::Aws, categories: aws::AWS_CATEGORIES },
    ProviderMenu { provider: CloudProvider::Okta, categories: okta::OKTA_CATEGORIES },
    ProviderMenu { provider: CloudProvider::Jira, categories: jira::JIRA_CATEGORIES },
    ProviderMenu { provider: CloudProvider::Tenable, categories: tenable::TENABLE_CATEGORIES },
];
```

to:

```rust
pub const PROVIDER_MENUS: &[ProviderMenu] = &[
    ProviderMenu { provider: CloudProvider::Aws, categories: aws::AWS_CATEGORIES },
    ProviderMenu { provider: CloudProvider::Okta, categories: okta::OKTA_CATEGORIES },
    ProviderMenu { provider: CloudProvider::Jira, categories: jira::JIRA_CATEGORIES },
    ProviderMenu { provider: CloudProvider::Tenable, categories: tenable::TENABLE_CATEGORIES },
    ProviderMenu { provider: CloudProvider::Orca, categories: orca::ORCA_CATEGORIES },
];
```

Note: `menu_for()` panics at runtime (`unwrap_or_else(|| panic!(...))`) if a provider has no registered menu — this step is required, not optional, before `CloudProvider::Orca` can ever reach the Collectors screen without crashing the TUI.

- [ ] **Step 3: Verify**

Run: `cargo check`
Expected: `Finished` with no errors.

- [ ] **Step 4: Commit**

```bash
git add src/tui/menus/orca.rs src/tui/menus/mod.rs
git commit -m "feat(orca): register Orca collector menu"
```

---

### Task 9: TUI wizard wiring (provider tile, navigation, validation, defaults)

**Files:**
- Modify: `src/tui/ui/account_screens.rs`
- Modify: `src/tui/events.rs`
- Modify: `src/tui/app/nav.rs`
- Modify: `src/tui/app/mod.rs`
- Modify: `src/tui/ui/collectors.rs`

**Interfaces:**
- Consumes: `CloudProvider::Orca` (Task 4), `menu_for(CloudProvider::Orca)` (Task 8).
- Produces: full wizard reachability for Orca — Provider Selection tile, arrow-key navigation entry, screen transitions (`ProviderSelection → SelectCollectors → SetOptions → Confirm`, matching Okta/Jira exactly, no extra screens), validation error when no `orca-config.toml` accounts exist, opt-in-by-default collector state.

- [ ] **Step 1: Add the provider tile**

In `src/tui/ui/account_screens.rs`, inside `draw_provider_selection()`, change:

```rust
        #[cfg(feature = "jira")]
        v.push((
            CloudProvider::Jira,
            "◆  Jira",
            "Collect projects and issues from Jira Cloud or Jira Server",
        ));
        v
    };
```

to:

```rust
        #[cfg(feature = "jira")]
        v.push((
            CloudProvider::Jira,
            "◆  Jira",
            "Collect projects and issues from Jira Cloud or Jira Server",
        ));
        #[cfg(feature = "orca")]
        v.push((
            CloudProvider::Orca,
            "◆  Orca Security",
            "Export cloud security alerts, asset inventory, and compliance results from Orca",
        ));
        v
    };
```

- [ ] **Step 2: Add Orca to the provider-selection key list**

In `src/tui/events.rs`, inside `handle_provider_selection()`, change:

```rust
        #[cfg(feature = "jira")]
        v.push(CloudProvider::Jira);
        v
```

to:

```rust
        #[cfg(feature = "jira")]
        v.push(CloudProvider::Jira);
        #[cfg(feature = "orca")]
        v.push(CloudProvider::Orca);
        v
```

This must list providers in the same order as Step 1's tiles (both now end with Jira then Orca) — the existing comment in this function already warns the two lists must stay in sync.

- [ ] **Step 3: Add the `ProviderSelection → SelectCollectors` transition**

In `src/tui/app/nav.rs`, inside `next_screen()`, change:

```rust
            Screen::ProviderSelection => {
                if self.selected_provider == CloudProvider::Tenable {
                    self.auto_select_provider_accounts();
                    self.clamp_collector_cursors();
                    Screen::TenableEndpoint
                } else if self.selected_provider == CloudProvider::Okta {
                    self.auto_select_provider_accounts();
                    self.clamp_collector_cursors();
                    Screen::SelectCollectors
                } else if self.selected_provider == CloudProvider::Jira {
                    self.auto_select_provider_accounts();
                    self.clamp_collector_cursors();
                    Screen::SelectCollectors
                } else if self.has_accounts() {
                    Screen::SelectAccount
                } else {
                    Screen::SelectProfile
                }
            }
```

to:

```rust
            Screen::ProviderSelection => {
                if self.selected_provider == CloudProvider::Tenable {
                    self.auto_select_provider_accounts();
                    self.clamp_collector_cursors();
                    Screen::TenableEndpoint
                } else if self.selected_provider == CloudProvider::Okta {
                    self.auto_select_provider_accounts();
                    self.clamp_collector_cursors();
                    Screen::SelectCollectors
                } else if self.selected_provider == CloudProvider::Jira {
                    self.auto_select_provider_accounts();
                    self.clamp_collector_cursors();
                    Screen::SelectCollectors
                } else if self.selected_provider == CloudProvider::Orca {
                    self.auto_select_provider_accounts();
                    self.clamp_collector_cursors();
                    Screen::SelectCollectors
                } else if self.has_accounts() {
                    Screen::SelectAccount
                } else {
                    Screen::SelectProfile
                }
            }
```

- [ ] **Step 4: Add the `SelectCollectors → ProviderSelection` back-transition**

In `src/tui/app/nav.rs`, inside `prev_screen()`, change:

```rust
            Screen::SelectCollectors => {
                if self.selected_provider == CloudProvider::Tenable {
                    Screen::TenableEndpoint
                } else if self.selected_provider == CloudProvider::Okta
                    || self.selected_provider == CloudProvider::Jira
                {
                    Screen::ProviderSelection
                } else {
                    Screen::SetDates
                }
            }
```

to:

```rust
            Screen::SelectCollectors => {
                if self.selected_provider == CloudProvider::Tenable {
                    Screen::TenableEndpoint
                } else if self.selected_provider == CloudProvider::Okta
                    || self.selected_provider == CloudProvider::Jira
                    || self.selected_provider == CloudProvider::Orca
                {
                    Screen::ProviderSelection
                } else {
                    Screen::SetDates
                }
            }
```

Note: `Screen::SetDates`'s own `prev_screen` arm already special-cases only `CloudProvider::Tenable` (line 139 area: `if self.selected_provider == CloudProvider::Tenable { Screen::ProviderSelection } else if self.has_accounts() { ... }`) — this arm is unreachable for Orca (Orca never transitions through `SetDates`, same as Okta/Jira today), so it needs no change.

- [ ] **Step 5: Add the "no accounts configured" validation**

In `src/tui/app/nav.rs`, inside `validate_current()`, change:

```rust
                #[cfg(feature = "jira")]
                if self.selected_provider == CloudProvider::Jira {
                    let has_jira = self
                        .accounts
                        .iter()
                        .any(|a| a.provider == CloudProvider::Jira);
                    if !has_jira {
                        self.error_msg =
                            Some("No Jira accounts configured in jira-config.toml".into());
                        return false;
                    }
                }
                true
            }
```

to:

```rust
                #[cfg(feature = "jira")]
                if self.selected_provider == CloudProvider::Jira {
                    let has_jira = self
                        .accounts
                        .iter()
                        .any(|a| a.provider == CloudProvider::Jira);
                    if !has_jira {
                        self.error_msg =
                            Some("No Jira accounts configured in jira-config.toml".into());
                        return false;
                    }
                }
                #[cfg(feature = "orca")]
                if self.selected_provider == CloudProvider::Orca {
                    let has_orca = self
                        .accounts
                        .iter()
                        .any(|a| a.provider == CloudProvider::Orca);
                    if !has_orca {
                        self.error_msg =
                            Some("No Orca accounts configured in orca-config.toml".into());
                        return false;
                    }
                }
                true
            }
```

- [ ] **Step 6: Add Orca collector keys to `hardcoded_optins`**

In `src/tui/app/mod.rs`, inside the `hardcoded_optins` array, change:

```rust
        let hardcoded_optins = [
            "s3",
            "elasticache-global",
            "scp",
            "macie",
            "inspector",
            "inspector-config",
            "org-config",
            "tenable-vulns",
            "tenable-was",
            "tenable-pci-asv",
            "tenable-assets",
            "tenable-compliance",
            "okta-users",
```

to:

```rust
        let hardcoded_optins = [
            "s3",
            "elasticache-global",
            "scp",
            "macie",
            "inspector",
            "inspector-config",
            "org-config",
            "tenable-vulns",
            "tenable-was",
            "tenable-pci-asv",
            "tenable-assets",
            "tenable-compliance",
            "orca-alerts",
            "orca-assets",
            "orca-compliance",
            "okta-users",
```

This makes all three Orca collectors unchecked by default (the user must explicitly select them), matching every existing Tenable collector's default state — a deliberate choice: Orca alert/asset volumes can be very large per tenant, so opt-in avoids surprise long-running default runs.

- [ ] **Step 7: Hide the search bar for Orca's single-category menu**

In `src/tui/ui/collectors.rs`, change:

```rust
    let is_tenable = app.selected_provider == CloudProvider::Tenable
        && app.selected_feature == crate::tui::state::Feature::Collectors;

    // Layout: search bar (3 or 0) | main panels (fill) | separator (1) | help (1)
    let search_height: u16 = if is_tenable { 0 } else { 3 };
```

to:

```rust
    let hide_search = matches!(
        app.selected_provider,
        CloudProvider::Tenable | CloudProvider::Orca
    ) && app.selected_feature == crate::tui::state::Feature::Collectors;

    // Layout: search bar (3 or 0) | main panels (fill) | separator (1) | help (1)
    let search_height: u16 = if hide_search { 0 } else { 3 };
```

Then further down in the same function, change:

```rust
    // ── Search bar (hidden for Tenable) ──────────────────────────
    if !is_tenable {
```

to:

```rust
    // ── Search bar (hidden for single-category providers: Tenable, Orca) ──
    if !hide_search {
```

- [ ] **Step 8: Verify**

Run: `cargo check`
Expected: `Finished` with no errors.

Run: `cargo test`
Expected: all existing tests pass, including `src/tui/app/mod.rs`'s per-provider menu tests (`search_empty_matches_all_items`, `selection_survives_provider_switch`, etc.) — these are structural (they read whichever provider's menu is currently active) and require no Orca-specific additions to keep passing.

- [ ] **Step 9: Commit**

```bash
git add src/tui/ui/account_screens.rs src/tui/events.rs src/tui/app/nav.rs src/tui/app/mod.rs src/tui/ui/collectors.rs
git commit -m "feat(orca): wire Orca into TUI provider selection, navigation, and defaults"
```

---

### Task 10: Runner — build Orca accounts into collector run

**Files:**
- Modify: `src/runner/tui_session.rs`

**Interfaces:**
- Consumes: `Account::orca_api_token_resolved()`/`orca_base_url_resolved()` (Task 5), `orca_rs::OrcaClient::new()` (Task 1), `crate::providers::orca::factory::OrcaProviderFactory` (Task 7), `crate::runner::multi_account::AccountCollectors` (pre-existing struct, unchanged).
- Produces: the actual runtime path that turns a selected Orca account into collectors dispatched by the run — this is the task that makes "select Orca Security in the wizard and press Run" actually work.

- [ ] **Step 1: Add the Orca account-build block**

In `src/runner/tui_session.rs`, find the end of the existing `// ── Okta accounts ──` block (it ends with the closing `}` that matches `#[cfg(feature = "okta")] if !app.selected_accounts.is_empty() {`). Immediately after that closing `}`, insert:

```rust

            // ── Orca Security accounts ──────────────────────────────────────
            #[cfg(feature = "orca")]
            if !app.selected_accounts.is_empty() {
                use crate::providers::ProviderFactory as _;

                let sorted_all: Vec<usize> = {
                    let mut v: Vec<usize> = app.selected_accounts.iter().copied().collect();
                    v.sort();
                    v
                };
                for &idx in &sorted_all {
                    if app.accounts[idx].provider != crate::providers::CloudProvider::Orca {
                        continue;
                    }
                    let acct = &app.accounts[idx];
                    let tenant_name = acct.name.clone();

                    let base_url = acct.orca_base_url_resolved();
                    let token = match acct.orca_api_token_resolved() {
                        Some(t) => t,
                        None => {
                            app.prep_log.push(format!(
                                "  ✗ Orca '{}' — missing orca_api_token (or ORCA_API_TOKEN env)",
                                tenant_name,
                            ));
                            terminal.draw(|f| crate::tui::ui::draw(f, &app))?;
                            continue;
                        }
                    };

                    app.prep_log
                        .push(format!("  Orca '{}' → {}", tenant_name, base_url));
                    terminal.draw(|f| crate::tui::ui::draw(f, &app))?;

                    let client = match orca_rs::OrcaClient::new(&base_url, &token) {
                        Ok(c) => c,
                        Err(e) => {
                            app.prep_log.push(format!(
                                "  ✗ Orca '{}' — client build failed: {e}",
                                tenant_name,
                            ));
                            terminal.draw(|f| crate::tui::ui::draw(f, &app))?;
                            continue;
                        }
                    };

                    let selected_keys: Vec<String> = app
                        .selected_collectors()
                        .into_iter()
                        .filter(|k| k.starts_with("orca-"))
                        .collect();

                    let factory = crate::providers::orca::factory::OrcaProviderFactory::new(
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

                    // Always include tenant_name so the final layout is:
                    // {base_output_dir}/{tenant_name}/{YYYY}/{MM-MMM}/
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
                        endpoint_label: Some(format!("Orca Security — {}", base_url)),
                    });

                    app.prep_log
                        .push(format!("  ✓ Orca '{}' ready.", tenant_name));
                    terminal.draw(|f| crate::tui::ui::draw(f, &app))?;
                }
            }
```

- [ ] **Step 2: Verify**

Run: `cargo check`
Expected: `Finished` with no errors.

Run: `cargo build`
Expected: builds successfully with default features (which now include `orca`).

- [ ] **Step 3: Commit**

```bash
git add src/runner/tui_session.rs
git commit -m "feat(orca): build Orca accounts into the collector run"
```

---

### Task 11: Documentation

**Files:**
- Modify: `README.md`
- Modify: `evidence-list.md`
- Modify: `docs/cli-reference.md`
- Modify: `AGENTS.md`
- Modify: `docs/implementation-plan.md`

**Interfaces:**
- Consumes: nothing (pure documentation, no code dependency).
- Produces: nothing consumed by later tasks — this is a leaf task.

- [ ] **Step 1: Add the `## Orca Security` section to `README.md`**

In `README.md`, the `## Tenable` section currently ends with a `---` divider immediately before `## Azure / GCP` (README.md:852-853). Insert a new section between them:

```markdown
## Orca Security

Optional feature — build with `--features orca` (enabled by default).

### Configuration

Create `orca-config.toml` in the repo root (gitignored):

```toml
[[account]]
name           = "Orca Security"
provider       = "orca"
description    = "Orca Security cloud posture and vulnerability findings"
output_dir     = "./evidence-output/orca"
orca_api_token = ""
```

Or via environment variables (env wins over TOML):

- `ORCA_API_TOKEN`
- `ORCA_BASE_URL` — omit for the US tenant (`https://app.us.orcasecurity.io`); set to `https://app.eu.orcasecurity.io` for an EU tenant.

Create an API token in the Orca console: **Settings → Users & Permissions → API → API Tokens → Add API Token**. The **Viewer** role is the minimum recommended for read-only evidence collection.

### Collectors

| Key | Output | Description |
|-----|--------|-------------|
| `orca-alerts` | CSV | Open security alerts (findings) across all monitored cloud accounts |
| `orca-assets` | CSV | Full cloud asset inventory |
| `orca-compliance` | CSV | Compliance framework requirement results |

---
```

- [ ] **Step 2: Update the feature-count summary line**

In `README.md`, change:

```markdown
- **200+ collectors across four providers** — 144 AWS, 24 Okta, 28 Jira, 5 Tenable (see `evidence-list.md` for the current catalog)
```

to:

```markdown
- **200+ collectors across five providers** — 144 AWS, 24 Okta, 28 Jira, 5 Tenable, 3 Orca Security (see `evidence-list.md` for the current catalog)
```

- [ ] **Step 3: Update the non-AWS provider-menu mention**

In `README.md`, change:

```markdown
A scrollable checklist of 144 AWS collectors grouped into categories (IAM, EC2/Networking, Storage, RDS, KMS, CloudTrail, Config, Security Services, SSM, Monitoring, Containers, etc.). Non-AWS providers (Okta, Jira, Tenable) surface their own per-provider collector menus with only the keys relevant to that provider.
```

to:

```markdown
A scrollable checklist of 144 AWS collectors grouped into categories (IAM, EC2/Networking, Storage, RDS, KMS, CloudTrail, Config, Security Services, SSM, Monitoring, Containers, etc.). Non-AWS providers (Okta, Jira, Tenable, Orca Security) surface their own per-provider collector menus with only the keys relevant to that provider.
```

- [ ] **Step 4: Add an Orca row to the `evidence-list.md` summary and a new provider section**

In `evidence-list.md`, find the `### Vulnerability Management — Tenable` section (its 5-row table, EV198–EV202). Immediately after that table (before the next `###` heading or the `## Summary` section, whichever comes first), insert:

```markdown
### Cloud Security Posture — Orca Security

| ID | Evidence | Output File Prefix | Columns |
|----|----------|--------------------|---------|
| EV203 | Orca Security Alerts | `Orca_Security_Alerts` | Alert ID, Type, State, Status, Risk Level, Score, Rule Name, Description, Cloud Provider, Cloud Account ID, Region, Asset Name, Asset ID, Created, Last Updated |
| EV204 | Orca Cloud Asset Inventory | `Orca_Cloud_Asset_Inventory` | Asset ID, Name, Type, Cloud Provider, Cloud Account ID, Region, State, Organization, First Seen, Last Seen |
| EV205 | Orca Compliance Framework Results | `Orca_Compliance_Framework_Results` | Framework, Requirement ID, Requirement Name, Category, Status, Score, Cloud Account ID, Cloud Provider, Last Evaluated |
```

Then in the `## Summary` table, change:

```markdown
| Category | Count |
|----------|-------|
| AWS collectors | 144 |
| Okta collectors | 24 |
| Jira collectors | 28 |
| Tenable collectors | 5 |
| **Total evidence collectors** | **201** |
| Asset Inventory asset types (Inventory feature) | 8 |
```

to:

```markdown
| Category | Count |
|----------|-------|
| AWS collectors | 144 |
| Okta collectors | 24 |
| Jira collectors | 28 |
| Tenable collectors | 5 |
| Orca Security collectors | 3 |
| **Total evidence collectors** | **204** |
| Asset Inventory asset types (Inventory feature) | 8 |
```

- [ ] **Step 5: Update `docs/cli-reference.md`**

Change:

```markdown
By default the tool collects from a single region (`--region`). These flags enable round-robin collection across multiple regions. **AWS only** — Okta, Jira, and Tenable are region-agnostic; the TUI hides the All-Regions toggle for those providers, and on the CLI these flags are silently ignored for non-AWS runs.
```

to:

```markdown
By default the tool collects from a single region (`--region`). These flags enable round-robin collection across multiple regions. **AWS only** — Okta, Jira, Tenable, and Orca Security are region-agnostic; the TUI hides the All-Regions toggle for those providers, and on the CLI these flags are silently ignored for non-AWS runs.
```

Change:

```markdown
All 144 AWS collector keys are organized by category below. Pass any combination to `--collectors`. Non-AWS keys are namespaced with their provider prefix (`okta-*`, `jira-*`, `tenable-*`) — see the provider sections in the main [README](../README.md) for the canonical lists.
```

to:

```markdown
All 144 AWS collector keys are organized by category below. Pass any combination to `--collectors`. Non-AWS keys are namespaced with their provider prefix (`okta-*`, `jira-*`, `tenable-*`, `orca-*`) — see the provider sections in the main [README](../README.md) for the canonical lists.
```

- [ ] **Step 6: Update `AGENTS.md`**

Change:

```markdown
- Provider-scoped module tree. Every collector lives under `src/providers/<provider>/<service>.rs`, where `<provider>` is one of `aws`, `okta`, `jira`, `tenable`, `azure`, or `gcp`. Each provider has a `factory.rs` (implements `CloudProvider` / `ProviderFactory` from `src/providers/mod.rs`) that registers keys to concrete collectors.
```

to:

```markdown
- Provider-scoped module tree. Every collector lives under `src/providers/<provider>/<service>.rs`, where `<provider>` is one of `aws`, `okta`, `jira`, `tenable`, `orca`, `azure`, or `gcp`. Each provider has a `factory.rs` (implements `CloudProvider` / `ProviderFactory` from `src/providers/mod.rs`) that registers keys to concrete collectors.
```

Change:

```markdown
- When you add a new AWS/Okta/Jira/Tenable collector: create `src/providers/<provider>/<name>.rs`, declare it in `src/providers/<provider>/mod.rs`, and register its key in that provider's `factory.rs`. Do **not** touch `main.rs` — new provider modules do not need to be declared there.
```

to:

```markdown
- When you add a new AWS/Okta/Jira/Tenable/Orca collector: create `src/providers/<provider>/<name>.rs`, declare it in `src/providers/<provider>/mod.rs`, and register its key in that provider's `factory.rs`. Do **not** touch `main.rs` — new provider modules do not need to be declared there.
```

- [ ] **Step 7: Update the status snapshot in `docs/implementation-plan.md`**

Change:

```markdown
| 3 — Provider trait generalization | **Done in shape.** `src/providers/mod.rs` defines `CloudProvider` + `ProviderFactory`; `aws`, `okta`, `jira`, `tenable`, `azure`, and `gcp` all implement it. Providers are inferred from each `[[account]]` block's `provider = "…"` field, not from a `--provider` CLI flag (that idea was dropped as unnecessary once accounts became provider-tagged). |
```

to:

```markdown
| 3 — Provider trait generalization | **Done in shape.** `src/providers/mod.rs` defines `CloudProvider` + `ProviderFactory`; `aws`, `okta`, `jira`, `tenable`, `orca`, `azure`, and `gcp` all implement it. Providers are inferred from each `[[account]]` block's `provider = "…"` field, not from a `--provider` CLI flag (that idea was dropped as unnecessary once accounts became provider-tagged). |
```

- [ ] **Step 8: Commit**

```bash
git add README.md evidence-list.md docs/cli-reference.md AGENTS.md docs/implementation-plan.md
git commit -m "docs(orca): document the Orca Security provider"
```

---

### Task 12: Final verification

**Files:** none (verification only).

**Interfaces:** none.

- [ ] **Step 1: Full build matrix**

Run: `cargo build`
Expected: succeeds (default features: `tenable`, `okta`, `jira`, `orca`).

Run: `cargo build --all-features`
Expected: succeeds (adds `azure`, `gcp` stub features).

Run: `cargo build --no-default-features --features orca`
Expected: succeeds (Orca alone, no Tenable/Okta/Jira).

Run: `cargo build --no-default-features`
Expected: succeeds (AWS only — confirms Orca stayed fully optional).

- [ ] **Step 2: Lint and format**

Run: `cargo clippy --all-features -- -D warnings`
Expected: no warnings.

Run: `cargo fmt --check`
Expected: no diff. If it reports one, run `cargo fmt` and re-stage.

- [ ] **Step 3: Test suite**

Run: `cargo test`
Expected: all tests pass, including the `src/tui/app/mod.rs` per-provider menu tests.

- [ ] **Step 4: Manual TUI smoke walkthrough**

No live Orca tenant is available in this environment, so this step verifies wizard *reachability and error handling*, not real data collection:

1. Run: `cp orca-config.example.toml orca-config.toml` and edit it to set `orca_api_token = "smoke-test-token"` (a fake value is fine for this step).
2. Run: `cargo run` to launch the TUI.
3. Navigate: Welcome → Enter → Feature Selection (Collectors) → Enter → Provider Selection.
4. Confirm an "◆ Orca Security" tile is visible and selectable via arrow keys, positioned after "◆ Jira".
5. Select it and press Enter. Confirm it advances directly to the Collectors screen (no intermediate endpoint-picker screen, matching Okta/Jira) and shows exactly one category, "Cloud Security Findings", with 3 items, all unchecked by default, and no search bar rendered.
6. Toggle all 3 items on with Space, press Enter to advance to Options, then Confirm. Confirm the All-Regions toggle and region list are **not** shown (region-agnostic, same as Tenable/Okta/Jira).
7. Press Enter on Confirm to start the run. Confirm the prep log shows `Orca 'Orca Security' → https://app.us.orcasecurity.io` followed by either a client-build success or a network/auth error (expected, since `smoke-test-token` is not a real token) — the key thing to verify is that the wizard reaches this point without a panic or a `menu_for` crash.
8. Press `q` to quit. Run: `rm orca-config.toml` (do not commit a real or fake token file — it's already gitignored per Task 5, but confirm `git status` shows it as untracked/ignored, not staged).

- [ ] **Step 5: Confirm no stray files were committed**

Run: `git status`
Expected: clean working tree (all task commits already made), and `orca-config.toml` (if still present locally) shows as ignored, not tracked.
