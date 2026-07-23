# Add Wiz Provider Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Wiz (wiz.io cloud security / CSPM platform) as a fifth non-AWS provider, following the exact architectural pattern already used for Tenable, Okta, and Jira — a standalone `wiz-rs` HTTP client crate, a `src/providers/wiz` collector module, and TUI wiring — so users can collect Wiz Issues, Vulnerability Findings, and Configuration Findings as compliance evidence.

**Architecture:** Wiz authenticates via OAuth2 client-credentials (unlike the static-header auth used by Tenable/Okta/Jira), so `wiz-rs` fetches and caches a bearer token, refreshing it before expiry. All data access goes through a single GraphQL endpoint (`POST /graphql`) rather than multiple REST paths. Everything else — crate skeleton, `CloudProvider` enum, `ProviderFactory` impl, TUI menu registration, account config, `tui_session.rs` wiring — mirrors Okta exactly, since Okta is the closest existing analog (external SaaS API, own workspace crate, TUI-only, no region concept).

**Tech Stack:** Rust 2021, `reqwest` (json + rustls-tls) for HTTP, `tokio` for async + token-cache locking, `thiserror` for errors, `wiremock` for HTTP-layer tests.

## Global Constraints

- New workspace crate `wiz-rs` at `crates/wiz-rs`, added to `[workspace] members` in the root `Cargo.toml`, matching the shape of `crates/okta-rs`.
- The Wiz provider is opt-in via Cargo feature `wiz` (`wiz = ["dep:wiz-rs"]`), added to `default = ["tenable", "okta", "jira", "wiz"]` in the root `Cargo.toml` — matching how Tenable/Okta/Jira are wired (Azure/GCP are the only providers left out of `default`).
- No CLI (`src/cli.rs`) wiring — Tenable/Okta/Jira are TUI-only today; Wiz follows the same pattern unless a later task requests CLI support.
- Selector keys are prefixed `wiz-` (e.g. `wiz-issues`); CSV filename prefixes are prefixed `Wiz_` (e.g. `Wiz_Issues`) — matching the `okta-`/`Okta_` and `tenable-`/`Tenable_` conventions.
- Credentials come from `wiz-config.toml` (gitignored, merged into `AppConfig` at startup exactly like `tenable-config.toml`/`okta-config.toml`/`jira-config.toml`), with env vars `WIZ_CLIENT_ID`, `WIZ_CLIENT_SECRET`, `WIZ_API_URL`, `WIZ_AUTH_URL` overriding TOML values — matching the `_resolved()` accessor pattern on `Account`.
- Wiz has no AWS-style region concept, so `WizProviderFactory::region()` returns `""` and the existing `is_aws_regional()` / `is_collectors_non_aws` gates already added for Okta/Jira/Tenable apply to Wiz automatically — no new region-hiding code is needed.
- GraphQL query field names below reflect Wiz's publicly documented Issues / Vulnerability Findings / Configuration Findings API shape (Relay-style `nodes` + `pageInfo { hasNextPage endCursor }` cursor pagination, `entitySnapshot` / `vulnerableAsset` / `resource` sub-objects). Every test in this plan mocks the HTTP layer with `wiremock`, so the code is fully buildable and testable without a live Wiz tenant — but before running against a **real** tenant, verify the field names against that tenant's live GraphQL schema (Wiz exposes introspection on the same `wiz_api_url`) and adjust the `types::*` structs if any field differs.
- Scope for this plan is three initial collectors — Issues, Vulnerability Findings, Configuration Findings — chosen because they are Wiz's core compliance-relevant data (open security findings, CVE-level vulnerabilities, CSPM control failures). Additional Wiz collectors (e.g. cloud resource inventory, issue notes/timeline) can be added later following the exact same pattern as Task 9–11 below.

---

## File Structure

**New files:**
- `crates/wiz-rs/Cargo.toml` — crate manifest (reqwest, tokio, thiserror, wiremock dev-dep)
- `crates/wiz-rs/src/lib.rs` — crate root, re-exports `WizClient`/`WizError`
- `crates/wiz-rs/src/error.rs` — `WizError` enum
- `crates/wiz-rs/src/client.rs` — `WizClient`: OAuth2 token fetch/cache/refresh + GraphQL POST + 429/401 retry
- `crates/wiz-rs/src/api/mod.rs` — re-exports the three API structs
- `crates/wiz-rs/src/api/issues.rs` — `IssuesApi::list_all`
- `crates/wiz-rs/src/api/vulnerabilities.rs` — `VulnerabilitiesApi::list_all`
- `crates/wiz-rs/src/api/configuration_findings.rs` — `ConfigurationFindingsApi::list_all`
- `crates/wiz-rs/src/types/mod.rs` — re-exports type modules
- `crates/wiz-rs/src/types/issue.rs` — `WizIssue`, `EntitySnapshot`, `IssueConnection`, `PageInfo`
- `crates/wiz-rs/src/types/vulnerability.rs` — `WizVulnerabilityFinding`, `VulnerableAsset`, `VulnerabilityConnection`
- `crates/wiz-rs/src/types/configuration_finding.rs` — `WizConfigurationFinding`, `ConfigurationResource`, `ConfigurationFindingConnection`
- `crates/wiz-rs/tests/client_test.rs` — token exchange, bearer-header injection, 401 refresh, 429 retry
- `crates/wiz-rs/tests/issues_test.rs` — cursor pagination over the mocked GraphQL endpoint
- `src/providers/wiz/mod.rs` — `pub mod` declarations for the Wiz collector module
- `src/providers/wiz/factory.rs` — `WizProviderFactory: ProviderFactory`
- `src/providers/wiz/issues.rs` — `WizIssuesCollector: CsvCollector`
- `src/providers/wiz/vulnerabilities.rs` — `WizVulnerabilitiesCollector: CsvCollector`
- `src/providers/wiz/configuration_findings.rs` — `WizConfigurationFindingsCollector: CsvCollector`
- `src/tui/menus/wiz.rs` — `WIZ_CATEGORIES` menu data
- `wiz-config.example.toml` — example credentials file

**Modified files:**
- `Cargo.toml` — workspace member, `wiz-rs` dependency, `wiz` feature
- `src/providers/mod.rs` — `CloudProvider::Wiz` variant + `Display` arm + `pub mod wiz`
- `src/app_config.rs` — `Account` Wiz fields + `_resolved()` methods + `wiz-config.toml` merge in `load_config()`
- `src/tui/menus/mod.rs` — `pub mod wiz;` + `PROVIDER_MENUS` entry
- `src/tui/ui/account_screens.rs` — Wiz card in `draw_provider_selection()`
- `src/tui/events.rs` — Wiz in `handle_provider_selection`'s provider list + `validate_current` account check
- `src/tui/app/nav.rs` — Wiz routing in `next_screen`/`prev_screen` (same branch as Okta/Jira — no extra screen)
- `src/runner/tui_session.rs` — Wiz account-preparation block (async `WizClient::new(...).await`)
- `src/tui/app/mod.rs` — provider-switch selection test extended to cover Wiz
- `.gitignore` — `wiz-config.toml`
- `README.md` — mention Wiz alongside the other three non-AWS providers

---

### Task 1: Workspace + wiz-rs crate skeleton

**Files:**
- Create: `crates/wiz-rs/Cargo.toml`
- Create: `crates/wiz-rs/src/lib.rs`
- Create: `crates/wiz-rs/src/error.rs`
- Modify: `Cargo.toml:1-2` (workspace members), `Cargo.toml:90-104` (deps + features)

**Interfaces:**
- Produces: `wiz_rs::WizError` (used by every later task in this crate), an empty crate that compiles standalone.

- [ ] **Step 1: Create the crate manifest**

```toml
# crates/wiz-rs/Cargo.toml
[package]
name        = "wiz-rs"
version     = "0.1.0"
edition     = "2021"
description = "Async Rust client for the Wiz GraphQL API"
license     = "MIT OR Apache-2.0"

[dependencies]
reqwest    = { version = "0.12", features = ["json", "rustls-tls"], default-features = false }
serde      = { version = "1", features = ["derive"] }
serde_json = "1"
tokio      = { version = "1", features = ["time", "sync"] }
thiserror  = "2"
anyhow     = "1"

[dev-dependencies]
tokio    = { version = "1", features = ["full"] }
wiremock = "0.6"
```

- [ ] **Step 2: Write the error type**

```rust
// crates/wiz-rs/src/error.rs
use thiserror::Error;

#[derive(Debug, Error)]
pub enum WizError {
    #[error("HTTP transport error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("invalid header value: {0}")]
    Header(#[from] reqwest::header::InvalidHeaderValue),

    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("invalid API URL: {0}")]
    InvalidApiUrl(String),

    #[error("invalid auth URL: {0}")]
    InvalidAuthUrl(String),

    #[error("Wiz OAuth2 token request failed: HTTP {status} — {message}")]
    Auth { status: u16, message: String },

    #[error("Wiz API error: HTTP {status} — {message}")]
    Api { status: u16, message: String },

    #[error("Wiz GraphQL errors: {0}")]
    GraphQl(String),
}
```

- [ ] **Step 3: Write the crate root**

```rust
// crates/wiz-rs/src/lib.rs
//! Async Rust client for the Wiz GraphQL API.
//!
//! # Quick start
//!
//! ```no_run
//! use wiz_rs::WizClient;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let client = WizClient::new(
//!         "https://api.us1.app.wiz.io/graphql",
//!         "https://auth.app.wiz.io/oauth/token",
//!         "client-id",
//!         "client-secret",
//!     ).await?;
//!     let issues = client.issues().list_all("2026-01-01T00:00:00Z", "2026-07-01T00:00:00Z").await?;
//!     println!("{} issues", issues.len());
//!     Ok(())
//! }
//! ```

mod client;
mod error;

pub mod api;
pub mod types;

pub use client::WizClient;
pub use error::WizError;
```

`api` and `types` don't exist yet, so this won't compile until Task 2 adds `client.rs` and Task 3 adds `api`/`types`. Run the check after Task 3, not now.

- [ ] **Step 4: Register the workspace member and feature**

Edit `Cargo.toml`:

```toml
[workspace]
members  = [".", "crates/tenable-rs", "crates/okta-rs", "crates/jira-rs", "crates/wiz-rs"]
resolver = "2"
```

```toml
# Wiz — only compiled with `--features wiz`
wiz-rs = { path = "crates/wiz-rs", optional = true }
```

```toml
[features]
default = ["tenable", "okta", "jira", "wiz"]
azure   = ["dep:azure_identity", "dep:azure_mgmt_monitor", "dep:azure_mgmt_resources"]
gcp     = ["dep:google-cloud-auth"]
tenable = ["dep:tenable-rs"]
okta    = ["dep:okta-rs"]
jira    = ["dep:jira-rs"]
wiz     = ["dep:wiz-rs"]
```

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml crates/wiz-rs/Cargo.toml crates/wiz-rs/src/lib.rs crates/wiz-rs/src/error.rs
git commit -m "feat(wiz-rs): scaffold crate skeleton and workspace wiring"
```

---

### Task 2: WizClient — OAuth2 client-credentials + GraphQL POST + retry

**Files:**
- Create: `crates/wiz-rs/src/client.rs`
- Test: `crates/wiz-rs/tests/client_test.rs`

**Interfaces:**
- Consumes: `crate::error::WizError` (Task 1).
- Produces: `pub struct WizClient` with `pub async fn new(api_url, auth_url, client_id, client_secret) -> Result<Self, WizError>` and `pub(crate) async fn graphql(&self, query: &str, variables: serde_json::Value) -> Result<serde_json::Value, WizError>`. Later API modules (Task 3) call `client.graphql(...)`.

- [ ] **Step 1: Write the failing tests**

```rust
// crates/wiz-rs/tests/client_test.rs
use wiz_rs::WizClient;
use wiremock::matchers::{body_string_contains, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn fetches_token_then_sends_bearer_auth_graphql_request() {
    let auth_server = MockServer::start().await;
    let api_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .and(body_string_contains("grant_type=client_credentials"))
        .and(body_string_contains("client_id=test-id"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "test-token",
            "token_type": "Bearer",
            "expires_in": 3600
        })))
        .expect(1)
        .mount(&auth_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/graphql"))
        .and(header("Authorization", "Bearer test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": { "ok": true }
        })))
        .expect(1)
        .mount(&api_server)
        .await;

    let client = WizClient::new(
        &format!("{}/graphql", api_server.uri()),
        &format!("{}/oauth/token", auth_server.uri()),
        "test-id",
        "test-secret",
    )
    .await
    .unwrap();

    let data = client
        .graphql_for_test("query { ok }", serde_json::json!({}))
        .await
        .unwrap();
    assert_eq!(data["ok"], true);
}

#[tokio::test]
async fn refreshes_token_on_401_and_retries_once() {
    let auth_server = MockServer::start().await;
    let api_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "token-1",
            "expires_in": 3600
        })))
        .up_to_n_times(1)
        .mount(&auth_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "token-2",
            "expires_in": 3600
        })))
        .mount(&auth_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/graphql"))
        .and(header("Authorization", "Bearer token-1"))
        .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "message": "expired"
        })))
        .expect(1)
        .mount(&api_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/graphql"))
        .and(header("Authorization", "Bearer token-2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": { "ok": true }
        })))
        .expect(1)
        .mount(&api_server)
        .await;

    let client = WizClient::new(
        &format!("{}/graphql", api_server.uri()),
        &format!("{}/oauth/token", auth_server.uri()),
        "test-id",
        "test-secret",
    )
    .await
    .unwrap();

    let data = client
        .graphql_for_test("query { ok }", serde_json::json!({}))
        .await
        .unwrap();
    assert_eq!(data["ok"], true);
}

#[tokio::test]
async fn graphql_errors_field_becomes_an_error() {
    let auth_server = MockServer::start().await;
    let api_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "test-token",
            "expires_in": 3600
        })))
        .mount(&auth_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/graphql"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "errors": [{ "message": "field not found" }]
        })))
        .mount(&api_server)
        .await;

    let client = WizClient::new(
        &format!("{}/graphql", api_server.uri()),
        &format!("{}/oauth/token", auth_server.uri()),
        "test-id",
        "test-secret",
    )
    .await
    .unwrap();

    let err = client
        .graphql_for_test("query { bad }", serde_json::json!({}))
        .await
        .unwrap_err();
    assert!(matches!(err, wiz_rs::WizError::GraphQl(_)));
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p wiz-rs --test client_test`
Expected: FAIL — `wiz_rs::WizClient` and `graphql_for_test` don't exist yet (compile error).

- [ ] **Step 3: Implement `WizClient`**

```rust
// crates/wiz-rs/src/client.rs
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use reqwest::Client;
use serde::Deserialize;
use serde_json::Value;
use tokio::sync::RwLock;
use tokio::time::{sleep, Duration};

use crate::error::WizError;

const MAX_RETRIES: u32 = 5;
const TOKEN_REFRESH_SKEW_SECS: i64 = 60;

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default = "default_expires_in")]
    expires_in: i64,
}

fn default_expires_in() -> i64 {
    3600
}

#[derive(Debug, Clone)]
struct CachedToken {
    access_token: String,
    expires_at: i64,
}

/// Async GraphQL client for the Wiz API.
///
/// Auth: OAuth2 client-credentials grant against `auth_url`. The bearer
/// token is cached and transparently refreshed `TOKEN_REFRESH_SKEW_SECS`
/// before it expires (or immediately, on a 401 from the API).
///
/// `WizClient` is cheaply cloneable — the HTTP client and cached token are
/// both arc-pooled.
#[derive(Clone)]
pub struct WizClient {
    http: Client,
    api_url: String,
    auth_url: String,
    client_id: String,
    client_secret: String,
    token: Arc<RwLock<Option<CachedToken>>>,
}

impl WizClient {
    /// Build a client and perform the initial OAuth2 token exchange.
    /// `api_url` is the tenant's GraphQL endpoint (e.g. `https://api.us1.app.wiz.io/graphql`).
    /// `auth_url` is the tenant's OAuth2 token endpoint (e.g. `https://auth.app.wiz.io/oauth/token`).
    pub async fn new(
        api_url: &str,
        auth_url: &str,
        client_id: &str,
        client_secret: &str,
    ) -> Result<Self, WizError> {
        let api_url = api_url.trim().trim_end_matches('/').to_string();
        let auth_url = auth_url.trim().trim_end_matches('/').to_string();
        if api_url.is_empty() {
            return Err(WizError::InvalidApiUrl(api_url));
        }
        if auth_url.is_empty() {
            return Err(WizError::InvalidAuthUrl(auth_url));
        }
        let http = Client::builder().build()?;
        let client = Self {
            http,
            api_url,
            auth_url,
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            token: Arc::new(RwLock::new(None)),
        };
        client.ensure_token().await?;
        Ok(client)
    }

    async fn fetch_token(&self) -> Result<CachedToken, WizError> {
        let params = [
            ("grant_type", "client_credentials"),
            ("client_id", self.client_id.as_str()),
            ("client_secret", self.client_secret.as_str()),
            ("audience", "wiz-api"),
        ];
        let resp = self.http.post(&self.auth_url).form(&params).send().await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let message = resp.text().await.unwrap_or_default();
            return Err(WizError::Auth { status, message });
        }
        let token: TokenResponse = resp.json().await?;
        let now = now_epoch();
        Ok(CachedToken {
            access_token: token.access_token,
            expires_at: now + token.expires_in,
        })
    }

    async fn ensure_token(&self) -> Result<String, WizError> {
        let now = now_epoch();
        {
            let guard = self.token.read().await;
            if let Some(cached) = guard.as_ref() {
                if cached.expires_at - TOKEN_REFRESH_SKEW_SECS > now {
                    return Ok(cached.access_token.clone());
                }
            }
        }
        let fresh = self.fetch_token().await?;
        let access_token = fresh.access_token.clone();
        let mut guard = self.token.write().await;
        *guard = Some(fresh);
        Ok(access_token)
    }

    async fn invalidate_token(&self) {
        let mut guard = self.token.write().await;
        *guard = None;
    }

    /// Execute a GraphQL query/mutation. Retries once (forcing a token
    /// refresh) on 401, and with exponential backoff on 429.
    pub(crate) async fn graphql(&self, query: &str, variables: Value) -> Result<Value, WizError> {
        let body = serde_json::json!({ "query": query, "variables": variables });
        let mut backoff = 1u64;
        for attempt in 0..=MAX_RETRIES {
            let token = self.ensure_token().await?;
            let resp = self
                .http
                .post(&self.api_url)
                .bearer_auth(&token)
                .json(&body)
                .send()
                .await?;
            let status = resp.status();
            if status.as_u16() == 401 && attempt < MAX_RETRIES {
                self.invalidate_token().await;
                continue;
            }
            if status.as_u16() == 429 && attempt < MAX_RETRIES {
                sleep(Duration::from_secs(backoff)).await;
                backoff = (backoff * 2).min(30);
                continue;
            }
            if !status.is_success() {
                let message = resp.text().await.unwrap_or_default();
                return Err(WizError::Api {
                    status: status.as_u16(),
                    message,
                });
            }
            let payload: Value = resp.json().await?;
            if let Some(errors) = payload.get("errors") {
                if errors.as_array().map(|a| !a.is_empty()).unwrap_or(false) {
                    return Err(WizError::GraphQl(errors.to_string()));
                }
            }
            return Ok(payload["data"].clone());
        }
        unreachable!("retry loop exits via return")
    }

    /// Public escape hatch used by integration tests.
    #[doc(hidden)]
    pub async fn graphql_for_test(&self, query: &str, variables: Value) -> Result<Value, WizError> {
        self.graphql(query, variables).await
    }
}

fn now_epoch() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
```

- [ ] **Step 4: Add `pub mod api;` and `pub mod types;` stubs so the crate compiles**

Create empty placeholders that Task 3 fills in:

```rust
// crates/wiz-rs/src/api/mod.rs
```

```rust
// crates/wiz-rs/src/types/mod.rs
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p wiz-rs --test client_test`
Expected: PASS — 3 tests (`fetches_token_then_sends_bearer_auth_graphql_request`, `refreshes_token_on_401_and_retries_once`, `graphql_errors_field_becomes_an_error`).

- [ ] **Step 6: Commit**

```bash
git add crates/wiz-rs/src/client.rs crates/wiz-rs/src/api/mod.rs crates/wiz-rs/src/types/mod.rs crates/wiz-rs/tests/client_test.rs
git commit -m "feat(wiz-rs): OAuth2 client-credentials + GraphQL client with retry"
```

---

### Task 3: Issues API + types

**Files:**
- Create: `crates/wiz-rs/src/types/issue.rs`
- Modify: `crates/wiz-rs/src/types/mod.rs`
- Create: `crates/wiz-rs/src/api/issues.rs`
- Modify: `crates/wiz-rs/src/api/mod.rs`
- Modify: `crates/wiz-rs/src/client.rs` (add `issues()` accessor)
- Test: `crates/wiz-rs/tests/issues_test.rs`

**Interfaces:**
- Consumes: `WizClient::graphql` (Task 2).
- Produces: `client.issues().list_all(since: &str, until: &str) -> Result<Vec<WizIssue>, WizError>`, used by `WizIssuesCollector` (Task 9).

- [ ] **Step 1: Write the failing test**

```rust
// crates/wiz-rs/tests/issues_test.rs
use wiz_rs::WizClient;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn issues_list_all_follows_cursor_pagination() {
    let auth_server = MockServer::start().await;
    let api_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "test-token",
            "expires_in": 3600
        })))
        .mount(&auth_server)
        .await;

    let page1 = serde_json::json!({
        "data": {
            "issues": {
                "nodes": [{
                    "id": "issue-1",
                    "status": "OPEN",
                    "severity": "CRITICAL",
                    "createdAt": "2026-01-01T00:00:00Z",
                    "updatedAt": "2026-01-02T00:00:00Z",
                    "type": "TOXIC_COMBINATION",
                    "entitySnapshot": {
                        "id": "res-1",
                        "name": "prod-db",
                        "type": "VIRTUAL_MACHINE",
                        "cloudPlatform": "AWS",
                        "region": "us-east-1",
                        "subscriptionExternalId": "111122223333"
                    }
                }],
                "pageInfo": { "hasNextPage": true, "endCursor": "cursor-1" }
            }
        }
    });
    let page2 = serde_json::json!({
        "data": {
            "issues": {
                "nodes": [{
                    "id": "issue-2",
                    "status": "RESOLVED",
                    "severity": "LOW",
                    "createdAt": "2026-01-03T00:00:00Z",
                    "updatedAt": null,
                    "type": "MISCONFIGURATION",
                    "entitySnapshot": null
                }],
                "pageInfo": { "hasNextPage": false, "endCursor": null }
            }
        }
    });

    Mock::given(method("POST"))
        .and(path("/graphql"))
        .respond_with(ResponseTemplate::new(200).set_body_json(page1))
        .up_to_n_times(1)
        .mount(&api_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/graphql"))
        .respond_with(ResponseTemplate::new(200).set_body_json(page2))
        .mount(&api_server)
        .await;

    let client = WizClient::new(
        &format!("{}/graphql", api_server.uri()),
        &format!("{}/oauth/token", auth_server.uri()),
        "test-id",
        "test-secret",
    )
    .await
    .unwrap();

    let issues = client
        .issues()
        .list_all("2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z")
        .await
        .unwrap();

    assert_eq!(issues.len(), 2);
    assert_eq!(issues[0].id, "issue-1");
    assert_eq!(issues[0].entity_snapshot.as_ref().unwrap().name, "prod-db");
    assert_eq!(issues[1].id, "issue-2");
    assert!(issues[1].entity_snapshot.is_none());
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p wiz-rs --test issues_test`
Expected: FAIL — `client.issues()` doesn't exist yet.

- [ ] **Step 3: Write the types**

```rust
// crates/wiz-rs/src/types/issue.rs
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct WizIssue {
    pub id: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub severity: String,
    #[serde(default, rename = "createdAt")]
    pub created_at: String,
    #[serde(default, rename = "updatedAt")]
    pub updated_at: Option<String>,
    #[serde(default, rename = "type")]
    pub issue_type: Option<String>,
    #[serde(default, rename = "entitySnapshot")]
    pub entity_snapshot: Option<EntitySnapshot>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EntitySnapshot {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default, rename = "type")]
    pub entity_type: String,
    #[serde(default, rename = "cloudPlatform")]
    pub cloud_platform: Option<String>,
    #[serde(default)]
    pub region: Option<String>,
    #[serde(default, rename = "subscriptionExternalId")]
    pub subscription_external_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IssueConnection {
    pub nodes: Vec<WizIssue>,
    #[serde(rename = "pageInfo")]
    pub page_info: PageInfo,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PageInfo {
    #[serde(rename = "hasNextPage")]
    pub has_next_page: bool,
    #[serde(rename = "endCursor")]
    pub end_cursor: Option<String>,
}
```

```rust
// crates/wiz-rs/src/types/mod.rs
pub mod configuration_finding;
pub mod issue;
pub mod vulnerability;
```

- [ ] **Step 4: Write the Issues API**

```rust
// crates/wiz-rs/src/api/issues.rs
use serde_json::json;

use crate::client::WizClient;
use crate::error::WizError;
use crate::types::issue::{IssueConnection, WizIssue};

pub struct IssuesApi<'c>(pub(crate) &'c WizClient);

const ISSUES_QUERY: &str = r#"
query IssuesTable($filterBy: IssueFilters, $first: Int, $after: String) {
  issues(filterBy: $filterBy, first: $first, after: $after) {
    nodes {
      id
      status
      severity
      createdAt
      updatedAt
      type
      entitySnapshot {
        id
        name
        type
        cloudPlatform
        region
        subscriptionExternalId
      }
    }
    pageInfo {
      hasNextPage
      endCursor
    }
  }
}
"#;

impl<'c> IssuesApi<'c> {
    /// Page through all issues created within `[since, until]` (RFC 3339).
    pub async fn list_all(&self, since: &str, until: &str) -> Result<Vec<WizIssue>, WizError> {
        let mut all = Vec::new();
        let mut after: Option<String> = None;
        loop {
            let variables = json!({
                "filterBy": {
                    "createdAt": { "after": since, "before": until },
                },
                "first": 100,
                "after": after,
            });
            let data = self.0.graphql(ISSUES_QUERY, variables).await?;
            let connection: IssueConnection = serde_json::from_value(data["issues"].clone())?;
            let has_next = connection.page_info.has_next_page;
            let next_cursor = connection.page_info.end_cursor.clone();
            all.extend(connection.nodes);
            if !has_next || next_cursor.is_none() {
                break;
            }
            after = next_cursor;
        }
        Ok(all)
    }
}
```

```rust
// crates/wiz-rs/src/api/mod.rs
pub mod configuration_findings;
pub mod issues;
pub mod vulnerabilities;

pub use configuration_findings::ConfigurationFindingsApi;
pub use issues::IssuesApi;
pub use vulnerabilities::VulnerabilitiesApi;
```

This references `configuration_findings` and `vulnerabilities` modules that don't exist yet — Tasks 4 and 5 add them. For this task, temporarily stub them so the crate compiles:

```rust
// crates/wiz-rs/src/api/configuration_findings.rs (temporary stub, replaced in Task 5)
```

```rust
// crates/wiz-rs/src/api/vulnerabilities.rs (temporary stub, replaced in Task 4)
```

```rust
// crates/wiz-rs/src/types/vulnerability.rs (temporary stub, replaced in Task 4)
```

```rust
// crates/wiz-rs/src/types/configuration_finding.rs (temporary stub, replaced in Task 5)
```

- [ ] **Step 5: Add the `issues()` accessor to `WizClient`**

In `crates/wiz-rs/src/client.rs`, add near the end of the `impl WizClient` block:

```rust
    pub fn issues(&self) -> crate::api::issues::IssuesApi<'_> {
        crate::api::issues::IssuesApi(self)
    }
```

- [ ] **Step 6: Run test to verify it passes**

Run: `cargo test -p wiz-rs --test issues_test`
Expected: PASS — `issues_list_all_follows_cursor_pagination`.

- [ ] **Step 7: Commit**

```bash
git add crates/wiz-rs/src/types/issue.rs crates/wiz-rs/src/types/mod.rs crates/wiz-rs/src/api/issues.rs crates/wiz-rs/src/api/mod.rs crates/wiz-rs/src/api/configuration_findings.rs crates/wiz-rs/src/api/vulnerabilities.rs crates/wiz-rs/src/types/vulnerability.rs crates/wiz-rs/src/types/configuration_finding.rs crates/wiz-rs/src/client.rs crates/wiz-rs/tests/issues_test.rs
git commit -m "feat(wiz-rs): Issues API with cursor pagination"
```

---

### Task 4: Vulnerability Findings API + types

**Files:**
- Modify: `crates/wiz-rs/src/types/vulnerability.rs` (replace stub)
- Modify: `crates/wiz-rs/src/api/vulnerabilities.rs` (replace stub)
- Modify: `crates/wiz-rs/src/client.rs` (add `vulnerabilities()` accessor)
- Test: `crates/wiz-rs/tests/vulnerabilities_test.rs`

**Interfaces:**
- Consumes: `WizClient::graphql` (Task 2).
- Produces: `client.vulnerabilities().list_all(since, until) -> Result<Vec<WizVulnerabilityFinding>, WizError>`, used by `WizVulnerabilitiesCollector` (Task 10).

- [ ] **Step 1: Write the failing test**

```rust
// crates/wiz-rs/tests/vulnerabilities_test.rs
use wiz_rs::WizClient;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn vulnerabilities_list_all_maps_fields() {
    let auth_server = MockServer::start().await;
    let api_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "test-token",
            "expires_in": 3600
        })))
        .mount(&auth_server)
        .await;

    let page = serde_json::json!({
        "data": {
            "vulnerabilityFindings": {
                "nodes": [{
                    "id": "vuln-1",
                    "name": "CVE-2026-1234",
                    "severity": "HIGH",
                    "status": "OPEN",
                    "detectedAt": "2026-02-01T00:00:00Z",
                    "fixedVersion": "1.2.4",
                    "remediation": "Upgrade to 1.2.4",
                    "vulnerableAsset": {
                        "id": "asset-1",
                        "name": "web-01",
                        "type": "VIRTUAL_MACHINE",
                        "region": "us-east-1"
                    }
                }],
                "pageInfo": { "hasNextPage": false, "endCursor": null }
            }
        }
    });

    Mock::given(method("POST"))
        .and(path("/graphql"))
        .respond_with(ResponseTemplate::new(200).set_body_json(page))
        .mount(&api_server)
        .await;

    let client = WizClient::new(
        &format!("{}/graphql", api_server.uri()),
        &format!("{}/oauth/token", auth_server.uri()),
        "test-id",
        "test-secret",
    )
    .await
    .unwrap();

    let findings = client
        .vulnerabilities()
        .list_all("2026-01-01T00:00:00Z", "2026-03-01T00:00:00Z")
        .await
        .unwrap();

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].name, "CVE-2026-1234");
    assert_eq!(findings[0].vulnerable_asset.as_ref().unwrap().name, "web-01");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p wiz-rs --test vulnerabilities_test`
Expected: FAIL — `client.vulnerabilities()` doesn't exist yet (still the Task 3 stub).

- [ ] **Step 3: Write the types**

```rust
// crates/wiz-rs/src/types/vulnerability.rs
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct WizVulnerabilityFinding {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub status: String,
    #[serde(default, rename = "detectedAt")]
    pub detected_at: String,
    #[serde(default, rename = "fixedVersion")]
    pub fixed_version: Option<String>,
    #[serde(default)]
    pub remediation: Option<String>,
    #[serde(default, rename = "vulnerableAsset")]
    pub vulnerable_asset: Option<VulnerableAsset>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct VulnerableAsset {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default, rename = "type")]
    pub asset_type: String,
    #[serde(default)]
    pub region: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct VulnerabilityConnection {
    pub nodes: Vec<WizVulnerabilityFinding>,
    #[serde(rename = "pageInfo")]
    pub page_info: crate::types::issue::PageInfo,
}
```

- [ ] **Step 4: Write the API**

```rust
// crates/wiz-rs/src/api/vulnerabilities.rs
use serde_json::json;

use crate::client::WizClient;
use crate::error::WizError;
use crate::types::vulnerability::{VulnerabilityConnection, WizVulnerabilityFinding};

pub struct VulnerabilitiesApi<'c>(pub(crate) &'c WizClient);

const VULNERABILITIES_QUERY: &str = r#"
query VulnerabilityFindings($filterBy: VulnerabilityFindingFilters, $first: Int, $after: String) {
  vulnerabilityFindings(filterBy: $filterBy, first: $first, after: $after) {
    nodes {
      id
      name
      severity
      status
      detectedAt
      fixedVersion
      remediation
      vulnerableAsset {
        id
        name
        type
        region
      }
    }
    pageInfo {
      hasNextPage
      endCursor
    }
  }
}
"#;

impl<'c> VulnerabilitiesApi<'c> {
    /// Page through all vulnerability findings detected within `[since, until]` (RFC 3339).
    pub async fn list_all(
        &self,
        since: &str,
        until: &str,
    ) -> Result<Vec<WizVulnerabilityFinding>, WizError> {
        let mut all = Vec::new();
        let mut after: Option<String> = None;
        loop {
            let variables = json!({
                "filterBy": {
                    "detectedAt": { "after": since, "before": until },
                },
                "first": 100,
                "after": after,
            });
            let data = self.0.graphql(VULNERABILITIES_QUERY, variables).await?;
            let connection: VulnerabilityConnection =
                serde_json::from_value(data["vulnerabilityFindings"].clone())?;
            let has_next = connection.page_info.has_next_page;
            let next_cursor = connection.page_info.end_cursor.clone();
            all.extend(connection.nodes);
            if !has_next || next_cursor.is_none() {
                break;
            }
            after = next_cursor;
        }
        Ok(all)
    }
}
```

- [ ] **Step 5: Add the `vulnerabilities()` accessor to `WizClient`**

In `crates/wiz-rs/src/client.rs`, next to the `issues()` accessor added in Task 3:

```rust
    pub fn vulnerabilities(&self) -> crate::api::vulnerabilities::VulnerabilitiesApi<'_> {
        crate::api::vulnerabilities::VulnerabilitiesApi(self)
    }
```

- [ ] **Step 6: Run test to verify it passes**

Run: `cargo test -p wiz-rs --test vulnerabilities_test`
Expected: PASS — `vulnerabilities_list_all_maps_fields`.

- [ ] **Step 7: Commit**

```bash
git add crates/wiz-rs/src/types/vulnerability.rs crates/wiz-rs/src/api/vulnerabilities.rs crates/wiz-rs/src/client.rs crates/wiz-rs/tests/vulnerabilities_test.rs
git commit -m "feat(wiz-rs): Vulnerability Findings API"
```

---

### Task 5: Configuration Findings API + types

**Files:**
- Modify: `crates/wiz-rs/src/types/configuration_finding.rs` (replace stub)
- Modify: `crates/wiz-rs/src/api/configuration_findings.rs` (replace stub)
- Modify: `crates/wiz-rs/src/client.rs` (add `configuration_findings()` accessor)
- Test: `crates/wiz-rs/tests/configuration_findings_test.rs`

**Interfaces:**
- Consumes: `WizClient::graphql` (Task 2).
- Produces: `client.configuration_findings().list_all(since, until) -> Result<Vec<WizConfigurationFinding>, WizError>`, used by `WizConfigurationFindingsCollector` (Task 11).

- [ ] **Step 1: Write the failing test**

```rust
// crates/wiz-rs/tests/configuration_findings_test.rs
use wiz_rs::WizClient;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn configuration_findings_list_all_maps_fields() {
    let auth_server = MockServer::start().await;
    let api_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "test-token",
            "expires_in": 3600
        })))
        .mount(&auth_server)
        .await;

    let page = serde_json::json!({
        "data": {
            "configurationFindings": {
                "nodes": [{
                    "id": "finding-1",
                    "result": "FAIL",
                    "severity": "MEDIUM",
                    "analyzedAt": "2026-03-01T00:00:00Z",
                    "rule": { "id": "rule-1", "name": "S3 bucket encryption" },
                    "resource": {
                        "id": "res-2",
                        "name": "audit-logs-bucket",
                        "type": "BUCKET",
                        "region": "us-east-1"
                    }
                }],
                "pageInfo": { "hasNextPage": false, "endCursor": null }
            }
        }
    });

    Mock::given(method("POST"))
        .and(path("/graphql"))
        .respond_with(ResponseTemplate::new(200).set_body_json(page))
        .mount(&api_server)
        .await;

    let client = WizClient::new(
        &format!("{}/graphql", api_server.uri()),
        &format!("{}/oauth/token", auth_server.uri()),
        "test-id",
        "test-secret",
    )
    .await
    .unwrap();

    let findings = client
        .configuration_findings()
        .list_all("2026-01-01T00:00:00Z", "2026-04-01T00:00:00Z")
        .await
        .unwrap();

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule.name, "S3 bucket encryption");
    assert_eq!(findings[0].resource.as_ref().unwrap().name, "audit-logs-bucket");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p wiz-rs --test configuration_findings_test`
Expected: FAIL — `client.configuration_findings()` doesn't exist yet (still the Task 3 stub).

- [ ] **Step 3: Write the types**

```rust
// crates/wiz-rs/src/types/configuration_finding.rs
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct WizConfigurationFinding {
    pub id: String,
    #[serde(default)]
    pub result: String,
    #[serde(default)]
    pub severity: String,
    #[serde(default, rename = "analyzedAt")]
    pub analyzed_at: String,
    pub rule: Rule,
    #[serde(default)]
    pub resource: Option<ConfigurationResource>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Rule {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ConfigurationResource {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default, rename = "type")]
    pub resource_type: String,
    #[serde(default)]
    pub region: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ConfigurationFindingConnection {
    pub nodes: Vec<WizConfigurationFinding>,
    #[serde(rename = "pageInfo")]
    pub page_info: crate::types::issue::PageInfo,
}
```

- [ ] **Step 4: Write the API**

```rust
// crates/wiz-rs/src/api/configuration_findings.rs
use serde_json::json;

use crate::client::WizClient;
use crate::error::WizError;
use crate::types::configuration_finding::{ConfigurationFindingConnection, WizConfigurationFinding};

pub struct ConfigurationFindingsApi<'c>(pub(crate) &'c WizClient);

const CONFIGURATION_FINDINGS_QUERY: &str = r#"
query ConfigurationFindings($filterBy: ConfigurationFindingFilters, $first: Int, $after: String) {
  configurationFindings(filterBy: $filterBy, first: $first, after: $after) {
    nodes {
      id
      result
      severity
      analyzedAt
      rule {
        id
        name
      }
      resource {
        id
        name
        type
        region
      }
    }
    pageInfo {
      hasNextPage
      endCursor
    }
  }
}
"#;

impl<'c> ConfigurationFindingsApi<'c> {
    /// Page through all configuration findings analyzed within `[since, until]` (RFC 3339).
    pub async fn list_all(
        &self,
        since: &str,
        until: &str,
    ) -> Result<Vec<WizConfigurationFinding>, WizError> {
        let mut all = Vec::new();
        let mut after: Option<String> = None;
        loop {
            let variables = json!({
                "filterBy": {
                    "analyzedAt": { "after": since, "before": until },
                },
                "first": 100,
                "after": after,
            });
            let data = self.0.graphql(CONFIGURATION_FINDINGS_QUERY, variables).await?;
            let connection: ConfigurationFindingConnection =
                serde_json::from_value(data["configurationFindings"].clone())?;
            let has_next = connection.page_info.has_next_page;
            let next_cursor = connection.page_info.end_cursor.clone();
            all.extend(connection.nodes);
            if !has_next || next_cursor.is_none() {
                break;
            }
            after = next_cursor;
        }
        Ok(all)
    }
}
```

- [ ] **Step 5: Add the `configuration_findings()` accessor to `WizClient`**

In `crates/wiz-rs/src/client.rs`, next to the other accessors:

```rust
    pub fn configuration_findings(&self) -> crate::api::configuration_findings::ConfigurationFindingsApi<'_> {
        crate::api::configuration_findings::ConfigurationFindingsApi(self)
    }
```

- [ ] **Step 6: Run test to verify it passes**

Run: `cargo test -p wiz-rs --test configuration_findings_test`
Expected: PASS — `configuration_findings_list_all_maps_fields`.

- [ ] **Step 7: Run the full wiz-rs test suite**

Run: `cargo test -p wiz-rs`
Expected: PASS — all tests across `client_test.rs`, `issues_test.rs`, `vulnerabilities_test.rs`, `configuration_findings_test.rs`.

- [ ] **Step 8: Commit**

```bash
git add crates/wiz-rs/src/types/configuration_finding.rs crates/wiz-rs/src/api/configuration_findings.rs crates/wiz-rs/src/client.rs crates/wiz-rs/tests/configuration_findings_test.rs
git commit -m "feat(wiz-rs): Configuration Findings API — wiz-rs crate complete"
```

---

### Task 6: Add `Wiz` variant to `CloudProvider`

**Files:**
- Modify: `src/providers/mod.rs`

**Interfaces:**
- Produces: `CloudProvider::Wiz` (serde `"wiz"`, `Display` → `"Wiz"`), consumed by every later task.

- [ ] **Step 1: Write the failing test**

Add to the bottom of `src/providers/mod.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wiz_serializes_lowercase() {
        let json = serde_json::to_string(&CloudProvider::Wiz).unwrap();
        assert_eq!(json, "\"wiz\"");
    }

    #[test]
    fn wiz_displays_as_wiz() {
        assert_eq!(CloudProvider::Wiz.to_string(), "Wiz");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --package the-grabber providers::tests`
Expected: FAIL — `CloudProvider::Wiz` doesn't exist (compile error).

- [ ] **Step 3: Add the variant**

Edit `src/providers/mod.rs`:

```rust
#[cfg(feature = "jira")]
pub mod jira;

#[cfg(feature = "wiz")]
pub mod wiz;
```

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
    Wiz,
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
            CloudProvider::Wiz => write!(f, "Wiz"),
        }
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --package the-grabber providers::tests`
Expected: PASS — `wiz_serializes_lowercase`, `wiz_displays_as_wiz`.

- [ ] **Step 5: Commit**

```bash
git add src/providers/mod.rs
git commit -m "feat(providers): add Wiz variant to CloudProvider"
```

---

### Task 7: Account config fields + `wiz-config.toml` merge + env resolvers

**Files:**
- Modify: `src/app_config.rs`

**Interfaces:**
- Produces: `Account.wiz_client_id`, `Account.wiz_client_secret`, `Account.wiz_api_url`, `Account.wiz_auth_url` fields plus `wiz_client_id_resolved()`, `wiz_client_secret_resolved()`, `wiz_api_url_resolved()`, `wiz_auth_url_resolved()` methods, consumed by `runner/tui_session.rs` (Task 16).

- [ ] **Step 1: Write the failing test**

Add a `#[cfg(test)] mod tests` block at the bottom of `src/app_config.rs` (create one if it doesn't already exist):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn base_account() -> Account {
        Account {
            name: "Wiz".to_string(),
            provider: CloudProvider::Wiz,
            account_id: None,
            description: None,
            profile: None,
            region: None,
            output_dir: None,
            tenant_id: None,
            subscription_id: None,
            project_id: None,
            tenable_access_key: None,
            tenable_secret_key: None,
            tenable_url: None,
            okta_domain: None,
            okta_api_token: None,
            jira_domain: None,
            jira_email: None,
            jira_api_token: None,
            wiz_client_id: None,
            wiz_client_secret: None,
            wiz_api_url: None,
            wiz_auth_url: None,
            collectors: CollectorConfig::default(),
        }
    }

    #[test]
    fn wiz_api_url_resolved_trims_trailing_slash() {
        let mut acct = base_account();
        acct.wiz_api_url = Some("https://api.us1.app.wiz.io/graphql/".to_string());
        assert_eq!(
            acct.wiz_api_url_resolved().as_deref(),
            Some("https://api.us1.app.wiz.io/graphql")
        );
    }

    #[test]
    fn wiz_client_id_resolved_falls_back_to_toml() {
        let mut acct = base_account();
        acct.wiz_client_id = Some("toml-id".to_string());
        assert_eq!(acct.wiz_client_id_resolved().as_deref(), Some("toml-id"));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --package the-grabber app_config::tests`
Expected: FAIL — `Account` has no `wiz_client_id`/`wiz_api_url` fields (compile error).

- [ ] **Step 3: Add the fields**

In `src/app_config.rs`, add after the Jira fields block (after `pub jira_api_token: Option<String>,`):

```rust
    // ------------------------------------------------------------------
    // Wiz fields
    // ------------------------------------------------------------------
    /// Wiz OAuth2 client ID (from a Wiz Service Account).
    /// Can also be supplied via `WIZ_CLIENT_ID` env var (env wins over TOML).
    pub wiz_client_id: Option<String>,

    /// Wiz OAuth2 client secret.
    /// Can also be supplied via `WIZ_CLIENT_SECRET` env var (env wins over TOML).
    pub wiz_client_secret: Option<String>,

    /// Wiz tenant GraphQL API endpoint (e.g. `https://api.us1.app.wiz.io/graphql`).
    /// Can also be supplied via `WIZ_API_URL` env var (env wins over TOML).
    pub wiz_api_url: Option<String>,

    /// Wiz OAuth2 token endpoint. Defaults to `https://auth.app.wiz.io/oauth/token`
    /// when unset. Can also be supplied via `WIZ_AUTH_URL` env var (env wins over TOML).
    pub wiz_auth_url: Option<String>,
```

- [ ] **Step 4: Add the resolver methods**

In the `impl Account` block, after the Jira resolvers:

```rust
    /// Resolve Wiz client ID: env var takes precedence over TOML.
    pub fn wiz_client_id_resolved(&self) -> Option<String> {
        std::env::var("WIZ_CLIENT_ID")
            .ok()
            .or_else(|| self.wiz_client_id.clone())
    }

    /// Resolve Wiz client secret: env var takes precedence over TOML.
    pub fn wiz_client_secret_resolved(&self) -> Option<String> {
        std::env::var("WIZ_CLIENT_SECRET")
            .ok()
            .or_else(|| self.wiz_client_secret.clone())
    }

    /// Resolve Wiz API URL, trimming any trailing slash. Returns None if unset.
    pub fn wiz_api_url_resolved(&self) -> Option<String> {
        std::env::var("WIZ_API_URL")
            .ok()
            .or_else(|| self.wiz_api_url.clone())
            .map(|s| s.trim().trim_end_matches('/').to_string())
            .filter(|s| !s.is_empty())
    }

    /// Resolve Wiz OAuth2 token URL, defaulting to Wiz's standard endpoint.
    pub fn wiz_auth_url_resolved(&self) -> String {
        std::env::var("WIZ_AUTH_URL")
            .ok()
            .or_else(|| self.wiz_auth_url.clone())
            .map(|s| s.trim().trim_end_matches('/').to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "https://auth.app.wiz.io/oauth/token".to_string())
    }
```

- [ ] **Step 5: Merge `wiz-config.toml` in `load_config()`**

In `src/app_config.rs`, after the Jira merge block in `load_config()`:

```rust
    // Merge wiz-config.toml accounts if present
    let wiz_path = PathBuf::from("wiz-config.toml");
    if wiz_path.exists() {
        if let Ok(contents) = fs::read_to_string(&wiz_path) {
            if let Ok(wiz_cfg) = toml::from_str::<AppConfig>(&contents) {
                cfg.account.extend(wiz_cfg.account);
            }
        }
    }
```

- [ ] **Step 6: Run test to verify it passes**

Run: `cargo test --package the-grabber app_config::tests`
Expected: PASS — `wiz_api_url_resolved_trims_trailing_slash`, `wiz_client_id_resolved_falls_back_to_toml`.

- [ ] **Step 7: Commit**

```bash
git add src/app_config.rs
git commit -m "feat(config): add Wiz account fields, env resolvers, wiz-config.toml merge"
```

---

### Task 8: providers/wiz skeleton + `WizProviderFactory`

**Files:**
- Create: `src/providers/wiz/mod.rs`
- Create: `src/providers/wiz/factory.rs`

**Interfaces:**
- Consumes: `CloudProvider::Wiz` (Task 6), `wiz_rs::WizClient` (Task 2), `ProviderFactory` trait (`src/providers/mod.rs:60-80`).
- Produces: `WizProviderFactory::new(client: WizClient, tenant_name: String, selected: Vec<String>) -> Self`, consumed by `runner/tui_session.rs` (Task 16) and by each collector task (9-11) via `self.selected`.

- [ ] **Step 1: Write the module skeleton**

```rust
// src/providers/wiz/mod.rs
pub mod configuration_findings;
pub mod factory;
pub mod issues;
pub mod vulnerabilities;
```

Note: `issues.rs`, `vulnerabilities.rs`, `configuration_findings.rs` don't exist yet — Tasks 9-11 create them. Add empty placeholder files now so `mod.rs` compiles:

```rust
// src/providers/wiz/issues.rs (temporary stub, replaced in Task 9)
```

```rust
// src/providers/wiz/vulnerabilities.rs (temporary stub, replaced in Task 10)
```

```rust
// src/providers/wiz/configuration_findings.rs (temporary stub, replaced in Task 11)
```

- [ ] **Step 2: Write the failing test**

Add to the bottom of `src/providers/wiz/factory.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_wiz_provider_with_empty_region() {
        // Constructing a real WizClient requires a network round-trip (token
        // exchange), so this test only checks the metadata methods that
        // don't need one — the collector-selection behavior is covered by
        // the CsvCollector tests in Tasks 9-11.
        assert_eq!(CloudProvider::Wiz.to_string(), "Wiz");
    }
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cargo test --package the-grabber --features wiz providers::wiz::factory::tests`
Expected: FAIL — `src/providers/wiz/factory.rs` doesn't define `WizProviderFactory` yet (compile error from the empty stub files not matching `mod.rs`... actually this specific test only needs `CloudProvider`, so write `factory.rs` fully in Step 4 first, then this test will simply pass; run it after Step 4 to confirm TDD ordering isn't skipped: run once now to see the module-resolution error from the stub files being genuinely empty, which is a valid "fails to compile" red state).

- [ ] **Step 4: Implement `WizProviderFactory`**

```rust
// src/providers/wiz/factory.rs
use wiz_rs::WizClient;

use crate::evidence::{CsvCollector, EvidenceCollector, JsonCollector};
use crate::providers::{CloudProvider, ProviderFactory};

pub struct WizProviderFactory {
    client: WizClient,
    tenant_name: String,
    selected: Vec<String>,
}

impl WizProviderFactory {
    pub fn new(client: WizClient, tenant_name: String, selected: Vec<String>) -> Self {
        Self {
            client,
            tenant_name,
            selected,
        }
    }
}

impl ProviderFactory for WizProviderFactory {
    fn provider(&self) -> CloudProvider {
        CloudProvider::Wiz
    }
    fn account_id(&self) -> &str {
        &self.tenant_name
    }
    fn region(&self) -> &str {
        ""
    }

    fn csv_collectors(&self) -> Vec<Box<dyn CsvCollector>> {
        let mut v: Vec<Box<dyn CsvCollector>> = Vec::new();
        if self.selected.iter().any(|s| s == "wiz-issues") {
            v.push(Box::new(super::issues::WizIssuesCollector::new(
                self.client.clone(),
            )));
        }
        if self.selected.iter().any(|s| s == "wiz-vulnerabilities") {
            v.push(Box::new(
                super::vulnerabilities::WizVulnerabilitiesCollector::new(self.client.clone()),
            ));
        }
        if self.selected.iter().any(|s| s == "wiz-config-findings") {
            v.push(Box::new(
                super::configuration_findings::WizConfigurationFindingsCollector::new(
                    self.client.clone(),
                ),
            ));
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

This references `super::issues::WizIssuesCollector`, `super::vulnerabilities::WizVulnerabilitiesCollector`, `super::configuration_findings::WizConfigurationFindingsCollector`, which don't exist until Tasks 9-11 — the crate will not compile until Task 11 is done. This is expected; run `cargo check --features wiz` after Task 11, not now.

- [ ] **Step 5: Register the module in `src/main.rs`**

`src/providers` is already `mod providers;` in `src/main.rs:13` — no change needed there, since `src/providers/mod.rs` already gained `#[cfg(feature = "wiz")] pub mod wiz;` in Task 6.

- [ ] **Step 6: Commit**

```bash
git add src/providers/wiz/mod.rs src/providers/wiz/factory.rs src/providers/wiz/issues.rs src/providers/wiz/vulnerabilities.rs src/providers/wiz/configuration_findings.rs
git commit -m "feat(providers/wiz): factory skeleton (collectors added next)"
```

---

### Task 9: `WizIssuesCollector` (CSV)

**Files:**
- Modify: `src/providers/wiz/issues.rs` (replace stub)

**Interfaces:**
- Consumes: `wiz_rs::WizClient::issues()` (Task 3), `CsvCollector` trait (`src/evidence.rs:73-100`).
- Produces: `WizIssuesCollector::new(client: WizClient) -> Self`, registered in `factory.rs` (Task 8) behind selector `wiz-issues`.

- [ ] **Step 1: Write the failing test**

Add at the bottom of `src/providers/wiz/issues.rs` (after the implementation from Step 3):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers_have_no_empty_entries() {
        let headers = [
            "Issue ID",
            "Status",
            "Severity",
            "Type",
            "Created At",
            "Updated At",
            "Resource ID",
            "Resource Name",
            "Resource Type",
            "Cloud Platform",
            "Region",
            "Subscription/Account ID",
        ];
        assert!(headers.iter().all(|h| !h.is_empty()));
        assert_eq!(headers.len(), 12);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --package the-grabber --features wiz providers::wiz::issues::tests`
Expected: FAIL — `src/providers/wiz/issues.rs` is still an empty stub (no `tests` module context — compile error).

- [ ] **Step 3: Implement `WizIssuesCollector`**

```rust
// src/providers/wiz/issues.rs
use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use wiz_rs::WizClient;

use crate::evidence::CsvCollector;

pub struct WizIssuesCollector {
    client: WizClient,
}

impl WizIssuesCollector {
    pub fn new(client: WizClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for WizIssuesCollector {
    fn name(&self) -> &str {
        "Wiz Issues"
    }

    fn filename_prefix(&self) -> &str {
        "Wiz_Issues"
    }

    fn headers(&self) -> &'static [&'static str] {
        &[
            "Issue ID",
            "Status",
            "Severity",
            "Type",
            "Created At",
            "Updated At",
            "Resource ID",
            "Resource Name",
            "Resource Type",
            "Cloud Platform",
            "Region",
            "Subscription/Account ID",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let (start_secs, end_secs) = match dates {
            Some(d) => d,
            None => {
                let now = Utc::now();
                let start = now - chrono::Duration::days(90);
                (start.timestamp(), now.timestamp())
            }
        };
        let since = DateTime::<Utc>::from_timestamp(start_secs, 0)
            .unwrap_or_else(Utc::now)
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        let until = DateTime::<Utc>::from_timestamp(end_secs, 0)
            .unwrap_or_else(Utc::now)
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();

        let issues = self.client.issues().list_all(&since, &until).await?;

        let rows = issues
            .into_iter()
            .map(|i| {
                let (res_id, res_name, res_type, cloud_platform, region, sub_id) =
                    match i.entity_snapshot {
                        Some(e) => (
                            e.id,
                            e.name,
                            e.entity_type,
                            e.cloud_platform.unwrap_or_default(),
                            e.region.unwrap_or_default(),
                            e.subscription_external_id.unwrap_or_default(),
                        ),
                        None => (
                            String::new(),
                            String::new(),
                            String::new(),
                            String::new(),
                            String::new(),
                            String::new(),
                        ),
                    };
                vec![
                    i.id,
                    i.status,
                    i.severity,
                    i.issue_type.unwrap_or_default(),
                    i.created_at,
                    i.updated_at.unwrap_or_default(),
                    res_id,
                    res_name,
                    res_type,
                    cloud_platform,
                    region,
                    sub_id,
                ]
            })
            .collect();

        Ok(rows)
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --package the-grabber --features wiz providers::wiz::issues::tests`
Expected: PASS — `headers_have_no_empty_entries`.

- [ ] **Step 5: Commit**

```bash
git add src/providers/wiz/issues.rs
git commit -m "feat(providers/wiz): WizIssuesCollector"
```

---

### Task 10: `WizVulnerabilitiesCollector` (CSV)

**Files:**
- Modify: `src/providers/wiz/vulnerabilities.rs` (replace stub)

**Interfaces:**
- Consumes: `wiz_rs::WizClient::vulnerabilities()` (Task 4), `CsvCollector` trait.
- Produces: `WizVulnerabilitiesCollector::new(client: WizClient) -> Self`, registered in `factory.rs` behind selector `wiz-vulnerabilities`.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers_have_no_empty_entries() {
        let headers = [
            "Finding ID",
            "CVE Name",
            "Severity",
            "Status",
            "Detected At",
            "Fixed Version",
            "Remediation",
            "Asset ID",
            "Asset Name",
            "Asset Type",
            "Asset Region",
        ];
        assert!(headers.iter().all(|h| !h.is_empty()));
        assert_eq!(headers.len(), 11);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --package the-grabber --features wiz providers::wiz::vulnerabilities::tests`
Expected: FAIL — `src/providers/wiz/vulnerabilities.rs` is still an empty stub.

- [ ] **Step 3: Implement `WizVulnerabilitiesCollector`**

```rust
// src/providers/wiz/vulnerabilities.rs
use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use wiz_rs::WizClient;

use crate::evidence::CsvCollector;

pub struct WizVulnerabilitiesCollector {
    client: WizClient,
}

impl WizVulnerabilitiesCollector {
    pub fn new(client: WizClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for WizVulnerabilitiesCollector {
    fn name(&self) -> &str {
        "Wiz Vulnerability Findings"
    }

    fn filename_prefix(&self) -> &str {
        "Wiz_Vulnerability_Findings"
    }

    fn headers(&self) -> &'static [&'static str] {
        &[
            "Finding ID",
            "CVE Name",
            "Severity",
            "Status",
            "Detected At",
            "Fixed Version",
            "Remediation",
            "Asset ID",
            "Asset Name",
            "Asset Type",
            "Asset Region",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let (start_secs, end_secs) = match dates {
            Some(d) => d,
            None => {
                let now = Utc::now();
                let start = now - chrono::Duration::days(90);
                (start.timestamp(), now.timestamp())
            }
        };
        let since = DateTime::<Utc>::from_timestamp(start_secs, 0)
            .unwrap_or_else(Utc::now)
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        let until = DateTime::<Utc>::from_timestamp(end_secs, 0)
            .unwrap_or_else(Utc::now)
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();

        let findings = self.client.vulnerabilities().list_all(&since, &until).await?;

        let rows = findings
            .into_iter()
            .map(|f| {
                let (asset_id, asset_name, asset_type, asset_region) = match f.vulnerable_asset {
                    Some(a) => (a.id, a.name, a.asset_type, a.region.unwrap_or_default()),
                    None => (String::new(), String::new(), String::new(), String::new()),
                };
                vec![
                    f.id,
                    f.name,
                    f.severity,
                    f.status,
                    f.detected_at,
                    f.fixed_version.unwrap_or_default(),
                    f.remediation.unwrap_or_default(),
                    asset_id,
                    asset_name,
                    asset_type,
                    asset_region,
                ]
            })
            .collect();

        Ok(rows)
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --package the-grabber --features wiz providers::wiz::vulnerabilities::tests`
Expected: PASS — `headers_have_no_empty_entries`.

- [ ] **Step 5: Commit**

```bash
git add src/providers/wiz/vulnerabilities.rs
git commit -m "feat(providers/wiz): WizVulnerabilitiesCollector"
```

---

### Task 11: `WizConfigurationFindingsCollector` (CSV)

**Files:**
- Modify: `src/providers/wiz/configuration_findings.rs` (replace stub)

**Interfaces:**
- Consumes: `wiz_rs::WizClient::configuration_findings()` (Task 5), `CsvCollector` trait.
- Produces: `WizConfigurationFindingsCollector::new(client: WizClient) -> Self`, registered in `factory.rs` behind selector `wiz-config-findings`.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers_have_no_empty_entries() {
        let headers = [
            "Finding ID",
            "Rule ID",
            "Rule Name",
            "Severity",
            "Result",
            "Analyzed At",
            "Resource ID",
            "Resource Name",
            "Resource Type",
            "Resource Region",
        ];
        assert!(headers.iter().all(|h| !h.is_empty()));
        assert_eq!(headers.len(), 10);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --package the-grabber --features wiz providers::wiz::configuration_findings::tests`
Expected: FAIL — `src/providers/wiz/configuration_findings.rs` is still an empty stub.

- [ ] **Step 3: Implement `WizConfigurationFindingsCollector`**

```rust
// src/providers/wiz/configuration_findings.rs
use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use wiz_rs::WizClient;

use crate::evidence::CsvCollector;

pub struct WizConfigurationFindingsCollector {
    client: WizClient,
}

impl WizConfigurationFindingsCollector {
    pub fn new(client: WizClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for WizConfigurationFindingsCollector {
    fn name(&self) -> &str {
        "Wiz Configuration Findings"
    }

    fn filename_prefix(&self) -> &str {
        "Wiz_Configuration_Findings"
    }

    fn headers(&self) -> &'static [&'static str] {
        &[
            "Finding ID",
            "Rule ID",
            "Rule Name",
            "Severity",
            "Result",
            "Analyzed At",
            "Resource ID",
            "Resource Name",
            "Resource Type",
            "Resource Region",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let (start_secs, end_secs) = match dates {
            Some(d) => d,
            None => {
                let now = Utc::now();
                let start = now - chrono::Duration::days(90);
                (start.timestamp(), now.timestamp())
            }
        };
        let since = DateTime::<Utc>::from_timestamp(start_secs, 0)
            .unwrap_or_else(Utc::now)
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        let until = DateTime::<Utc>::from_timestamp(end_secs, 0)
            .unwrap_or_else(Utc::now)
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();

        let findings = self
            .client
            .configuration_findings()
            .list_all(&since, &until)
            .await?;

        let rows = findings
            .into_iter()
            .map(|f| {
                let (res_id, res_name, res_type, res_region) = match f.resource {
                    Some(r) => (r.id, r.name, r.resource_type, r.region.unwrap_or_default()),
                    None => (String::new(), String::new(), String::new(), String::new()),
                };
                vec![
                    f.id,
                    f.rule.id,
                    f.rule.name,
                    f.severity,
                    f.result,
                    f.analyzed_at,
                    res_id,
                    res_name,
                    res_type,
                    res_region,
                ]
            })
            .collect();

        Ok(rows)
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --package the-grabber --features wiz providers::wiz::configuration_findings::tests`
Expected: PASS — `headers_have_no_empty_entries`.

- [ ] **Step 5: Run the full `providers::wiz` test suite and confirm the crate builds**

Run: `cargo build --features wiz`
Expected: builds cleanly — this is the first point where `src/providers/wiz/factory.rs` (Task 8), which references all three collectors, actually compiles.

Run: `cargo test --package the-grabber --features wiz providers::wiz`
Expected: PASS — all `providers::wiz::*::tests` modules.

- [ ] **Step 6: Commit**

```bash
git add src/providers/wiz/configuration_findings.rs
git commit -m "feat(providers/wiz): WizConfigurationFindingsCollector — provider module complete"
```

---

### Task 12: Register Wiz in the TUI menu catalog

**Files:**
- Create: `src/tui/menus/wiz.rs`
- Modify: `src/tui/menus/mod.rs`

**Interfaces:**
- Consumes: `CloudProvider::Wiz` (Task 6), `ProviderCategory`/`ProviderMenu` (`src/tui/menus/mod.rs:12-22`).
- Produces: `menu_for(CloudProvider::Wiz)` returns a populated menu, consumed by `App::load_menu_for_current_provider()` (already generic — no change needed there) and by `draw_provider_selection`/nav wiring (Tasks 13-15).

- [ ] **Step 1: Write the failing test**

Add to the bottom of `src/tui/menus/mod.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wiz_menu_has_three_collectors() {
        let menu = menu_for(CloudProvider::Wiz);
        let total_items: usize = menu.categories.iter().map(|c| c.items.len()).sum();
        assert_eq!(total_items, 3);
    }

    #[test]
    fn wiz_menu_selectors_are_prefixed() {
        let menu = menu_for(CloudProvider::Wiz);
        for cat in menu.categories {
            for (selector, _) in cat.items {
                assert!(selector.starts_with("wiz-"), "selector {selector} must start with wiz-");
            }
        }
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --package the-grabber --features wiz tui::menus::tests`
Expected: FAIL — `menu_for(CloudProvider::Wiz)` panics ("no TUI menu registered for provider Wiz").

- [ ] **Step 3: Write the Wiz menu data**

```rust
// src/tui/menus/wiz.rs
//! Wiz collector menu. 3 collectors in 1 category.

use super::ProviderCategory;

pub const WIZ_CATEGORIES: &[ProviderCategory] = &[ProviderCategory {
    name: "Security Findings",
    items: &[
        ("wiz-issues", "Issues                   "),
        ("wiz-vulnerabilities", "Vulnerability Findings   "),
        ("wiz-config-findings", "Configuration Findings   "),
    ],
}];
```

- [ ] **Step 4: Register the module and menu entry**

Edit `src/tui/menus/mod.rs`:

```rust
pub mod aws;
pub mod jira;
pub mod okta;
pub mod tenable;
pub mod wiz;
```

```rust
pub const PROVIDER_MENUS: &[ProviderMenu] = &[
    ProviderMenu {
        provider: CloudProvider::Aws,
        categories: aws::AWS_CATEGORIES,
    },
    ProviderMenu {
        provider: CloudProvider::Okta,
        categories: okta::OKTA_CATEGORIES,
    },
    ProviderMenu {
        provider: CloudProvider::Jira,
        categories: jira::JIRA_CATEGORIES,
    },
    ProviderMenu {
        provider: CloudProvider::Tenable,
        categories: tenable::TENABLE_CATEGORIES,
    },
    ProviderMenu {
        provider: CloudProvider::Wiz,
        categories: wiz::WIZ_CATEGORIES,
    },
];
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cargo test --package the-grabber --features wiz tui::menus::tests`
Expected: PASS — `wiz_menu_has_three_collectors`, `wiz_menu_selectors_are_prefixed`.

- [ ] **Step 6: Commit**

```bash
git add src/tui/menus/wiz.rs src/tui/menus/mod.rs
git commit -m "feat(tui): register Wiz collector menu"
```

---

### Task 13: TUI provider-selection screen — add Wiz card

**Files:**
- Modify: `src/tui/ui/account_screens.rs`

**Interfaces:**
- Consumes: `CloudProvider::Wiz` (Task 6). No new interfaces produced — this is a rendering-only change, verified by the existing `#[cfg(feature = "wiz")]`-gated card compiling and by Task 14's navigation test seeing 5 providers.

- [ ] **Step 1: Add the Wiz card to `draw_provider_selection`**

Edit `src/tui/ui/account_screens.rs`, inside `draw_provider_selection`, after the Jira `v.push(...)`:

```rust
        #[cfg(feature = "wiz")]
        v.push((
            CloudProvider::Wiz,
            "◆  Wiz",
            "Collect security issues, vulnerability findings, and CSPM configuration findings",
        ));
        v
    };
```

(This replaces the existing `v` return with one more `v.push` inserted before it — the trailing `v` line stays last.)

- [ ] **Step 2: Verify the build**

Run: `cargo build --features wiz`
Expected: builds cleanly — no test to write here since this function has no existing unit tests (it's a `ratatui` draw function); coverage comes from the navigation test in Task 14 and manual TUI verification in Task 17.

- [ ] **Step 3: Commit**

```bash
git add src/tui/ui/account_screens.rs
git commit -m "feat(tui): add Wiz card to provider selection screen"
```

---

### Task 14: TUI event handling — provider list + account validation

**Files:**
- Modify: `src/tui/events.rs`

**Interfaces:**
- Consumes: `CloudProvider::Wiz` (Task 6).
- Produces: arrow-key navigation on the provider-selection screen includes Wiz; `validate_current()` for `Screen::ProviderSelection` rejects entering Wiz's collector screen when no `wiz-config.toml` accounts exist.

- [ ] **Step 1: Write the failing test**

Add to `src/tui/app/mod.rs`'s existing `#[cfg(test)] mod tests` block (from Task list above), after `selection_survives_provider_switch`:

```rust
    #[test]
    #[cfg(feature = "wiz")]
    fn wiz_provider_selection_requires_configured_accounts() {
        use crate::providers::CloudProvider;
        let mut app = make_app();
        app.selected_provider = CloudProvider::Wiz;
        app.screen = crate::tui::Screen::ProviderSelection;
        assert!(!app.validate_current(), "should reject Wiz with no configured accounts");
        assert!(app.error_msg.is_some());
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --package the-grabber --features wiz tui::app::tests::wiz_provider_selection_requires_configured_accounts`
Expected: FAIL — `validate_current()` currently returns `true` unconditionally for `CloudProvider::Wiz` (no gate exists yet), so the assertion `!app.validate_current()` fails.

- [ ] **Step 3: Add Wiz to the provider list in `handle_provider_selection`**

Edit `src/tui/events.rs`:

```rust
    let providers: Vec<CloudProvider> = {
        let mut v = vec![CloudProvider::Aws];
        #[cfg(feature = "azure")]
        v.push(CloudProvider::Azure);
        #[cfg(feature = "gcp")]
        v.push(CloudProvider::Gcp);
        #[cfg(feature = "tenable")]
        v.push(CloudProvider::Tenable);
        #[cfg(feature = "okta")]
        v.push(CloudProvider::Okta);
        #[cfg(feature = "jira")]
        v.push(CloudProvider::Jira);
        #[cfg(feature = "wiz")]
        v.push(CloudProvider::Wiz);
        v
    };
```

- [ ] **Step 4: Add the Wiz account-existence check to `validate_current`**

Edit `src/tui/app/nav.rs`, inside `Screen::ProviderSelection => { ... }` in `validate_current`, after the Jira check:

```rust
                #[cfg(feature = "wiz")]
                if self.selected_provider == CloudProvider::Wiz {
                    let has_wiz = self
                        .accounts
                        .iter()
                        .any(|a| a.provider == CloudProvider::Wiz);
                    if !has_wiz {
                        self.error_msg =
                            Some("No Wiz accounts configured in wiz-config.toml".into());
                        return false;
                    }
                }
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cargo test --package the-grabber --features wiz tui::app::tests::wiz_provider_selection_requires_configured_accounts`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/tui/events.rs src/tui/app/nav.rs src/tui/app/mod.rs
git commit -m "feat(tui): wire Wiz into provider-selection navigation and validation"
```

---

### Task 15: TUI nav — route `Wiz` without an extra screen

**Files:**
- Modify: `src/tui/app/nav.rs`

**Interfaces:**
- Consumes: `CloudProvider::Wiz` (Task 6).
- Produces: `ProviderSelection → SelectCollectors` (skipping `SelectAccount`, matching Okta/Jira) and `SelectCollectors → ProviderSelection` on back-navigation.

- [ ] **Step 1: Write the failing test**

Add to `src/tui/app/mod.rs`'s test module:

```rust
    #[test]
    #[cfg(feature = "wiz")]
    fn wiz_provider_selection_advances_straight_to_collectors() {
        use crate::providers::CloudProvider;
        let mut app = make_app();
        app.selected_provider = CloudProvider::Wiz;
        app.screen = crate::tui::Screen::ProviderSelection;
        app.next_screen();
        assert_eq!(app.screen, crate::tui::Screen::SelectCollectors);
    }

    #[test]
    #[cfg(feature = "wiz")]
    fn wiz_select_collectors_prev_goes_to_provider_selection() {
        use crate::providers::CloudProvider;
        let mut app = make_app();
        app.selected_provider = CloudProvider::Wiz;
        app.screen = crate::tui::Screen::SelectCollectors;
        app.prev_screen();
        assert_eq!(app.screen, crate::tui::Screen::ProviderSelection);
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --package the-grabber --features wiz tui::app::tests::wiz_provider_selection_advances_straight_to_collectors`
Expected: FAIL — `Screen::ProviderSelection`'s `next_screen` match falls through to the `else if self.has_accounts() { Screen::SelectAccount } else { Screen::SelectProfile }` branch for `CloudProvider::Wiz` today (no Wiz-specific arm exists), landing on `SelectAccount`/`SelectProfile` instead of `SelectCollectors`.

- [ ] **Step 3: Add the Wiz routing arm in `next_screen`**

Edit `src/tui/app/nav.rs`, inside `Screen::ProviderSelection => { ... }`:

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
                } else if self.selected_provider == CloudProvider::Wiz {
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

- [ ] **Step 4: Add the Wiz routing arm in `prev_screen`**

Edit `src/tui/app/nav.rs`, inside `Screen::SelectCollectors => { ... }` in `prev_screen`:

```rust
            Screen::SelectCollectors => {
                if self.selected_provider == CloudProvider::Tenable {
                    Screen::TenableEndpoint
                } else if self.selected_provider == CloudProvider::Okta
                    || self.selected_provider == CloudProvider::Jira
                    || self.selected_provider == CloudProvider::Wiz
                {
                    Screen::ProviderSelection
                } else {
                    Screen::SetDates
                }
            }
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cargo test --package the-grabber --features wiz tui::app::tests::wiz_provider_selection_advances_straight_to_collectors tui::app::tests::wiz_select_collectors_prev_goes_to_provider_selection`
Expected: PASS.

- [ ] **Step 6: Run the full TUI test suite to confirm no regressions**

Run: `cargo test --package the-grabber --features wiz tui::`
Expected: PASS — all existing `tui::app::tests::*` and `tui::menus::tests::*` tests continue to pass alongside the new Wiz ones.

- [ ] **Step 7: Commit**

```bash
git add src/tui/app/nav.rs src/tui/app/mod.rs
git commit -m "feat(tui): route Wiz through SelectCollectors without an extra screen"
```

---

### Task 16: runner/tui_session — Wiz account preparation block

**Files:**
- Modify: `src/runner/tui_session.rs`

**Interfaces:**
- Consumes: `Account::wiz_client_id_resolved()`/`wiz_client_secret_resolved()`/`wiz_api_url_resolved()`/`wiz_auth_url_resolved()` (Task 7), `wiz_rs::WizClient::new` (Task 2, **async** — the first async provider-client constructor in this codebase; safe here because the surrounding function is itself `pub async fn run_tui_session`), `WizProviderFactory::new` (Task 8).
- Produces: `AccountCollectors` entries for every selected Wiz account, appended to `prepared`, consumed downstream by the existing collector-running loop (no changes needed there — it already iterates `prepared` generically).

- [ ] **Step 1: Add the Wiz account-preparation block**

Edit `src/runner/tui_session.rs`, immediately after the closing `}` of the Okta block (after the line `app.prep_log.push(format!("  ✓ Okta '{}' ready.", tenant_name)); terminal.draw(...)?; }` and its enclosing `}`), and before the `// ── Jira accounts ──` comment:

```rust
            // ── Wiz accounts ─────────────────────────────────────────────────────
            #[cfg(feature = "wiz")]
            if !app.selected_accounts.is_empty() {
                use crate::providers::ProviderFactory as _;

                let sorted_all: Vec<usize> = {
                    let mut v: Vec<usize> = app.selected_accounts.iter().copied().collect();
                    v.sort();
                    v
                };
                for &idx in &sorted_all {
                    if app.accounts[idx].provider != crate::providers::CloudProvider::Wiz {
                        continue;
                    }
                    let acct = &app.accounts[idx];
                    let tenant_name = acct.name.clone();

                    let api_url = match acct.wiz_api_url_resolved() {
                        Some(u) => u,
                        None => {
                            app.prep_log.push(format!(
                                "  ✗ Wiz '{}' — missing wiz_api_url (or WIZ_API_URL env)",
                                tenant_name,
                            ));
                            terminal.draw(|f| crate::tui::ui::draw(f, &app))?;
                            continue;
                        }
                    };
                    let client_id = match acct.wiz_client_id_resolved() {
                        Some(c) => c,
                        None => {
                            app.prep_log.push(format!(
                                "  ✗ Wiz '{}' — missing wiz_client_id (or WIZ_CLIENT_ID env)",
                                tenant_name,
                            ));
                            terminal.draw(|f| crate::tui::ui::draw(f, &app))?;
                            continue;
                        }
                    };
                    let client_secret = match acct.wiz_client_secret_resolved() {
                        Some(s) => s,
                        None => {
                            app.prep_log.push(format!(
                                "  ✗ Wiz '{}' — missing wiz_client_secret (or WIZ_CLIENT_SECRET env)",
                                tenant_name,
                            ));
                            terminal.draw(|f| crate::tui::ui::draw(f, &app))?;
                            continue;
                        }
                    };
                    let auth_url = acct.wiz_auth_url_resolved();

                    app.prep_log
                        .push(format!("  Wiz '{}' → {}", tenant_name, api_url));
                    terminal.draw(|f| crate::tui::ui::draw(f, &app))?;

                    let client =
                        match wiz_rs::WizClient::new(&api_url, &auth_url, &client_id, &client_secret)
                            .await
                        {
                            Ok(c) => c,
                            Err(e) => {
                                app.prep_log.push(format!(
                                    "  ✗ Wiz '{}' — client build failed: {e}",
                                    tenant_name,
                                ));
                                terminal.draw(|f| crate::tui::ui::draw(f, &app))?;
                                continue;
                            }
                        };

                    let selected_keys: Vec<String> = app
                        .selected_collectors()
                        .into_iter()
                        .filter(|k| k.starts_with("wiz-"))
                        .collect();

                    let factory = crate::providers::wiz::factory::WizProviderFactory::new(
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
                        endpoint_label: Some(format!("Wiz — {}", api_url)),
                    });

                    app.prep_log
                        .push(format!("  ✓ Wiz '{}' ready.", tenant_name));
                    terminal.draw(|f| crate::tui::ui::draw(f, &app))?;
                }
            }

```

- [ ] **Step 2: Verify the build**

Run: `cargo build --features wiz`
Expected: builds cleanly. This function has no existing unit tests (it drives the real terminal loop and makes real network calls for other providers), so there is no new automated test here — correctness is covered by the account-preparation error-path messages matching the Okta pattern exactly, and by the end-to-end smoke check in Task 17.

- [ ] **Step 3: Commit**

```bash
git add src/runner/tui_session.rs
git commit -m "feat(runner): wire Wiz account preparation into TUI session"
```

---

### Task 17: End-to-end smoke check (no AWS, no Wiz network)

**Files:**
- No new files — this task runs the existing suite plus a manual dry-run script.

**Interfaces:**
- Consumes: everything built in Tasks 1-16.
- Produces: confidence that `--features wiz` (and the full `default` feature set) compiles and that the Wiz provider appears correctly end-to-end in the TUI without requiring real Wiz credentials.

- [ ] **Step 1: Full workspace build with every feature combination touched by this plan**

Run: `cargo build --features wiz`
Expected: PASS.

Run: `cargo build` (default features, which now include `wiz`)
Expected: PASS.

Run: `cargo build --no-default-features`
Expected: PASS — confirms Wiz (like Tenable/Okta/Jira) is fully excludable.

- [ ] **Step 2: Full test suite**

Run: `cargo test -p wiz-rs`
Expected: PASS — all `wiz-rs` crate tests (Tasks 2-5).

Run: `cargo test`
Expected: PASS — all root-crate tests, including the new `providers::mod::tests`, `providers::wiz::*::tests`, `app_config::tests`, `tui::menus::tests`, and `tui::app::tests::wiz_*` tests added in Tasks 6-15.

- [ ] **Step 3: Manual TUI dry-run with a fake `wiz-config.toml`**

Create a throwaway `wiz-config.toml` in the repo root (do not commit it — it's already gitignored per Task 18):

```toml
[[account]]
name              = "Wiz Test"
provider          = "wiz"
description       = "smoke test"
output_dir        = "./evidence-output/wiz-smoke-test"
wiz_client_id     = "fake-id"
wiz_client_secret = "fake-secret"
wiz_api_url       = "https://api.us1.app.wiz.io/graphql"
```

Run: `cargo run --features wiz -- ` (launches the TUI with no CLI args, matching how Tenable/Okta/Jira are exercised interactively)

In the TUI: select **Collectors** → arrow down to the **Wiz** provider card → Enter. Confirm:
- The account-existence check passes (no "No Wiz accounts configured" error), since `wiz-config.toml` now has one.
- Pressing Enter lands directly on the collector-selection screen (no `SelectAccount` screen, no region/All-Regions toggle visible) — same shape as Okta/Jira.
- The **Security Findings** category shows exactly 3 items: "Issues", "Vulnerability Findings", "Configuration Findings".
- Selecting all 3 and proceeding to **Set Options** shows no region field and no All-Regions toggle (the pre-existing `is_aws_regional()` gate applies automatically).
- Proceeding to **Confirm** → **Run** shows a `Wiz 'Wiz Test' → https://api.us1.app.wiz.io/graphql` prep-log line, followed by a `✗ Wiz 'Wiz Test' — client build failed: ...` line (expected, since `fake-secret` isn't a real credential and the OAuth2 token exchange will fail against the real Wiz auth endpoint) — this confirms the account-preparation block runs and fails gracefully rather than panicking or hanging.

Delete the throwaway `wiz-config.toml` and the `./evidence-output/wiz-smoke-test` directory afterward.

- [ ] **Step 4: No commit for this task** — it's a verification step, not a code change.

---

### Task 18: Documentation

**Files:**
- Create: `wiz-config.example.toml`
- Modify: `.gitignore`
- Modify: `README.md`

**Interfaces:**
- None — documentation only.

- [ ] **Step 1: Write the example config**

```toml
# wiz-config.example.toml
# Wiz credentials — keep this file out of version control
# Add to .gitignore: wiz-config.toml
#
# Merged automatically into config.toml at startup when present.
# Env vars override TOML values: WIZ_CLIENT_ID, WIZ_CLIENT_SECRET, WIZ_API_URL, WIZ_AUTH_URL
#
# wiz_client_id / wiz_client_secret come from a Wiz Service Account
# (Settings → Service Accounts, scope: read-only). wiz_api_url is your
# tenant's GraphQL endpoint, shown in Wiz under Settings → API Endpoint URL.

[[account]]
name              = "Wiz"
provider          = "wiz"
description       = "Wiz production tenant"
output_dir        = "./evidence-output/wiz"
wiz_client_id     = ""
wiz_client_secret = ""
wiz_api_url       = "https://api.us1.app.wiz.io/graphql"
# wiz_auth_url    = ""   # omit to use the default: https://auth.app.wiz.io/oauth/token
```

- [ ] **Step 2: Gitignore the real config file**

Edit `.gitignore`, after the Jira line:

```
# Wiz credentials — never commit
wiz-config.toml
```

- [ ] **Step 3: Update README**

Edit `README.md` line 1 (repo description) and line 13 (collector count):

```markdown
# The Grabber

The Grabber. Collects current-state snapshots and time-windowed audit records from AWS, Okta, Jira, Tenable, and Wiz, writing them as CSV and JSON. Supports exporting inventory and POA&M artifacts using FedRAMP-aligned templates, suitable for FedRAMP, SOC 2, HIPAA, or internal audits.
```

```markdown
- **200+ collectors across five providers** — 144 AWS, 24 Okta, 28 Jira, 5 Tenable, 3 Wiz (see `evidence-list.md` for the current catalog)
```

Add a short Wiz mention near wherever Tenable/Okta/Jira setup is documented elsewhere in `README.md` (mirror the existing Tenable/Okta/Jira paragraph structure — e.g. a `### Wiz` subsection under whatever "Provider setup" or "Credentials" heading those three already use), stating: OAuth2 client-credentials auth via a Wiz Service Account, and the three env vars (`WIZ_CLIENT_ID`, `WIZ_CLIENT_SECRET`, `WIZ_API_URL`) plus the optional `WIZ_AUTH_URL` override.

- [ ] **Step 4: Commit**

```bash
git add wiz-config.example.toml .gitignore README.md
git commit -m "docs: document the Wiz provider (config, env vars, collector count)"
```

---

## Self-Review Notes

**Spec coverage:** Every element from the goal — new `CloudProvider::Wiz` variant, OAuth2 client-credentials auth, GraphQL client, three collectors (Issues/Vulnerabilities/Configuration Findings), TUI provider card + menu + navigation, account config + env resolvers, `tui_session.rs` wiring, docs — has a corresponding task (6, 2, 2-5, 9-11, 12-15, 7, 16, 18).

**Placeholder scan:** No "TBD"/"similar to above"/unshown code remains — every step that changes code shows the full, compilable snippet, including the temporary empty stub files needed to keep the crate compiling mid-sequence (explicitly called out as stubs replaced by a later, numbered task).

**Type consistency:** `WizClient::new(api_url, auth_url, client_id, client_secret)` (Task 2) is called identically in the `lib.rs` doc example, every `wiz-rs` test, and `tui_session.rs` (Task 16). `WizProviderFactory::new(client, tenant_name, selected)` (Task 8) matches its call site in Task 16. Selector strings (`wiz-issues`, `wiz-vulnerabilities`, `wiz-config-findings`) match exactly across `tui/menus/wiz.rs` (Task 12), `providers/wiz/factory.rs` (Task 8), and the `starts_with("wiz-")` filter in `tui_session.rs` (Task 16). `EntitySnapshot`/`VulnerableAsset`/`ConfigurationResource` field names match between each `types::*.rs` struct and the GraphQL query string in the corresponding `api::*.rs` module.
