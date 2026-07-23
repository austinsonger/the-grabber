# Add Cloudflare Provider Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Cloudflare as a fifth non-AWS provider, following the exact architectural pattern already used for Tenable, Okta, and Jira — a standalone `cloudflare-rs` HTTP client crate, a `src/providers/cloudflare` collector module, and TUI wiring — so users can collect Cloudflare Account Members, Account Roles, API Tokens, Zones, DNS Records, SSL/TLS Settings, WAF Rulesets, and Audit Logs as compliance evidence.

**Architecture:** Cloudflare authenticates via a single Bearer API Token against one global REST API base URL (`https://api.cloudflare.com/client/v4`), unlike Okta/Jira's per-tenant domain — simpler than either. Every Cloudflare v4 response is wrapped in a `{success, errors, result, result_info}` envelope with page-number pagination (`page`/`per_page`/`total_count`), so `cloudflare-rs`'s client centralizes envelope-unwrapping and pagination in two generic helpers that every API module calls. Zone-scoped collectors (DNS Records, SSL/TLS Settings, WAF Rulesets) list every zone under the account first, then iterate — no zone-selection TUI screen is needed. Everything else — crate skeleton, `CloudProvider` enum, `ProviderFactory` impl, TUI menu registration, account config, `tui_session.rs` wiring — mirrors Okta exactly, since Okta is the closest existing analog (external SaaS API, own workspace crate, TUI-only, no region concept, single-token auth).

**Tech Stack:** Rust 2021, `reqwest` (json + rustls-tls) for HTTP, `tokio` for async, `thiserror` for errors, `wiremock` for HTTP-layer tests.

## Global Constraints

- New workspace crate `cloudflare-rs` at `crates/cloudflare-rs`, added to `[workspace] members` in the root `Cargo.toml`, matching the shape of `crates/tenable-rs` / `crates/okta-rs`.
- The Cloudflare provider is **default-on** via Cargo feature `cloudflare` (`cloudflare = ["dep:cloudflare-rs"]`), added to `default = ["tenable", "okta", "jira", "cloudflare"]` — matching how Tenable/Okta/Jira are wired (Azure/GCP are the only providers left out of `default`).
- No CLI (`src/cli.rs`) wiring — Tenable/Okta/Jira are TUI-only today; Cloudflare follows the same pattern unless a later task requests CLI support.
- Selector keys are prefixed `cloudflare-` (e.g. `cloudflare-zones`); CSV/JSON filename prefixes are prefixed `Cloudflare_` (e.g. `Cloudflare_Zones`) — matching the `okta-`/`Okta_` and `tenable-`/`Tenable_` conventions.
- Credentials come from `cloudflare-config.toml` (gitignored, merged into `AppConfig` at startup exactly like `tenable-config.toml`/`okta-config.toml`/`jira-config.toml`), with env vars `CLOUDFLARE_ACCOUNT_ID` and `CLOUDFLARE_API_TOKEN` overriding TOML values — matching the `_resolved()` accessor pattern on `Account`.
- Auth is a single Cloudflare **API Token** (Bearer), scoped read-only (`Account Settings:Read`, `Account Members:Read`, `Zone:Read`, `DNS:Read`, `Firewall Services:Read`, `Audit Logs:Read`). No legacy Global API Key + Email support.
- Cloudflare has one global API base URL, unlike Okta's per-tenant domain — no per-account base-URL field is needed on `Account`; `CloudflareClient::new` takes only the API token.
- Cloudflare has no AWS-style region concept, so `CloudflareProviderFactory::region()` returns `""` and the existing `is_collectors_non_aws` gate in `nav.rs`'s `SetOptions` arm applies automatically — no new region-hiding code is needed.
- Zone-scoped collectors (DNS Records, SSL/TLS Settings, WAF Rulesets) auto-iterate every zone under the account by calling `client.zones().list(account_id)` internally — no zone-selection TUI screen, per the brainstormed design decision to keep zone scoping out of v1.
- Scope for this plan is **8 initial collectors** across three categories — Directory & Access (Account Members, Account Roles, API Tokens), Network & Security (Zones, DNS Records, SSL/TLS Settings, WAF Rulesets), Audit & Logging (Audit Logs) — Cloudflare's core FedRAMP-relevant config/access/audit surface. Broader coverage (Zero Trust/Access, Workers, R2, Load Balancers) can be added later following the exact same pattern as any collector task below.
- Cloudflare's WAF ruleset "entrypoint" endpoints (`GET /zones/{zone_id}/rulesets/phases/{phase}/entrypoint`) return HTTP 404 when a zone has no ruleset configured for that phase. This plan treats HTTP 404 as "no ruleset" (`Ok(None)`), matching the `TenableError::Api{status:404,..}` → `Ok(vec![])` idiom already used in `TenableAssetsCollector`. Field names and error codes below reflect Cloudflare's publicly documented v4 API shape — verify against a live account/token before running for real, and adjust `types::*` structs if any field differs. Every test in this plan mocks the HTTP layer with `wiremock`, so the code is fully buildable and testable without a live Cloudflare account.
- Per your test-scope decision: `cloudflare-rs` gets a `wiremock`-based `tests/` suite (mirroring `tenable-rs`/`okta-rs`/`jira-rs`); the main-crate collector/TUI/factory wiring gets **zero tests**, consistent with your standing "no tests, just implementation" preference for this project outside of client crates.

---

## File Structure

**New files:**
- `crates/cloudflare-rs/Cargo.toml` — crate manifest (reqwest, tokio, thiserror, wiremock dev-dep)
- `crates/cloudflare-rs/src/lib.rs` — crate root, re-exports `CloudflareClient`/`CloudflareError`
- `crates/cloudflare-rs/src/error.rs` — `CloudflareError` enum
- `crates/cloudflare-rs/src/client.rs` — `CloudflareClient`: Bearer auth + envelope unwrap + pagination + 429 retry
- `crates/cloudflare-rs/src/api/mod.rs` — re-exports the five API structs
- `crates/cloudflare-rs/src/api/accounts.rs` — `AccountsApi::list_members` / `list_roles`
- `crates/cloudflare-rs/src/api/tokens.rs` — `TokensApi::list`
- `crates/cloudflare-rs/src/api/zones.rs` — `ZonesApi::list` / `list_dns_records` / `ssl_tls_settings`
- `crates/cloudflare-rs/src/api/firewall.rs` — `FirewallApi::custom_ruleset` / `managed_ruleset`
- `crates/cloudflare-rs/src/api/audit_logs.rs` — `AuditLogsApi::list`
- `crates/cloudflare-rs/src/types/mod.rs` — re-exports type modules
- `crates/cloudflare-rs/src/types/member.rs` — `Member`, `MemberUser`, `MemberRole`
- `crates/cloudflare-rs/src/types/role.rs` — `Role`
- `crates/cloudflare-rs/src/types/token.rs` — `ApiToken`
- `crates/cloudflare-rs/src/types/zone.rs` — `Zone`, `ZonePlan`, `DnsRecord`
- `crates/cloudflare-rs/src/types/zone_settings.rs` — `ZoneSettingValue`, `ZoneSslSettings`
- `crates/cloudflare-rs/src/types/ruleset.rs` — `Ruleset`
- `crates/cloudflare-rs/src/types/audit_log.rs` — `AuditLogEntry`, `AuditAction`, `AuditActor`, `AuditResource`
- `crates/cloudflare-rs/tests/client_test.rs` — auth header, envelope unwrap, 429 retry, `success:false` mapping
- `crates/cloudflare-rs/tests/accounts_test.rs` — page-number pagination
- `crates/cloudflare-rs/tests/tokens_test.rs` — `ApiToken` field parsing
- `crates/cloudflare-rs/tests/zones_test.rs` — SSL/TLS settings 5-endpoint fan-out/assembly
- `crates/cloudflare-rs/tests/firewall_test.rs` — HTTP 404 → `Ok(None)`
- `crates/cloudflare-rs/tests/audit_logs_test.rs` — query params + nested-struct parsing
- `src/providers/cloudflare/mod.rs` — `pub mod` declarations for the Cloudflare collector module
- `src/providers/cloudflare/factory.rs` — `CloudflareProviderFactory: ProviderFactory`
- `src/providers/cloudflare/account_members.rs` — `CloudflareAccountMembersCollector: CsvCollector`
- `src/providers/cloudflare/account_roles.rs` — `CloudflareAccountRolesCollector: JsonCollector`
- `src/providers/cloudflare/api_tokens.rs` — `CloudflareApiTokensCollector: CsvCollector`
- `src/providers/cloudflare/zones.rs` — `CloudflareZonesCollector: CsvCollector`
- `src/providers/cloudflare/dns_records.rs` — `CloudflareDnsRecordsCollector: CsvCollector`
- `src/providers/cloudflare/ssl_tls_settings.rs` — `CloudflareSslTlsSettingsCollector: JsonCollector`
- `src/providers/cloudflare/waf_rulesets.rs` — `CloudflareWafRulesetsCollector: JsonCollector`
- `src/providers/cloudflare/audit_logs.rs` — `CloudflareAuditLogsCollector: CsvCollector` (time-windowed)
- `src/tui/menus/cloudflare.rs` — `CLOUDFLARE_CATEGORIES` menu data
- `cloudflare-config.example.toml` — example credentials file

**Modified files:**
- `Cargo.toml` — workspace member, `cloudflare-rs` dependency, `cloudflare` feature
- `src/providers/mod.rs` — `CloudProvider::Cloudflare` variant + `Display` arm + `pub mod cloudflare`
- `src/app_config.rs` — `Account` Cloudflare fields + `_resolved()` methods + `cloudflare-config.toml` merge in `load_config()`
- `src/tui/menus/mod.rs` — `pub mod cloudflare;` + `PROVIDER_MENUS` entry
- `src/tui/ui/account_screens.rs` — Cloudflare card in `draw_provider_selection()`
- `src/tui/events.rs` — Cloudflare in `handle_provider_selection`'s provider list
- `src/tui/app/nav.rs` — Cloudflare routing in `next_screen`/`prev_screen`/`validate_current`
- `src/runner/tui_session.rs` — Cloudflare account-preparation block
- `assets/fedramp-map.json` — 8 new collector entries (placeholder empty `req_ids`/`control_ids`)
- `.gitignore` — `cloudflare-config.toml`
- `README.md` — mention Cloudflare, update collector count
- `evidence-list.md` — new Cloudflare collector table section

---

### Task 1: Workspace + cloudflare-rs crate skeleton

**Files:**
- Create: `crates/cloudflare-rs/Cargo.toml`
- Create: `crates/cloudflare-rs/src/lib.rs`
- Create: `crates/cloudflare-rs/src/error.rs`
- Modify: `Cargo.toml` (workspace members, deps + features)

**Interfaces:**
- Produces: `cloudflare_rs::CloudflareError` (used by every later task in this crate), an empty crate that compiles standalone.

- [ ] **Step 1: Create the crate manifest**

```toml
# crates/cloudflare-rs/Cargo.toml
[package]
name        = "cloudflare-rs"
version     = "0.1.0"
edition     = "2021"
description = "Async Rust client for the Cloudflare REST API v4"
license     = "MIT OR Apache-2.0"

[dependencies]
reqwest    = { version = "0.12", features = ["json", "rustls-tls"], default-features = false }
serde      = { version = "1", features = ["derive"] }
serde_json = "1"
tokio      = { version = "1", features = ["time"] }
thiserror  = "2"
anyhow     = "1"

[dev-dependencies]
tokio    = { version = "1", features = ["full"] }
wiremock = "0.6"
```

- [ ] **Step 2: Write the error type**

```rust
// crates/cloudflare-rs/src/error.rs
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CloudflareError {
    #[error("HTTP transport error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("invalid header value: {0}")]
    InvalidHeader(#[from] reqwest::header::InvalidHeaderValue),

    #[error("JSON parse error: {0}")]
    Parse(#[from] serde_json::Error),

    #[error("Cloudflare API error (HTTP {status}, code {code}): {message}")]
    Api {
        status: u16,
        code: i64,
        message: String,
    },

    #[error("Cloudflare API token must not be empty")]
    EmptyApiToken,
}
```

- [ ] **Step 3: Write the crate root**

```rust
// crates/cloudflare-rs/src/lib.rs
//! Async Rust client for the Cloudflare REST API v4.
//!
//! # Quick start
//!
//! ```no_run
//! use cloudflare_rs::CloudflareClient;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let client = CloudflareClient::new("my-api-token")?;
//!     let zones = client.zones().list("account-id").await?;
//!     println!("{} zones", zones.len());
//!     Ok(())
//! }
//! ```

mod client;
mod error;

pub mod api;
pub mod types;

pub use client::CloudflareClient;
pub use error::CloudflareError;
```

`api` and `types` don't exist yet, so this won't compile until Task 2 adds `client.rs` and Task 3 adds stub `api`/`types` modules. Run the check after Task 3, not now.

- [ ] **Step 4: Register the workspace member and feature**

Edit `Cargo.toml`:

```toml
[workspace]
members  = [".", "crates/tenable-rs", "crates/okta-rs", "crates/jira-rs", "crates/cloudflare-rs"]
resolver = "2"
```

Add the dependency, after the `jira-rs` block:

```toml
# Jira — only compiled with `--features jira`
jira-rs = { path = "crates/jira-rs", optional = true }

# Cloudflare — only compiled with `--features cloudflare`
cloudflare-rs = { path = "crates/cloudflare-rs", optional = true }
```

Update the features section:

```toml
[features]
default    = ["tenable", "okta", "jira", "cloudflare"]
azure      = ["dep:azure_identity", "dep:azure_mgmt_monitor", "dep:azure_mgmt_resources"]
gcp        = ["dep:google-cloud-auth"]
tenable    = ["dep:tenable-rs"]
okta       = ["dep:okta-rs"]
jira       = ["dep:jira-rs"]
cloudflare = ["dep:cloudflare-rs"]
```

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml crates/cloudflare-rs/Cargo.toml crates/cloudflare-rs/src/lib.rs crates/cloudflare-rs/src/error.rs
git commit -m "feat(cloudflare-rs): crate skeleton and workspace registration"
```

---

### Task 2: CloudflareClient — Bearer auth + envelope unwrap + pagination + 429 retry

**Files:**
- Create: `crates/cloudflare-rs/src/client.rs`
- Create: `crates/cloudflare-rs/src/api/mod.rs` (empty stub)
- Create: `crates/cloudflare-rs/src/types/mod.rs` (empty stub)
- Test: `crates/cloudflare-rs/tests/client_test.rs`

**Interfaces:**
- Consumes: `crate::error::CloudflareError` (Task 1).
- Produces: `pub struct CloudflareClient` with `pub fn new(api_token: &str) -> Result<Self, CloudflareError>`, `pub(crate) async fn get_result<T: DeserializeOwned>(&self, path: &str) -> Result<T, CloudflareError>`, and `pub(crate) async fn get_paginated<T: DeserializeOwned>(&self, path: &str) -> Result<Vec<T>, CloudflareError>`. Every API module (Tasks 3–7) calls these two methods.

- [ ] **Step 1: Write the failing tests**

```rust
// crates/cloudflare-rs/tests/client_test.rs
use cloudflare_rs::{CloudflareClient, CloudflareError};
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn injects_bearer_auth_and_unwraps_envelope_result() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/user/tokens"))
        .and(header("Authorization", "Bearer test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "errors": [],
            "result": [{"id": "tok-1"}],
            "result_info": {"page": 1, "per_page": 50, "total_count": 1}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = CloudflareClient::with_base_url(&server.uri(), "test-token").unwrap();
    let tokens = client.tokens().list().await.unwrap();
    assert_eq!(tokens.len(), 1);
    assert_eq!(tokens[0].id, "tok-1");
}

#[tokio::test]
async fn retries_429_then_succeeds() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/user/tokens"))
        .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "1"))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/user/tokens"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "errors": [],
            "result": [],
            "result_info": {"page": 1, "per_page": 50, "total_count": 0}
        })))
        .mount(&server)
        .await;

    let client = CloudflareClient::with_base_url(&server.uri(), "test-token").unwrap();
    let tokens = client.tokens().list().await.unwrap();
    assert!(tokens.is_empty());
}

#[tokio::test]
async fn success_false_envelope_becomes_api_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/user/tokens"))
        .and(query_param("page", "1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": false,
            "errors": [{"code": 9109, "message": "Invalid API token"}],
            "result": null
        })))
        .mount(&server)
        .await;

    let client = CloudflareClient::with_base_url(&server.uri(), "bad-token").unwrap();
    let err = client.tokens().list().await.unwrap_err();
    match err {
        CloudflareError::Api { code, message, .. } => {
            assert_eq!(code, 9109);
            assert_eq!(message, "Invalid API token");
        }
        other => panic!("expected CloudflareError::Api, got {other:?}"),
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p cloudflare-rs --test client_test`
Expected: FAIL — `cloudflare_rs::CloudflareClient` doesn't exist yet (compile error), and `client.tokens()` has no implementation.

- [ ] **Step 3: Implement `CloudflareClient`**

```rust
// crates/cloudflare-rs/src/client.rs
use reqwest::{header, Client, Response};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use tokio::time::{sleep, Duration};

use crate::api::{AccountsApi, AuditLogsApi, FirewallApi, TokensApi, ZonesApi};
use crate::error::CloudflareError;

const CLOUDFLARE_API_BASE: &str = "https://api.cloudflare.com/client/v4";
const MAX_RETRIES: u32 = 5;
const DEFAULT_RETRY_AFTER_SECS: u64 = 30;
const PER_PAGE: u32 = 50;

#[derive(Debug, Deserialize)]
struct Envelope<T> {
    success: bool,
    #[serde(default)]
    errors: Vec<CfError>,
    result: Option<T>,
    #[serde(default)]
    result_info: Option<ResultInfo>,
}

#[derive(Debug, Deserialize)]
struct CfError {
    code: i64,
    message: String,
}

#[derive(Debug, Deserialize)]
struct ResultInfo {
    #[serde(default)]
    total_count: u32,
}

/// Thin async HTTP client for the Cloudflare REST API v4.
///
/// Injects `Authorization: Bearer <token>` on every request and transparently
/// retries HTTP 429 responses with exponential backoff (up to 5 retries,
/// honouring `Retry-After`).
///
/// `CloudflareClient` is cheaply cloneable — `reqwest::Client` wraps an
/// arc-pooled connection pool. Build one instance and clone into each collector.
#[derive(Clone)]
pub struct CloudflareClient {
    pub(crate) http: Client,
    pub(crate) base_url: String,
}

impl CloudflareClient {
    /// Build a client against the real Cloudflare API using an API Token.
    pub fn new(api_token: &str) -> Result<Self, CloudflareError> {
        Self::with_base_url(CLOUDFLARE_API_BASE, api_token)
    }

    /// Build a client against a custom base URL — used by tests to point at
    /// a `wiremock` server.
    pub fn with_base_url(base_url: &str, api_token: &str) -> Result<Self, CloudflareError> {
        if api_token.trim().is_empty() {
            return Err(CloudflareError::EmptyApiToken);
        }
        let auth = format!("Bearer {api_token}");
        let mut headers = header::HeaderMap::new();
        headers.insert(header::AUTHORIZATION, header::HeaderValue::from_str(&auth)?);
        headers.insert(
            header::ACCEPT,
            header::HeaderValue::from_static("application/json"),
        );
        let http = Client::builder().default_headers(headers).build()?;
        Ok(Self {
            http,
            base_url: base_url.trim_end_matches('/').to_string(),
        })
    }

    /// Absolute URL for a path beginning with `/`.
    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    pub fn accounts(&self) -> AccountsApi<'_> {
        AccountsApi(self)
    }
    pub fn tokens(&self) -> TokensApi<'_> {
        TokensApi(self)
    }
    pub fn zones(&self) -> ZonesApi<'_> {
        ZonesApi(self)
    }
    pub fn firewall(&self) -> FirewallApi<'_> {
        FirewallApi(self)
    }
    pub fn audit_logs(&self) -> AuditLogsApi<'_> {
        AuditLogsApi(self)
    }

    async fn send_with_retry<F, Fut>(&self, make_req: F) -> Result<Response, CloudflareError>
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
            let wait = resp
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(backoff)
                .max(backoff);
            sleep(Duration::from_secs(wait)).await;
            backoff = (backoff * 2).min(DEFAULT_RETRY_AFTER_SECS);
        }
        unreachable!()
    }

    pub(crate) async fn get(&self, path: &str) -> Result<Response, CloudflareError> {
        let url = self.url(path);
        self.send_with_retry(|| self.http.get(&url).send()).await
    }

    /// GET a single-object (non-paginated) endpoint and unwrap `result`.
    pub(crate) async fn get_result<T: DeserializeOwned>(
        &self,
        path: &str,
    ) -> Result<T, CloudflareError> {
        let resp = self.get(path).await?;
        let status = resp.status();
        let body: Envelope<T> = resp.json().await?;
        if !body.success {
            let (code, message) = body
                .errors
                .first()
                .map(|e| (e.code, e.message.clone()))
                .unwrap_or((0, format!("HTTP {status}")));
            return Err(CloudflareError::Api {
                status: status.as_u16(),
                code,
                message,
            });
        }
        body.result.ok_or(CloudflareError::Api {
            status: status.as_u16(),
            code: 0,
            message: "Cloudflare API returned success with no result".into(),
        })
    }

    /// GET a list endpoint, following `page`/`per_page`/`total_count`
    /// pagination until every page has been fetched.
    pub(crate) async fn get_paginated<T: DeserializeOwned>(
        &self,
        path: &str,
    ) -> Result<Vec<T>, CloudflareError> {
        let sep = if path.contains('?') { "&" } else { "?" };
        let mut all = Vec::new();
        let mut page = 1u32;
        loop {
            let paged_path = format!("{path}{sep}page={page}&per_page={PER_PAGE}");
            let resp = self.get(&paged_path).await?;
            let status = resp.status();
            let body: Envelope<Vec<T>> = resp.json().await?;
            if !body.success {
                let (code, message) = body
                    .errors
                    .first()
                    .map(|e| (e.code, e.message.clone()))
                    .unwrap_or((0, format!("HTTP {status}")));
                return Err(CloudflareError::Api {
                    status: status.as_u16(),
                    code,
                    message,
                });
            }
            let items = body.result.unwrap_or_default();
            let got = items.len() as u32;
            all.extend(items);
            let total = body
                .result_info
                .map(|i| i.total_count)
                .unwrap_or(all.len() as u32);
            if got == 0 || all.len() as u32 >= total {
                break;
            }
            page += 1;
        }
        Ok(all)
    }
}
```

- [ ] **Step 4: Add empty `api`/`types` stub modules so the crate compiles**

```rust
// crates/cloudflare-rs/src/api/mod.rs
```

```rust
// crates/cloudflare-rs/src/types/mod.rs
```

This won't yet compile — `crate::api::{AccountsApi, ...}` doesn't exist. Tasks 3–7 add each `XApi` struct one at a time; only run `cargo build -p cloudflare-rs` after Task 7. For now, just verify the test file's *shape* compiles conceptually — proceed to Task 3 immediately, then come back and run the full test suite at the end of Task 7 (Step 5 there covers `client_test.rs`).

- [ ] **Step 5: Commit**

```bash
git add crates/cloudflare-rs/src/client.rs crates/cloudflare-rs/src/api/mod.rs crates/cloudflare-rs/src/types/mod.rs crates/cloudflare-rs/tests/client_test.rs
git commit -m "feat(cloudflare-rs): Bearer auth client with envelope unwrap, pagination, and 429 retry"
```

---

### Task 3: Accounts API — members + roles + types

**Files:**
- Create: `crates/cloudflare-rs/src/types/member.rs`
- Create: `crates/cloudflare-rs/src/types/role.rs`
- Modify: `crates/cloudflare-rs/src/types/mod.rs`
- Create: `crates/cloudflare-rs/src/api/accounts.rs`
- Modify: `crates/cloudflare-rs/src/api/mod.rs`
- Test: `crates/cloudflare-rs/tests/accounts_test.rs`

**Interfaces:**
- Consumes: `CloudflareClient::get_paginated` (Task 2).
- Produces: `client.accounts().list_members(account_id: &str) -> Result<Vec<Member>, CloudflareError>` and `client.accounts().list_roles(account_id: &str) -> Result<Vec<Role>, CloudflareError>`, used by `CloudflareAccountMembersCollector` (Task 11) and `CloudflareAccountRolesCollector` (Task 12).

- [ ] **Step 1: Write the failing test**

```rust
// crates/cloudflare-rs/tests/accounts_test.rs
use cloudflare_rs::CloudflareClient;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn list_members_follows_page_number_pagination() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/accounts/acct-1/members"))
        .and(query_param("page", "1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "errors": [],
            "result": [{
                "id": "mem-1",
                "status": "accepted",
                "user": {"email": "a@example.com", "two_factor_authentication_enabled": true},
                "roles": [{"id": "role-1", "name": "Administrator"}]
            }],
            "result_info": {"page": 1, "per_page": 50, "total_count": 2}
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/accounts/acct-1/members"))
        .and(query_param("page", "2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "errors": [],
            "result": [{
                "id": "mem-2",
                "status": "pending",
                "user": {"email": "b@example.com", "two_factor_authentication_enabled": false},
                "roles": []
            }],
            "result_info": {"page": 2, "per_page": 50, "total_count": 2}
        })))
        .mount(&server)
        .await;

    let client = CloudflareClient::with_base_url(&server.uri(), "test-token").unwrap();
    let members = client.accounts().list_members("acct-1").await.unwrap();

    assert_eq!(members.len(), 2);
    assert_eq!(members[0].id, "mem-1");
    assert_eq!(members[0].user.email, "a@example.com");
    assert!(members[0].user.two_factor_authentication_enabled);
    assert_eq!(members[0].roles[0].name, "Administrator");
    assert_eq!(members[1].id, "mem-2");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p cloudflare-rs --test accounts_test`
Expected: FAIL — `crate::api::AccountsApi` doesn't exist yet (compile error).

- [ ] **Step 3: Add the types**

```rust
// crates/cloudflare-rs/src/types/member.rs
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Member {
    pub id: String,
    pub status: String,
    pub user: MemberUser,
    #[serde(default)]
    pub roles: Vec<MemberRole>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MemberUser {
    pub email: String,
    #[serde(default)]
    pub two_factor_authentication_enabled: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MemberRole {
    pub id: String,
    pub name: String,
}
```

```rust
// crates/cloudflare-rs/src/types/role.rs
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Role {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub permissions: serde_json::Value,
}
```

Edit `crates/cloudflare-rs/src/types/mod.rs`:

```rust
// crates/cloudflare-rs/src/types/mod.rs
pub mod member;
pub mod role;
```

- [ ] **Step 4: Implement `AccountsApi`**

```rust
// crates/cloudflare-rs/src/api/accounts.rs
use crate::client::CloudflareClient;
use crate::error::CloudflareError;
use crate::types::member::Member;
use crate::types::role::Role;

pub struct AccountsApi<'c>(pub(crate) &'c CloudflareClient);

impl<'c> AccountsApi<'c> {
    /// GET /accounts/{account_id}/members — every member of the account.
    pub async fn list_members(&self, account_id: &str) -> Result<Vec<Member>, CloudflareError> {
        self.0
            .get_paginated(&format!("/accounts/{account_id}/members"))
            .await
    }

    /// GET /accounts/{account_id}/roles — every role defined for the account.
    pub async fn list_roles(&self, account_id: &str) -> Result<Vec<Role>, CloudflareError> {
        self.0
            .get_paginated(&format!("/accounts/{account_id}/roles"))
            .await
    }
}
```

Edit `crates/cloudflare-rs/src/api/mod.rs`:

```rust
// crates/cloudflare-rs/src/api/mod.rs
pub mod accounts;

pub use accounts::AccountsApi;
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cargo test -p cloudflare-rs --test accounts_test`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/cloudflare-rs/src/types/member.rs crates/cloudflare-rs/src/types/role.rs crates/cloudflare-rs/src/types/mod.rs crates/cloudflare-rs/src/api/accounts.rs crates/cloudflare-rs/src/api/mod.rs crates/cloudflare-rs/tests/accounts_test.rs
git commit -m "feat(cloudflare-rs): Accounts API — members and roles"
```

---

### Task 4: Tokens API + types

**Files:**
- Create: `crates/cloudflare-rs/src/types/token.rs`
- Modify: `crates/cloudflare-rs/src/types/mod.rs`
- Create: `crates/cloudflare-rs/src/api/tokens.rs`
- Modify: `crates/cloudflare-rs/src/api/mod.rs`
- Test: `crates/cloudflare-rs/tests/tokens_test.rs`

**Interfaces:**
- Consumes: `CloudflareClient::get_paginated` (Task 2).
- Produces: `client.tokens().list() -> Result<Vec<ApiToken>, CloudflareError>`, used by `CloudflareApiTokensCollector` (Task 13) and already exercised by `client_test.rs` (Task 2).

- [ ] **Step 1: Write the failing test**

```rust
// crates/cloudflare-rs/tests/tokens_test.rs
use cloudflare_rs::CloudflareClient;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn list_parses_optional_expiry_and_last_used_fields() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/user/tokens"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "errors": [],
            "result": [
                {
                    "id": "tok-1",
                    "name": "Evidence Collector",
                    "status": "active",
                    "issued_on": "2026-01-01T00:00:00Z",
                    "modified_on": "2026-01-01T00:00:00Z",
                    "last_used_on": "2026-07-01T00:00:00Z",
                    "expires_on": "2027-01-01T00:00:00Z",
                    "policies": []
                },
                {
                    "id": "tok-2",
                    "name": "No Expiry",
                    "status": "active",
                    "issued_on": "2026-02-01T00:00:00Z",
                    "modified_on": "2026-02-01T00:00:00Z",
                    "policies": []
                }
            ],
            "result_info": {"page": 1, "per_page": 50, "total_count": 2}
        })))
        .mount(&server)
        .await;

    let client = CloudflareClient::with_base_url(&server.uri(), "test-token").unwrap();
    let tokens = client.tokens().list().await.unwrap();

    assert_eq!(tokens.len(), 2);
    assert_eq!(tokens[0].last_used_on.as_deref(), Some("2026-07-01T00:00:00Z"));
    assert_eq!(tokens[0].expires_on.as_deref(), Some("2027-01-01T00:00:00Z"));
    assert_eq!(tokens[1].last_used_on, None);
    assert_eq!(tokens[1].expires_on, None);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p cloudflare-rs --test tokens_test`
Expected: FAIL — `crate::api::TokensApi` doesn't exist yet (compile error).

- [ ] **Step 3: Add the type**

```rust
// crates/cloudflare-rs/src/types/token.rs
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct ApiToken {
    pub id: String,
    pub name: String,
    pub status: String,
    #[serde(default)]
    pub issued_on: String,
    #[serde(default)]
    pub modified_on: String,
    #[serde(default)]
    pub last_used_on: Option<String>,
    #[serde(default)]
    pub expires_on: Option<String>,
    #[serde(default)]
    pub policies: serde_json::Value,
}
```

Edit `crates/cloudflare-rs/src/types/mod.rs`:

```rust
// crates/cloudflare-rs/src/types/mod.rs
pub mod member;
pub mod role;
pub mod token;
```

- [ ] **Step 4: Implement `TokensApi`**

```rust
// crates/cloudflare-rs/src/api/tokens.rs
use crate::client::CloudflareClient;
use crate::error::CloudflareError;
use crate::types::token::ApiToken;

pub struct TokensApi<'c>(pub(crate) &'c CloudflareClient);

impl<'c> TokensApi<'c> {
    /// GET /user/tokens — API tokens owned by the authenticated user.
    pub async fn list(&self) -> Result<Vec<ApiToken>, CloudflareError> {
        self.0.get_paginated("/user/tokens").await
    }
}
```

Edit `crates/cloudflare-rs/src/api/mod.rs`:

```rust
// crates/cloudflare-rs/src/api/mod.rs
pub mod accounts;
pub mod tokens;

pub use accounts::AccountsApi;
pub use tokens::TokensApi;
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cargo test -p cloudflare-rs --test tokens_test`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/cloudflare-rs/src/types/token.rs crates/cloudflare-rs/src/types/mod.rs crates/cloudflare-rs/src/api/tokens.rs crates/cloudflare-rs/src/api/mod.rs crates/cloudflare-rs/tests/tokens_test.rs
git commit -m "feat(cloudflare-rs): Tokens API"
```

---

### Task 5: Zones API — zones, DNS records, SSL/TLS settings + types

**Files:**
- Create: `crates/cloudflare-rs/src/types/zone.rs`
- Create: `crates/cloudflare-rs/src/types/zone_settings.rs`
- Modify: `crates/cloudflare-rs/src/types/mod.rs`
- Create: `crates/cloudflare-rs/src/api/zones.rs`
- Modify: `crates/cloudflare-rs/src/api/mod.rs`
- Test: `crates/cloudflare-rs/tests/zones_test.rs`

**Interfaces:**
- Consumes: `CloudflareClient::get_paginated`, `CloudflareClient::get_result` (Task 2).
- Produces: `client.zones().list(account_id) -> Result<Vec<Zone>, CloudflareError>`, `client.zones().list_dns_records(zone_id) -> Result<Vec<DnsRecord>, CloudflareError>`, `client.zones().ssl_tls_settings(zone_id, zone_name) -> Result<ZoneSslSettings, CloudflareError>` — used by `CloudflareZonesCollector` (Task 14), `CloudflareDnsRecordsCollector` (Task 15), `CloudflareSslTlsSettingsCollector` (Task 16), and internally by `CloudflareWafRulesetsCollector`/`CloudflareAuditLogsCollector`'s "list zones first" step.

- [ ] **Step 1: Write the failing test**

```rust
// crates/cloudflare-rs/tests/zones_test.rs
use cloudflare_rs::CloudflareClient;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn setting_response(id: &str, value: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "success": true,
        "errors": [],
        "result": {"id": id, "value": value}
    })
}

#[tokio::test]
async fn ssl_tls_settings_assembles_all_five_sub_settings() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/zones/zone-1/settings/ssl"))
        .respond_with(ResponseTemplate::new(200).set_body_json(setting_response("ssl", serde_json::json!("full"))))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/zones/zone-1/settings/min_tls_version"))
        .respond_with(ResponseTemplate::new(200).set_body_json(setting_response("min_tls_version", serde_json::json!("1.2"))))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/zones/zone-1/settings/tls_1_3"))
        .respond_with(ResponseTemplate::new(200).set_body_json(setting_response("tls_1_3", serde_json::json!("on"))))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/zones/zone-1/settings/always_use_https"))
        .respond_with(ResponseTemplate::new(200).set_body_json(setting_response("always_use_https", serde_json::json!("on"))))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/zones/zone-1/settings/automatic_https_rewrites"))
        .respond_with(ResponseTemplate::new(200).set_body_json(setting_response("automatic_https_rewrites", serde_json::json!("off"))))
        .mount(&server)
        .await;

    let client = CloudflareClient::with_base_url(&server.uri(), "test-token").unwrap();
    let settings = client
        .zones()
        .ssl_tls_settings("zone-1", "example.com")
        .await
        .unwrap();

    assert_eq!(settings.zone_id, "zone-1");
    assert_eq!(settings.zone_name, "example.com");
    assert_eq!(settings.ssl_mode, serde_json::json!("full"));
    assert_eq!(settings.min_tls_version, serde_json::json!("1.2"));
    assert_eq!(settings.tls_1_3, serde_json::json!("on"));
    assert_eq!(settings.always_use_https, serde_json::json!("on"));
    assert_eq!(settings.automatic_https_rewrites, serde_json::json!("off"));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p cloudflare-rs --test zones_test`
Expected: FAIL — `crate::api::ZonesApi` doesn't exist yet (compile error).

- [ ] **Step 3: Add the types**

```rust
// crates/cloudflare-rs/src/types/zone.rs
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Zone {
    pub id: String,
    pub name: String,
    pub status: String,
    #[serde(default)]
    pub paused: bool,
    #[serde(default)]
    pub name_servers: Vec<String>,
    #[serde(default)]
    pub created_on: String,
    #[serde(default)]
    pub activated_on: Option<String>,
    pub plan: ZonePlan,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ZonePlan {
    #[serde(default)]
    pub name: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DnsRecord {
    pub id: String,
    #[serde(rename = "type")]
    pub record_type: String,
    pub name: String,
    #[serde(default)]
    pub content: String,
    #[serde(default)]
    pub ttl: i64,
    #[serde(default)]
    pub proxied: bool,
    #[serde(default)]
    pub created_on: String,
    #[serde(default)]
    pub modified_on: String,
}
```

```rust
// crates/cloudflare-rs/src/types/zone_settings.rs
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ZoneSettingValue {
    #[allow(dead_code)]
    pub id: String,
    pub value: serde_json::Value,
}

/// The five SSL/TLS-related zone settings that matter for compliance
/// evidence, bundled into one document per zone.
#[derive(Debug, Clone, Serialize)]
pub struct ZoneSslSettings {
    pub zone_id: String,
    pub zone_name: String,
    pub ssl_mode: serde_json::Value,
    pub min_tls_version: serde_json::Value,
    pub tls_1_3: serde_json::Value,
    pub always_use_https: serde_json::Value,
    pub automatic_https_rewrites: serde_json::Value,
}
```

Edit `crates/cloudflare-rs/src/types/mod.rs`:

```rust
// crates/cloudflare-rs/src/types/mod.rs
pub mod member;
pub mod role;
pub mod token;
pub mod zone;
pub mod zone_settings;
```

- [ ] **Step 4: Implement `ZonesApi`**

```rust
// crates/cloudflare-rs/src/api/zones.rs
use crate::client::CloudflareClient;
use crate::error::CloudflareError;
use crate::types::zone::{DnsRecord, Zone};
use crate::types::zone_settings::{ZoneSettingValue, ZoneSslSettings};

pub struct ZonesApi<'c>(pub(crate) &'c CloudflareClient);

impl<'c> ZonesApi<'c> {
    /// GET /zones?account.id={account_id} — every zone under the account.
    pub async fn list(&self, account_id: &str) -> Result<Vec<Zone>, CloudflareError> {
        self.0
            .get_paginated(&format!("/zones?account.id={account_id}"))
            .await
    }

    /// GET /zones/{zone_id}/dns_records — every DNS record in one zone.
    pub async fn list_dns_records(&self, zone_id: &str) -> Result<Vec<DnsRecord>, CloudflareError> {
        self.0
            .get_paginated(&format!("/zones/{zone_id}/dns_records"))
            .await
    }

    /// Fetch the five SSL/TLS settings that matter for compliance evidence,
    /// combining them into one document per zone.
    pub async fn ssl_tls_settings(
        &self,
        zone_id: &str,
        zone_name: &str,
    ) -> Result<ZoneSslSettings, CloudflareError> {
        let ssl_mode = self.setting(zone_id, "ssl").await?;
        let min_tls_version = self.setting(zone_id, "min_tls_version").await?;
        let tls_1_3 = self.setting(zone_id, "tls_1_3").await?;
        let always_use_https = self.setting(zone_id, "always_use_https").await?;
        let automatic_https_rewrites = self.setting(zone_id, "automatic_https_rewrites").await?;

        Ok(ZoneSslSettings {
            zone_id: zone_id.to_string(),
            zone_name: zone_name.to_string(),
            ssl_mode,
            min_tls_version,
            tls_1_3,
            always_use_https,
            automatic_https_rewrites,
        })
    }

    async fn setting(
        &self,
        zone_id: &str,
        setting_id: &str,
    ) -> Result<serde_json::Value, CloudflareError> {
        let path = format!("/zones/{zone_id}/settings/{setting_id}");
        let value: ZoneSettingValue = self.0.get_result(&path).await?;
        Ok(value.value)
    }
}
```

Edit `crates/cloudflare-rs/src/api/mod.rs`:

```rust
// crates/cloudflare-rs/src/api/mod.rs
pub mod accounts;
pub mod tokens;
pub mod zones;

pub use accounts::AccountsApi;
pub use tokens::TokensApi;
pub use zones::ZonesApi;
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cargo test -p cloudflare-rs --test zones_test`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/cloudflare-rs/src/types/zone.rs crates/cloudflare-rs/src/types/zone_settings.rs crates/cloudflare-rs/src/types/mod.rs crates/cloudflare-rs/src/api/zones.rs crates/cloudflare-rs/src/api/mod.rs crates/cloudflare-rs/tests/zones_test.rs
git commit -m "feat(cloudflare-rs): Zones API — zones, DNS records, SSL/TLS settings"
```

---

### Task 6: Firewall API — custom + managed WAF rulesets + types

**Files:**
- Create: `crates/cloudflare-rs/src/types/ruleset.rs`
- Modify: `crates/cloudflare-rs/src/types/mod.rs`
- Create: `crates/cloudflare-rs/src/api/firewall.rs`
- Modify: `crates/cloudflare-rs/src/api/mod.rs`
- Test: `crates/cloudflare-rs/tests/firewall_test.rs`

**Interfaces:**
- Consumes: `CloudflareClient::get_result` (Task 2).
- Produces: `client.firewall().custom_ruleset(zone_id) -> Result<Option<Ruleset>, CloudflareError>` and `client.firewall().managed_ruleset(zone_id) -> Result<Option<Ruleset>, CloudflareError>`, used by `CloudflareWafRulesetsCollector` (Task 17).

- [ ] **Step 1: Write the failing test**

```rust
// crates/cloudflare-rs/tests/firewall_test.rs
use cloudflare_rs::CloudflareClient;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn custom_ruleset_returns_some_when_configured() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/zones/zone-1/rulesets/phases/http_request_firewall_custom/entrypoint"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "errors": [],
            "result": {
                "id": "ruleset-1",
                "name": "default",
                "phase": "http_request_firewall_custom",
                "rules": [{"action": "block", "expression": "ip.src eq 1.2.3.4"}]
            }
        })))
        .mount(&server)
        .await;

    let client = CloudflareClient::with_base_url(&server.uri(), "test-token").unwrap();
    let ruleset = client.firewall().custom_ruleset("zone-1").await.unwrap();

    assert!(ruleset.is_some());
    assert_eq!(ruleset.unwrap().id, "ruleset-1");
}

#[tokio::test]
async fn managed_ruleset_returns_none_on_http_404() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/zones/zone-2/rulesets/phases/http_request_firewall_managed/entrypoint"))
        .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
            "success": false,
            "errors": [{"code": 10001, "message": "no entrypoint ruleset for phase"}],
            "result": null
        })))
        .mount(&server)
        .await;

    let client = CloudflareClient::with_base_url(&server.uri(), "test-token").unwrap();
    let ruleset = client.firewall().managed_ruleset("zone-2").await.unwrap();

    assert!(ruleset.is_none());
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p cloudflare-rs --test firewall_test`
Expected: FAIL — `crate::api::FirewallApi` doesn't exist yet (compile error).

- [ ] **Step 3: Add the type**

```rust
// crates/cloudflare-rs/src/types/ruleset.rs
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Ruleset {
    pub id: String,
    pub name: String,
    pub phase: String,
    #[serde(default)]
    pub rules: serde_json::Value,
}
```

Edit `crates/cloudflare-rs/src/types/mod.rs`:

```rust
// crates/cloudflare-rs/src/types/mod.rs
pub mod member;
pub mod role;
pub mod ruleset;
pub mod token;
pub mod zone;
pub mod zone_settings;
```

- [ ] **Step 4: Implement `FirewallApi`**

```rust
// crates/cloudflare-rs/src/api/firewall.rs
use crate::client::CloudflareClient;
use crate::error::CloudflareError;
use crate::types::ruleset::Ruleset;

pub struct FirewallApi<'c>(pub(crate) &'c CloudflareClient);

impl<'c> FirewallApi<'c> {
    /// GET /zones/{zone_id}/rulesets/phases/http_request_firewall_custom/entrypoint
    /// The zone's custom WAF rules, if any are configured.
    pub async fn custom_ruleset(&self, zone_id: &str) -> Result<Option<Ruleset>, CloudflareError> {
        self.phase_entrypoint(zone_id, "http_request_firewall_custom")
            .await
    }

    /// GET /zones/{zone_id}/rulesets/phases/http_request_firewall_managed/entrypoint
    /// Which Cloudflare-managed WAF rulesets are deployed and how they're configured.
    pub async fn managed_ruleset(&self, zone_id: &str) -> Result<Option<Ruleset>, CloudflareError> {
        self.phase_entrypoint(zone_id, "http_request_firewall_managed")
            .await
    }

    async fn phase_entrypoint(
        &self,
        zone_id: &str,
        phase: &str,
    ) -> Result<Option<Ruleset>, CloudflareError> {
        let path = format!("/zones/{zone_id}/rulesets/phases/{phase}/entrypoint");
        match self.0.get_result::<Ruleset>(&path).await {
            Ok(r) => Ok(Some(r)),
            Err(CloudflareError::Api { status: 404, .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }
}
```

Edit `crates/cloudflare-rs/src/api/mod.rs`:

```rust
// crates/cloudflare-rs/src/api/mod.rs
pub mod accounts;
pub mod firewall;
pub mod tokens;
pub mod zones;

pub use accounts::AccountsApi;
pub use firewall::FirewallApi;
pub use tokens::TokensApi;
pub use zones::ZonesApi;
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cargo test -p cloudflare-rs --test firewall_test`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/cloudflare-rs/src/types/ruleset.rs crates/cloudflare-rs/src/types/mod.rs crates/cloudflare-rs/src/api/firewall.rs crates/cloudflare-rs/src/api/mod.rs crates/cloudflare-rs/tests/firewall_test.rs
git commit -m "feat(cloudflare-rs): Firewall API — custom and managed WAF rulesets"
```

---

### Task 7: Audit Logs API + types

**Files:**
- Create: `crates/cloudflare-rs/src/types/audit_log.rs`
- Modify: `crates/cloudflare-rs/src/types/mod.rs`
- Create: `crates/cloudflare-rs/src/api/audit_logs.rs`
- Modify: `crates/cloudflare-rs/src/api/mod.rs`
- Test: `crates/cloudflare-rs/tests/audit_logs_test.rs`

**Interfaces:**
- Consumes: `CloudflareClient::get_paginated` (Task 2).
- Produces: `client.audit_logs().list(account_id, since, before) -> Result<Vec<AuditLogEntry>, CloudflareError>`, used by `CloudflareAuditLogsCollector` (Task 18). This is the last crate task — the crate is feature-complete after this.

- [ ] **Step 1: Write the failing test**

```rust
// crates/cloudflare-rs/tests/audit_logs_test.rs
use cloudflare_rs::CloudflareClient;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn list_sends_since_before_and_parses_nested_fields() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/accounts/acct-1/audit_logs"))
        .and(query_param("since", "2026-01-01T00:00:00Z"))
        .and(query_param("before", "2026-02-01T00:00:00Z"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "errors": [],
            "result": [{
                "id": "log-1",
                "when": "2026-01-15T12:00:00Z",
                "action": {"type": "update"},
                "actor": {"email": "admin@example.com", "type": "user"},
                "resource": {"type": "zone", "id": "zone-1"},
                "new_value": {"ssl": "full"}
            }],
            "result_info": {"page": 1, "per_page": 50, "total_count": 1}
        })))
        .mount(&server)
        .await;

    let client = CloudflareClient::with_base_url(&server.uri(), "test-token").unwrap();
    let entries = client
        .audit_logs()
        .list("acct-1", "2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z")
        .await
        .unwrap();

    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].id, "log-1");
    assert_eq!(entries[0].action.action_type, "update");
    assert_eq!(entries[0].actor.email.as_deref(), Some("admin@example.com"));
    assert_eq!(entries[0].actor.actor_type, "user");
    assert_eq!(entries[0].resource.resource_type, "zone");
    assert_eq!(entries[0].resource.id.as_deref(), Some("zone-1"));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p cloudflare-rs --test audit_logs_test`
Expected: FAIL — `crate::api::AuditLogsApi` doesn't exist yet (compile error).

- [ ] **Step 3: Add the types**

```rust
// crates/cloudflare-rs/src/types/audit_log.rs
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct AuditLogEntry {
    pub id: String,
    pub when: String,
    pub action: AuditAction,
    pub actor: AuditActor,
    pub resource: AuditResource,
    #[serde(default)]
    pub new_value: serde_json::Value,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuditAction {
    #[serde(rename = "type")]
    pub action_type: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuditActor {
    #[serde(default)]
    pub email: Option<String>,
    #[serde(rename = "type")]
    pub actor_type: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuditResource {
    #[serde(rename = "type")]
    pub resource_type: String,
    #[serde(default)]
    pub id: Option<String>,
}
```

Edit `crates/cloudflare-rs/src/types/mod.rs`:

```rust
// crates/cloudflare-rs/src/types/mod.rs
pub mod audit_log;
pub mod member;
pub mod role;
pub mod ruleset;
pub mod token;
pub mod zone;
pub mod zone_settings;
```

- [ ] **Step 4: Implement `AuditLogsApi`**

```rust
// crates/cloudflare-rs/src/api/audit_logs.rs
use crate::client::CloudflareClient;
use crate::error::CloudflareError;
use crate::types::audit_log::AuditLogEntry;

pub struct AuditLogsApi<'c>(pub(crate) &'c CloudflareClient);

impl<'c> AuditLogsApi<'c> {
    /// GET /accounts/{account_id}/audit_logs?since=...&before=... (RFC3339 timestamps).
    pub async fn list(
        &self,
        account_id: &str,
        since: &str,
        before: &str,
    ) -> Result<Vec<AuditLogEntry>, CloudflareError> {
        self.0
            .get_paginated(&format!(
                "/accounts/{account_id}/audit_logs?since={since}&before={before}"
            ))
            .await
    }
}
```

Edit `crates/cloudflare-rs/src/api/mod.rs`:

```rust
// crates/cloudflare-rs/src/api/mod.rs
pub mod accounts;
pub mod audit_logs;
pub mod firewall;
pub mod tokens;
pub mod zones;

pub use accounts::AccountsApi;
pub use audit_logs::AuditLogsApi;
pub use firewall::FirewallApi;
pub use tokens::TokensApi;
pub use zones::ZonesApi;
```

- [ ] **Step 5: Run the full crate test suite to verify everything passes**

Run: `cargo test -p cloudflare-rs`
Expected: PASS — all tests across `client_test.rs`, `accounts_test.rs`, `tokens_test.rs`, `zones_test.rs`, `firewall_test.rs`, and `audit_logs_test.rs`.

Run: `cargo build -p cloudflare-rs`
Expected: builds cleanly — this is the first point the crate is fully feature-complete (Task 2's stub `api`/`types` modules are now fully populated).

- [ ] **Step 6: Commit**

```bash
git add crates/cloudflare-rs/src/types/audit_log.rs crates/cloudflare-rs/src/types/mod.rs crates/cloudflare-rs/src/api/audit_logs.rs crates/cloudflare-rs/src/api/mod.rs crates/cloudflare-rs/tests/audit_logs_test.rs
git commit -m "feat(cloudflare-rs): Audit Logs API"
```

---

### Task 8: Add `Cloudflare` variant to `CloudProvider`

**Files:**
- Modify: `src/providers/mod.rs`

**Interfaces:**
- Consumes: nothing new.
- Produces: `CloudProvider::Cloudflare`, consumed by every remaining task in this plan.

- [ ] **Step 1: Add the module declaration and enum variant**

Edit `src/providers/mod.rs`:

```rust
pub mod aws;

#[cfg(feature = "azure")]
pub mod azure;

#[cfg(feature = "gcp")]
pub mod gcp;

#[cfg(feature = "tenable")]
pub mod tenable;

#[cfg(feature = "okta")]
pub mod okta;

#[cfg(feature = "jira")]
pub mod jira;

#[cfg(feature = "cloudflare")]
pub mod cloudflare;
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
    Cloudflare,
}
```

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
            CloudProvider::Cloudflare => write!(f, "Cloudflare"),
        }
    }
}
```

- [ ] **Step 2: Verify the build**

Run: `cargo check` (the `#[cfg(feature = "cloudflare")] pub mod cloudflare;` line references a module that doesn't exist yet — Task 10 creates it)
Expected: FAIL — `unresolved module cloudflare`. This is expected; proceed to Task 9 and 10 before the tree compiles again. If you want a green check right now, temporarily comment out the `pub mod cloudflare;` line, verify, then uncomment before moving on — otherwise just continue, since Task 10 resolves it.

- [ ] **Step 3: Commit**

```bash
git add src/providers/mod.rs
git commit -m "feat(providers): add CloudProvider::Cloudflare variant"
```

---

### Task 9: Account config fields + `cloudflare-config.toml` merge + env resolvers

**Files:**
- Modify: `src/app_config.rs`

**Interfaces:**
- Consumes: nothing new.
- Produces: `Account::cloudflare_account_id_resolved() -> Option<String>` and `Account::cloudflare_api_token_resolved() -> Option<String>`, consumed by `tui_session.rs` (Task 23). `load_config()` now also merges `cloudflare-config.toml`.

- [ ] **Step 1: Add the Cloudflare fields to `Account`**

Edit `src/app_config.rs`, after the Jira fields block:

```rust
    // ------------------------------------------------------------------
    // Jira fields
    // ------------------------------------------------------------------
    /// Jira Cloud tenant base URL (e.g. `https://acme.atlassian.net`).
    pub jira_domain: Option<String>,

    /// Jira account email (used as the username half of Basic auth).
    /// Can also be supplied via `JIRA_EMAIL` env var (env wins over TOML).
    pub jira_email: Option<String>,

    /// Jira API token.
    /// Can also be supplied via `JIRA_API_TOKEN` env var (env wins over TOML).
    pub jira_api_token: Option<String>,

    // ------------------------------------------------------------------
    // Cloudflare fields
    // ------------------------------------------------------------------
    /// Cloudflare account ID (32-character hex string, shown in the
    /// Cloudflare dashboard sidebar).
    /// Can also be supplied via `CLOUDFLARE_ACCOUNT_ID` env var (env wins over TOML).
    pub cloudflare_account_id: Option<String>,

    /// Cloudflare API Token (Bearer auth).
    /// Can also be supplied via `CLOUDFLARE_API_TOKEN` env var (env wins over TOML).
    pub cloudflare_api_token: Option<String>,
```

- [ ] **Step 2: Add the resolver methods**

Edit `src/app_config.rs`, in `impl Account`, after `jira_domain_resolved`:

```rust
    /// Resolve Cloudflare account ID: env var takes precedence over TOML.
    pub fn cloudflare_account_id_resolved(&self) -> Option<String> {
        std::env::var("CLOUDFLARE_ACCOUNT_ID")
            .ok()
            .or_else(|| self.cloudflare_account_id.clone())
    }

    /// Resolve Cloudflare API token: env var takes precedence over TOML.
    pub fn cloudflare_api_token_resolved(&self) -> Option<String> {
        std::env::var("CLOUDFLARE_API_TOKEN")
            .ok()
            .or_else(|| self.cloudflare_api_token.clone())
    }
```

- [ ] **Step 3: Merge `cloudflare-config.toml` in `load_config()`**

Edit `src/app_config.rs`, after the `jira-config.toml` merge block:

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

    // Merge cloudflare-config.toml accounts if present
    let cloudflare_path = PathBuf::from("cloudflare-config.toml");
    if cloudflare_path.exists() {
        if let Ok(contents) = fs::read_to_string(&cloudflare_path) {
            if let Ok(cloudflare_cfg) = toml::from_str::<AppConfig>(&contents) {
                cfg.account.extend(cloudflare_cfg.account);
            }
        }
    }
```

Also update the doc comment immediately above `load_config()`:

```rust
/// After loading the primary config, `./tenable-config.toml`, `./okta-config.toml`,
/// `./jira-config.toml`, and `./cloudflare-config.toml` are merged in (accounts only)
/// if those files exist.
```

- [ ] **Step 4: Verify the build**

Run: `cargo check`
Expected: PASS (this file has no dependency on the not-yet-created `providers::cloudflare` module).

- [ ] **Step 5: Commit**

```bash
git add src/app_config.rs
git commit -m "feat(config): add Cloudflare account fields, resolvers, and config merge"
```

---

### Task 10: `providers/cloudflare` skeleton + `CloudflareProviderFactory`

**Files:**
- Create: `src/providers/cloudflare/mod.rs`
- Create: `src/providers/cloudflare/factory.rs`

**Interfaces:**
- Consumes: `cloudflare_rs::CloudflareClient` (Task 7), `CloudProvider::Cloudflare` (Task 8), `crate::evidence::{CsvCollector, JsonCollector, EvidenceCollector, ProviderFactory}`.
- Produces: `CloudflareProviderFactory::new(client: CloudflareClient, account_id: String, selected: Vec<String>) -> Self`, consumed by `tui_session.rs` (Task 23). Collector modules referenced in `factory.rs` (`account_members`, `account_roles`, `api_tokens`, `zones`, `dns_records`, `ssl_tls_settings`, `waf_rulesets`, `audit_logs`) are stubbed as empty files here and filled in by Tasks 11–18.

- [ ] **Step 1: Create the module skeleton and stub collector files**

```rust
// src/providers/cloudflare/mod.rs
pub mod factory;

pub mod account_members;
pub mod account_roles;
pub mod api_tokens;
pub mod audit_logs;
pub mod dns_records;
pub mod ssl_tls_settings;
pub mod waf_rulesets;
pub mod zones;
```

Create eight empty stub files — Tasks 11–18 fill each one in:

```rust
// src/providers/cloudflare/account_members.rs
```

```rust
// src/providers/cloudflare/account_roles.rs
```

```rust
// src/providers/cloudflare/api_tokens.rs
```

```rust
// src/providers/cloudflare/zones.rs
```

```rust
// src/providers/cloudflare/dns_records.rs
```

```rust
// src/providers/cloudflare/ssl_tls_settings.rs
```

```rust
// src/providers/cloudflare/waf_rulesets.rs
```

```rust
// src/providers/cloudflare/audit_logs.rs
```

- [ ] **Step 2: Implement `CloudflareProviderFactory`**

```rust
// src/providers/cloudflare/factory.rs
use cloudflare_rs::CloudflareClient;

use crate::evidence::{CsvCollector, EvidenceCollector, JsonCollector};
use crate::providers::{CloudProvider, ProviderFactory};

pub struct CloudflareProviderFactory {
    client: CloudflareClient,
    account_id: String,
    selected: Vec<String>,
}

impl CloudflareProviderFactory {
    pub fn new(client: CloudflareClient, account_id: String, selected: Vec<String>) -> Self {
        Self {
            client,
            account_id,
            selected,
        }
    }
}

impl ProviderFactory for CloudflareProviderFactory {
    fn provider(&self) -> CloudProvider {
        CloudProvider::Cloudflare
    }
    fn account_id(&self) -> &str {
        &self.account_id
    }
    fn region(&self) -> &str {
        ""
    }

    fn csv_collectors(&self) -> Vec<Box<dyn CsvCollector>> {
        let mut v: Vec<Box<dyn CsvCollector>> = Vec::new();
        if self.selected.iter().any(|s| s == "cloudflare-account-members") {
            v.push(Box::new(
                super::account_members::CloudflareAccountMembersCollector::new(
                    self.client.clone(),
                ),
            ));
        }
        if self.selected.iter().any(|s| s == "cloudflare-api-tokens") {
            v.push(Box::new(super::api_tokens::CloudflareApiTokensCollector::new(
                self.client.clone(),
            )));
        }
        if self.selected.iter().any(|s| s == "cloudflare-zones") {
            v.push(Box::new(super::zones::CloudflareZonesCollector::new(
                self.client.clone(),
            )));
        }
        if self.selected.iter().any(|s| s == "cloudflare-dns-records") {
            v.push(Box::new(super::dns_records::CloudflareDnsRecordsCollector::new(
                self.client.clone(),
            )));
        }
        if self.selected.iter().any(|s| s == "cloudflare-audit-logs") {
            v.push(Box::new(super::audit_logs::CloudflareAuditLogsCollector::new(
                self.client.clone(),
            )));
        }
        v
    }

    fn json_collectors(&self) -> Vec<Box<dyn JsonCollector>> {
        let mut v: Vec<Box<dyn JsonCollector>> = Vec::new();
        if self.selected.iter().any(|s| s == "cloudflare-account-roles") {
            v.push(Box::new(
                super::account_roles::CloudflareAccountRolesCollector::new(self.client.clone()),
            ));
        }
        if self
            .selected
            .iter()
            .any(|s| s == "cloudflare-ssl-tls-settings")
        {
            v.push(Box::new(
                super::ssl_tls_settings::CloudflareSslTlsSettingsCollector::new(
                    self.client.clone(),
                ),
            ));
        }
        if self.selected.iter().any(|s| s == "cloudflare-waf-rulesets") {
            v.push(Box::new(
                super::waf_rulesets::CloudflareWafRulesetsCollector::new(self.client.clone()),
            ));
        }
        v
    }

    fn evidence_collectors(&self) -> Vec<Box<dyn EvidenceCollector>> {
        Vec::new()
    }
}
```

- [ ] **Step 3: Verify the build**

Run: `cargo check --features cloudflare`
Expected: FAIL — `factory.rs` references `super::account_members::CloudflareAccountMembersCollector`, which doesn't exist yet (the stub files are empty). This is expected; Tasks 11–18 fill them in one at a time. Proceed to Task 11.

- [ ] **Step 4: Commit**

```bash
git add src/providers/cloudflare/mod.rs src/providers/cloudflare/factory.rs src/providers/cloudflare/account_members.rs src/providers/cloudflare/account_roles.rs src/providers/cloudflare/api_tokens.rs src/providers/cloudflare/zones.rs src/providers/cloudflare/dns_records.rs src/providers/cloudflare/ssl_tls_settings.rs src/providers/cloudflare/waf_rulesets.rs src/providers/cloudflare/audit_logs.rs
git commit -m "feat(cloudflare): provider module skeleton and CloudflareProviderFactory"
```

---

### Task 11: `CloudflareAccountMembersCollector` (CSV)

**Files:**
- Modify: `src/providers/cloudflare/account_members.rs`

**Interfaces:**
- Consumes: `cloudflare_rs::CloudflareClient::accounts().list_members()` (Task 3).
- Produces: `CloudflareAccountMembersCollector::new(client: CloudflareClient) -> Self`, referenced by `factory.rs` (Task 10).

- [ ] **Step 1: Implement the collector**

```rust
// src/providers/cloudflare/account_members.rs
use anyhow::Result;
use async_trait::async_trait;

use cloudflare_rs::CloudflareClient;

use crate::evidence::CsvCollector;

pub struct CloudflareAccountMembersCollector {
    client: CloudflareClient,
}

impl CloudflareAccountMembersCollector {
    pub fn new(client: CloudflareClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for CloudflareAccountMembersCollector {
    fn name(&self) -> &str {
        "Cloudflare Account Members"
    }

    fn filename_prefix(&self) -> &str {
        "Cloudflare_Account_Members"
    }

    fn headers(&self) -> &'static [&'static str] {
        &["Member ID", "Email", "Status", "Two-Factor Enabled", "Roles"]
    }

    async fn collect_rows(
        &self,
        account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let members = match self.client.accounts().list_members(account_id).await {
            Ok(m) => m,
            Err(cloudflare_rs::CloudflareError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };

        let rows = members
            .into_iter()
            .map(|m| {
                let roles = m
                    .roles
                    .iter()
                    .map(|r| r.name.clone())
                    .collect::<Vec<_>>()
                    .join("; ");
                vec![
                    m.id,
                    m.user.email,
                    m.status,
                    if m.user.two_factor_authentication_enabled {
                        "YES".to_string()
                    } else {
                        "NO".to_string()
                    },
                    roles,
                ]
            })
            .collect();

        Ok(rows)
    }
}
```

- [ ] **Step 2: Verify the build**

Run: `cargo check --features cloudflare`
Expected: still FAIL — Tasks 12–18's stub files are still empty and `factory.rs` references all of them. Continue to Task 12.

- [ ] **Step 3: Commit**

```bash
git add src/providers/cloudflare/account_members.rs
git commit -m "feat(cloudflare): Account Members collector"
```

---

### Task 12: `CloudflareAccountRolesCollector` (JSON)

**Files:**
- Modify: `src/providers/cloudflare/account_roles.rs`

**Interfaces:**
- Consumes: `cloudflare_rs::CloudflareClient::accounts().list_roles()` (Task 3).
- Produces: `CloudflareAccountRolesCollector::new(client: CloudflareClient) -> Self`, referenced by `factory.rs` (Task 10).

- [ ] **Step 1: Implement the collector**

```rust
// src/providers/cloudflare/account_roles.rs
use anyhow::Result;
use async_trait::async_trait;

use cloudflare_rs::CloudflareClient;

use crate::evidence::JsonCollector;

pub struct CloudflareAccountRolesCollector {
    client: CloudflareClient,
}

impl CloudflareAccountRolesCollector {
    pub fn new(client: CloudflareClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl JsonCollector for CloudflareAccountRolesCollector {
    fn name(&self) -> &str {
        "Cloudflare Account Roles"
    }

    fn filename_prefix(&self) -> &str {
        "Cloudflare_Account_Roles"
    }

    async fn collect_records(
        &self,
        account_id: &str,
        _region: &str,
    ) -> Result<Vec<serde_json::Value>> {
        let roles = match self.client.accounts().list_roles(account_id).await {
            Ok(r) => r,
            Err(cloudflare_rs::CloudflareError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };

        roles
            .into_iter()
            .map(|r| serde_json::to_value(r).map_err(anyhow::Error::from))
            .collect()
    }
}
```

- [ ] **Step 2: Commit**

```bash
git add src/providers/cloudflare/account_roles.rs
git commit -m "feat(cloudflare): Account Roles collector"
```

---

### Task 13: `CloudflareApiTokensCollector` (CSV)

**Files:**
- Modify: `src/providers/cloudflare/api_tokens.rs`

**Interfaces:**
- Consumes: `cloudflare_rs::CloudflareClient::tokens().list()` (Task 4).
- Produces: `CloudflareApiTokensCollector::new(client: CloudflareClient) -> Self`, referenced by `factory.rs` (Task 10).

- [ ] **Step 1: Implement the collector**

```rust
// src/providers/cloudflare/api_tokens.rs
use anyhow::Result;
use async_trait::async_trait;

use cloudflare_rs::CloudflareClient;

use crate::evidence::CsvCollector;

pub struct CloudflareApiTokensCollector {
    client: CloudflareClient,
}

impl CloudflareApiTokensCollector {
    pub fn new(client: CloudflareClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for CloudflareApiTokensCollector {
    fn name(&self) -> &str {
        "Cloudflare API Tokens"
    }

    fn filename_prefix(&self) -> &str {
        "Cloudflare_API_Tokens"
    }

    fn headers(&self) -> &'static [&'static str] {
        &[
            "Token ID",
            "Name",
            "Status",
            "Issued On",
            "Modified On",
            "Last Used On",
            "Expires On",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let tokens = match self.client.tokens().list().await {
            Ok(t) => t,
            Err(cloudflare_rs::CloudflareError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };

        let rows = tokens
            .into_iter()
            .map(|t| {
                vec![
                    t.id,
                    t.name,
                    t.status,
                    t.issued_on,
                    t.modified_on,
                    t.last_used_on.unwrap_or_default(),
                    t.expires_on.unwrap_or_default(),
                ]
            })
            .collect();

        Ok(rows)
    }
}
```

- [ ] **Step 2: Commit**

```bash
git add src/providers/cloudflare/api_tokens.rs
git commit -m "feat(cloudflare): API Tokens collector"
```

---

### Task 14: `CloudflareZonesCollector` (CSV)

**Files:**
- Modify: `src/providers/cloudflare/zones.rs`

**Interfaces:**
- Consumes: `cloudflare_rs::CloudflareClient::zones().list()` (Task 5).
- Produces: `CloudflareZonesCollector::new(client: CloudflareClient) -> Self`, referenced by `factory.rs` (Task 10).

- [ ] **Step 1: Implement the collector**

```rust
// src/providers/cloudflare/zones.rs
use anyhow::Result;
use async_trait::async_trait;

use cloudflare_rs::CloudflareClient;

use crate::evidence::CsvCollector;

pub struct CloudflareZonesCollector {
    client: CloudflareClient,
}

impl CloudflareZonesCollector {
    pub fn new(client: CloudflareClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for CloudflareZonesCollector {
    fn name(&self) -> &str {
        "Cloudflare Zones"
    }

    fn filename_prefix(&self) -> &str {
        "Cloudflare_Zones"
    }

    fn headers(&self) -> &'static [&'static str] {
        &[
            "Zone ID",
            "Name",
            "Status",
            "Paused",
            "Plan",
            "Name Servers",
            "Created On",
            "Activated On",
        ]
    }

    async fn collect_rows(
        &self,
        account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let zones = match self.client.zones().list(account_id).await {
            Ok(z) => z,
            Err(cloudflare_rs::CloudflareError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };

        let rows = zones
            .into_iter()
            .map(|z| {
                vec![
                    z.id,
                    z.name,
                    z.status,
                    if z.paused {
                        "YES".to_string()
                    } else {
                        "NO".to_string()
                    },
                    z.plan.name,
                    z.name_servers.join("; "),
                    z.created_on,
                    z.activated_on.unwrap_or_default(),
                ]
            })
            .collect();

        Ok(rows)
    }
}
```

- [ ] **Step 2: Commit**

```bash
git add src/providers/cloudflare/zones.rs
git commit -m "feat(cloudflare): Zones collector"
```

---

### Task 15: `CloudflareDnsRecordsCollector` (CSV)

**Files:**
- Modify: `src/providers/cloudflare/dns_records.rs`

**Interfaces:**
- Consumes: `cloudflare_rs::CloudflareClient::zones().list()` and `.list_dns_records()` (Task 5).
- Produces: `CloudflareDnsRecordsCollector::new(client: CloudflareClient) -> Self`, referenced by `factory.rs` (Task 10).

- [ ] **Step 1: Implement the collector**

```rust
// src/providers/cloudflare/dns_records.rs
use anyhow::Result;
use async_trait::async_trait;

use cloudflare_rs::CloudflareClient;

use crate::evidence::CsvCollector;

pub struct CloudflareDnsRecordsCollector {
    client: CloudflareClient,
}

impl CloudflareDnsRecordsCollector {
    pub fn new(client: CloudflareClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for CloudflareDnsRecordsCollector {
    fn name(&self) -> &str {
        "Cloudflare DNS Records"
    }

    fn filename_prefix(&self) -> &str {
        "Cloudflare_DNS_Records"
    }

    fn headers(&self) -> &'static [&'static str] {
        &[
            "Zone Name",
            "Record ID",
            "Type",
            "Name",
            "Content",
            "TTL",
            "Proxied",
            "Created On",
            "Modified On",
        ]
    }

    async fn collect_rows(
        &self,
        account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let zones = match self.client.zones().list(account_id).await {
            Ok(z) => z,
            Err(cloudflare_rs::CloudflareError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };

        let mut rows = Vec::new();
        for zone in zones {
            let records = match self.client.zones().list_dns_records(&zone.id).await {
                Ok(r) => r,
                Err(cloudflare_rs::CloudflareError::Api { status: 404, .. }) => continue,
                Err(e) => return Err(e.into()),
            };
            for r in records {
                rows.push(vec![
                    zone.name.clone(),
                    r.id,
                    r.record_type,
                    r.name,
                    r.content,
                    r.ttl.to_string(),
                    if r.proxied {
                        "YES".to_string()
                    } else {
                        "NO".to_string()
                    },
                    r.created_on,
                    r.modified_on,
                ]);
            }
        }

        Ok(rows)
    }
}
```

- [ ] **Step 2: Commit**

```bash
git add src/providers/cloudflare/dns_records.rs
git commit -m "feat(cloudflare): DNS Records collector"
```

---

### Task 16: `CloudflareSslTlsSettingsCollector` (JSON)

**Files:**
- Modify: `src/providers/cloudflare/ssl_tls_settings.rs`

**Interfaces:**
- Consumes: `cloudflare_rs::CloudflareClient::zones().list()` and `.ssl_tls_settings()` (Task 5).
- Produces: `CloudflareSslTlsSettingsCollector::new(client: CloudflareClient) -> Self`, referenced by `factory.rs` (Task 10).

- [ ] **Step 1: Implement the collector**

```rust
// src/providers/cloudflare/ssl_tls_settings.rs
use anyhow::Result;
use async_trait::async_trait;

use cloudflare_rs::CloudflareClient;

use crate::evidence::JsonCollector;

pub struct CloudflareSslTlsSettingsCollector {
    client: CloudflareClient,
}

impl CloudflareSslTlsSettingsCollector {
    pub fn new(client: CloudflareClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl JsonCollector for CloudflareSslTlsSettingsCollector {
    fn name(&self) -> &str {
        "Cloudflare SSL/TLS Settings"
    }

    fn filename_prefix(&self) -> &str {
        "Cloudflare_SSL_TLS_Settings"
    }

    async fn collect_records(
        &self,
        account_id: &str,
        _region: &str,
    ) -> Result<Vec<serde_json::Value>> {
        let zones = match self.client.zones().list(account_id).await {
            Ok(z) => z,
            Err(cloudflare_rs::CloudflareError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };

        let mut records = Vec::new();
        for zone in zones {
            match self
                .client
                .zones()
                .ssl_tls_settings(&zone.id, &zone.name)
                .await
            {
                Ok(settings) => records.push(serde_json::to_value(settings)?),
                Err(cloudflare_rs::CloudflareError::Api { status: 404, .. }) => continue,
                Err(e) => return Err(e.into()),
            }
        }

        Ok(records)
    }
}
```

- [ ] **Step 2: Commit**

```bash
git add src/providers/cloudflare/ssl_tls_settings.rs
git commit -m "feat(cloudflare): SSL/TLS Settings collector"
```

---

### Task 17: `CloudflareWafRulesetsCollector` (JSON)

**Files:**
- Modify: `src/providers/cloudflare/waf_rulesets.rs`

**Interfaces:**
- Consumes: `cloudflare_rs::CloudflareClient::zones().list()` (Task 5), `.firewall().custom_ruleset()` / `.managed_ruleset()` (Task 6).
- Produces: `CloudflareWafRulesetsCollector::new(client: CloudflareClient) -> Self`, referenced by `factory.rs` (Task 10).

- [ ] **Step 1: Implement the collector**

```rust
// src/providers/cloudflare/waf_rulesets.rs
use anyhow::Result;
use async_trait::async_trait;

use cloudflare_rs::CloudflareClient;

use crate::evidence::JsonCollector;

pub struct CloudflareWafRulesetsCollector {
    client: CloudflareClient,
}

impl CloudflareWafRulesetsCollector {
    pub fn new(client: CloudflareClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl JsonCollector for CloudflareWafRulesetsCollector {
    fn name(&self) -> &str {
        "Cloudflare WAF Rulesets"
    }

    fn filename_prefix(&self) -> &str {
        "Cloudflare_WAF_Rulesets"
    }

    async fn collect_records(
        &self,
        account_id: &str,
        _region: &str,
    ) -> Result<Vec<serde_json::Value>> {
        let zones = match self.client.zones().list(account_id).await {
            Ok(z) => z,
            Err(cloudflare_rs::CloudflareError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };

        let mut records = Vec::new();
        for zone in zones {
            let custom = self.client.firewall().custom_ruleset(&zone.id).await?;
            let managed = self.client.firewall().managed_ruleset(&zone.id).await?;
            records.push(serde_json::json!({
                "zone_id": zone.id,
                "zone_name": zone.name,
                "custom_ruleset": custom,
                "managed_ruleset": managed,
            }));
        }

        Ok(records)
    }
}
```

- [ ] **Step 2: Commit**

```bash
git add src/providers/cloudflare/waf_rulesets.rs
git commit -m "feat(cloudflare): WAF Rulesets collector"
```

---

### Task 18: `CloudflareAuditLogsCollector` (CSV, time-windowed)

**Files:**
- Modify: `src/providers/cloudflare/audit_logs.rs`

**Interfaces:**
- Consumes: `cloudflare_rs::CloudflareClient::audit_logs().list()` (Task 7).
- Produces: `CloudflareAuditLogsCollector::new(client: CloudflareClient) -> Self`, referenced by `factory.rs` (Task 10). This is the last collector task — `providers/cloudflare` is feature-complete after this.

- [ ] **Step 1: Implement the collector**

```rust
// src/providers/cloudflare/audit_logs.rs
use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};

use cloudflare_rs::CloudflareClient;

use crate::evidence::CsvCollector;

pub struct CloudflareAuditLogsCollector {
    client: CloudflareClient,
}

impl CloudflareAuditLogsCollector {
    pub fn new(client: CloudflareClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for CloudflareAuditLogsCollector {
    fn name(&self) -> &str {
        "Cloudflare Audit Logs"
    }

    fn filename_prefix(&self) -> &str {
        "Cloudflare_Audit_Logs"
    }

    fn headers(&self) -> &'static [&'static str] {
        &[
            "Log ID",
            "When",
            "Action",
            "Actor Email",
            "Actor Type",
            "Resource Type",
            "Resource ID",
        ]
    }

    async fn collect_rows(
        &self,
        account_id: &str,
        _region: &str,
        dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let (start_secs, end_secs) = match dates {
            Some(d) => d,
            None => {
                // No date range provided → default to last 90 days.
                let now = Utc::now();
                let start = now - chrono::Duration::days(90);
                (start.timestamp(), now.timestamp())
            }
        };
        let since = DateTime::<Utc>::from_timestamp(start_secs, 0)
            .unwrap_or_else(Utc::now)
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        let before = DateTime::<Utc>::from_timestamp(end_secs, 0)
            .unwrap_or_else(Utc::now)
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();

        let entries = match self
            .client
            .audit_logs()
            .list(account_id, &since, &before)
            .await
        {
            Ok(e) => e,
            Err(cloudflare_rs::CloudflareError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };

        let rows = entries
            .into_iter()
            .map(|e| {
                vec![
                    e.id,
                    e.when,
                    e.action.action_type,
                    e.actor.email.unwrap_or_default(),
                    e.actor.actor_type,
                    e.resource.resource_type,
                    e.resource.id.unwrap_or_default(),
                ]
            })
            .collect();

        Ok(rows)
    }
}
```

- [ ] **Step 2: Verify the build**

Run: `cargo check --features cloudflare`
Expected: PASS — every module `factory.rs` references (Task 10) now has a real implementation, and `providers/mod.rs`'s `pub mod cloudflare;` (Task 8) now resolves.

Run: `cargo clippy --features cloudflare -- -D warnings`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add src/providers/cloudflare/audit_logs.rs
git commit -m "feat(cloudflare): Audit Logs collector"
```

---

### Task 19: Register Cloudflare in the TUI menu catalog

**Files:**
- Create: `src/tui/menus/cloudflare.rs`
- Modify: `src/tui/menus/mod.rs`

**Interfaces:**
- Consumes: `CloudProvider::Cloudflare` (Task 8).
- Produces: `CLOUDFLARE_CATEGORIES`, registered in `PROVIDER_MENUS` so `menu_for(CloudProvider::Cloudflare)` resolves instead of panicking.

- [ ] **Step 1: Write the menu data**

```rust
// src/tui/menus/cloudflare.rs
//! Cloudflare collector menu. 8 collectors across 3 categories.

use super::ProviderCategory;

pub const CLOUDFLARE_CATEGORIES: &[ProviderCategory] = &[
    ProviderCategory {
        name: "Directory & Access",
        items: &[
            ("cloudflare-account-members", "Account Members         "),
            ("cloudflare-account-roles", "Account Roles           "),
            ("cloudflare-api-tokens", "API Tokens              "),
        ],
    },
    ProviderCategory {
        name: "Network & Security",
        items: &[
            ("cloudflare-zones", "Zones                   "),
            ("cloudflare-dns-records", "DNS Records             "),
            ("cloudflare-ssl-tls-settings", "SSL/TLS Settings        "),
            ("cloudflare-waf-rulesets", "WAF Rulesets            "),
        ],
    },
    ProviderCategory {
        name: "Audit & Logging",
        items: &[("cloudflare-audit-logs", "Audit Logs              ")],
    },
];
```

- [ ] **Step 2: Register the menu**

Edit `src/tui/menus/mod.rs`:

```rust
//! Per-provider TUI collector menu data. Each provider owns its own
//! category structure, keeping AWS-shaped categories from bleeding into
//! Okta/Jira/Tenable/Cloudflare flows.

pub mod aws;
pub mod cloudflare;
pub mod jira;
pub mod okta;
pub mod tenable;
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
        provider: CloudProvider::Cloudflare,
        categories: cloudflare::CLOUDFLARE_CATEGORIES,
    },
];
```

- [ ] **Step 3: Verify the build**

Run: `cargo check --features cloudflare`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add src/tui/menus/cloudflare.rs src/tui/menus/mod.rs
git commit -m "feat(tui): register the Cloudflare collector menu"
```

---

### Task 20: TUI provider-selection screen — add Cloudflare card

**Files:**
- Modify: `src/tui/ui/account_screens.rs`

**Interfaces:**
- Consumes: `CloudProvider::Cloudflare` (Task 8).
- Produces: a Cloudflare tile on the provider-selection screen. **Must stay in the same enumeration order as `handle_provider_selection` in `src/tui/events.rs`** (Task 21) — the file has an explicit comment tying the two together.

- [ ] **Step 1: Add the Cloudflare tile**

Edit `src/tui/ui/account_screens.rs`, in `draw_provider_selection`, after the Jira tile:

```rust
        #[cfg(feature = "jira")]
        v.push((
            CloudProvider::Jira,
            "◆  Jira",
            "Collect projects and issues from Jira Cloud or Jira Server",
        ));
        #[cfg(feature = "cloudflare")]
        v.push((
            CloudProvider::Cloudflare,
            "◆  Cloudflare",
            "Collect account members, zones, DNS, WAF rulesets, and audit logs",
        ));
        v
    };
```

- [ ] **Step 2: Verify the build**

Run: `cargo check --features cloudflare`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add src/tui/ui/account_screens.rs
git commit -m "feat(tui): add Cloudflare card to provider-selection screen"
```

---

### Task 21: TUI event handling — provider list

**Files:**
- Modify: `src/tui/events.rs`

**Interfaces:**
- Consumes: `CloudProvider::Cloudflare` (Task 8).
- Produces: arrow-key navigation on the provider-selection screen includes Cloudflare, in the same order as Task 20's tile list.

- [ ] **Step 1: Add Cloudflare to the provider list in `handle_provider_selection`**

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
        #[cfg(feature = "cloudflare")]
        v.push(CloudProvider::Cloudflare);
        v
    };
```

- [ ] **Step 2: Verify the build**

Run: `cargo check --features cloudflare`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add src/tui/events.rs
git commit -m "feat(tui): add Cloudflare to provider-selection arrow-key navigation"
```

---

### Task 22: TUI nav — route Cloudflare without an extra screen + account validation

**Files:**
- Modify: `src/tui/app/nav.rs`

**Interfaces:**
- Consumes: `CloudProvider::Cloudflare` (Task 8).
- Produces: `ProviderSelection → SelectCollectors` (skipping `SelectAccount`, matching Okta/Jira), `SelectCollectors → ProviderSelection` on back-navigation, and a "no accounts configured" validation guard.

- [ ] **Step 1: Add the Cloudflare routing arm in `next_screen`**

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
                } else if self.selected_provider == CloudProvider::Cloudflare {
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

- [ ] **Step 2: Add Cloudflare to the combined check in `prev_screen`**

Edit `src/tui/app/nav.rs`, inside `Screen::SelectCollectors => { ... }` in `prev_screen`:

```rust
            Screen::SelectCollectors => {
                if self.selected_provider == CloudProvider::Tenable {
                    Screen::TenableEndpoint
                } else if self.selected_provider == CloudProvider::Okta
                    || self.selected_provider == CloudProvider::Jira
                    || self.selected_provider == CloudProvider::Cloudflare
                {
                    Screen::ProviderSelection
                } else {
                    Screen::SetDates
                }
            }
```

- [ ] **Step 3: Add the Cloudflare account-existence check to `validate_current`**

Edit `src/tui/app/nav.rs`, inside `Screen::ProviderSelection => { ... }` in `validate_current`, after the Jira check:

```rust
                #[cfg(feature = "cloudflare")]
                if self.selected_provider == CloudProvider::Cloudflare {
                    let has_cloudflare = self
                        .accounts
                        .iter()
                        .any(|a| a.provider == CloudProvider::Cloudflare);
                    if !has_cloudflare {
                        self.error_msg = Some(
                            "No Cloudflare accounts configured in cloudflare-config.toml".into(),
                        );
                        return false;
                    }
                }
```

- [ ] **Step 4: Verify the build**

Run: `cargo check --features cloudflare`
Expected: PASS.

Run: `cargo test --features cloudflare tui::`
Expected: PASS — all existing `tui::app::tests::*` and `tui::menus::tests::*` tests continue to pass (this task adds no new tests, per your test-scope decision, but must not break existing ones).

- [ ] **Step 5: Commit**

```bash
git add src/tui/app/nav.rs
git commit -m "feat(tui): route Cloudflare through SelectCollectors without an extra screen"
```

---

### Task 23: runner/tui_session — Cloudflare account preparation block

**Files:**
- Modify: `src/runner/tui_session.rs`

**Interfaces:**
- Consumes: `Account::cloudflare_account_id_resolved()`/`cloudflare_api_token_resolved()` (Task 9), `cloudflare_rs::CloudflareClient::new` (Task 2), `CloudflareProviderFactory::new` (Task 10).
- Produces: `AccountCollectors` entries for every selected Cloudflare account, appended to `prepared`, consumed downstream by the existing collector-running loop (no changes needed there — it already iterates `prepared` generically).

- [ ] **Step 1: Add the Cloudflare account-preparation block**

Edit `src/runner/tui_session.rs`, immediately after the closing `}` of the Okta block (after the line `app.prep_log.push(format!("  ✓ Okta '{}' ready.", tenant_name)); terminal.draw(...)?; }` and its enclosing `}`), and before the `// ── Jira accounts ──` comment:

```rust
            // ── Cloudflare accounts ─────────────────────────────────────────────────
            #[cfg(feature = "cloudflare")]
            if !app.selected_accounts.is_empty() {
                use crate::providers::ProviderFactory as _;

                let sorted_all: Vec<usize> = {
                    let mut v: Vec<usize> = app.selected_accounts.iter().copied().collect();
                    v.sort();
                    v
                };
                for &idx in &sorted_all {
                    if app.accounts[idx].provider != crate::providers::CloudProvider::Cloudflare {
                        continue;
                    }
                    let acct = &app.accounts[idx];
                    let account_name = acct.name.clone();

                    let cf_account_id = match acct.cloudflare_account_id_resolved() {
                        Some(a) => a,
                        None => {
                            app.prep_log.push(format!(
                                "  ✗ Cloudflare '{}' — missing cloudflare_account_id (or CLOUDFLARE_ACCOUNT_ID env)",
                                account_name,
                            ));
                            terminal.draw(|f| crate::tui::ui::draw(f, &app))?;
                            continue;
                        }
                    };
                    let api_token = match acct.cloudflare_api_token_resolved() {
                        Some(t) => t,
                        None => {
                            app.prep_log.push(format!(
                                "  ✗ Cloudflare '{}' — missing cloudflare_api_token (or CLOUDFLARE_API_TOKEN env)",
                                account_name,
                            ));
                            terminal.draw(|f| crate::tui::ui::draw(f, &app))?;
                            continue;
                        }
                    };

                    app.prep_log
                        .push(format!("  Cloudflare '{}' → account {}", account_name, cf_account_id));
                    terminal.draw(|f| crate::tui::ui::draw(f, &app))?;

                    let client = match cloudflare_rs::CloudflareClient::new(&api_token) {
                        Ok(c) => c,
                        Err(e) => {
                            app.prep_log.push(format!(
                                "  ✗ Cloudflare '{}' — client build failed: {e}",
                                account_name,
                            ));
                            terminal.draw(|f| crate::tui::ui::draw(f, &app))?;
                            continue;
                        }
                    };

                    let selected_keys: Vec<String> = app
                        .selected_collectors()
                        .into_iter()
                        .filter(|k| k.starts_with("cloudflare-"))
                        .collect();

                    let factory = crate::providers::cloudflare::factory::CloudflareProviderFactory::new(
                        client,
                        cf_account_id.clone(),
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
                            .join(&account_name),
                    );

                    prepared.push(crate::runner::multi_account::AccountCollectors {
                        account_id: account_name.clone(),
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
                        endpoint_label: Some(format!("Cloudflare — account {}", cf_account_id)),
                    });

                    app.prep_log
                        .push(format!("  ✓ Cloudflare '{}' ready.", account_name));
                    terminal.draw(|f| crate::tui::ui::draw(f, &app))?;
                }
            }

```

Note: `account_id` on `AccountCollectors` is set to `account_name` (the config's `name` field, e.g. `"Cloudflare"`), not `cf_account_id` (the Cloudflare account ID) — this matches how Okta uses `tenant_name` for output-directory naming while the actual API-scoping identifier (`domain`/`cf_account_id`) is only used for the client and log messages. `CloudflareProviderFactory::account_id()` still returns the real Cloudflare account ID (Task 10), used inside collector calls, not for output paths.

- [ ] **Step 2: Verify the build**

Run: `cargo build --features cloudflare`
Expected: builds cleanly. This function has no existing unit tests (it drives the real terminal loop and makes real network calls for other providers), so there is no new automated test here — correctness is covered by the account-preparation error-path messages matching the Okta pattern exactly, and by the end-to-end smoke check in Task 25.

- [ ] **Step 3: Commit**

```bash
git add src/runner/tui_session.rs
git commit -m "feat(runner): wire Cloudflare account preparation into TUI session"
```

---

### Task 24: FedRAMP mapping entries

**Files:**
- Modify: `assets/fedramp-map.json`

**Interfaces:**
- Consumes: nothing new.
- Produces: entries for all 8 Cloudflare `filename_prefix()` values, so `fedramp_mapping()`'s default lookup (`bundled().get(self.filename_prefix())`) finds an explicit (if empty) entry instead of silently falling through — matching many existing stub AWS entries like `"ALB_AccessLogs"`.

- [ ] **Step 1: Add the entries**

Edit `assets/fedramp-map.json`, inside the top-level `"collectors"` object (alphabetical position doesn't matter — JSON key order has no semantic effect here, so appending at the end is simplest and lowest-risk for merge conflicts):

```json
    "Cloudflare_Account_Members": {
      "req_ids": [],
      "control_ids": []
    },
    "Cloudflare_Account_Roles": {
      "req_ids": [],
      "control_ids": []
    },
    "Cloudflare_API_Tokens": {
      "req_ids": [],
      "control_ids": []
    },
    "Cloudflare_Zones": {
      "req_ids": [],
      "control_ids": []
    },
    "Cloudflare_DNS_Records": {
      "req_ids": [],
      "control_ids": []
    },
    "Cloudflare_SSL_TLS_Settings": {
      "req_ids": [],
      "control_ids": []
    },
    "Cloudflare_WAF_Rulesets": {
      "req_ids": [],
      "control_ids": []
    },
    "Cloudflare_Audit_Logs": {
      "req_ids": [],
      "control_ids": []
    }
```

Add a trailing comma after the previous last entry's closing `}` if it doesn't already have one, and make sure this new block is the new last entry before the closing `}` of `"collectors"`.

Real NIST control mapping can be filled in later — nothing breaks if left empty; `fedramp_mapping()` already tolerates a missing key by returning an empty mapping, so this task is about documentation/completeness, not correctness.

- [ ] **Step 2: Verify the JSON is valid**

Run: `cargo check` (the file is loaded via `serde_json` at either build or runtime — check `src/fedramp_map.rs` for whether it's `include_str!`'d at compile time; if so this step also catches a syntax error at compile time)
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add assets/fedramp-map.json
git commit -m "docs(fedramp): add placeholder mapping entries for Cloudflare collectors"
```

---

### Task 25: End-to-end smoke check (no AWS, no Cloudflare network)

**Files:**
- No new files — this task runs the existing suite plus a manual dry-run script.

**Interfaces:**
- Consumes: everything built in Tasks 1–24.
- Produces: confidence that `--features cloudflare` (and the full `default` feature set) compiles and that the Cloudflare provider appears correctly end-to-end in the TUI without requiring a real Cloudflare account.

- [ ] **Step 1: Full workspace build with every feature combination touched by this plan**

Run: `cargo build --features cloudflare`
Expected: PASS.

Run: `cargo build` (default features, which now include `cloudflare`)
Expected: PASS.

Run: `cargo build --no-default-features`
Expected: PASS — confirms Cloudflare (like Tenable/Okta/Jira) is fully excludable.

- [ ] **Step 2: Full test suite**

Run: `cargo test -p cloudflare-rs`
Expected: PASS — all `cloudflare-rs` crate tests (Tasks 2–7): `client_test`, `accounts_test`, `tokens_test`, `zones_test`, `firewall_test`, `audit_logs_test`.

Run: `cargo test`
Expected: PASS — all root-crate tests, unaffected by this plan (no new root-crate tests were added, per your test-scope decision), still passing alongside the new Cloudflare code.

Run: `cargo clippy --workspace --features cloudflare -- -D warnings`
Expected: PASS.

Run: `cargo fmt --check`
Expected: PASS.

- [ ] **Step 3: Manual TUI dry-run with a fake `cloudflare-config.toml`**

Create a throwaway `cloudflare-config.toml` in the repo root (do not commit it — it's already gitignored per Task 26):

```toml
[[account]]
name                    = "Cloudflare Test"
provider                = "cloudflare"
description             = "smoke test"
output_dir              = "./evidence-output/cloudflare-smoke-test"
cloudflare_account_id   = "0123456789abcdef0123456789abcdef"
cloudflare_api_token    = "fake-token"
```

Run: `cargo run --features cloudflare -- ` (launches the TUI with no CLI args, matching how Tenable/Okta/Jira are exercised interactively)

In the TUI: select **Collectors** → arrow down to the **Cloudflare** provider card → Enter. Confirm:
- The account-existence check passes (no "No Cloudflare accounts configured" error), since `cloudflare-config.toml` now has one.
- Pressing Enter lands directly on the collector-selection screen (no `SelectAccount` screen, no region/All-Regions toggle visible) — same shape as Okta/Jira.
- The three categories show exactly 8 items total: **Directory & Access** (Account Members, Account Roles, API Tokens), **Network & Security** (Zones, DNS Records, SSL/TLS Settings, WAF Rulesets), **Audit & Logging** (Audit Logs).
- Selecting all 8 and proceeding to **Set Options** shows no region field and no All-Regions toggle (the pre-existing `is_collectors_non_aws` gate applies automatically).
- Proceeding to **Confirm** → **Run** shows a `Cloudflare 'Cloudflare Test' → account 0123456789abcdef0123456789abcdef` prep-log line, followed by a `✗ Cloudflare 'Cloudflare Test' — ...` failure line for each collector once it actually calls the real Cloudflare API with `fake-token` (expected, since it isn't a real credential) — this confirms the account-preparation block and collectors run and fail gracefully rather than panicking or hanging.

Delete the throwaway `cloudflare-config.toml` and the `./evidence-output/cloudflare-smoke-test` directory afterward.

- [ ] **Step 4: No commit for this task** — it's a verification step, not a code change.

---

### Task 26: Documentation

**Files:**
- Create: `cloudflare-config.example.toml`
- Modify: `.gitignore`
- Modify: `README.md`
- Modify: `evidence-list.md`

**Interfaces:**
- None — documentation only.

- [ ] **Step 1: Write the example config**

```toml
# cloudflare-config.example.toml
# Cloudflare credentials — keep this file out of version control
# Add to .gitignore: cloudflare-config.toml
#
# Merged automatically into config.toml at startup when present.
# Env vars override TOML values: CLOUDFLARE_ACCOUNT_ID, CLOUDFLARE_API_TOKEN
#
# cloudflare_account_id is the 32-character hex Account ID shown in the
# Cloudflare dashboard sidebar. cloudflare_api_token is a scoped API Token
# (My Profile → API Tokens → Create Token) with read-only permissions:
# Account Settings:Read, Account Members:Read, Zone:Read, DNS:Read,
# Firewall Services:Read, Audit Logs:Read.

[[account]]
name                  = "Cloudflare"
provider              = "cloudflare"
description           = "Cloudflare production account"
output_dir            = "./evidence-output/cloudflare"
cloudflare_account_id = ""
cloudflare_api_token  = ""
```

- [ ] **Step 2: Gitignore the real config file**

Edit `.gitignore`, after the Jira line:

```
# Cloudflare credentials — never commit
cloudflare-config.toml
```

- [ ] **Step 3: Update README**

Edit `README.md` line 3 (repo description) and line 13 (collector count):

```markdown
The Grabber. Collects current-state snapshots and time-windowed audit records from AWS, Okta, Jira, Tenable, and Cloudflare, writing them as CSV and JSON. Supports exporting inventory and POA&M artifacts using FedRAMP-aligned templates, suitable for FedRAMP, SOC 2, HIPAA, or internal audits.
```

```markdown
- **200+ collectors across five providers** — 144 AWS, 24 Okta, 28 Jira, 5 Tenable, 8 Cloudflare (see `evidence-list.md` for the current catalog)
```

Add a new `## Cloudflare` section, mirroring the existing `## Okta` section structure exactly (config example, env var override list, how to create the API token, and a collector table):

```markdown
## Cloudflare

Optional feature — build with `--features cloudflare` (enabled by default).

### Configuration

Create `cloudflare-config.toml` in the repo root (gitignored):

```toml
[[account]]
name                  = "Cloudflare"
provider              = "cloudflare"
description           = "Cloudflare production account"
output_dir            = "./evidence-output/cloudflare"
cloudflare_account_id = ""
cloudflare_api_token  = ""
```

Or set the values via environment variables (env wins over TOML):

- `CLOUDFLARE_ACCOUNT_ID` — the 32-character hex Account ID shown in the Cloudflare dashboard sidebar
- `CLOUDFLARE_API_TOKEN` — a scoped API Token

Create an API Token in the Cloudflare dashboard: **My Profile → API Tokens → Create Token**. Scope it read-only: `Account Settings:Read`, `Account Members:Read`, `Zone:Read`, `DNS:Read`, `Firewall Services:Read`, `Audit Logs:Read`.

### Collectors

| Key | Output | Description |
|-----|--------|-------------|
| `cloudflare-account-members` | CSV | Account members with email, status, 2FA status, roles |
| `cloudflare-account-roles` | JSON | Role definitions and their nested permission grants |
| `cloudflare-api-tokens` | CSV | API tokens owned by the authenticated user (metadata only, never the token value) |
| `cloudflare-zones` | CSV | Zones (domains) under the account with plan and status |
| `cloudflare-dns-records` | CSV | DNS records across every zone in the account |
| `cloudflare-ssl-tls-settings` | JSON | Per-zone SSL mode, minimum TLS version, TLS 1.3, Always Use HTTPS, Automatic HTTPS Rewrites |
| `cloudflare-waf-rulesets` | JSON | Per-zone custom and Cloudflare-managed WAF ruleset configuration |
| `cloudflare-audit-logs` | CSV | Time-windowed account audit log events |

Zone-scoped collectors (DNS Records, SSL/TLS Settings, WAF Rulesets) automatically iterate every zone under the configured account — there's no separate zone-selection step.
```

- [ ] **Step 4: Add a Cloudflare section to `evidence-list.md`**

Edit `evidence-list.md`, adding a new section after the existing `### Vulnerability Management — Tenable` section, following the same table format used there:

```markdown
### Cloud Security — Cloudflare

| # | Name | Filename Prefix | Columns / Description |
|---|------|----------------|---------|
| EV-CF1 | Cloudflare Account Members | `Cloudflare_Account_Members` | Member ID, Email, Status, Two-Factor Enabled, Roles |
| EV-CF2 | Cloudflare Account Roles | `Cloudflare_Account_Roles` | JSON — role id, name, description, nested permissions |
| EV-CF3 | Cloudflare API Tokens | `Cloudflare_API_Tokens` | Token ID, Name, Status, Issued On, Modified On, Last Used On, Expires On |
| EV-CF4 | Cloudflare Zones | `Cloudflare_Zones` | Zone ID, Name, Status, Paused, Plan, Name Servers, Created On, Activated On |
| EV-CF5 | Cloudflare DNS Records | `Cloudflare_DNS_Records` | Zone Name, Record ID, Type, Name, Content, TTL, Proxied, Created On, Modified On |
| EV-CF6 | Cloudflare SSL/TLS Settings | `Cloudflare_SSL_TLS_Settings` | JSON — per-zone SSL mode, min TLS version, TLS 1.3, Always Use HTTPS, Automatic HTTPS Rewrites |
| EV-CF7 | Cloudflare WAF Rulesets | `Cloudflare_WAF_Rulesets` | JSON — per-zone custom and managed WAF ruleset configuration |
| EV-CF8 | Cloudflare Audit Logs | `Cloudflare_Audit_Logs` | Log ID, When, Action, Actor Email, Actor Type, Resource Type, Resource ID |
```

- [ ] **Step 5: Commit**

```bash
git add cloudflare-config.example.toml .gitignore README.md evidence-list.md
git commit -m "docs: document the Cloudflare provider (config, env vars, collector catalog)"
```

---

## Self-Review Notes

**Spec coverage:** Every element from the brainstormed design — new `CloudProvider::Cloudflare` variant, Bearer API Token auth, envelope-unwrapping + paginated REST client, 8 collectors (Account Members/Roles, API Tokens, Zones, DNS Records, SSL/TLS Settings, WAF Rulesets, Audit Logs) split across `CsvCollector`/`JsonCollector` as designed, TUI provider card + menu + navigation, account config + env resolvers, `tui_session.rs` wiring, FedRAMP mapping stubs, docs — has a corresponding task (8, 2, 11–18, 19–22, 9, 23, 24, 26).

**Placeholder scan:** No "TBD"/"similar to above"/unshown code remains — every step that changes code shows the full, compilable snippet, including the temporary empty stub files needed to keep the crate and provider module compiling mid-sequence (explicitly called out as stubs replaced by a later, numbered task, e.g. Task 2's `api`/`types` stubs resolved by Task 7, Task 10's 8 collector stubs resolved by Tasks 11–18).

**Type consistency:** `CloudflareClient::new(api_token)` / `CloudflareClient::with_base_url(base_url, api_token)` (Task 2) are called identically in the `lib.rs` doc example, every `cloudflare-rs` test, and `tui_session.rs` (Task 23). `CloudflareProviderFactory::new(client, account_id, selected)` (Task 10) matches its call site in Task 23 — note `account_id` there is the TOML account **name** (`account_name`, for output-path/log purposes), while `CloudflareProviderFactory::account_id()` internally returns the real Cloudflare account ID passed at construction; this mirrors Okta's `tenant_name` vs. `domain` split exactly. Selector strings (`cloudflare-account-members`, `cloudflare-account-roles`, `cloudflare-api-tokens`, `cloudflare-zones`, `cloudflare-dns-records`, `cloudflare-ssl-tls-settings`, `cloudflare-waf-rulesets`, `cloudflare-audit-logs`) match exactly across `tui/menus/cloudflare.rs` (Task 19), `providers/cloudflare/factory.rs` (Task 10), and the `starts_with("cloudflare-")` filter in `tui_session.rs` (Task 23). `Zone`/`DnsRecord`/`ZoneSslSettings`/`Ruleset`/`AuditLogEntry` field names match between each `types::*.rs` struct (Tasks 3, 5–7) and the code that reads those fields in the corresponding collector (Tasks 11–18).
