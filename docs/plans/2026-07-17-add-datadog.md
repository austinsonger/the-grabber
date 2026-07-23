# Add Datadog Provider Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Datadog as a first-class evidence-collection provider — a workspace crate for the Datadog REST API plus collectors for users, roles, API/application keys, monitors, Cloud SIEM detection rules, security signals, and audit-trail events, wired into the existing TUI/CLI plumbing.

**Architecture:** Mirror the existing Okta/Tenable integration exactly. A new `crates/datadog-rs` workspace crate wraps the Datadog REST API (`DD-API-KEY` / `DD-APPLICATION-KEY` header auth, 429 retry honoring `X-RateLimit-Reset`, page-number pagination for JSON:API v2 list endpoints, cursor pagination for time-windowed search endpoints). A new `src/providers/datadog` module implements `ProviderFactory` and produces collectors using the existing `CsvCollector` / `JsonCollector` / `EvidenceCollector` traits. Datadog-specific config lives in `datadog-config.toml` (gitignored), merged into the main `AppConfig` at startup like `okta-config.toml`. The TUI gains a `Datadog` variant on `CloudProvider`, routed through navigation exactly like Okta/Jira (no endpoint-selection screen — the Datadog site/region is a per-account config value).

**Tech Stack:** Rust 1.75+, `reqwest` (rustls), `serde`/`serde_json`, `tokio`, `async_trait`, `thiserror`, `url`, `chrono`. Optional Cargo feature `datadog`.

**Reference patterns to mirror:**
- API client: `crates/okta-rs/src/{client,error,lib}.rs`
- API endpoint module (page-number pagination): `crates/okta-rs/src/api/users.rs`, `src/providers/okta/users.rs`
- Provider factory: `src/providers/okta/factory.rs`
- Time-windowed evidence collector: `src/providers/aws/cloudtrail.rs` (real `EvidenceCollector` implementation using `CollectParams`/`EvidenceRecord`)
- TUI wiring: every place `okta` is referenced in `src/tui/app/mod.rs`, `src/tui/app/nav.rs`, `src/tui/events.rs`, `src/tui/ui/account_screens.rs`, `src/tui/menus/{mod.rs,okta.rs}`, `src/runner/tui_session.rs`

**Out of scope:** No write/mutation endpoints (create/update/delete users, roles, monitors, rules). No Datadog Logs Search or Metrics query collectors (can be added later as their own tasks). No dashboards/notebooks/SLOs collectors in this pass. No FedRAMP control-mapping entries in `assets/fedramp-map.json` for the new collectors — they will show an empty mapping (via the trait's default `fedramp_mapping()`) until a follow-up task adds entries; this does not block collection or output.

## Global Constraints

- This project's established convention (confirmed across prior provider work in this repo) is to **skip dedicated test-writing steps** — no new `wiremock` integration tests or `#[cfg(test)]` unit tests are added by this plan. Each task instead ends with a compile-verification step (`cargo check` / `cargo build`) and a commit. Do not add test files unless separately asked.
- Follow the exact `ProviderFactory` / `CsvCollector` / `JsonCollector` / `EvidenceCollector` trait contracts defined in `src/providers/mod.rs` and `src/evidence.rs` — do not modify those trait definitions.
- Auth headers are `DD-API-KEY` and `DD-APPLICATION-KEY` (both required for read endpoints) — never log or print their values.
- Env vars override TOML config values (env wins), matching every other provider's `_resolved()` accessor pattern in `src/app_config.rs`.
- New workspace crate depends only on the same dependency set already used by `okta-rs`/`tenable-rs` (`reqwest`, `serde`, `serde_json`, `tokio`, `thiserror`, `anyhow`, `url`, `chrono`) — no new external crates.
- All new Rust code must compile under `cargo check --workspace --all-features` with zero warnings introduced.

---

## File Structure

**New files (crate):**
- `crates/datadog-rs/Cargo.toml`
- `crates/datadog-rs/src/lib.rs` — re-exports `DatadogClient`, `DatadogError`
- `crates/datadog-rs/src/client.rs` — auth, site→base-URL resolution, 429 retry, generic GET, cursor helper
- `crates/datadog-rs/src/error.rs` — `DatadogError` enum (`thiserror`)
- `crates/datadog-rs/src/api/mod.rs` — pub mod declarations
- `crates/datadog-rs/src/api/users.rs` — `UsersApi::list_all`
- `crates/datadog-rs/src/api/roles.rs` — `RolesApi::list_all`
- `crates/datadog-rs/src/api/keys.rs` — `KeysApi::list_api_keys`, `KeysApi::list_application_keys`
- `crates/datadog-rs/src/api/monitors.rs` — `MonitorsApi::list_all`
- `crates/datadog-rs/src/api/security_monitoring.rs` — `SecurityMonitoringApi::list_rules`, `SecurityMonitoringApi::list_signals`
- `crates/datadog-rs/src/api/audit.rs` — `AuditApi::list_events`
- `crates/datadog-rs/src/types/mod.rs` — shared JSON:API envelope structs
- `crates/datadog-rs/src/types/user.rs`
- `crates/datadog-rs/src/types/role.rs`
- `crates/datadog-rs/src/types/api_key.rs`
- `crates/datadog-rs/src/types/application_key.rs`

**New files (provider + config):**
- `src/providers/datadog/mod.rs`
- `src/providers/datadog/factory.rs` — `DatadogProviderFactory: ProviderFactory`
- `src/providers/datadog/users.rs` — `DatadogUsersCollector: CsvCollector`
- `src/providers/datadog/roles.rs` — `DatadogRolesCollector: CsvCollector`
- `src/providers/datadog/keys.rs` — `DatadogKeysCollector: CsvCollector`
- `src/providers/datadog/monitors.rs` — `DatadogMonitorsCollector: JsonCollector`
- `src/providers/datadog/security_rules.rs` — `DatadogSecurityRulesCollector: JsonCollector`
- `src/providers/datadog/security_signals.rs` — `DatadogSecuritySignalsCollector: EvidenceCollector`
- `src/providers/datadog/audit_log.rs` — `DatadogAuditLogCollector: EvidenceCollector`
- `src/tui/menus/datadog.rs`
- `datadog-config.example.toml`

**Modified files:**
- `Cargo.toml` — add workspace member, optional `datadog-rs` dep, `datadog` feature
- `.gitignore` — ignore `datadog-config.toml`
- `src/evidence.rs` — add `DatadogSecuritySignals`, `DatadogAuditLog` to `EvidenceSource`
- `src/providers/mod.rs` — add `Datadog` variant to `CloudProvider`, `pub mod datadog` behind feature
- `src/app_config.rs` — Datadog config fields on `Account`, `datadog-config.toml` merge, env-var resolvers
- `src/tui/menus/mod.rs` — register `DATADOG_CATEGORIES`
- `src/tui/app/mod.rs` — Datadog collector keys added to `hardcoded_optins`
- `src/tui/app/nav.rs` — route `Datadog` through navigation without `TenableEndpoint`
- `src/tui/events.rs` — add `Datadog` to the provider-selection cycle list
- `src/tui/ui/account_screens.rs` — add the Datadog provider card
- `src/runner/tui_session.rs` — Datadog account preparation block (build client + factory)
- `README.md` — add Datadog section + collectors table
- `evidence-list.md` — add Datadog rows + update summary counts

---

## Self-Review Notes (run after writing, before handoff)

- Spec coverage: all 7 collectors (users, roles, keys, monitors, security rules, security signals, audit log) have a dedicated task (Tasks 4–10).
- No placeholders: every step below contains complete code, not descriptions of code.
- Type/method consistency: `DatadogClient`, `DatadogError::Api`, `next_cursor`, `UsersApi`/`RolesApi`/`KeysApi`/`MonitorsApi`/`SecurityMonitoringApi`/`AuditApi` accessor names are defined once in Task 2 and used identically in every later task.

---

### Task 1: Workspace + datadog-rs crate skeleton

**Files:**
- Create: `crates/datadog-rs/Cargo.toml`
- Create: `crates/datadog-rs/src/lib.rs`
- Create: `crates/datadog-rs/src/error.rs`
- Create: `crates/datadog-rs/src/client.rs` (stub)
- Create: `crates/datadog-rs/src/api/mod.rs` (stub)
- Create: `crates/datadog-rs/src/types/mod.rs` (stub)
- Modify: `Cargo.toml`
- Modify: `.gitignore`

**Interfaces:**
- Produces: `DatadogClient`, `DatadogError` (re-exported from `datadog-rs`), the `datadog` Cargo feature.

- [ ] **Step 1: Register the workspace member and optional dependency**

Edit `Cargo.toml`:

```toml
[workspace]
members  = [".", "crates/tenable-rs", "crates/okta-rs", "crates/jira-rs", "crates/datadog-rs"]
resolver = "2"
```

Add alongside the other optional provider deps (near the `jira-rs` block):

```toml
# Datadog — only compiled with `--features datadog`
datadog-rs = { path = "crates/datadog-rs", optional = true }
```

Update `[features]`:

```toml
[features]
default = ["tenable", "okta", "jira", "datadog"]
azure   = ["dep:azure_identity", "dep:azure_mgmt_monitor", "dep:azure_mgmt_resources"]
gcp     = ["dep:google-cloud-auth"]
tenable = ["dep:tenable-rs"]
okta    = ["dep:okta-rs"]
jira    = ["dep:jira-rs"]
datadog = ["dep:datadog-rs"]
```

- [ ] **Step 2: Create `crates/datadog-rs/Cargo.toml`**

```toml
[package]
name        = "datadog-rs"
version     = "0.1.0"
edition     = "2021"
description = "Async Rust client for the Datadog REST API"
license     = "MIT OR Apache-2.0"

[dependencies]
reqwest    = { version = "0.12", features = ["json", "rustls-tls"], default-features = false }
serde      = { version = "1", features = ["derive"] }
serde_json = "1"
tokio      = { version = "1", features = ["time"] }
thiserror  = "2"
anyhow     = "1"
url        = "2"
chrono     = { version = "0.4", features = ["serde"] }
```

- [ ] **Step 3: Create `crates/datadog-rs/src/error.rs`**

```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DatadogError {
    #[error("HTTP transport error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("invalid header value: {0}")]
    Header(#[from] reqwest::header::InvalidHeaderValue),

    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Datadog API error: HTTP {status} — {message}")]
    Api { status: u16, message: String },

    #[error("invalid Datadog site: {0}")]
    InvalidSite(String),
}
```

- [ ] **Step 4: Create empty stubs so the crate compiles**

```rust
// crates/datadog-rs/src/client.rs
use crate::error::DatadogError;

#[derive(Clone)]
pub struct DatadogClient;

impl DatadogClient {
    pub fn new(_site: &str, _api_key: &str, _app_key: &str) -> Result<Self, DatadogError> {
        Ok(Self)
    }
}
```

```rust
// crates/datadog-rs/src/api/mod.rs
// (populated in Task 2+)
```

```rust
// crates/datadog-rs/src/types/mod.rs
// (populated in Task 2)
```

- [ ] **Step 5: Create `crates/datadog-rs/src/lib.rs`**

```rust
//! Async Rust client for the Datadog REST API.
//!
//! # Quick start
//!
//! ```no_run
//! use datadog_rs::DatadogClient;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let client = DatadogClient::new("datadoghq.com", "api-key", "app-key")?;
//!     let users = client.users().list_all().await?;
//!     println!("{} users", users.len());
//!     Ok(())
//! }
//! ```

mod client;
mod error;

pub mod api;
pub mod types;

pub use client::DatadogClient;
pub use error::DatadogError;
```

- [ ] **Step 6: Update `.gitignore`**

Append at the end:

```
# Datadog credentials — never commit
datadog-config.toml
```

- [ ] **Step 7: Verify the workspace compiles**

Run: `cargo check --workspace --all-features`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add Cargo.toml .gitignore crates/datadog-rs
git commit -m "feat(datadog): scaffold datadog-rs workspace crate and feature flag"
```

---

### Task 2: HTTP client — auth, site resolution, 429 retry, pagination helpers

**Files:**
- Modify: `crates/datadog-rs/src/client.rs`
- Modify: `crates/datadog-rs/src/types/mod.rs`

**Interfaces:**
- Consumes: `DatadogError` (Task 1).
- Produces: `DatadogClient::new(site, api_key, app_key)`, `DatadogClient::get_json(path, query) -> Result<Value, DatadogError>` (page-number and single-shot callers), `DatadogClient::get_json_with_headers` not needed — callers read `meta.page.after` themselves via `next_cursor`. `pub(crate) fn next_cursor(v: &Value) -> Option<String>`. `types::JsonApiList<T>`, `types::JsonApiResource<T>`, `types::CursorPageList<T>` used by Tasks 4–6 and 9–10.

- [ ] **Step 1: Write the full client**

Replace `crates/datadog-rs/src/client.rs`:

```rust
use reqwest::{header, Client, Response};
use serde_json::Value;
use tokio::time::{sleep, Duration};

use crate::api::{AuditApi, KeysApi, MonitorsApi, RolesApi, SecurityMonitoringApi, UsersApi};
use crate::error::DatadogError;

const MAX_RETRIES: u32 = 5;
const DEFAULT_RETRY_AFTER_SECS: u64 = 30;

/// Async HTTP client for the Datadog REST API.
///
/// Auth: `DD-API-KEY` and `DD-APPLICATION-KEY` headers are injected on every
/// request. Retries 429 responses with exponential backoff, honouring
/// `X-RateLimit-Reset` (seconds until the window resets) when present.
///
/// `DatadogClient` is cheaply cloneable — `reqwest::Client` is arc-pooled.
#[derive(Clone)]
pub struct DatadogClient {
    pub(crate) http: Client,
    pub(crate) base_url: String,
}

impl DatadogClient {
    /// Build a client for a Datadog site (e.g. `datadoghq.com`, `datadoghq.eu`,
    /// `us3.datadoghq.com`, `us5.datadoghq.com`, `ap1.datadoghq.com`, `ddog-gov.com`).
    pub fn new(site: &str, api_key: &str, app_key: &str) -> Result<Self, DatadogError> {
        let trimmed = site.trim().trim_end_matches('/');
        if trimmed.is_empty() {
            return Err(DatadogError::InvalidSite(site.to_string()));
        }
        let base_url = format!("https://api.{trimmed}");

        let mut headers = header::HeaderMap::new();
        headers.insert(
            header::HeaderName::from_static("dd-api-key"),
            header::HeaderValue::from_str(api_key)?,
        );
        headers.insert(
            header::HeaderName::from_static("dd-application-key"),
            header::HeaderValue::from_str(app_key)?,
        );
        headers.insert(
            header::ACCEPT,
            header::HeaderValue::from_static("application/json"),
        );

        let http = Client::builder().default_headers(headers).build()?;
        Ok(Self { http, base_url })
    }

    /// GET a relative path with query parameters, parsing the body as JSON.
    /// Returns `DatadogError::Api` for non-2xx responses.
    pub(crate) async fn get_json(
        &self,
        path: &str,
        query: &[(&str, String)],
    ) -> Result<Value, DatadogError> {
        let url = format!("{}{}", self.base_url, path);
        let query_owned: Vec<(String, String)> =
            query.iter().map(|(k, v)| (k.to_string(), v.clone())).collect();

        let resp = self
            .send_with_retry(|| self.http.get(&url).query(&query_owned).send())
            .await?;
        let status = resp.status();
        let body = resp.text().await?;
        if !status.is_success() {
            return Err(DatadogError::Api {
                status: status.as_u16(),
                message: body,
            });
        }
        Ok(serde_json::from_str(&body)?)
    }

    async fn send_with_retry<F, Fut>(&self, make_req: F) -> Result<Response, DatadogError>
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

    // API accessors -------------------------------------------------------
    pub fn users(&self) -> UsersApi<'_> {
        UsersApi(self)
    }
    pub fn roles(&self) -> RolesApi<'_> {
        RolesApi(self)
    }
    pub fn keys(&self) -> KeysApi<'_> {
        KeysApi(self)
    }
    pub fn monitors(&self) -> MonitorsApi<'_> {
        MonitorsApi(self)
    }
    pub fn security_monitoring(&self) -> SecurityMonitoringApi<'_> {
        SecurityMonitoringApi(self)
    }
    pub fn audit(&self) -> AuditApi<'_> {
        AuditApi(self)
    }
}

/// Honour `X-RateLimit-Reset` (seconds until the window resets) when present.
fn parse_retry_after(resp: &Response) -> u64 {
    resp.headers()
        .get("X-RateLimit-Reset")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(DEFAULT_RETRY_AFTER_SECS)
}

/// Extract the `meta.page.after` cursor from a cursor-paginated v2 response
/// (Security Signals, Audit Events). Returns `None` when there is no next page.
#[doc(hidden)]
pub fn next_cursor(v: &Value) -> Option<String> {
    v.get("meta")?
        .get("page")?
        .get("after")?
        .as_str()
        .map(String::from)
}
```

This references `crate::api::{AuditApi, KeysApi, MonitorsApi, RolesApi, SecurityMonitoringApi, UsersApi}`, which don't exist yet — that's expected, Task 3 onward creates them. To keep this task independently compilable, temporarily stub them:

- [ ] **Step 2: Add temporary stub API types so Step 1 compiles**

Replace `crates/datadog-rs/src/api/mod.rs`:

```rust
mod stub;
pub use stub::{AuditApi, KeysApi, MonitorsApi, RolesApi, SecurityMonitoringApi, UsersApi};
```

Create `crates/datadog-rs/src/api/stub.rs` (deleted in Task 3 when the real `users.rs`/`roles.rs` modules land):

```rust
use crate::client::DatadogClient;

pub struct UsersApi<'a>(pub(crate) &'a DatadogClient);
pub struct RolesApi<'a>(pub(crate) &'a DatadogClient);
pub struct KeysApi<'a>(pub(crate) &'a DatadogClient);
pub struct MonitorsApi<'a>(pub(crate) &'a DatadogClient);
pub struct SecurityMonitoringApi<'a>(pub(crate) &'a DatadogClient);
pub struct AuditApi<'a>(pub(crate) &'a DatadogClient);
```

- [ ] **Step 3: Add the shared JSON:API envelope types**

Replace `crates/datadog-rs/src/types/mod.rs`:

```rust
pub mod api_key;
pub mod application_key;
pub mod role;
pub mod user;

use serde::Deserialize;

/// Generic JSON:API list envelope used by page-number-paginated v2 endpoints
/// (Users, Roles, API Keys, Application Keys).
#[derive(Debug, Deserialize)]
pub(crate) struct JsonApiList<T> {
    #[serde(default)]
    pub data: Vec<JsonApiResource<T>>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct JsonApiResource<T> {
    pub id: String,
    pub attributes: T,
}
```

Cursor-paginated v2 endpoints (Security Signals, Audit Events — Tasks 8 and 10) read `data` and `meta.page.after` directly off the raw `serde_json::Value` response instead of a typed envelope, since those collectors only ever project a few fields and keep the rest as `raw` — no separate envelope type is needed for them.

- [ ] **Step 4: Verify it compiles**

Run: `cargo check -p datadog-rs`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/datadog-rs
git commit -m "feat(datadog): add HTTP client with DD-API-KEY/DD-APPLICATION-KEY auth, 429 retry, pagination helpers"
```

---

### Task 3: CloudProvider variant, Account config fields, provider module skeleton

**Files:**
- Modify: `src/providers/mod.rs`
- Modify: `src/evidence.rs`
- Modify: `src/app_config.rs`
- Create: `src/providers/datadog/mod.rs`
- Create: `src/providers/datadog/factory.rs`

**Interfaces:**
- Consumes: `datadog_rs::DatadogClient` (Task 1–2).
- Produces: `CloudProvider::Datadog`, `Account::datadog_site_resolved() -> String`, `Account::datadog_api_key_resolved() -> Option<String>`, `Account::datadog_app_key_resolved() -> Option<String>`, `DatadogProviderFactory::new(client, account_label, selected) -> Self` implementing `ProviderFactory`.

- [ ] **Step 1: Add the `Datadog` variant to `CloudProvider`**

Edit `src/providers/mod.rs`:

```rust
#[cfg(feature = "datadog")]
pub mod datadog;
```

(insert this block after the existing `#[cfg(feature = "jira")] pub mod jira;` block)

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
    Datadog,
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
            CloudProvider::Datadog => write!(f, "Datadog"),
        }
    }
}
```

- [ ] **Step 2: Add Datadog evidence sources**

Edit `src/evidence.rs`, in the `EvidenceSource` enum:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSource {
    // AWS
    CloudTrail,
    BackupApi,
    RdsApi,
    CloudTrailS3,
    // Azure
    AzureActivityLog,
    AzureMonitor,
    // GCP
    GcpCloudAuditLogs,
    GcpCloudMonitoring,
    // Tenable
    TenableVulnerabilities,
    TenableAssets,
    TenableScans,
    TenableAuditLog,
    TenableCompliance,
    // Okta
    OktaSystemLog,
    // Datadog
    DatadogSecuritySignals,
    DatadogAuditLog,
}
```

- [ ] **Step 3: Add Datadog fields + resolvers to `Account`**

Edit `src/app_config.rs`, add fields to `Account` (after the Jira fields block):

```rust
    // ------------------------------------------------------------------
    // Datadog fields
    // ------------------------------------------------------------------
    /// Datadog site suffix (e.g. `datadoghq.com`, `datadoghq.eu`,
    /// `us3.datadoghq.com`, `us5.datadoghq.com`, `ap1.datadoghq.com`,
    /// `ddog-gov.com`). Defaults to `datadoghq.com` when unset.
    pub datadog_site: Option<String>,

    /// Datadog API key.
    /// Can also be supplied via `DD_API_KEY` env var (env wins over TOML).
    pub datadog_api_key: Option<String>,

    /// Datadog Application key.
    /// Can also be supplied via `DD_APP_KEY` env var (env wins over TOML).
    pub datadog_app_key: Option<String>,
```

Add resolver methods in `impl Account` (after `jira_domain_resolved`):

```rust
    /// Resolve Datadog site, trimming any trailing slash. Defaults to
    /// `datadoghq.com` when unset.
    pub fn datadog_site_resolved(&self) -> String {
        std::env::var("DD_SITE")
            .ok()
            .or_else(|| self.datadog_site.clone())
            .map(|s| s.trim().trim_end_matches('/').to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "datadoghq.com".to_string())
    }

    /// Resolve Datadog API key: env var takes precedence over TOML.
    pub fn datadog_api_key_resolved(&self) -> Option<String> {
        std::env::var("DD_API_KEY")
            .ok()
            .or_else(|| self.datadog_api_key.clone())
    }

    /// Resolve Datadog Application key: env var takes precedence over TOML.
    pub fn datadog_app_key_resolved(&self) -> Option<String> {
        std::env::var("DD_APP_KEY")
            .ok()
            .or_else(|| self.datadog_app_key.clone())
    }
```

- [ ] **Step 4: Merge `datadog-config.toml` in `load_config()`**

Edit `src/app_config.rs`, after the "Merge jira-config.toml accounts if present" block:

```rust
    // Merge datadog-config.toml accounts if present
    let datadog_path = PathBuf::from("datadog-config.toml");
    if datadog_path.exists() {
        if let Ok(contents) = fs::read_to_string(&datadog_path) {
            if let Ok(datadog_cfg) = toml::from_str::<AppConfig>(&contents) {
                cfg.account.extend(datadog_cfg.account);
            }
        }
    }
```

- [ ] **Step 5: Create the provider module skeleton**

Create `src/providers/datadog/mod.rs`:

```rust
pub mod audit_log;
pub mod factory;
pub mod keys;
pub mod monitors;
pub mod roles;
pub mod security_rules;
pub mod security_signals;
pub mod users;

// Authentication:
//   DD-API-KEY: <api_key>
//   DD-APPLICATION-KEY: <app_key>
//
// Base URL: https://api.<site>, where <site> is one of datadoghq.com,
// datadoghq.eu, us3.datadoghq.com, us5.datadoghq.com, ap1.datadoghq.com,
// ddog-gov.com. Supplied via the `datadog_site` config field or the
// `DD_SITE` env var (defaults to datadoghq.com).
```

Create `src/providers/datadog/factory.rs`:

```rust
use datadog_rs::DatadogClient;

use crate::evidence::{CsvCollector, EvidenceCollector, JsonCollector};
use crate::providers::{CloudProvider, ProviderFactory};

pub struct DatadogProviderFactory {
    client: DatadogClient,
    account_label: String,
    selected: Vec<String>,
}

impl DatadogProviderFactory {
    pub fn new(client: DatadogClient, account_label: String, selected: Vec<String>) -> Self {
        Self {
            client,
            account_label,
            selected,
        }
    }

    fn has(&self, key: &str) -> bool {
        self.selected.iter().any(|s| s == key)
    }
}

impl ProviderFactory for DatadogProviderFactory {
    fn provider(&self) -> CloudProvider {
        CloudProvider::Datadog
    }
    fn account_id(&self) -> &str {
        &self.account_label
    }
    fn region(&self) -> &str {
        ""
    }

    fn csv_collectors(&self) -> Vec<Box<dyn CsvCollector>> {
        let mut v: Vec<Box<dyn CsvCollector>> = Vec::new();
        if self.has("datadog-users") {
            v.push(Box::new(super::users::DatadogUsersCollector::new(
                self.client.clone(),
            )));
        }
        if self.has("datadog-roles") {
            v.push(Box::new(super::roles::DatadogRolesCollector::new(
                self.client.clone(),
            )));
        }
        if self.has("datadog-keys") {
            v.push(Box::new(super::keys::DatadogKeysCollector::new(
                self.client.clone(),
            )));
        }
        v
    }

    fn json_collectors(&self) -> Vec<Box<dyn JsonCollector>> {
        let mut v: Vec<Box<dyn JsonCollector>> = Vec::new();
        if self.has("datadog-monitors") {
            v.push(Box::new(super::monitors::DatadogMonitorsCollector::new(
                self.client.clone(),
            )));
        }
        if self.has("datadog-security-rules") {
            v.push(Box::new(
                super::security_rules::DatadogSecurityRulesCollector::new(self.client.clone()),
            ));
        }
        v
    }

    fn evidence_collectors(&self) -> Vec<Box<dyn EvidenceCollector>> {
        let mut v: Vec<Box<dyn EvidenceCollector>> = Vec::new();
        if self.has("datadog-security-signals") {
            v.push(Box::new(
                super::security_signals::DatadogSecuritySignalsCollector::new(
                    self.client.clone(),
                ),
            ));
        }
        if self.has("datadog-audit-log") {
            v.push(Box::new(super::audit_log::DatadogAuditLogCollector::new(
                self.client.clone(),
            )));
        }
        v
    }
}
```

This references `super::{users,roles,keys,monitors,security_rules,security_signals,audit_log}` collector structs that don't exist yet. To keep this task independently compilable, do **not** run `cargo check` on the main crate yet — Task 4 onward creates each module. Skip straight to commit.

- [ ] **Step 6: Verify only the crate-level pieces compile so far**

Run: `cargo check -p datadog-rs`
Expected: PASS (the main crate will not compile until Task 4 lands `src/providers/datadog/users.rs`; that's expected and fixed in the next task).

- [ ] **Step 7: Commit**

```bash
git add src/providers/mod.rs src/evidence.rs src/app_config.rs src/providers/datadog/mod.rs src/providers/datadog/factory.rs
git commit -m "feat(datadog): add CloudProvider variant, Account config fields, provider factory skeleton"
```

---

### Task 4: Users collector

**Files:**
- Create: `crates/datadog-rs/src/types/user.rs`
- Create: `crates/datadog-rs/src/api/users.rs`
- Modify: `crates/datadog-rs/src/api/mod.rs`
- Delete: `crates/datadog-rs/src/api/stub.rs` (its `UsersApi` moves into `users.rs`; other stub types stay until their own tasks replace them)
- Create: `src/providers/datadog/users.rs`

**Interfaces:**
- Consumes: `DatadogClient::get_json`, `types::JsonApiList<T>`, `types::JsonApiResource<T>` (Task 2).
- Produces: `datadog_rs::api::UsersApi::list_all() -> Result<Vec<DatadogUser>, DatadogError>`, `DatadogUsersCollector: CsvCollector`.

- [ ] **Step 1: Add the `DatadogUser` type**

Create `crates/datadog-rs/src/types/user.rs`:

```rust
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct UserAttributes {
    pub name: Option<String>,
    pub handle: String,
    pub email: Option<String>,
    pub status: Option<String>,
    #[serde(default)]
    pub disabled: bool,
    pub title: Option<String>,
    pub created_at: Option<String>,
    pub modified_at: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DatadogUser {
    pub id: String,
    pub attributes: UserAttributes,
}
```

- [ ] **Step 2: Implement `UsersApi::list_all` with page-number pagination**

Create `crates/datadog-rs/src/api/users.rs`:

```rust
use crate::client::DatadogClient;
use crate::error::DatadogError;
use crate::types::user::{DatadogUser, UserAttributes};
use crate::types::JsonApiList;

pub struct UsersApi<'a>(pub(crate) &'a DatadogClient);

const PAGE_SIZE: u32 = 100;

impl<'a> UsersApi<'a> {
    /// List every user in the org, paginating via `page[number]`/`page[size]`.
    pub async fn list_all(&self) -> Result<Vec<DatadogUser>, DatadogError> {
        let mut out = Vec::new();
        let mut page_number = 0u32;
        loop {
            let body = self
                .0
                .get_json(
                    "/api/v2/users",
                    &[
                        ("page[number]", page_number.to_string()),
                        ("page[size]", PAGE_SIZE.to_string()),
                    ],
                )
                .await?;
            let parsed: JsonApiList<UserAttributes> = serde_json::from_value(body)?;
            let page_len = parsed.data.len();
            out.extend(parsed.data.into_iter().map(|r| DatadogUser {
                id: r.id,
                attributes: r.attributes,
            }));
            if (page_len as u32) < PAGE_SIZE {
                break;
            }
            page_number += 1;
        }
        Ok(out)
    }
}
```

- [ ] **Step 3: Register the module and remove the `UsersApi` stub**

Delete `crates/datadog-rs/src/api/stub.rs`'s `UsersApi` line (keep the rest until later tasks). Replace `crates/datadog-rs/src/api/mod.rs`:

```rust
mod stub;
pub mod users;

pub use stub::{AuditApi, KeysApi, MonitorsApi, RolesApi, SecurityMonitoringApi};
pub use users::UsersApi;
```

And edit `crates/datadog-rs/src/api/stub.rs` to drop the now-duplicate `UsersApi` line:

```rust
use crate::client::DatadogClient;

pub struct RolesApi<'a>(pub(crate) &'a DatadogClient);
pub struct KeysApi<'a>(pub(crate) &'a DatadogClient);
pub struct MonitorsApi<'a>(pub(crate) &'a DatadogClient);
pub struct SecurityMonitoringApi<'a>(pub(crate) &'a DatadogClient);
pub struct AuditApi<'a>(pub(crate) &'a DatadogClient);
```

- [ ] **Step 4: Implement the CSV collector**

Create `src/providers/datadog/users.rs`:

```rust
use anyhow::Result;
use async_trait::async_trait;
use datadog_rs::DatadogClient;

use crate::evidence::CsvCollector;

pub struct DatadogUsersCollector {
    client: DatadogClient,
}

impl DatadogUsersCollector {
    pub fn new(client: DatadogClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for DatadogUsersCollector {
    fn name(&self) -> &str {
        "Datadog Users"
    }
    fn filename_prefix(&self) -> &str {
        "Datadog_Users"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "User ID",
            "Handle",
            "Name",
            "Email",
            "Status",
            "Disabled",
            "Title",
            "Created At",
            "Modified At",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let users = match self.client.users().list_all().await {
            Ok(u) => u,
            Err(datadog_rs::DatadogError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };
        let rows = users
            .into_iter()
            .map(|u| {
                vec![
                    u.id,
                    u.attributes.handle,
                    u.attributes.name.unwrap_or_default(),
                    u.attributes.email.unwrap_or_default(),
                    u.attributes.status.unwrap_or_default(),
                    u.attributes.disabled.to_string(),
                    u.attributes.title.unwrap_or_default(),
                    u.attributes.created_at.unwrap_or_default(),
                    u.attributes.modified_at.unwrap_or_default(),
                ]
            })
            .collect();
        Ok(rows)
    }
}
```

- [ ] **Step 5: Verify compilation**

Run: `cargo check -p datadog-rs && cargo check --features datadog`
Expected: `datadog-rs` PASSES. The main crate check will still fail on the missing `roles`/`keys`/`monitors`/`security_rules`/`security_signals`/`audit_log` collector modules referenced by `factory.rs` — expected until Tasks 5–10 land. Confirm the only errors reported are "unresolved import" / "cannot find" for those six modules, nothing else.

- [ ] **Step 6: Commit**

```bash
git add crates/datadog-rs src/providers/datadog/users.rs
git commit -m "feat(datadog): add Users collector"
```

---

### Task 5: Roles collector

**Files:**
- Create: `crates/datadog-rs/src/types/role.rs`
- Create: `crates/datadog-rs/src/api/roles.rs`
- Modify: `crates/datadog-rs/src/api/mod.rs`, `crates/datadog-rs/src/api/stub.rs`
- Create: `src/providers/datadog/roles.rs`

**Interfaces:**
- Produces: `datadog_rs::api::RolesApi::list_all() -> Result<Vec<DatadogRole>, DatadogError>`, `DatadogRolesCollector: CsvCollector`.

- [ ] **Step 1: Add the `DatadogRole` type**

Create `crates/datadog-rs/src/types/role.rs`:

```rust
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct RoleAttributes {
    pub name: String,
    #[serde(default)]
    pub user_count: i64,
    pub created_at: Option<String>,
    pub modified_at: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DatadogRole {
    pub id: String,
    pub attributes: RoleAttributes,
}
```

Add `pub mod role;` to `crates/datadog-rs/src/types/mod.rs` (alongside the existing `pub mod user;`).

- [ ] **Step 2: Implement `RolesApi::list_all`**

Create `crates/datadog-rs/src/api/roles.rs`:

```rust
use crate::client::DatadogClient;
use crate::error::DatadogError;
use crate::types::role::{DatadogRole, RoleAttributes};
use crate::types::JsonApiList;

pub struct RolesApi<'a>(pub(crate) &'a DatadogClient);

const PAGE_SIZE: u32 = 100;

impl<'a> RolesApi<'a> {
    pub async fn list_all(&self) -> Result<Vec<DatadogRole>, DatadogError> {
        let mut out = Vec::new();
        let mut page_number = 0u32;
        loop {
            let body = self
                .0
                .get_json(
                    "/api/v2/roles",
                    &[
                        ("page[number]", page_number.to_string()),
                        ("page[size]", PAGE_SIZE.to_string()),
                    ],
                )
                .await?;
            let parsed: JsonApiList<RoleAttributes> = serde_json::from_value(body)?;
            let page_len = parsed.data.len();
            out.extend(parsed.data.into_iter().map(|r| DatadogRole {
                id: r.id,
                attributes: r.attributes,
            }));
            if (page_len as u32) < PAGE_SIZE {
                break;
            }
            page_number += 1;
        }
        Ok(out)
    }
}
```

- [ ] **Step 3: Register the module, drop the stub**

Edit `crates/datadog-rs/src/api/stub.rs` — remove the `RolesApi` line:

```rust
use crate::client::DatadogClient;

pub struct KeysApi<'a>(pub(crate) &'a DatadogClient);
pub struct MonitorsApi<'a>(pub(crate) &'a DatadogClient);
pub struct SecurityMonitoringApi<'a>(pub(crate) &'a DatadogClient);
pub struct AuditApi<'a>(pub(crate) &'a DatadogClient);
```

Edit `crates/datadog-rs/src/api/mod.rs`:

```rust
mod stub;
pub mod roles;
pub mod users;

pub use roles::RolesApi;
pub use stub::{AuditApi, KeysApi, MonitorsApi, SecurityMonitoringApi};
pub use users::UsersApi;
```

- [ ] **Step 4: Implement the CSV collector**

Create `src/providers/datadog/roles.rs`:

```rust
use anyhow::Result;
use async_trait::async_trait;
use datadog_rs::DatadogClient;

use crate::evidence::CsvCollector;

pub struct DatadogRolesCollector {
    client: DatadogClient,
}

impl DatadogRolesCollector {
    pub fn new(client: DatadogClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for DatadogRolesCollector {
    fn name(&self) -> &str {
        "Datadog Roles"
    }
    fn filename_prefix(&self) -> &str {
        "Datadog_Roles"
    }
    fn headers(&self) -> &'static [&'static str] {
        &["Role ID", "Name", "User Count", "Created At", "Modified At"]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let roles = match self.client.roles().list_all().await {
            Ok(r) => r,
            Err(datadog_rs::DatadogError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };
        let rows = roles
            .into_iter()
            .map(|r| {
                vec![
                    r.id,
                    r.attributes.name,
                    r.attributes.user_count.to_string(),
                    r.attributes.created_at.unwrap_or_default(),
                    r.attributes.modified_at.unwrap_or_default(),
                ]
            })
            .collect();
        Ok(rows)
    }
}
```

- [ ] **Step 5: Verify compilation**

Run: `cargo check -p datadog-rs`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/datadog-rs src/providers/datadog/roles.rs
git commit -m "feat(datadog): add Roles collector"
```

---

### Task 6: API/Application Keys collector

**Files:**
- Create: `crates/datadog-rs/src/types/api_key.rs`, `crates/datadog-rs/src/types/application_key.rs`
- Create: `crates/datadog-rs/src/api/keys.rs`
- Modify: `crates/datadog-rs/src/api/mod.rs`, `crates/datadog-rs/src/api/stub.rs`
- Create: `src/providers/datadog/keys.rs`

**Interfaces:**
- Produces: `datadog_rs::api::KeysApi::list_api_keys() -> Result<Vec<DatadogApiKey>, DatadogError>`, `KeysApi::list_application_keys() -> Result<Vec<DatadogApplicationKey>, DatadogError>`, `DatadogKeysCollector: CsvCollector`.

- [ ] **Step 1: Add the key types**

Create `crates/datadog-rs/src/types/api_key.rs`:

```rust
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct ApiKeyAttributes {
    pub name: String,
    pub last4: Option<String>,
    pub created_at: Option<String>,
    #[serde(default)]
    pub remote_config_read_enabled: bool,
}

#[derive(Debug, Clone)]
pub struct DatadogApiKey {
    pub id: String,
    pub attributes: ApiKeyAttributes,
}
```

Create `crates/datadog-rs/src/types/application_key.rs`:

```rust
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct ApplicationKeyAttributes {
    pub name: String,
    pub last4: Option<String>,
    pub created_at: Option<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct DatadogApplicationKey {
    pub id: String,
    pub attributes: ApplicationKeyAttributes,
}
```

Edit `crates/datadog-rs/src/types/mod.rs`, add:

```rust
pub mod api_key;
pub mod application_key;
```

- [ ] **Step 2: Implement `KeysApi`**

Create `crates/datadog-rs/src/api/keys.rs`:

```rust
use crate::client::DatadogClient;
use crate::error::DatadogError;
use crate::types::api_key::{ApiKeyAttributes, DatadogApiKey};
use crate::types::application_key::{ApplicationKeyAttributes, DatadogApplicationKey};
use crate::types::JsonApiList;

pub struct KeysApi<'a>(pub(crate) &'a DatadogClient);

const PAGE_SIZE: u32 = 100;

impl<'a> KeysApi<'a> {
    pub async fn list_api_keys(&self) -> Result<Vec<DatadogApiKey>, DatadogError> {
        let mut out = Vec::new();
        let mut page_number = 0u32;
        loop {
            let body = self
                .0
                .get_json(
                    "/api/v2/api_keys",
                    &[
                        ("page[number]", page_number.to_string()),
                        ("page[size]", PAGE_SIZE.to_string()),
                    ],
                )
                .await?;
            let parsed: JsonApiList<ApiKeyAttributes> = serde_json::from_value(body)?;
            let page_len = parsed.data.len();
            out.extend(parsed.data.into_iter().map(|r| DatadogApiKey {
                id: r.id,
                attributes: r.attributes,
            }));
            if (page_len as u32) < PAGE_SIZE {
                break;
            }
            page_number += 1;
        }
        Ok(out)
    }

    pub async fn list_application_keys(&self) -> Result<Vec<DatadogApplicationKey>, DatadogError> {
        let mut out = Vec::new();
        let mut page_number = 0u32;
        loop {
            let body = self
                .0
                .get_json(
                    "/api/v2/application_keys",
                    &[
                        ("page[number]", page_number.to_string()),
                        ("page[size]", PAGE_SIZE.to_string()),
                    ],
                )
                .await?;
            let parsed: JsonApiList<ApplicationKeyAttributes> = serde_json::from_value(body)?;
            let page_len = parsed.data.len();
            out.extend(parsed.data.into_iter().map(|r| DatadogApplicationKey {
                id: r.id,
                attributes: r.attributes,
            }));
            if (page_len as u32) < PAGE_SIZE {
                break;
            }
            page_number += 1;
        }
        Ok(out)
    }
}
```

- [ ] **Step 3: Register the module, drop the stub**

Edit `crates/datadog-rs/src/api/stub.rs` — remove the `KeysApi` line:

```rust
use crate::client::DatadogClient;

pub struct MonitorsApi<'a>(pub(crate) &'a DatadogClient);
pub struct SecurityMonitoringApi<'a>(pub(crate) &'a DatadogClient);
pub struct AuditApi<'a>(pub(crate) &'a DatadogClient);
```

Edit `crates/datadog-rs/src/api/mod.rs`:

```rust
mod stub;
pub mod keys;
pub mod roles;
pub mod users;

pub use keys::KeysApi;
pub use roles::RolesApi;
pub use stub::{AuditApi, MonitorsApi, SecurityMonitoringApi};
pub use users::UsersApi;
```

- [ ] **Step 4: Implement the CSV collector (combines both key types with a "Key Type" column)**

Create `src/providers/datadog/keys.rs`:

```rust
use anyhow::Result;
use async_trait::async_trait;
use datadog_rs::DatadogClient;

use crate::evidence::CsvCollector;

pub struct DatadogKeysCollector {
    client: DatadogClient,
}

impl DatadogKeysCollector {
    pub fn new(client: DatadogClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for DatadogKeysCollector {
    fn name(&self) -> &str {
        "Datadog API & Application Keys"
    }
    fn filename_prefix(&self) -> &str {
        "Datadog_API_And_Application_Keys"
    }
    fn headers(&self) -> &'static [&'static str] {
        &["Key Type", "Key ID", "Name", "Last 4", "Created At", "Scopes"]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        match self.client.keys().list_api_keys().await {
            Ok(keys) => {
                for k in keys {
                    rows.push(vec![
                        "API Key".to_string(),
                        k.id,
                        k.attributes.name,
                        k.attributes.last4.unwrap_or_default(),
                        k.attributes.created_at.unwrap_or_default(),
                        String::new(),
                    ]);
                }
            }
            Err(datadog_rs::DatadogError::Api { status: 404, .. }) => {}
            Err(e) => return Err(e.into()),
        }

        match self.client.keys().list_application_keys().await {
            Ok(keys) => {
                for k in keys {
                    rows.push(vec![
                        "Application Key".to_string(),
                        k.id,
                        k.attributes.name,
                        k.attributes.last4.unwrap_or_default(),
                        k.attributes.created_at.unwrap_or_default(),
                        k.attributes.scopes.join("|"),
                    ]);
                }
            }
            Err(datadog_rs::DatadogError::Api { status: 404, .. }) => {}
            Err(e) => return Err(e.into()),
        }

        Ok(rows)
    }
}
```

- [ ] **Step 5: Verify compilation**

Run: `cargo check -p datadog-rs`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/datadog-rs src/providers/datadog/keys.rs
git commit -m "feat(datadog): add API/Application Keys collector"
```

---

### Task 7: Monitors collector (JSON snapshot)

**Files:**
- Create: `crates/datadog-rs/src/api/monitors.rs`
- Modify: `crates/datadog-rs/src/api/mod.rs`, `crates/datadog-rs/src/api/stub.rs`
- Create: `src/providers/datadog/monitors.rs`

**Interfaces:**
- Produces: `datadog_rs::api::MonitorsApi::list_all() -> Result<Vec<Value>, DatadogError>`, `DatadogMonitorsCollector: JsonCollector`.

- [ ] **Step 1: Implement `MonitorsApi::list_all`**

The Monitors v1 endpoint returns a plain JSON array (no envelope) and paginates via `page`/`page_size` query params (0-indexed page number).

Create `crates/datadog-rs/src/api/monitors.rs`:

```rust
use serde_json::Value;

use crate::client::DatadogClient;
use crate::error::DatadogError;

pub struct MonitorsApi<'a>(pub(crate) &'a DatadogClient);

const PAGE_SIZE: u32 = 100;

impl<'a> MonitorsApi<'a> {
    /// List every monitor's configuration as raw JSON records.
    pub async fn list_all(&self) -> Result<Vec<Value>, DatadogError> {
        let mut out = Vec::new();
        let mut page = 0u32;
        loop {
            let body = self
                .0
                .get_json(
                    "/api/v1/monitor",
                    &[("page", page.to_string()), ("page_size", PAGE_SIZE.to_string())],
                )
                .await?;
            let items = body.as_array().cloned().unwrap_or_default();
            let page_len = items.len();
            out.extend(items);
            if (page_len as u32) < PAGE_SIZE {
                break;
            }
            page += 1;
        }
        Ok(out)
    }
}
```

- [ ] **Step 2: Register the module, drop the stub**

Edit `crates/datadog-rs/src/api/stub.rs` — remove the `MonitorsApi` line:

```rust
use crate::client::DatadogClient;

pub struct SecurityMonitoringApi<'a>(pub(crate) &'a DatadogClient);
pub struct AuditApi<'a>(pub(crate) &'a DatadogClient);
```

Edit `crates/datadog-rs/src/api/mod.rs`:

```rust
mod stub;
pub mod keys;
pub mod monitors;
pub mod roles;
pub mod users;

pub use keys::KeysApi;
pub use monitors::MonitorsApi;
pub use roles::RolesApi;
pub use stub::{AuditApi, SecurityMonitoringApi};
pub use users::UsersApi;
```

- [ ] **Step 3: Implement the JSON collector**

Create `src/providers/datadog/monitors.rs`:

```rust
use anyhow::Result;
use async_trait::async_trait;
use datadog_rs::DatadogClient;

use crate::evidence::JsonCollector;

pub struct DatadogMonitorsCollector {
    client: DatadogClient,
}

impl DatadogMonitorsCollector {
    pub fn new(client: DatadogClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl JsonCollector for DatadogMonitorsCollector {
    fn name(&self) -> &str {
        "Datadog Monitors"
    }
    fn filename_prefix(&self) -> &str {
        "Datadog_Monitors"
    }

    async fn collect_records(
        &self,
        _account_id: &str,
        _region: &str,
    ) -> Result<Vec<serde_json::Value>> {
        match self.client.monitors().list_all().await {
            Ok(records) => Ok(records),
            Err(datadog_rs::DatadogError::Api { status: 404, .. }) => Ok(vec![]),
            Err(e) => Err(e.into()),
        }
    }
}
```

- [ ] **Step 4: Verify compilation**

Run: `cargo check -p datadog-rs`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/datadog-rs src/providers/datadog/monitors.rs
git commit -m "feat(datadog): add Monitors collector"
```

---

### Task 8: Security Monitoring Rules collector (JSON snapshot)

**Files:**
- Create: `crates/datadog-rs/src/api/security_monitoring.rs`
- Modify: `crates/datadog-rs/src/api/mod.rs`, `crates/datadog-rs/src/api/stub.rs`
- Create: `src/providers/datadog/security_rules.rs`

**Interfaces:**
- Produces: `datadog_rs::api::SecurityMonitoringApi::list_rules() -> Result<Vec<Value>, DatadogError>` (the `list_signals` method used by Task 9 is added in this same file to avoid a second stub/real split for the same struct).

- [ ] **Step 1: Implement `SecurityMonitoringApi` with both `list_rules` and `list_signals`**

Cloud SIEM detection rules (`/api/v2/security_monitoring/rules`) return `{"data": [...]}` with no pagination (rule counts are small — a single call is sufficient). Security Signals (`/api/v2/security_monitoring/signals`) are cursor-paginated and time-windowed — implemented here now so Task 9 only has to add the provider-layer collector.

Create `crates/datadog-rs/src/api/security_monitoring.rs`:

```rust
use serde_json::Value;

use crate::client::DatadogClient;
use crate::error::DatadogError;

pub struct SecurityMonitoringApi<'a>(pub(crate) &'a DatadogClient);

const PAGE_LIMIT: u32 = 1000;

impl<'a> SecurityMonitoringApi<'a> {
    /// List every Cloud SIEM detection rule as a raw JSON record.
    pub async fn list_rules(&self) -> Result<Vec<Value>, DatadogError> {
        let body = self
            .0
            .get_json("/api/v2/security_monitoring/rules", &[])
            .await?;
        Ok(body.get("data").and_then(Value::as_array).cloned().unwrap_or_default())
    }

    /// List security signals in `[from, to]` (RFC 3339 timestamps), cursor-paginated.
    pub async fn list_signals(&self, from: &str, to: &str) -> Result<Vec<Value>, DatadogError> {
        let mut out = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let mut query = vec![
                ("filter[from]".to_string(), from.to_string()),
                ("filter[to]".to_string(), to.to_string()),
                ("page[limit]".to_string(), PAGE_LIMIT.to_string()),
            ];
            if let Some(c) = &cursor {
                query.push(("page[cursor]".to_string(), c.clone()));
            }
            let query_refs: Vec<(&str, String)> =
                query.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
            let body = self
                .0
                .get_json("/api/v2/security_monitoring/signals", &query_refs)
                .await?;
            let items = body.get("data").and_then(Value::as_array).cloned().unwrap_or_default();
            let item_count = items.len();
            out.extend(items);
            cursor = crate::client::next_cursor(&body);
            if cursor.is_none() || item_count == 0 {
                break;
            }
        }
        Ok(out)
    }
}
```

- [ ] **Step 2: Register the module, drop the stub**

Edit `crates/datadog-rs/src/api/stub.rs` — remove the `SecurityMonitoringApi` line:

```rust
use crate::client::DatadogClient;

pub struct AuditApi<'a>(pub(crate) &'a DatadogClient);
```

Edit `crates/datadog-rs/src/api/mod.rs`:

```rust
mod stub;
pub mod keys;
pub mod monitors;
pub mod roles;
pub mod security_monitoring;
pub mod users;

pub use keys::KeysApi;
pub use monitors::MonitorsApi;
pub use roles::RolesApi;
pub use security_monitoring::SecurityMonitoringApi;
pub use stub::AuditApi;
pub use users::UsersApi;
```

- [ ] **Step 3: Implement the JSON collector for rules**

Create `src/providers/datadog/security_rules.rs`:

```rust
use anyhow::Result;
use async_trait::async_trait;
use datadog_rs::DatadogClient;

use crate::evidence::JsonCollector;

pub struct DatadogSecurityRulesCollector {
    client: DatadogClient,
}

impl DatadogSecurityRulesCollector {
    pub fn new(client: DatadogClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl JsonCollector for DatadogSecurityRulesCollector {
    fn name(&self) -> &str {
        "Datadog Cloud SIEM Detection Rules"
    }
    fn filename_prefix(&self) -> &str {
        "Datadog_Security_Monitoring_Rules"
    }

    async fn collect_records(
        &self,
        _account_id: &str,
        _region: &str,
    ) -> Result<Vec<serde_json::Value>> {
        match self.client.security_monitoring().list_rules().await {
            Ok(records) => Ok(records),
            Err(datadog_rs::DatadogError::Api { status: 404, .. }) => Ok(vec![]),
            Err(e) => Err(e.into()),
        }
    }
}
```

- [ ] **Step 4: Verify compilation**

Run: `cargo check -p datadog-rs`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/datadog-rs src/providers/datadog/security_rules.rs
git commit -m "feat(datadog): add Security Monitoring Rules collector"
```

---

### Task 9: Security Signals collector (time-windowed evidence)

**Files:**
- Create: `src/providers/datadog/security_signals.rs`

**Interfaces:**
- Consumes: `datadog_rs::api::SecurityMonitoringApi::list_signals(from, to)` (Task 8), `crate::evidence::{CollectParams, EvidenceCollector, EvidenceRecord, EvidenceSource}`.
- Produces: `DatadogSecuritySignalsCollector: EvidenceCollector`.

- [ ] **Step 1: Implement the evidence collector**

Create `src/providers/datadog/security_signals.rs`:

```rust
use anyhow::Result;
use async_trait::async_trait;
use datadog_rs::DatadogClient;
use serde_json::Value;

use crate::evidence::{CollectParams, EvidenceCollector, EvidenceRecord, EvidenceSource};

pub struct DatadogSecuritySignalsCollector {
    client: DatadogClient,
}

impl DatadogSecuritySignalsCollector {
    pub fn new(client: DatadogClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl EvidenceCollector for DatadogSecuritySignalsCollector {
    fn name(&self) -> &str {
        "Datadog Security Signals"
    }

    fn filename_prefix(&self) -> &str {
        "Datadog_Security_Signals"
    }

    async fn collect(&self, params: &CollectParams) -> Result<Vec<EvidenceRecord>> {
        let from = params.start_time.to_rfc3339();
        let to = params.end_time.to_rfc3339();

        let signals = match self.client.security_monitoring().list_signals(&from, &to).await {
            Ok(s) => s,
            Err(datadog_rs::DatadogError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };

        let mut records: Vec<EvidenceRecord> = signals
            .iter()
            .map(|item| {
                let attrs = item.get("attributes").cloned().unwrap_or(Value::Null);
                let rule_name = attrs
                    .get("attributes")
                    .and_then(|a| a.get("rule"))
                    .and_then(|r| r.get("name"))
                    .and_then(Value::as_str)
                    .unwrap_or("security_signal")
                    .to_string();
                let timestamp = attrs
                    .get("timestamp")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                let status = attrs
                    .get("status")
                    .and_then(Value::as_str)
                    .map(String::from);

                EvidenceRecord {
                    source: EvidenceSource::DatadogSecuritySignals,
                    event_name: rule_name,
                    timestamp,
                    job_id: None,
                    plan_id: None,
                    resource_arn: None,
                    resource_type: Some("security_signal".to_string()),
                    status,
                    completion_timestamp: None,
                    raw: if params.include_raw { Some(item.clone()) } else { None },
                }
            })
            .collect();

        if let Some(ref f) = params.filter {
            records.retain(|r| r.event_name.contains(f.as_str()));
        }

        Ok(records)
    }
}
```

- [ ] **Step 2: Verify compilation**

Run: `cargo check --features datadog`
Expected: Errors remain only for the still-missing `audit_log` module (Task 10). Confirm no other errors.

- [ ] **Step 3: Commit**

```bash
git add src/providers/datadog/security_signals.rs
git commit -m "feat(datadog): add Security Signals evidence collector"
```

---

### Task 10: Audit Log collector (time-windowed evidence)

**Files:**
- Create: `crates/datadog-rs/src/api/audit.rs`
- Modify: `crates/datadog-rs/src/api/mod.rs` (drop the final stub)
- Delete: `crates/datadog-rs/src/api/stub.rs`
- Create: `src/providers/datadog/audit_log.rs`

**Interfaces:**
- Produces: `datadog_rs::api::AuditApi::list_events(from, to) -> Result<Vec<Value>, DatadogError>`, `DatadogAuditLogCollector: EvidenceCollector`.

- [ ] **Step 1: Implement `AuditApi::list_events`**

Audit Trail events (`/api/v2/audit/events`) share the same cursor-pagination shape as Security Signals.

Create `crates/datadog-rs/src/api/audit.rs`:

```rust
use serde_json::Value;

use crate::client::DatadogClient;
use crate::error::DatadogError;

pub struct AuditApi<'a>(pub(crate) &'a DatadogClient);

const PAGE_LIMIT: u32 = 1000;

impl<'a> AuditApi<'a> {
    /// List audit-trail events in `[from, to]` (RFC 3339 timestamps), cursor-paginated.
    pub async fn list_events(&self, from: &str, to: &str) -> Result<Vec<Value>, DatadogError> {
        let mut out = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let mut query = vec![
                ("filter[from]".to_string(), from.to_string()),
                ("filter[to]".to_string(), to.to_string()),
                ("page[limit]".to_string(), PAGE_LIMIT.to_string()),
            ];
            if let Some(c) = &cursor {
                query.push(("page[cursor]".to_string(), c.clone()));
            }
            let query_refs: Vec<(&str, String)> =
                query.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
            let body = self.0.get_json("/api/v2/audit/events", &query_refs).await?;
            let items = body.get("data").and_then(Value::as_array).cloned().unwrap_or_default();
            let item_count = items.len();
            out.extend(items);
            cursor = crate::client::next_cursor(&body);
            if cursor.is_none() || item_count == 0 {
                break;
            }
        }
        Ok(out)
    }
}
```

- [ ] **Step 2: Register the module and delete the now-empty stub file**

Delete `crates/datadog-rs/src/api/stub.rs` (its last remaining type, `AuditApi`, is replaced by the real implementation above).

Replace `crates/datadog-rs/src/api/mod.rs`:

```rust
pub mod audit;
pub mod keys;
pub mod monitors;
pub mod roles;
pub mod security_monitoring;
pub mod users;

pub use audit::AuditApi;
pub use keys::KeysApi;
pub use monitors::MonitorsApi;
pub use roles::RolesApi;
pub use security_monitoring::SecurityMonitoringApi;
pub use users::UsersApi;
```

- [ ] **Step 3: Implement the evidence collector**

Create `src/providers/datadog/audit_log.rs`:

```rust
use anyhow::Result;
use async_trait::async_trait;
use datadog_rs::DatadogClient;
use serde_json::Value;

use crate::evidence::{CollectParams, EvidenceCollector, EvidenceRecord, EvidenceSource};

pub struct DatadogAuditLogCollector {
    client: DatadogClient,
}

impl DatadogAuditLogCollector {
    pub fn new(client: DatadogClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl EvidenceCollector for DatadogAuditLogCollector {
    fn name(&self) -> &str {
        "Datadog Audit Log"
    }

    fn filename_prefix(&self) -> &str {
        "Datadog_Audit_Log_Events"
    }

    async fn collect(&self, params: &CollectParams) -> Result<Vec<EvidenceRecord>> {
        let from = params.start_time.to_rfc3339();
        let to = params.end_time.to_rfc3339();

        let events = match self.client.audit().list_events(&from, &to).await {
            Ok(e) => e,
            Err(datadog_rs::DatadogError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };

        let mut records: Vec<EvidenceRecord> = events
            .iter()
            .map(|item| {
                let attrs = item.get("attributes").cloned().unwrap_or(Value::Null);
                let inner = attrs.get("attributes").cloned().unwrap_or(Value::Null);
                let event_name = inner
                    .get("evt")
                    .and_then(|e| e.get("name"))
                    .and_then(Value::as_str)
                    .unwrap_or("audit_event")
                    .to_string();
                let timestamp = attrs
                    .get("timestamp")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                let actor = inner
                    .get("usr")
                    .and_then(|u| u.get("id"))
                    .and_then(Value::as_str)
                    .map(String::from);

                EvidenceRecord {
                    source: EvidenceSource::DatadogAuditLog,
                    event_name,
                    timestamp,
                    job_id: None,
                    plan_id: None,
                    resource_arn: actor,
                    resource_type: Some("audit_event".to_string()),
                    status: None,
                    completion_timestamp: None,
                    raw: if params.include_raw { Some(item.clone()) } else { None },
                }
            })
            .collect();

        if let Some(ref f) = params.filter {
            records.retain(|r| r.event_name.contains(f.as_str()));
        }

        Ok(records)
    }
}
```

- [ ] **Step 4: Verify the full workspace compiles**

Run: `cargo check --workspace --all-features`
Expected: PASS. This is the first point at which `src/providers/datadog/factory.rs` (Task 3) resolves all six `super::*` collector modules — confirm zero errors and zero new warnings.

- [ ] **Step 5: Commit**

```bash
git add crates/datadog-rs src/providers/datadog/audit_log.rs
git commit -m "feat(datadog): add Audit Log evidence collector; workspace compiles with datadog feature"
```

---

### Task 11: TUI menu + navigation wiring

**Files:**
- Create: `src/tui/menus/datadog.rs`
- Modify: `src/tui/menus/mod.rs`
- Modify: `src/tui/app/mod.rs`
- Modify: `src/tui/app/nav.rs`
- Modify: `src/tui/events.rs`
- Modify: `src/tui/ui/account_screens.rs`

**Interfaces:**
- Consumes: `CloudProvider::Datadog` (Task 3), the seven `datadog-*` collector keys used by `factory.rs`'s `has()` gates (Task 3).
- Produces: `DATADOG_CATEGORIES` const consumed by `menu_for(CloudProvider::Datadog)`.

- [ ] **Step 1: Add the collector menu**

Create `src/tui/menus/datadog.rs`:

```rust
//! Datadog collector menu. 7 collectors, one category.

use super::ProviderCategory;

pub const DATADOG_CATEGORIES: &[ProviderCategory] = &[ProviderCategory {
    name: "Identity & Security",
    items: &[
        ("datadog-users", "Users                    "),
        ("datadog-roles", "Roles                    "),
        ("datadog-keys", "API & Application Keys   "),
        ("datadog-monitors", "Monitors                 "),
        ("datadog-security-rules", "Cloud SIEM Detection Rules"),
        ("datadog-security-signals", "Security Signals         "),
        ("datadog-audit-log", "Audit Log Events         "),
    ],
}];
```

- [ ] **Step 2: Register the menu**

Edit `src/tui/menus/mod.rs`:

```rust
pub mod aws;
pub mod datadog;
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
        provider: CloudProvider::Datadog,
        categories: datadog::DATADOG_CATEGORIES,
    },
];
```

- [ ] **Step 3: Make all Datadog collectors opt-in by default**

Edit `src/tui/app/mod.rs`, add to the `hardcoded_optins` array (after the `"jira-issues"` entry):

```rust
            "jira-projects",
            "jira-issues",
            "datadog-users",
            "datadog-roles",
            "datadog-keys",
            "datadog-monitors",
            "datadog-security-rules",
            "datadog-security-signals",
            "datadog-audit-log",
```

- [ ] **Step 4: Route `Datadog` through navigation like Okta/Jira**

Edit `src/tui/app/nav.rs`, in `next_screen`'s `Screen::ProviderSelection` arm:

```rust
            Screen::ProviderSelection => {
                if self.selected_provider == CloudProvider::Tenable {
                    self.auto_select_provider_accounts();
                    self.clamp_collector_cursors();
                    Screen::TenableEndpoint
                } else if self.selected_provider == CloudProvider::Okta
                    || self.selected_provider == CloudProvider::Jira
                    || self.selected_provider == CloudProvider::Datadog
                {
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

In `prev_screen`'s `Screen::SelectCollectors` arm:

```rust
            Screen::SelectCollectors => {
                if self.selected_provider == CloudProvider::Tenable {
                    Screen::TenableEndpoint
                } else if self.selected_provider == CloudProvider::Okta
                    || self.selected_provider == CloudProvider::Jira
                    || self.selected_provider == CloudProvider::Datadog
                {
                    Screen::ProviderSelection
                } else {
                    Screen::SetDates
                }
            }
```

In `validate_current`'s `Screen::ProviderSelection` arm, add a Datadog account-existence check alongside the existing Okta/Jira ones:

```rust
                #[cfg(feature = "datadog")]
                if self.selected_provider == CloudProvider::Datadog {
                    let has_datadog = self
                        .accounts
                        .iter()
                        .any(|a| a.provider == CloudProvider::Datadog);
                    if !has_datadog {
                        self.error_msg = Some(
                            "No Datadog accounts configured in datadog-config.toml".into(),
                        );
                        return false;
                    }
                }
```

(Insert this block immediately after the existing `#[cfg(feature = "jira")]` block in the same match arm.)

- [ ] **Step 5: Add `Datadog` to the provider-selection cycle**

Edit `src/tui/events.rs`, in `handle_provider_selection`:

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
        #[cfg(feature = "datadog")]
        v.push(CloudProvider::Datadog);
        v
    };
```

- [ ] **Step 6: Add the Datadog provider-selection card**

Edit `src/tui/ui/account_screens.rs`, in `draw_provider_selection`:

```rust
        #[cfg(feature = "jira")]
        v.push((
            CloudProvider::Jira,
            "◆  Jira",
            "Collect projects and issues from Jira Cloud or Jira Server",
        ));
        #[cfg(feature = "datadog")]
        v.push((
            CloudProvider::Datadog,
            "◆  Datadog",
            "Collect users, roles, keys, monitors, Cloud SIEM rules, signals, and audit log events",
        ));
        v
```

- [ ] **Step 7: Verify compilation**

Run: `cargo check --workspace --all-features`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add src/tui
git commit -m "feat(datadog): wire Datadog into TUI provider selection, menu, and navigation"
```

---

### Task 12: Runner account-preparation wiring

**Files:**
- Modify: `src/runner/tui_session.rs`

**Interfaces:**
- Consumes: `Account::datadog_site_resolved`, `Account::datadog_api_key_resolved`, `Account::datadog_app_key_resolved` (Task 3), `datadog_rs::DatadogClient::new` (Task 2), `crate::providers::datadog::factory::DatadogProviderFactory::new` (Task 3), `crate::runner::multi_account::AccountCollectors` (existing).

- [ ] **Step 1: Add the Datadog account-preparation block**

Edit `src/runner/tui_session.rs`, immediately after the closing brace of the "── Jira accounts ──" block (which itself follows the Okta block shown in the codebase today), add:

```rust
            // ── Datadog accounts ────────────────────────────────────────────────
            #[cfg(feature = "datadog")]
            if !app.selected_accounts.is_empty() {
                use crate::providers::ProviderFactory as _;

                let sorted_all: Vec<usize> = {
                    let mut v: Vec<usize> = app.selected_accounts.iter().copied().collect();
                    v.sort();
                    v
                };
                for &idx in &sorted_all {
                    if app.accounts[idx].provider != crate::providers::CloudProvider::Datadog {
                        continue;
                    }
                    let acct = &app.accounts[idx];
                    let account_label = acct.name.clone();
                    let site = acct.datadog_site_resolved();

                    let api_key = match acct.datadog_api_key_resolved() {
                        Some(k) => k,
                        None => {
                            app.prep_log.push(format!(
                                "  ✗ Datadog '{}' — missing datadog_api_key (or DD_API_KEY env)",
                                account_label,
                            ));
                            terminal.draw(|f| crate::tui::ui::draw(f, &app))?;
                            continue;
                        }
                    };
                    let app_key = match acct.datadog_app_key_resolved() {
                        Some(k) => k,
                        None => {
                            app.prep_log.push(format!(
                                "  ✗ Datadog '{}' — missing datadog_app_key (or DD_APP_KEY env)",
                                account_label,
                            ));
                            terminal.draw(|f| crate::tui::ui::draw(f, &app))?;
                            continue;
                        }
                    };

                    app.prep_log
                        .push(format!("  Datadog '{}' → {}", account_label, site));
                    terminal.draw(|f| crate::tui::ui::draw(f, &app))?;

                    let client = match datadog_rs::DatadogClient::new(&site, &api_key, &app_key) {
                        Ok(c) => c,
                        Err(e) => {
                            app.prep_log.push(format!(
                                "  ✗ Datadog '{}' — client build failed: {e}",
                                account_label,
                            ));
                            terminal.draw(|f| crate::tui::ui::draw(f, &app))?;
                            continue;
                        }
                    };

                    let selected_keys: Vec<String> = app
                        .selected_collectors()
                        .into_iter()
                        .filter(|k| k.starts_with("datadog-"))
                        .collect();

                    let factory = crate::providers::datadog::factory::DatadogProviderFactory::new(
                        client,
                        account_label.clone(),
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
                            .join(&account_label),
                    );

                    prepared.push(crate::runner::multi_account::AccountCollectors {
                        account_id: account_label.clone(),
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
                        endpoint_label: Some(format!("Datadog — {}", site)),
                    });

                    app.prep_log
                        .push(format!("  ✓ Datadog '{}' ready.", account_label));
                    terminal.draw(|f| crate::tui::ui::draw(f, &app))?;
                }
            }
```

- [ ] **Step 2: Verify compilation**

Run: `cargo check --workspace --all-features`
Expected: PASS.

- [ ] **Step 3: Run the existing test suite**

Run: `cargo test --workspace --all-features`
Expected: PASS — no existing test references `CloudProvider::Datadog`, so this confirms nothing regressed. (Per project convention, no new tests are added by this plan.)

- [ ] **Step 4: Commit**

```bash
git add src/runner/tui_session.rs
git commit -m "feat(datadog): wire Datadog account preparation into the TUI runner"
```

---

### Task 13: Config example, README, evidence catalog

**Files:**
- Create: `datadog-config.example.toml`
- Modify: `README.md`
- Modify: `evidence-list.md`

- [ ] **Step 1: Create the example config**

Create `datadog-config.example.toml`:

```toml
# Datadog credentials — keep this file out of version control
# Add to .gitignore: datadog-config.toml
#
# Merged automatically into config.toml at startup when present.
# Env vars override TOML values: DD_SITE, DD_API_KEY, DD_APP_KEY

[[account]]
name             = "Datadog"
provider         = "datadog"
description      = "Datadog production org"
output_dir       = "./evidence-output/datadog"
datadog_site     = "datadoghq.com"
datadog_api_key  = ""
datadog_app_key  = ""
```

- [ ] **Step 2: Add the README section**

Edit `README.md`, insert a new `## Datadog` section after the existing `## Jira` section (matching the Okta/Jira section format):

```markdown
## Datadog

Optional feature — build with `--features datadog` (enabled by default).

### Configuration

Create `datadog-config.toml` in the repo root (gitignored):

\`\`\`toml
[[account]]
name             = "Datadog"
provider         = "datadog"
description      = "Datadog production org"
output_dir       = "./evidence-output/datadog"
datadog_site     = "datadoghq.com"
datadog_api_key  = ""
datadog_app_key  = ""
\`\`\`

Or set the values via environment variables (env wins over TOML):

- `DD_SITE` — e.g. `datadoghq.com`, `datadoghq.eu`, `us3.datadoghq.com`, `us5.datadoghq.com`, `ap1.datadoghq.com`, `ddog-gov.com` (defaults to `datadoghq.com`)
- `DD_API_KEY` — Datadog API key
- `DD_APP_KEY` — Datadog Application key

Create both keys in the Datadog admin console: **Organization Settings → API Keys** and **Organization Settings → Application Keys**. The Application key inherits the permissions of the user that created it; for evidence collection the user needs at least the **Datadog Read Only Role**, plus `security_monitoring_signals_read` and `security_monitoring_rules_read` permissions for the Security collectors.

### Collectors

| Key | Output | Description |
|-----|--------|-------------|
| `datadog-users` | CSV | Org users with status, title, timestamps |
| `datadog-roles` | CSV | RBAC roles with assigned user counts |
| `datadog-keys` | CSV | API keys and Application keys (name, last 4, scopes) |
| `datadog-monitors` | JSON | Monitor configuration (query, type, tags, notification options) |
| `datadog-security-rules` | JSON | Cloud SIEM detection rule configuration |
| `datadog-security-signals` | JSON | Time-windowed Cloud SIEM security signals |
| `datadog-audit-log` | JSON | Time-windowed Audit Trail events (who changed what, when) |
```

- [ ] **Step 3: Update the evidence catalog**

Edit `evidence-list.md`:

Add two rows to the "JSON Evidence (Time-Windowed)" table (after the existing `EV4` row):

```markdown
| EV191 | Datadog Security Signals | `Datadog_Security_Signals` | Time-windowed Cloud SIEM security signals via Security Monitoring Signals API |
| EV192 | Datadog Audit Log | `Datadog_Audit_Log_Events` | Time-windowed Audit Trail events via Audit Events API |
```

Add a new subsection at the end of the "CSV Evidence (Current-State Snapshots)" section, before the "## Asset Inventory" heading:

```markdown
### Identity & Monitoring — Datadog

| # | Name | Filename Prefix | Description |
|---|------|----------------|-------------|
| EV193 | Datadog Users | `Datadog_Users` | User ID, Handle, Name, Email, Status, Disabled, Title, Created At, Modified At |
| EV194 | Datadog Roles | `Datadog_Roles` | Role ID, Name, User Count, Created At, Modified At |
| EV195 | Datadog API & Application Keys | `Datadog_API_And_Application_Keys` | Key Type, Key ID, Name, Last 4, Created At, Scopes |
| EV196 | Datadog Monitors | `Datadog_Monitors` | Raw monitor configuration JSON (query, type, tags, options) |
| EV197 | Datadog Cloud SIEM Detection Rules | `Datadog_Security_Monitoring_Rules` | Raw detection-rule configuration JSON (queries, cases, options) |
```

Update the "## Summary" table:

```markdown
| Category | Count |
|----------|-------|
| AWS collectors | 144 |
| Okta collectors | 24 |
| Jira collectors | 28 |
| Tenable collectors | 5 |
| Datadog collectors | 7 |
| **Total evidence collectors** | **208** |
| Asset Inventory asset types (Inventory feature) | 8 |
```

- [ ] **Step 4: Commit**

```bash
git add datadog-config.example.toml README.md evidence-list.md
git commit -m "docs(datadog): add config example, README section, evidence catalog entries"
```

---

### Task 14: Final integration verification

**Files:**
- None (verification only).

- [ ] **Step 1: Full workspace build with all features**

Run: `cargo build --workspace --all-features`
Expected: PASS, zero warnings introduced by the new code.

- [ ] **Step 2: Clippy**

Run: `cargo clippy --workspace --all-features -- -D warnings`
Expected: PASS. Fix any lints in the new `crates/datadog-rs` or `src/providers/datadog` code before proceeding — do not add `#[allow(...)]` unless an existing provider module already uses the same pattern for the same lint.

- [ ] **Step 3: Existing test suite**

Run: `cargo test --workspace --all-features`
Expected: PASS.

- [ ] **Step 4: Manual CLI smoke test**

Create a throwaway `datadog-config.toml` with a real or dummy account, then run:

```bash
DD_API_KEY=dummy DD_APP_KEY=dummy cargo run --features datadog -- --collectors datadog-users --start-date 2026-01-01 --end-date 2026-01-02
```

Expected: the CLI resolves the Datadog account, attempts the HTTP call, and fails cleanly with a `DatadogError::Api` (HTTP 403, invalid credentials) rather than a panic — confirming the wiring from CLI flags through `AppConfig` → `DatadogProviderFactory` → `DatadogUsersCollector` → `DatadogClient` is intact end-to-end. Delete the throwaway config file afterward (do not commit dummy credentials).

- [ ] **Step 5: Commit** (only if Steps 1–4 required fixes; otherwise this task produces no diff and is skipped)

```bash
git add -A
git commit -m "fix(datadog): address clippy findings from final integration pass"
```
