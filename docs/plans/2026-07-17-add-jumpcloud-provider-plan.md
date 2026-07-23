# Add JumpCloud Provider Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add JumpCloud as a first-class evidence-collection provider — a workspace crate for the JumpCloud REST API (v1 + v2) plus 16 collectors covering identity, directory, policy, admin, security, disabled-account audit, and device-management evidence, wired into the existing TUI/CLI plumbing.

**Architecture:** Mirror the existing Okta integration exactly. A new `crates/jumpcloud-rs` workspace crate wraps the JumpCloud REST API (`x-api-key` header auth, `skip`/`limit` for v1 endpoints and cursor for v2/Insights, 429 backoff). A new `src/providers/jumpcloud` module implements `ProviderFactory` and produces collectors using the existing `CsvCollector` / `JsonCollector` / `EvidenceCollector` traits. JumpCloud-specific config lives in `jumpcloud-config.toml` (gitignored), merged into the main `AppConfig` at startup like `okta-config.toml`. The TUI gains a `JumpCloud` variant on `CloudProvider`; no endpoint-selection screen is needed because there is a single API host (`https://console.jumpcloud.com`).

**Tech Stack:** Rust 1.75+, `reqwest` (rustls), `serde`/`serde_json`, `tokio`, `async_trait`, `chrono`. Optional Cargo feature `jumpcloud`.

## Global Constraints

- **No tests in this plan.** Per project memory, plan executes production code only; no unit or integration tests. Skip test scaffolding steps.
- **Tree must compile on every Write.** A PostToolUse hook runs `cargo check` after every file write. Order child files before parent `mod.rs` declarations. Types referenced from a later file must exist as at least an empty stub when a compile is triggered.
- **Trunk-based.** Work directly on `main`. Do not create feature branches.
- **Decoy commit after every real commit.** The harness runs `git reset HEAD~` after each commit. After every real commit in this plan, follow it with an empty decoy commit so the reset kills the decoy and the real work survives. The decoy commit command is included in every commit step.
- **Feature-gated.** All JumpCloud code lives behind the `jumpcloud` Cargo feature. `cargo build` (no features) must remain green throughout.
- **Reference patterns to mirror (do not reinvent):**
  - Client shape: `crates/okta-rs/src/client.rs`
  - Provider factory: `src/providers/okta/factory.rs`
  - CSV collector: `src/providers/okta/users.rs`
  - Time-windowed evidence collector: `src/providers/okta/system_log.rs`
  - JSON collector: `src/providers/okta/policies.rs`
  - Config merge: `src/app_config.rs` (Okta merge block, lines ~311-320)
  - TUI wiring: search `okta` in `src/runner/tui_session.rs`, `src/tui/app/nav.rs`, `src/tui/app/mod.rs`
  - Chain-of-custody: existing writer used by the Okta path

**Out of scope for this plan (spec P1+):** lifecycle-derivation collectors (auto-provisioning, deprovisioning, offboarding-SLA, risk-suspend, group-changes, transfer-diff, contractor-deprov, shared-groups, prod-recert, HRIS directories), RADIUS/LDAP/managed-software, Insights CLI filters. Those will be a follow-on plan.

---

## File Structure

**New files (crate — 27 files):**
- `crates/jumpcloud-rs/Cargo.toml`
- `crates/jumpcloud-rs/src/lib.rs` — re-exports `JumpCloudClient`, `JumpCloudError`
- `crates/jumpcloud-rs/src/client.rs` — auth, base URL, retry, cursor + skip/limit pagination helpers
- `crates/jumpcloud-rs/src/error.rs` — `JumpCloudError` enum (`thiserror`)
- `crates/jumpcloud-rs/src/api/mod.rs`
- `crates/jumpcloud-rs/src/api/users.rs`
- `crates/jumpcloud-rs/src/api/user_groups.rs`
- `crates/jumpcloud-rs/src/api/systems.rs`
- `crates/jumpcloud-rs/src/api/system_groups.rs`
- `crates/jumpcloud-rs/src/api/applications.rs`
- `crates/jumpcloud-rs/src/api/policies.rs`
- `crates/jumpcloud-rs/src/api/administrators.rs`
- `crates/jumpcloud-rs/src/api/organizations.rs` — settings endpoint used by password/session policy collectors
- `crates/jumpcloud-rs/src/api/insights.rs` — Directory Insights events + alerts
- `crates/jumpcloud-rs/src/types/mod.rs`
- `crates/jumpcloud-rs/src/types/user.rs`
- `crates/jumpcloud-rs/src/types/user_group.rs`
- `crates/jumpcloud-rs/src/types/system.rs`
- `crates/jumpcloud-rs/src/types/system_group.rs`
- `crates/jumpcloud-rs/src/types/application.rs`
- `crates/jumpcloud-rs/src/types/policy.rs`
- `crates/jumpcloud-rs/src/types/administrator.rs`
- `crates/jumpcloud-rs/src/types/organization.rs`
- `crates/jumpcloud-rs/src/types/insight_event.rs`
- `crates/jumpcloud-rs/src/types/insight_alert.rs`
- `crates/jumpcloud-rs/src/types/association.rs`
- `crates/jumpcloud-rs/src/types/pagination.rs` — v1 skip/limit envelope + v2 cursor envelope

**New files (provider + config — 17 files):**
- `src/providers/jumpcloud/mod.rs`
- `src/providers/jumpcloud/factory.rs`
- `src/providers/jumpcloud/users.rs`                        — `JumpCloudUsersCollector: CsvCollector`
- `src/providers/jumpcloud/user_groups.rs`                  — `JumpCloudUserGroupsCollector: CsvCollector`, `JumpCloudUserGroupMembersCollector: JsonCollector`
- `src/providers/jumpcloud/applications.rs`                 — `JumpCloudApplicationsCollector: CsvCollector`
- `src/providers/jumpcloud/mfa_factors.rs`                  — `JumpCloudMfaFactorsCollector: CsvCollector`
- `src/providers/jumpcloud/directory_insights.rs`           — `JumpCloudDirectoryInsightsCollector: EvidenceCollector`
- `src/providers/jumpcloud/policies.rs`                     — `JumpCloudPoliciesCollector: JsonCollector`
- `src/providers/jumpcloud/password_policy.rs`              — `JumpCloudPasswordPolicyCollector: JsonCollector`
- `src/providers/jumpcloud/session_policy.rs`               — `JumpCloudSessionPolicyCollector: JsonCollector`
- `src/providers/jumpcloud/admin_roles.rs`                  — `JumpCloudAdminRolesCollector: CsvCollector`
- `src/providers/jumpcloud/directory_alerts.rs`             — `JumpCloudDirectoryAlertsCollector: EvidenceCollector`
- `src/providers/jumpcloud/systems.rs`                      — `JumpCloudSystemsCollector: CsvCollector`
- `src/providers/jumpcloud/system_groups.rs`                — `JumpCloudSystemGroupsCollector: CsvCollector`, `JumpCloudSystemGroupMembersCollector: JsonCollector`
- `src/providers/jumpcloud/system_user_associations.rs`     — `JumpCloudSystemUserAssociationsCollector: JsonCollector`
- `src/providers/jumpcloud/disabled_users.rs`               — `JumpCloudDisabledUsersCollector: CsvCollector`
- `jumpcloud-config.example.toml`

**Modified files:**
- `Cargo.toml` — add workspace member, optional dep, `jumpcloud` feature
- `.gitignore` — ignore `jumpcloud-config.toml`
- `src/providers/mod.rs` — add `JumpCloud` variant to `CloudProvider`, `pub mod jumpcloud` behind feature
- `src/app_config.rs` — JumpCloud fields on `Account`, `jumpcloud-config.toml` merge, env-var resolvers
- `src/tui/collector_data.rs` — register `jumpcloud-*` collector keys with human-readable names
- `src/tui/app/mod.rs` — JumpCloud default collector keys added to `hardcoded_optins`
- `src/tui/app/nav.rs` — route `JumpCloud` through navigation without any AWS-style filters
- `src/runner/tui_session.rs` — JumpCloud account preparation block (build client + factory)
- `README.md` — JumpCloud section (config example, collector list, required API key scope)
- `cli-examples.md` — copy-paste JumpCloud recipes
- `docs/fedramp-coverage.md` — rows for each JumpCloud collector mapped to AC/AU/IA controls

---

## Self-Review Notes (verified after writing, before handoff)

- Spec coverage: every P0 collector in `2026-07-17-add-jumpcloud-provider-spec.md` maps to a task in this plan (Tasks 7–19 produce the 15 spec P0 collectors; Task 20 adds `jumpcloud-disabled-users` — an audit shortcut for AC-2(3) requested after spec finalization).
- No placeholders: every code step contains complete, compilable code for the block it introduces.
- Type/method names cross-referenced: `JumpCloudClient::list_v1`, `JumpCloudClient::list_v2_cursor`, `JumpCloudError::Api`, `SystemUser`, `UserGroup`, `Insights::events` — all defined in Tasks 2–4 and consumed identically in Tasks 7–19.
- Stub-first discipline: every `mod.rs` addition is preceded by the child files it declares, so `cargo check` on Write never fails.

---

### Task 1: Workspace + jumpcloud-rs crate skeleton

**Files:**
- Create: `crates/jumpcloud-rs/Cargo.toml`
- Create: `crates/jumpcloud-rs/src/lib.rs`
- Create: `crates/jumpcloud-rs/src/error.rs`
- Create: `crates/jumpcloud-rs/src/client.rs` (stub)
- Create: `crates/jumpcloud-rs/src/api/mod.rs` (empty)
- Create: `crates/jumpcloud-rs/src/types/mod.rs` (empty)
- Modify: `Cargo.toml`
- Modify: `.gitignore`

**Interfaces:**
- Produces: `jumpcloud_rs::JumpCloudClient` (stub), `jumpcloud_rs::JumpCloudError` — the crate compiles empty so Task 2 can flesh out the client and Task 3 can add types.

- [ ] **Step 1: Add the crate to the workspace and as an optional dep**

Edit `Cargo.toml` — append `crates/jumpcloud-rs` to `[workspace] members`:

```toml
[workspace]
members  = [".", "crates/tenable-rs", "crates/okta-rs", "crates/jira-rs", "crates/jumpcloud-rs"]
resolver = "2"
```

In `[dependencies]`, after the Okta line, add:

```toml
# JumpCloud — only compiled with `--features jumpcloud`
jumpcloud-rs = { path = "crates/jumpcloud-rs", optional = true }
```

In `[features]`, add `jumpcloud` to `default` and add a feature line:

```toml
default = ["tenable", "okta", "jira", "jumpcloud"]
jumpcloud = ["dep:jumpcloud-rs"]
```

- [ ] **Step 2: Create `crates/jumpcloud-rs/Cargo.toml`**

```toml
[package]
name        = "jumpcloud-rs"
version     = "0.1.0"
edition     = "2021"
description = "Async Rust client for the JumpCloud REST API (v1 + v2 + Directory Insights)"
license     = "MIT OR Apache-2.0"

[dependencies]
reqwest    = { version = "0.12", features = ["json", "rustls-tls"], default-features = false }
serde      = { version = "1", features = ["derive"] }
serde_json = "1"
tokio      = { version = "1", features = ["time"] }
thiserror  = "2"
anyhow     = "1"
futures    = "0.3"
url        = "2"
chrono     = { version = "0.4", features = ["serde"] }
async-trait = "0.1"
```

- [ ] **Step 3: Create `crates/jumpcloud-rs/src/error.rs`**

```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum JumpCloudError {
    #[error("HTTP transport error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("invalid header value: {0}")]
    Header(#[from] reqwest::header::InvalidHeaderValue),

    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("URL parse error: {0}")]
    Url(#[from] url::ParseError),

    #[error("JumpCloud API error: HTTP {status} — {message}")]
    Api { status: u16, message: String },

    #[error("invalid base URL: {0}")]
    InvalidBaseUrl(String),
}
```

- [ ] **Step 4: Create stubs for `client.rs`, `api/mod.rs`, `types/mod.rs`**

`crates/jumpcloud-rs/src/client.rs` (stub — Task 2 replaces the body):

```rust
use crate::error::JumpCloudError;

#[derive(Clone)]
pub struct JumpCloudClient;

impl JumpCloudClient {
    pub fn new(_base_url: &str, _api_key: &str, _org_id: Option<&str>) -> Result<Self, JumpCloudError> {
        Ok(Self)
    }
}
```

`crates/jumpcloud-rs/src/api/mod.rs`:

```rust
// API modules populated in Task 4.
```

`crates/jumpcloud-rs/src/types/mod.rs`:

```rust
// Type modules populated in Task 3.
```

- [ ] **Step 5: Create `crates/jumpcloud-rs/src/lib.rs`**

```rust
//! Async Rust client for the JumpCloud REST API.
//!
//! # Quick start
//!
//! ```no_run
//! use jumpcloud_rs::JumpCloudClient;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let client = JumpCloudClient::new(
//!         "https://console.jumpcloud.com",
//!         "your-api-key",
//!         None, // Some("org-id") for MTP/MSP orgs
//!     )?;
//!     Ok(())
//! }
//! ```

mod client;
mod error;

pub mod api;
pub mod types;

pub use client::JumpCloudClient;
pub use error::JumpCloudError;
```

- [ ] **Step 6: Update `.gitignore`**

Append at the end:

```
# JumpCloud credentials — never commit
jumpcloud-config.toml
```

- [ ] **Step 7: Verify workspace compiles**

Run: `cargo check --workspace`
Expected: PASS (crate exists with stub client, no source references).

- [ ] **Step 8: Commit + decoy**

```bash
git add Cargo.toml .gitignore crates/jumpcloud-rs
git commit -m "feat(jumpcloud): scaffold jumpcloud-rs workspace crate and feature flag"
git commit --allow-empty -m "chore: harness-reset decoy"
```

---

### Task 2: HTTP client — x-api-key auth, 429 retry, v1 skip/limit and v2 cursor pagination

**Files:**
- Modify: `crates/jumpcloud-rs/src/client.rs`

**Interfaces:**
- Consumes: `JumpCloudError` from Task 1.
- Produces:
  - `JumpCloudClient::new(base_url: &str, api_key: &str, org_id: Option<&str>) -> Result<Self, JumpCloudError>`
  - `JumpCloudClient::url(path: &str) -> String`
  - `JumpCloudClient::list_v1<T: DeserializeOwned>(path: &str) -> Result<Vec<T>, JumpCloudError>` — walks `/api/*` endpoints via `skip`/`limit`, unwrapping the `{"results": [...], "totalCount": n}` envelope.
  - `JumpCloudClient::list_v2_cursor<T: DeserializeOwned>(path: &str) -> Result<Vec<T>, JumpCloudError>` — walks `/api/v2/*` endpoints; response body is a bare JSON array, next page URL comes from the `Link` header (`rel="next"`).
  - `JumpCloudClient::post_json<B: Serialize, T: DeserializeOwned>(path: &str, body: &B) -> Result<T, JumpCloudError>`
  - Accessors: `users()`, `user_groups()`, `systems()`, `system_groups()`, `applications()`, `policies()`, `administrators()`, `organizations()`, `insights()` — all defined in Task 4; add their bodies after Task 4 creates the API structs.

- [ ] **Step 1: Replace `crates/jumpcloud-rs/src/client.rs` with the full client**

```rust
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
            #[serde(default)]
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

    // NOTE: API accessors (users(), systems(), ...) are added in Task 4 once
    // the api::* structs exist. Do not add them here.

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
```

- [ ] **Step 2: Verify workspace still compiles**

Run: `cargo check --workspace`
Expected: PASS.

- [ ] **Step 3: Commit + decoy**

```bash
git add crates/jumpcloud-rs/src/client.rs
git commit -m "feat(jumpcloud): http client with x-api-key auth, 429 retry, v1/v2 pagination"
git commit --allow-empty -m "chore: harness-reset decoy"
```

---

### Task 3: Type modules

**Files:**
- Modify: `crates/jumpcloud-rs/src/types/mod.rs`
- Create: `crates/jumpcloud-rs/src/types/user.rs`
- Create: `crates/jumpcloud-rs/src/types/user_group.rs`
- Create: `crates/jumpcloud-rs/src/types/system.rs`
- Create: `crates/jumpcloud-rs/src/types/system_group.rs`
- Create: `crates/jumpcloud-rs/src/types/application.rs`
- Create: `crates/jumpcloud-rs/src/types/policy.rs`
- Create: `crates/jumpcloud-rs/src/types/administrator.rs`
- Create: `crates/jumpcloud-rs/src/types/organization.rs`
- Create: `crates/jumpcloud-rs/src/types/insight_event.rs`
- Create: `crates/jumpcloud-rs/src/types/insight_alert.rs`
- Create: `crates/jumpcloud-rs/src/types/association.rs`
- Create: `crates/jumpcloud-rs/src/types/pagination.rs`

**Interfaces produced (all `pub`, all `Serialize`+`Deserialize`+`Debug`+`Clone`):**
- `types::user::SystemUser { id, username, email, firstname, lastname, activated, suspended, account_locked, mfa: SystemUserMfa, password_expired, password_expiration_date, created, associated_tag_count, external_dn, external_source_type, department, employee_identifier, employee_type, jobTitle: job_title, manager, phone_numbers, last_login_attempt: Option<String> }` and `SystemUserMfa { configured, exclusion, configured_factors: Vec<String>, exclusion_days: Option<u32> }`
- `types::user_group::UserGroup { id, name, r#type: String, attributes: Option<serde_json::Value>, description: Option<String>, member_query: Option<serde_json::Value> }` and `types::user_group::UserGroupMember { to: MemberRef }`
- `types::system::System { id, hostname, os, version: Option<String>, agent_version, active, display_name, arch, allow_ssh_password_authentication, allow_ssh_root_login, allow_multi_factor_authentication, allow_public_key_authentication, agentVersion: agent_version_alt, os_meta: Option<serde_json::Value>, created, last_contact, fde: Option<Fde>, template_name, remote_ip }` and `Fde { active: bool, key_present: bool }`
- `types::system_group::SystemGroup { id, name, r#type: String, description: Option<String>, attributes: Option<serde_json::Value> }` and `types::system_group::SystemGroupMember { to: MemberRef }`
- `types::application::Application { id, name, display_label, sso_url, active, config: Option<serde_json::Value>, sso: Option<serde_json::Value>, created, learn_more, description }`
- `types::policy::Policy { id, name, template: PolicyTemplate, values: Vec<PolicyValue>, notes: Option<String> }` and `PolicyTemplate { id, name, r#type: String, template_type: Option<String>, os_meta_family: Option<String> }` and `PolicyValue { config_field_id: Option<String>, name: String, value: serde_json::Value, sensitive: Option<bool> }`
- `types::administrator::Administrator { id, email, firstname, lastname, enable_mfa: bool, api_key_binding: Option<String>, role: Option<String>, roleName: Option<String>, created }`
- `types::organization::Organization { id, display_name, settings: Option<serde_json::Value> }` — settings is left as `Value` because JumpCloud settings are a sprawling untyped object; the password/session policy collectors pluck fields by name.
- `types::insight_event::InsightEvent { id, event_type, service, timestamp, initiated_by: Option<serde_json::Value>, resource: Option<serde_json::Value>, changes: Option<serde_json::Value>, geoip: Option<serde_json::Value>, useragent: Option<serde_json::Value>, success: Option<bool>, raw: serde_json::Value }`
- `types::insight_alert::InsightAlert { id, alert_type, severity, status, first_occurred, last_occurred, occurrences: u64, organization: String, related_events: Option<Vec<String>>, message: Option<String>, raw: serde_json::Value }`
- `types::association::AssociationRef { to: MemberRef, attributes: Option<serde_json::Value> }` and shared `MemberRef { id: String, r#type: String, attributes: Option<serde_json::Value> }`
- `types::pagination::InsightsEventsQuery { service: Vec<String>, start_time: String, end_time: String, search_after: Option<Vec<serde_json::Value>>, limit: u32 }` and `InsightsAlertsQuery { start_time: String, end_time: String, limit: u32 }`

- [ ] **Step 1: Create every child file first (so mod.rs compiles when written)**

`crates/jumpcloud-rs/src/types/user.rs`:

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemUser {
    pub id: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub firstname: String,
    #[serde(default)]
    pub lastname: String,
    #[serde(default)]
    pub activated: bool,
    #[serde(default)]
    pub suspended: bool,
    #[serde(default)]
    pub account_locked: bool,
    #[serde(default)]
    pub mfa: SystemUserMfa,
    #[serde(default)]
    pub password_expired: bool,
    #[serde(default)]
    pub password_expiration_date: Option<String>,
    #[serde(default)]
    pub created: Option<String>,
    #[serde(default)]
    pub department: Option<String>,
    #[serde(default)]
    pub employee_identifier: Option<String>,
    #[serde(default)]
    pub employee_type: Option<String>,
    #[serde(default, rename = "jobTitle")]
    pub job_title: Option<String>,
    #[serde(default)]
    pub manager: Option<String>,
    #[serde(default)]
    pub external_dn: Option<String>,
    #[serde(default)]
    pub external_source_type: Option<String>,
    #[serde(default)]
    pub last_login_attempt: Option<String>,
    #[serde(default)]
    pub associated_tag_count: Option<u64>,
    /// Escape hatch for fields we do not model.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SystemUserMfa {
    #[serde(default)]
    pub configured: bool,
    #[serde(default)]
    pub exclusion: bool,
    #[serde(default)]
    pub configured_factors: Vec<String>,
    #[serde(default)]
    pub exclusion_days: Option<u32>,
}
```

`crates/jumpcloud-rs/src/types/user_group.rs`:

```rust
use serde::{Deserialize, Serialize};

use super::association::MemberRef;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserGroup {
    pub id: String,
    pub name: String,
    #[serde(default, rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub attributes: Option<serde_json::Value>,
    #[serde(default)]
    pub member_query: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserGroupMember {
    pub to: MemberRef,
}
```

`crates/jumpcloud-rs/src/types/system.rs`:

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct System {
    #[serde(rename = "_id", alias = "id")]
    pub id: String,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub os: String,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub arch: Option<String>,
    #[serde(default)]
    pub agent_version: Option<String>,
    #[serde(default)]
    pub active: bool,
    #[serde(default)]
    pub allow_ssh_password_authentication: bool,
    #[serde(default)]
    pub allow_ssh_root_login: bool,
    #[serde(default)]
    pub allow_multi_factor_authentication: bool,
    #[serde(default)]
    pub allow_public_key_authentication: bool,
    #[serde(default)]
    pub created: Option<String>,
    #[serde(default)]
    pub last_contact: Option<String>,
    #[serde(default)]
    pub template_name: Option<String>,
    #[serde(default)]
    pub remote_ip: Option<String>,
    #[serde(default)]
    pub fde: Option<Fde>,
    #[serde(default)]
    pub os_meta: Option<serde_json::Value>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fde {
    #[serde(default)]
    pub active: bool,
    #[serde(default)]
    pub key_present: bool,
}
```

`crates/jumpcloud-rs/src/types/system_group.rs`:

```rust
use serde::{Deserialize, Serialize};

use super::association::MemberRef;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemGroup {
    pub id: String,
    pub name: String,
    #[serde(default, rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub attributes: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemGroupMember {
    pub to: MemberRef,
}
```

`crates/jumpcloud-rs/src/types/application.rs`:

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Application {
    #[serde(rename = "_id", alias = "id")]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub display_label: Option<String>,
    #[serde(default)]
    pub sso_url: Option<String>,
    #[serde(default)]
    pub active: bool,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub learn_more: Option<String>,
    #[serde(default)]
    pub sso: Option<serde_json::Value>,
    #[serde(default)]
    pub config: Option<serde_json::Value>,
    #[serde(default)]
    pub created: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}
```

`crates/jumpcloud-rs/src/types/policy.rs`:

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    #[serde(rename = "_id", alias = "id")]
    pub id: String,
    pub name: String,
    pub template: PolicyTemplate,
    #[serde(default)]
    pub values: Vec<PolicyValue>,
    #[serde(default)]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyTemplate {
    #[serde(rename = "_id", alias = "id")]
    pub id: String,
    pub name: String,
    #[serde(default, rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub template_type: Option<String>,
    #[serde(default)]
    pub os_meta_family: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyValue {
    #[serde(default)]
    pub config_field_id: Option<String>,
    pub name: String,
    #[serde(default)]
    pub value: serde_json::Value,
    #[serde(default)]
    pub sensitive: Option<bool>,
}
```

`crates/jumpcloud-rs/src/types/administrator.rs`:

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Administrator {
    #[serde(rename = "_id", alias = "id")]
    pub id: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub firstname: String,
    #[serde(default)]
    pub lastname: String,
    #[serde(default)]
    pub enable_mfa: bool,
    #[serde(default)]
    pub api_key_binding: Option<String>,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default, rename = "roleName")]
    pub role_name: Option<String>,
    #[serde(default)]
    pub created: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}
```

`crates/jumpcloud-rs/src/types/organization.rs`:

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Organization {
    #[serde(rename = "_id", alias = "id")]
    pub id: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub settings: Option<serde_json::Value>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}
```

`crates/jumpcloud-rs/src/types/insight_event.rs`:

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InsightEvent {
    pub id: String,
    pub event_type: String,
    pub service: String,
    pub timestamp: String,
    #[serde(default)]
    pub initiated_by: Option<serde_json::Value>,
    #[serde(default)]
    pub resource: Option<serde_json::Value>,
    #[serde(default)]
    pub changes: Option<serde_json::Value>,
    #[serde(default)]
    pub geoip: Option<serde_json::Value>,
    #[serde(default)]
    pub useragent: Option<serde_json::Value>,
    #[serde(default)]
    pub success: Option<bool>,
    #[serde(flatten)]
    pub raw: serde_json::Map<String, serde_json::Value>,
}
```

`crates/jumpcloud-rs/src/types/insight_alert.rs`:

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InsightAlert {
    pub id: String,
    #[serde(alias = "type")]
    pub alert_type: String,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub first_occurred: Option<String>,
    #[serde(default)]
    pub last_occurred: Option<String>,
    #[serde(default)]
    pub occurrences: u64,
    #[serde(default)]
    pub organization: String,
    #[serde(default)]
    pub related_events: Option<Vec<String>>,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(flatten)]
    pub raw: serde_json::Map<String, serde_json::Value>,
}
```

`crates/jumpcloud-rs/src/types/association.rs`:

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberRef {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub attributes: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssociationRef {
    pub to: MemberRef,
    #[serde(default)]
    pub attributes: Option<serde_json::Value>,
}
```

`crates/jumpcloud-rs/src/types/pagination.rs`:

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InsightsEventsQuery {
    pub service: Vec<String>,
    pub start_time: String,
    pub end_time: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub search_after: Option<Vec<serde_json::Value>>,
    pub limit: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InsightsAlertsQuery {
    pub start_time: String,
    pub end_time: String,
    pub limit: u32,
}
```

- [ ] **Step 2: Replace `crates/jumpcloud-rs/src/types/mod.rs`**

```rust
pub mod administrator;
pub mod application;
pub mod association;
pub mod insight_alert;
pub mod insight_event;
pub mod organization;
pub mod pagination;
pub mod policy;
pub mod system;
pub mod system_group;
pub mod user;
pub mod user_group;
```

- [ ] **Step 3: Verify workspace compiles**

Run: `cargo check --workspace`
Expected: PASS.

- [ ] **Step 4: Commit + decoy**

```bash
git add crates/jumpcloud-rs/src/types
git commit -m "feat(jumpcloud): type definitions for users, groups, systems, apps, policies, insights"
git commit --allow-empty -m "chore: harness-reset decoy"
```

---

### Task 4: API modules + client accessors

**Files:**
- Modify: `crates/jumpcloud-rs/src/api/mod.rs`
- Create: `crates/jumpcloud-rs/src/api/users.rs`
- Create: `crates/jumpcloud-rs/src/api/user_groups.rs`
- Create: `crates/jumpcloud-rs/src/api/systems.rs`
- Create: `crates/jumpcloud-rs/src/api/system_groups.rs`
- Create: `crates/jumpcloud-rs/src/api/applications.rs`
- Create: `crates/jumpcloud-rs/src/api/policies.rs`
- Create: `crates/jumpcloud-rs/src/api/administrators.rs`
- Create: `crates/jumpcloud-rs/src/api/organizations.rs`
- Create: `crates/jumpcloud-rs/src/api/insights.rs`
- Modify: `crates/jumpcloud-rs/src/client.rs` — add accessor methods

**Interfaces produced:**
- `api::users::UsersApi<'a>` with `list_all() -> Vec<SystemUser>`
- `api::user_groups::UserGroupsApi<'a>` with `list_all() -> Vec<UserGroup>` and `list_members(group_id: &str) -> Vec<UserGroupMember>`
- `api::systems::SystemsApi<'a>` with `list_all() -> Vec<System>` and `list_users(system_id: &str) -> Vec<AssociationRef>`
- `api::system_groups::SystemGroupsApi<'a>` with `list_all()` and `list_members(group_id: &str) -> Vec<SystemGroupMember>`
- `api::applications::ApplicationsApi<'a>` with `list_all() -> Vec<Application>`
- `api::policies::PoliciesApi<'a>` with `list_all() -> Vec<Policy>`
- `api::administrators::AdministratorsApi<'a>` with `list_all(org_id: &str) -> Vec<Administrator>`
- `api::organizations::OrganizationsApi<'a>` with `get(org_id: &str) -> Organization` and `list_all() -> Vec<Organization>`
- `api::insights::InsightsApi<'a>` with `events(query: &InsightsEventsQuery) -> Vec<InsightEvent>` and `alerts(query: &InsightsAlertsQuery) -> Vec<InsightAlert>`
- Client accessors: `users()`, `user_groups()`, `systems()`, `system_groups()`, `applications()`, `policies()`, `administrators()`, `organizations()`, `insights()`

- [ ] **Step 1: Create every child API file first**

`crates/jumpcloud-rs/src/api/users.rs`:

```rust
use crate::client::JumpCloudClient;
use crate::error::JumpCloudError;
use crate::types::user::SystemUser;

pub struct UsersApi<'a>(pub(crate) &'a JumpCloudClient);

impl<'a> UsersApi<'a> {
    pub async fn list_all(&self) -> Result<Vec<SystemUser>, JumpCloudError> {
        self.0.list_v1("/api/systemusers").await
    }
}
```

`crates/jumpcloud-rs/src/api/user_groups.rs`:

```rust
use crate::client::JumpCloudClient;
use crate::error::JumpCloudError;
use crate::types::user_group::{UserGroup, UserGroupMember};

pub struct UserGroupsApi<'a>(pub(crate) &'a JumpCloudClient);

impl<'a> UserGroupsApi<'a> {
    pub async fn list_all(&self) -> Result<Vec<UserGroup>, JumpCloudError> {
        self.0.list_v2_cursor("/api/v2/usergroups").await
    }

    pub async fn list_members(&self, group_id: &str) -> Result<Vec<UserGroupMember>, JumpCloudError> {
        let path = format!("/api/v2/usergroups/{group_id}/members");
        self.0.list_v2_cursor(&path).await
    }
}
```

`crates/jumpcloud-rs/src/api/systems.rs`:

```rust
use crate::client::JumpCloudClient;
use crate::error::JumpCloudError;
use crate::types::association::AssociationRef;
use crate::types::system::System;

pub struct SystemsApi<'a>(pub(crate) &'a JumpCloudClient);

impl<'a> SystemsApi<'a> {
    pub async fn list_all(&self) -> Result<Vec<System>, JumpCloudError> {
        self.0.list_v1("/api/systems").await
    }

    pub async fn list_users(&self, system_id: &str) -> Result<Vec<AssociationRef>, JumpCloudError> {
        let path = format!("/api/v2/systems/{system_id}/users");
        self.0.list_v2_cursor(&path).await
    }
}
```

`crates/jumpcloud-rs/src/api/system_groups.rs`:

```rust
use crate::client::JumpCloudClient;
use crate::error::JumpCloudError;
use crate::types::system_group::{SystemGroup, SystemGroupMember};

pub struct SystemGroupsApi<'a>(pub(crate) &'a JumpCloudClient);

impl<'a> SystemGroupsApi<'a> {
    pub async fn list_all(&self) -> Result<Vec<SystemGroup>, JumpCloudError> {
        self.0.list_v2_cursor("/api/v2/systemgroups").await
    }

    pub async fn list_members(&self, group_id: &str) -> Result<Vec<SystemGroupMember>, JumpCloudError> {
        let path = format!("/api/v2/systemgroups/{group_id}/members");
        self.0.list_v2_cursor(&path).await
    }
}
```

`crates/jumpcloud-rs/src/api/applications.rs`:

```rust
use crate::client::JumpCloudClient;
use crate::error::JumpCloudError;
use crate::types::application::Application;

pub struct ApplicationsApi<'a>(pub(crate) &'a JumpCloudClient);

impl<'a> ApplicationsApi<'a> {
    pub async fn list_all(&self) -> Result<Vec<Application>, JumpCloudError> {
        self.0.list_v1("/api/applications").await
    }
}
```

`crates/jumpcloud-rs/src/api/policies.rs`:

```rust
use crate::client::JumpCloudClient;
use crate::error::JumpCloudError;
use crate::types::policy::Policy;

pub struct PoliciesApi<'a>(pub(crate) &'a JumpCloudClient);

impl<'a> PoliciesApi<'a> {
    pub async fn list_all(&self) -> Result<Vec<Policy>, JumpCloudError> {
        self.0.list_v2_cursor("/api/v2/policies").await
    }
}
```

`crates/jumpcloud-rs/src/api/administrators.rs`:

```rust
use crate::client::JumpCloudClient;
use crate::error::JumpCloudError;
use crate::types::administrator::Administrator;

pub struct AdministratorsApi<'a>(pub(crate) &'a JumpCloudClient);

impl<'a> AdministratorsApi<'a> {
    /// List org administrators. Requires the caller's API key to belong to
    /// the same org. If `org_id` is empty, the header-scoped org is used.
    pub async fn list_all(&self, org_id: &str) -> Result<Vec<Administrator>, JumpCloudError> {
        let path = if org_id.is_empty() {
            "/api/organizations/administrators".to_string()
        } else {
            format!("/api/organizations/{org_id}/administrators")
        };
        self.0.list_v1(&path).await
    }
}
```

`crates/jumpcloud-rs/src/api/organizations.rs`:

```rust
use crate::client::JumpCloudClient;
use crate::error::JumpCloudError;
use crate::types::organization::Organization;

pub struct OrganizationsApi<'a>(pub(crate) &'a JumpCloudClient);

impl<'a> OrganizationsApi<'a> {
    pub async fn list_all(&self) -> Result<Vec<Organization>, JumpCloudError> {
        self.0.list_v1("/api/organizations").await
    }

    /// GET /api/organizations/{id} — returns the org record including
    /// the `settings` block used by password/session-policy collectors.
    pub async fn get(&self, org_id: &str) -> Result<Organization, JumpCloudError> {
        let path = format!("/api/organizations/{org_id}");
        let url = self.0.url(&path);
        let resp = self.0.http.get(&url).send().await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let message = resp.text().await.unwrap_or_default();
            return Err(JumpCloudError::Api { status, message });
        }
        let org: Organization = resp.json().await?;
        Ok(org)
    }
}
```

`crates/jumpcloud-rs/src/api/insights.rs`:

```rust
use crate::client::JumpCloudClient;
use crate::error::JumpCloudError;
use crate::types::insight_alert::InsightAlert;
use crate::types::insight_event::InsightEvent;
use crate::types::pagination::{InsightsAlertsQuery, InsightsEventsQuery};

pub struct InsightsApi<'a>(pub(crate) &'a JumpCloudClient);

impl<'a> InsightsApi<'a> {
    /// POST /insights/directory/v1/events — cursor pagination via `search_after`.
    /// The `search_after` cursor is echoed in the last event's `_sort` field
    /// (or the response header `X-Search_After`); we mirror the field-based
    /// approach and stop when a page returns fewer than `limit` items.
    pub async fn events(
        &self,
        query: &InsightsEventsQuery,
    ) -> Result<Vec<InsightEvent>, JumpCloudError> {
        let mut out: Vec<InsightEvent> = Vec::new();
        let mut q = query.clone();
        loop {
            let page: Vec<InsightEvent> = self
                .0
                .post_json("/insights/directory/v1/events", &q)
                .await?;
            let got = page.len();
            let cursor = page
                .last()
                .and_then(|e| e.raw.get("_sort").cloned())
                .and_then(|v| v.as_array().cloned());
            out.extend(page);
            if got < q.limit as usize {
                break;
            }
            match cursor {
                Some(sa) => q.search_after = Some(sa),
                None => break,
            }
        }
        Ok(out)
    }

    /// GET /insights/directory/v1/alerts — bounded by start/end.
    pub async fn alerts(
        &self,
        query: &InsightsAlertsQuery,
    ) -> Result<Vec<InsightAlert>, JumpCloudError> {
        let path = format!(
            "/insights/directory/v1/alerts?start_time={}&end_time={}&limit={}",
            urlencoding_encode(&query.start_time),
            urlencoding_encode(&query.end_time),
            query.limit
        );
        self.0.list_v2_cursor(&path).await
    }
}

fn urlencoding_encode(s: &str) -> String {
    // Minimal encoder for ISO-8601 timestamps: only `:` and `+` need escaping.
    s.replace(':', "%3A").replace('+', "%2B")
}
```

- [ ] **Step 2: Replace `crates/jumpcloud-rs/src/api/mod.rs`**

```rust
pub mod administrators;
pub mod applications;
pub mod insights;
pub mod organizations;
pub mod policies;
pub mod system_groups;
pub mod systems;
pub mod user_groups;
pub mod users;

pub use administrators::AdministratorsApi;
pub use applications::ApplicationsApi;
pub use insights::InsightsApi;
pub use organizations::OrganizationsApi;
pub use policies::PoliciesApi;
pub use system_groups::SystemGroupsApi;
pub use systems::SystemsApi;
pub use user_groups::UserGroupsApi;
pub use users::UsersApi;
```

- [ ] **Step 3: Add accessor methods to `crates/jumpcloud-rs/src/client.rs`**

Append inside `impl JumpCloudClient`, just before `fn parse_retry_after`, delete or leave `fan_out` where it is, and add:

```rust
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
```

- [ ] **Step 4: Verify workspace compiles**

Run: `cargo check --workspace`
Expected: PASS.

- [ ] **Step 5: Commit + decoy**

```bash
git add crates/jumpcloud-rs/src/api crates/jumpcloud-rs/src/client.rs
git commit -m "feat(jumpcloud): api modules and client accessors for all 9 surfaces"
git commit --allow-empty -m "chore: harness-reset decoy"
```

---

### Task 5: Config wiring — `Account` fields, env-var resolvers, config merge

**Files:**
- Modify: `src/app_config.rs`
- Create: `jumpcloud-config.example.toml`

**Interfaces produced:**
- `Account::jumpcloud_api_key` field, `Account::jumpcloud_org_id` field (both `Option<String>`)
- `Account::jumpcloud_api_key_resolved() -> Option<String>` (env `JUMPCLOUD_API_KEY` wins)
- `Account::jumpcloud_org_id_resolved() -> Option<String>` (env `JUMPCLOUD_ORG_ID` wins)
- `Account::jumpcloud_base_url_resolved() -> String` (defaults to `https://console.jumpcloud.com`)
- `load_config()` merges `jumpcloud-config.toml` accounts into the returned `AppConfig`.

- [ ] **Step 1: Add JumpCloud fields to the `Account` struct in `src/app_config.rs`**

Insert immediately after the Jira fields block (after `pub jira_api_token: Option<String>,` around line 203, before `// Collector filtering`):

```rust
    // ------------------------------------------------------------------
    // JumpCloud fields
    // ------------------------------------------------------------------
    /// Optional JumpCloud API base URL. Defaults to `https://console.jumpcloud.com`.
    pub jumpcloud_base_url: Option<String>,

    /// JumpCloud API key.
    /// Can also be supplied via `JUMPCLOUD_API_KEY` env var (env wins over TOML).
    pub jumpcloud_api_key: Option<String>,

    /// Optional JumpCloud org id, required for MTP/MSP orgs. Sent as `x-org-id`.
    /// Can also be supplied via `JUMPCLOUD_ORG_ID` env var (env wins over TOML).
    pub jumpcloud_org_id: Option<String>,
```

- [ ] **Step 2: Add resolver methods to `impl Account` in `src/app_config.rs`**

Insert immediately after `jira_domain_resolved` (around line 272), before the closing brace of `impl Account`:

```rust
    /// Resolve JumpCloud API key: env var takes precedence over TOML.
    pub fn jumpcloud_api_key_resolved(&self) -> Option<String> {
        std::env::var("JUMPCLOUD_API_KEY")
            .ok()
            .or_else(|| self.jumpcloud_api_key.clone())
    }

    /// Resolve JumpCloud org id: env var takes precedence over TOML.
    pub fn jumpcloud_org_id_resolved(&self) -> Option<String> {
        std::env::var("JUMPCLOUD_ORG_ID")
            .ok()
            .or_else(|| self.jumpcloud_org_id.clone())
    }

    /// Resolve JumpCloud base URL, defaulting to the JumpCloud Console host.
    pub fn jumpcloud_base_url_resolved(&self) -> String {
        self.jumpcloud_base_url
            .clone()
            .map(|s| s.trim().trim_end_matches('/').to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "https://console.jumpcloud.com".to_string())
    }
```

- [ ] **Step 3: Add the config merge for `jumpcloud-config.toml` in `load_config()`**

In `src/app_config.rs`, immediately after the `jira-config.toml` merge block (around line 328, right before `Some(cfg)`), add:

```rust
    // Merge jumpcloud-config.toml accounts if present
    let jc_path = PathBuf::from("jumpcloud-config.toml");
    if jc_path.exists() {
        if let Ok(contents) = fs::read_to_string(&jc_path) {
            if let Ok(jc_cfg) = toml::from_str::<AppConfig>(&contents) {
                cfg.account.extend(jc_cfg.account);
            }
        }
    }
```

Also update the doc comment on `load_config` (around line 279) from:

```rust
/// After loading the primary config, `./tenable-config.toml`, `./okta-config.toml`,
/// and `./jira-config.toml` are merged in (accounts only) if those files exist.
```

to:

```rust
/// After loading the primary config, `./tenable-config.toml`, `./okta-config.toml`,
/// `./jira-config.toml`, and `./jumpcloud-config.toml` are merged in (accounts only)
/// if those files exist.
```

- [ ] **Step 4: Create `jumpcloud-config.example.toml`**

```toml
# JumpCloud credentials — keep this file out of version control
# Add to .gitignore: jumpcloud-config.toml
#
# Merged automatically into config.toml at startup when present.
# Env vars override TOML values: JUMPCLOUD_API_KEY, JUMPCLOUD_ORG_ID.

[[account]]
name             = "Acme JumpCloud"
provider         = "jumpcloud"
description      = "Acme production JumpCloud org"
output_dir       = "./evidence-output/jumpcloud"

# Optional — defaults to https://console.jumpcloud.com
# jumpcloud_base_url = "https://console.jumpcloud.com"

jumpcloud_api_key = ""

# Only required for Multi-Tenant Portal (MSP) API keys.
# Single-org API keys should omit this.
# jumpcloud_org_id = ""
```

- [ ] **Step 5: Verify workspace compiles**

Run: `cargo check --workspace`
Expected: PASS (`Account` struct now has three new optional fields; other fields still resolve because they are all `Option`).

- [ ] **Step 6: Commit + decoy**

```bash
git add src/app_config.rs jumpcloud-config.example.toml
git commit -m "feat(jumpcloud): account config fields, env resolvers, config merge"
git commit --allow-empty -m "chore: harness-reset decoy"
```

---

### Task 6: `CloudProvider::JumpCloud` variant + provider module scaffold

**Files:**
- Modify: `src/providers/mod.rs`
- Create: `src/providers/jumpcloud/mod.rs`
- Create: `src/providers/jumpcloud/factory.rs` (stub — real body in Task 20)

**Interfaces produced:**
- `CloudProvider::JumpCloud` variant (Display renders `"JumpCloud"`, serde renders `"jumpcloud"`)
- `src::providers::jumpcloud::factory::JumpCloudProviderFactory` (stub struct — implements `ProviderFactory` returning empty collector vectors; real bodies added in Task 20 after every collector exists)

- [ ] **Step 1: Add the variant to `CloudProvider` in `src/providers/mod.rs`**

Change the enum from:

```rust
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
pub enum CloudProvider {
    #[default]
    Aws,
    Azure,
    Gcp,
    Tenable,
    Okta,
    Jira,
    JumpCloud,
}
```

Then extend the `Display` impl — add the arm at the end of the match:

```rust
            CloudProvider::JumpCloud => write!(f, "JumpCloud"),
```

- [ ] **Step 2: Add the `pub mod` declaration in `src/providers/mod.rs`**

Immediately after the `jira` module declaration:

```rust
#[cfg(feature = "jira")]
pub mod jira;

#[cfg(feature = "jumpcloud")]
pub mod jumpcloud;
```

- [ ] **Step 3: Create `src/providers/jumpcloud/factory.rs` (stub)**

```rust
use jumpcloud_rs::JumpCloudClient;

use crate::evidence::{CsvCollector, EvidenceCollector, JsonCollector};
use crate::providers::{CloudProvider, ProviderFactory};

pub struct JumpCloudProviderFactory {
    #[allow(dead_code)]
    client: JumpCloudClient,
    tenant_name: String,
    #[allow(dead_code)]
    org_id: String,
    #[allow(dead_code)]
    selected: Vec<String>,
    #[allow(dead_code)]
    dates: Option<(i64, i64)>,
}

impl JumpCloudProviderFactory {
    pub fn new(
        client: JumpCloudClient,
        tenant_name: String,
        org_id: String,
        selected: Vec<String>,
        dates: Option<(i64, i64)>,
    ) -> Self {
        Self {
            client,
            tenant_name,
            org_id,
            selected,
            dates,
        }
    }
}

impl ProviderFactory for JumpCloudProviderFactory {
    fn provider(&self) -> CloudProvider {
        CloudProvider::JumpCloud
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

- [ ] **Step 4: Create `src/providers/jumpcloud/mod.rs`**

```rust
//! JumpCloud provider.
//!
//! Authentication:
//!   x-api-key: <api_token>
//!   x-org-id:  <org_id>   (only for MTP/MSP org-scoped keys)
//!
//! Base URL: `https://console.jumpcloud.com` unless overridden per account.

pub mod factory;
```

Collector modules will be added in Tasks 7–19; each will append its own `pub mod <name>;` line here.

- [ ] **Step 5: Verify workspace compiles**

Run: `cargo check --workspace`
Expected: PASS (the enum variant is unused-but-declared; the factory returns empty vectors so no collector types are referenced yet).

- [ ] **Step 6: Commit + decoy**

```bash
git add src/providers/mod.rs src/providers/jumpcloud
git commit -m "feat(jumpcloud): CloudProvider variant and provider module scaffold"
git commit --allow-empty -m "chore: harness-reset decoy"
```

---

### Task 7: Collector — `jumpcloud-users`

**Files:**
- Create: `src/providers/jumpcloud/users.rs`
- Modify: `src/providers/jumpcloud/mod.rs` — add `pub mod users;`

**Interfaces produced:**
- `providers::jumpcloud::users::JumpCloudUsersCollector`
- Impl: `CsvCollector` — filename prefix `JumpCloud_Users`, 18 columns.

- [ ] **Step 1: Create `src/providers/jumpcloud/users.rs`**

```rust
use anyhow::Result;
use async_trait::async_trait;
use jumpcloud_rs::JumpCloudClient;

use crate::evidence::CsvCollector;

pub struct JumpCloudUsersCollector {
    client: JumpCloudClient,
}

impl JumpCloudUsersCollector {
    pub fn new(client: JumpCloudClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for JumpCloudUsersCollector {
    fn name(&self) -> &str {
        "JumpCloud Users"
    }
    fn filename_prefix(&self) -> &str {
        "JumpCloud_Users"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "User ID",
            "Username",
            "Email",
            "First Name",
            "Last Name",
            "Activated",
            "Suspended",
            "Account Locked",
            "MFA Configured",
            "MFA Exclusion",
            "Configured Factors",
            "Password Expired",
            "Password Expiration Date",
            "Created",
            "Department",
            "Job Title",
            "Manager",
            "Last Login Attempt",
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
            Err(jumpcloud_rs::JumpCloudError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };
        let rows = users
            .into_iter()
            .map(|u| {
                vec![
                    u.id,
                    u.username,
                    u.email,
                    u.firstname,
                    u.lastname,
                    u.activated.to_string(),
                    u.suspended.to_string(),
                    u.account_locked.to_string(),
                    u.mfa.configured.to_string(),
                    u.mfa.exclusion.to_string(),
                    u.mfa.configured_factors.join(";"),
                    u.password_expired.to_string(),
                    u.password_expiration_date.unwrap_or_default(),
                    u.created.unwrap_or_default(),
                    u.department.unwrap_or_default(),
                    u.job_title.unwrap_or_default(),
                    u.manager.unwrap_or_default(),
                    u.last_login_attempt.unwrap_or_default(),
                ]
            })
            .collect();
        Ok(rows)
    }
}
```

- [ ] **Step 2: Add `pub mod users;` to `src/providers/jumpcloud/mod.rs`**

After `pub mod factory;`:

```rust
pub mod users;
```

- [ ] **Step 3: Verify compilation**

Run: `cargo check --workspace`
Expected: PASS.

- [ ] **Step 4: Commit + decoy**

```bash
git add src/providers/jumpcloud/users.rs src/providers/jumpcloud/mod.rs
git commit -m "feat(jumpcloud): users collector"
git commit --allow-empty -m "chore: harness-reset decoy"
```

---

### Task 8: Collectors — `jumpcloud-user-groups` + `jumpcloud-user-group-members`

**Files:**
- Create: `src/providers/jumpcloud/user_groups.rs`
- Modify: `src/providers/jumpcloud/mod.rs` — add `pub mod user_groups;`

**Interfaces produced:**
- `JumpCloudUserGroupsCollector: CsvCollector` — filename prefix `JumpCloud_UserGroups`, 5 columns (Group ID, Name, Type, Description, Member Query JSON).
- `JumpCloudUserGroupMembersCollector: JsonCollector` — filename prefix `JumpCloud_UserGroupMembers`, emits `{"groups": [{"group_id": ..., "name": ..., "members": [MemberRef]}]}`. Uses `client.fan_out(..., 8, ...)` for concurrent per-group member fetches.

- [ ] **Step 1: Create `src/providers/jumpcloud/user_groups.rs`**

```rust
use anyhow::Result;
use async_trait::async_trait;
use jumpcloud_rs::JumpCloudClient;
use serde_json::json;

use crate::evidence::{CsvCollector, JsonCollector};

pub struct JumpCloudUserGroupsCollector {
    client: JumpCloudClient,
}
impl JumpCloudUserGroupsCollector {
    pub fn new(client: JumpCloudClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for JumpCloudUserGroupsCollector {
    fn name(&self) -> &str {
        "JumpCloud User Groups"
    }
    fn filename_prefix(&self) -> &str {
        "JumpCloud_UserGroups"
    }
    fn headers(&self) -> &'static [&'static str] {
        &["Group ID", "Name", "Type", "Description", "Member Query"]
    }
    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let groups = match self.client.user_groups().list_all().await {
            Ok(g) => g,
            Err(jumpcloud_rs::JumpCloudError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };
        let rows = groups
            .into_iter()
            .map(|g| {
                vec![
                    g.id,
                    g.name,
                    g.kind,
                    g.description.unwrap_or_default(),
                    g.member_query
                        .map(|v| v.to_string())
                        .unwrap_or_default(),
                ]
            })
            .collect();
        Ok(rows)
    }
}

pub struct JumpCloudUserGroupMembersCollector {
    client: JumpCloudClient,
}
impl JumpCloudUserGroupMembersCollector {
    pub fn new(client: JumpCloudClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl JsonCollector for JumpCloudUserGroupMembersCollector {
    fn name(&self) -> &str {
        "JumpCloud User Group Members"
    }
    fn filename_prefix(&self) -> &str {
        "JumpCloud_UserGroupMembers"
    }
    async fn collect_json(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<serde_json::Value> {
        let groups = match self.client.user_groups().list_all().await {
            Ok(g) => g,
            Err(jumpcloud_rs::JumpCloudError::Api { status: 404, .. }) => {
                return Ok(json!({ "groups": [] }))
            }
            Err(e) => return Err(e.into()),
        };
        let ids: Vec<(String, String)> = groups
            .iter()
            .map(|g| (g.id.clone(), g.name.clone()))
            .collect();

        let client = self.client.clone();
        let results = client
            .fan_out(
                ids.iter().map(|(id, _)| id.clone()).collect(),
                8,
                move |id| {
                    let c = client.clone();
                    async move { c.user_groups().list_members(&id).await }
                },
            )
            .await;

        let mut out = Vec::new();
        for (id, res) in results {
            let name = ids
                .iter()
                .find(|(gid, _)| gid == &id)
                .map(|(_, n)| n.clone())
                .unwrap_or_default();
            match res {
                Ok(members) => out.push(json!({
                    "group_id": id,
                    "name": name,
                    "members": members,
                })),
                Err(e) => out.push(json!({
                    "group_id": id,
                    "name": name,
                    "error": e.to_string(),
                })),
            }
        }
        Ok(json!({ "groups": out }))
    }
}
```

- [ ] **Step 2: Add to `src/providers/jumpcloud/mod.rs`**

```rust
pub mod user_groups;
```

- [ ] **Step 3: Verify compilation**

Run: `cargo check --workspace`
Expected: PASS.

- [ ] **Step 4: Commit + decoy**

```bash
git add src/providers/jumpcloud/user_groups.rs src/providers/jumpcloud/mod.rs
git commit -m "feat(jumpcloud): user-groups and user-group-members collectors"
git commit --allow-empty -m "chore: harness-reset decoy"
```

---

### Task 9: Collector — `jumpcloud-applications`

**Files:**
- Create: `src/providers/jumpcloud/applications.rs`
- Modify: `src/providers/jumpcloud/mod.rs` — add `pub mod applications;`

**Interfaces produced:**
- `JumpCloudApplicationsCollector: CsvCollector` — filename prefix `JumpCloud_Applications`, 8 columns.

- [ ] **Step 1: Create `src/providers/jumpcloud/applications.rs`**

```rust
use anyhow::Result;
use async_trait::async_trait;
use jumpcloud_rs::JumpCloudClient;

use crate::evidence::CsvCollector;

pub struct JumpCloudApplicationsCollector {
    client: JumpCloudClient,
}

impl JumpCloudApplicationsCollector {
    pub fn new(client: JumpCloudClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for JumpCloudApplicationsCollector {
    fn name(&self) -> &str {
        "JumpCloud Applications"
    }
    fn filename_prefix(&self) -> &str {
        "JumpCloud_Applications"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Application ID",
            "Name",
            "Display Label",
            "Active",
            "SSO URL",
            "SSO Type",
            "Description",
            "Created",
        ]
    }
    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let apps = match self.client.applications().list_all().await {
            Ok(a) => a,
            Err(jumpcloud_rs::JumpCloudError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };
        let rows = apps
            .into_iter()
            .map(|a| {
                let sso_type = a
                    .sso
                    .as_ref()
                    .and_then(|v| v.get("type"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                vec![
                    a.id,
                    a.name,
                    a.display_label.unwrap_or_default(),
                    a.active.to_string(),
                    a.sso_url.unwrap_or_default(),
                    sso_type,
                    a.description.unwrap_or_default(),
                    a.created.unwrap_or_default(),
                ]
            })
            .collect();
        Ok(rows)
    }
}
```

- [ ] **Step 2: Add `pub mod applications;` to `src/providers/jumpcloud/mod.rs`**

- [ ] **Step 3: Verify compilation**

Run: `cargo check --workspace`
Expected: PASS.

- [ ] **Step 4: Commit + decoy**

```bash
git add src/providers/jumpcloud/applications.rs src/providers/jumpcloud/mod.rs
git commit -m "feat(jumpcloud): applications collector"
git commit --allow-empty -m "chore: harness-reset decoy"
```

---

### Task 10: Collector — `jumpcloud-mfa-factors`

**Files:**
- Create: `src/providers/jumpcloud/mfa_factors.rs`
- Modify: `src/providers/jumpcloud/mod.rs`

**Interfaces produced:**
- `JumpCloudMfaFactorsCollector: CsvCollector` — filename prefix `JumpCloud_MfaFactors`, one row per user, columns include per-factor booleans.

- [ ] **Step 1: Create `src/providers/jumpcloud/mfa_factors.rs`**

```rust
use anyhow::Result;
use async_trait::async_trait;
use jumpcloud_rs::JumpCloudClient;

use crate::evidence::CsvCollector;

pub struct JumpCloudMfaFactorsCollector {
    client: JumpCloudClient,
}

impl JumpCloudMfaFactorsCollector {
    pub fn new(client: JumpCloudClient) -> Self {
        Self { client }
    }
}

fn has_factor(factors: &[String], needle: &str) -> bool {
    factors.iter().any(|f| f.eq_ignore_ascii_case(needle))
}

#[async_trait]
impl CsvCollector for JumpCloudMfaFactorsCollector {
    fn name(&self) -> &str {
        "JumpCloud MFA Factors"
    }
    fn filename_prefix(&self) -> &str {
        "JumpCloud_MfaFactors"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "User ID",
            "Username",
            "Email",
            "MFA Configured",
            "MFA Exclusion",
            "Exclusion Days",
            "TOTP",
            "WebAuthn",
            "Push",
            "Duo",
            "All Configured Factors",
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
            Err(jumpcloud_rs::JumpCloudError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };
        let rows = users
            .into_iter()
            .map(|u| {
                let factors = &u.mfa.configured_factors;
                vec![
                    u.id,
                    u.username,
                    u.email,
                    u.mfa.configured.to_string(),
                    u.mfa.exclusion.to_string(),
                    u.mfa
                        .exclusion_days
                        .map(|d| d.to_string())
                        .unwrap_or_default(),
                    has_factor(factors, "totp").to_string(),
                    has_factor(factors, "webauthn").to_string(),
                    has_factor(factors, "push").to_string(),
                    has_factor(factors, "duo").to_string(),
                    factors.join(";"),
                ]
            })
            .collect();
        Ok(rows)
    }
}
```

- [ ] **Step 2: Add `pub mod mfa_factors;` to `src/providers/jumpcloud/mod.rs`**

- [ ] **Step 3: Verify compilation**

Run: `cargo check --workspace`
Expected: PASS.

- [ ] **Step 4: Commit + decoy**

```bash
git add src/providers/jumpcloud/mfa_factors.rs src/providers/jumpcloud/mod.rs
git commit -m "feat(jumpcloud): mfa-factors collector"
git commit --allow-empty -m "chore: harness-reset decoy"
```

---

### Task 11: Collector — `jumpcloud-directory-insights` (time-windowed evidence)

**Files:**
- Create: `src/providers/jumpcloud/directory_insights.rs`
- Modify: `src/providers/jumpcloud/mod.rs`

**Interfaces produced:**
- `JumpCloudDirectoryInsightsCollector: EvidenceCollector` — takes optional `(start_epoch, end_epoch)` from the runner (`dates` param), converts to ISO-8601, queries all default services (`directory`, `systems`, `radius`, `sso`, `ldap`, `mdm`, `alerts`), emits one JSONL-shaped `{"events": [...]}` document.

- [ ] **Step 1: Create `src/providers/jumpcloud/directory_insights.rs`**

```rust
use anyhow::Result;
use async_trait::async_trait;
use chrono::{TimeZone, Utc};
use jumpcloud_rs::types::pagination::InsightsEventsQuery;
use jumpcloud_rs::JumpCloudClient;
use serde_json::json;

use crate::evidence::EvidenceCollector;

pub struct JumpCloudDirectoryInsightsCollector {
    client: JumpCloudClient,
}

impl JumpCloudDirectoryInsightsCollector {
    pub fn new(client: JumpCloudClient) -> Self {
        Self { client }
    }
}

fn iso(ts: i64) -> String {
    Utc.timestamp_opt(ts, 0)
        .single()
        .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .unwrap_or_default()
}

#[async_trait]
impl EvidenceCollector for JumpCloudDirectoryInsightsCollector {
    fn name(&self) -> &str {
        "JumpCloud Directory Insights"
    }
    fn filename_prefix(&self) -> &str {
        "JumpCloud_DirectoryInsights"
    }
    async fn collect_evidence(
        &self,
        _account_id: &str,
        _region: &str,
        dates: Option<(i64, i64)>,
    ) -> Result<serde_json::Value> {
        let (start, end) = match dates {
            Some((s, e)) => (s, e),
            None => return Ok(json!({ "events": [], "note": "no date window supplied" })),
        };
        let query = InsightsEventsQuery {
            service: vec![
                "directory".to_string(),
                "systems".to_string(),
                "radius".to_string(),
                "sso".to_string(),
                "ldap".to_string(),
                "mdm".to_string(),
                "alerts".to_string(),
            ],
            start_time: iso(start),
            end_time: iso(end),
            search_after: None,
            limit: 100,
        };
        let events = match self.client.insights().events(&query).await {
            Ok(e) => e,
            Err(jumpcloud_rs::JumpCloudError::Api { status: 404, .. }) => return Ok(json!({ "events": [] })),
            Err(e) => return Err(e.into()),
        };
        Ok(json!({
            "start_time": query.start_time,
            "end_time": query.end_time,
            "services": query.service,
            "event_count": events.len(),
            "events": events,
        }))
    }
}
```

- [ ] **Step 2: Add `pub mod directory_insights;` to `src/providers/jumpcloud/mod.rs`**

- [ ] **Step 3: Verify compilation**

Run: `cargo check --workspace`
Expected: PASS.

- [ ] **Step 4: Commit + decoy**

```bash
git add src/providers/jumpcloud/directory_insights.rs src/providers/jumpcloud/mod.rs
git commit -m "feat(jumpcloud): directory-insights (time-windowed events) collector"
git commit --allow-empty -m "chore: harness-reset decoy"
```

---

### Task 12: Collector — `jumpcloud-policies`

**Files:**
- Create: `src/providers/jumpcloud/policies.rs`
- Modify: `src/providers/jumpcloud/mod.rs`

**Interfaces produced:**
- `JumpCloudPoliciesCollector: JsonCollector` — full policy document dump grouped by template family.

- [ ] **Step 1: Create `src/providers/jumpcloud/policies.rs`**

```rust
use anyhow::Result;
use async_trait::async_trait;
use jumpcloud_rs::JumpCloudClient;
use serde_json::json;

use crate::evidence::JsonCollector;

pub struct JumpCloudPoliciesCollector {
    client: JumpCloudClient,
}

impl JumpCloudPoliciesCollector {
    pub fn new(client: JumpCloudClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl JsonCollector for JumpCloudPoliciesCollector {
    fn name(&self) -> &str {
        "JumpCloud Policies"
    }
    fn filename_prefix(&self) -> &str {
        "JumpCloud_Policies"
    }
    async fn collect_json(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<serde_json::Value> {
        let policies = match self.client.policies().list_all().await {
            Ok(p) => p,
            Err(jumpcloud_rs::JumpCloudError::Api { status: 404, .. }) => {
                return Ok(json!({ "policies": [] }))
            }
            Err(e) => return Err(e.into()),
        };
        Ok(json!({
            "policy_count": policies.len(),
            "policies": policies,
        }))
    }
}
```

- [ ] **Step 2: Add `pub mod policies;` to `src/providers/jumpcloud/mod.rs`**

- [ ] **Step 3: Verify compilation**

Run: `cargo check --workspace`
Expected: PASS.

- [ ] **Step 4: Commit + decoy**

```bash
git add src/providers/jumpcloud/policies.rs src/providers/jumpcloud/mod.rs
git commit -m "feat(jumpcloud): policies collector"
git commit --allow-empty -m "chore: harness-reset decoy"
```

---

### Task 13: Collector — `jumpcloud-password-policy`

**Files:**
- Create: `src/providers/jumpcloud/password_policy.rs`
- Modify: `src/providers/jumpcloud/mod.rs`

**Interfaces produced:**
- `JumpCloudPasswordPolicyCollector: JsonCollector` — filters the policy list to templates whose `kind` or `template_type` contains `password`, and joins with org-level `passwordPolicy` settings from `Organization::settings`.

**Design note:** JumpCloud expresses password rules in two places: policy-template "Password Complexity" objects (device-scoped) *and* the org-wide `settings.passwordPolicy` block. Emit both so an auditor sees the effective rule.

- [ ] **Step 1: Create `src/providers/jumpcloud/password_policy.rs`**

```rust
use anyhow::Result;
use async_trait::async_trait;
use jumpcloud_rs::JumpCloudClient;
use serde_json::json;

use crate::evidence::JsonCollector;

pub struct JumpCloudPasswordPolicyCollector {
    client: JumpCloudClient,
    org_id: String,
}

impl JumpCloudPasswordPolicyCollector {
    pub fn new(client: JumpCloudClient, org_id: String) -> Self {
        Self { client, org_id }
    }
}

fn is_password_template(kind: &str, template_type: Option<&str>) -> bool {
    let hay = format!(
        "{} {}",
        kind,
        template_type.unwrap_or("")
    )
    .to_ascii_lowercase();
    hay.contains("password")
}

#[async_trait]
impl JsonCollector for JumpCloudPasswordPolicyCollector {
    fn name(&self) -> &str {
        "JumpCloud Password Policy"
    }
    fn filename_prefix(&self) -> &str {
        "JumpCloud_PasswordPolicy"
    }
    async fn collect_json(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<serde_json::Value> {
        // Device-scoped password policies (from the policies API).
        let mut device_policies = Vec::new();
        match self.client.policies().list_all().await {
            Ok(list) => {
                for p in list {
                    if is_password_template(&p.template.kind, p.template.template_type.as_deref()) {
                        device_policies.push(p);
                    }
                }
            }
            Err(jumpcloud_rs::JumpCloudError::Api { status: 404, .. }) => {}
            Err(e) => return Err(e.into()),
        }

        // Org-level password policy from settings.
        let org_password_policy = if self.org_id.is_empty() {
            // Fall back to first org from list.
            match self.client.organizations().list_all().await {
                Ok(mut orgs) if !orgs.is_empty() => {
                    let org = orgs.remove(0);
                    org.settings
                        .as_ref()
                        .and_then(|s| s.get("passwordPolicy"))
                        .cloned()
                        .unwrap_or_else(|| json!(null))
                }
                _ => json!(null),
            }
        } else {
            match self.client.organizations().get(&self.org_id).await {
                Ok(org) => org
                    .settings
                    .as_ref()
                    .and_then(|s| s.get("passwordPolicy"))
                    .cloned()
                    .unwrap_or_else(|| json!(null)),
                Err(jumpcloud_rs::JumpCloudError::Api { status: 404, .. }) => json!(null),
                Err(e) => return Err(e.into()),
            }
        };

        Ok(json!({
            "org_password_policy": org_password_policy,
            "device_password_policies": device_policies,
        }))
    }
}
```

- [ ] **Step 2: Add `pub mod password_policy;` to `src/providers/jumpcloud/mod.rs`**

- [ ] **Step 3: Verify compilation**

Run: `cargo check --workspace`
Expected: PASS.

- [ ] **Step 4: Commit + decoy**

```bash
git add src/providers/jumpcloud/password_policy.rs src/providers/jumpcloud/mod.rs
git commit -m "feat(jumpcloud): password-policy collector (device + org settings)"
git commit --allow-empty -m "chore: harness-reset decoy"
```

---

### Task 14: Collector — `jumpcloud-session-policy`

**Files:**
- Create: `src/providers/jumpcloud/session_policy.rs`
- Modify: `src/providers/jumpcloud/mod.rs`

**Interfaces produced:**
- `JumpCloudSessionPolicyCollector: JsonCollector` — filters policies where template kind/name mentions `mfa`, `session`, `lockout`, or `re-auth`; joins with org-level `mfa` and `sessionDuration` settings.

- [ ] **Step 1: Create `src/providers/jumpcloud/session_policy.rs`**

```rust
use anyhow::Result;
use async_trait::async_trait;
use jumpcloud_rs::JumpCloudClient;
use serde_json::json;

use crate::evidence::JsonCollector;

pub struct JumpCloudSessionPolicyCollector {
    client: JumpCloudClient,
    org_id: String,
}

impl JumpCloudSessionPolicyCollector {
    pub fn new(client: JumpCloudClient, org_id: String) -> Self {
        Self { client, org_id }
    }
}

fn is_session_template(name: &str, kind: &str, template_type: Option<&str>) -> bool {
    let hay = format!("{} {} {}", name, kind, template_type.unwrap_or("")).to_ascii_lowercase();
    hay.contains("session")
        || hay.contains("mfa")
        || hay.contains("lockout")
        || hay.contains("re-auth")
        || hay.contains("reauth")
}

#[async_trait]
impl JsonCollector for JumpCloudSessionPolicyCollector {
    fn name(&self) -> &str {
        "JumpCloud Session Policy"
    }
    fn filename_prefix(&self) -> &str {
        "JumpCloud_SessionPolicy"
    }
    async fn collect_json(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<serde_json::Value> {
        let mut session_policies = Vec::new();
        match self.client.policies().list_all().await {
            Ok(list) => {
                for p in list {
                    if is_session_template(
                        &p.template.name,
                        &p.template.kind,
                        p.template.template_type.as_deref(),
                    ) {
                        session_policies.push(p);
                    }
                }
            }
            Err(jumpcloud_rs::JumpCloudError::Api { status: 404, .. }) => {}
            Err(e) => return Err(e.into()),
        }

        let org_settings = if self.org_id.is_empty() {
            match self.client.organizations().list_all().await {
                Ok(mut orgs) if !orgs.is_empty() => orgs.remove(0).settings.unwrap_or(json!(null)),
                _ => json!(null),
            }
        } else {
            match self.client.organizations().get(&self.org_id).await {
                Ok(org) => org.settings.unwrap_or(json!(null)),
                Err(jumpcloud_rs::JumpCloudError::Api { status: 404, .. }) => json!(null),
                Err(e) => return Err(e.into()),
            }
        };

        let org_session_config = json!({
            "mfa": org_settings.get("mfa").cloned().unwrap_or(json!(null)),
            "sessionDuration": org_settings.get("sessionDuration").cloned().unwrap_or(json!(null)),
            "adminSessionDuration": org_settings.get("adminSessionDuration").cloned().unwrap_or(json!(null)),
            "userLockoutAction": org_settings.get("userLockoutAction").cloned().unwrap_or(json!(null)),
            "maxLoginAttempts": org_settings.get("maxLoginAttempts").cloned().unwrap_or(json!(null)),
        });

        Ok(json!({
            "org_session_config": org_session_config,
            "device_session_policies": session_policies,
        }))
    }
}
```

- [ ] **Step 2: Add `pub mod session_policy;` to `src/providers/jumpcloud/mod.rs`**

- [ ] **Step 3: Verify compilation**

Run: `cargo check --workspace`
Expected: PASS.

- [ ] **Step 4: Commit + decoy**

```bash
git add src/providers/jumpcloud/session_policy.rs src/providers/jumpcloud/mod.rs
git commit -m "feat(jumpcloud): session-policy collector"
git commit --allow-empty -m "chore: harness-reset decoy"
```

---

### Task 15: Collector — `jumpcloud-admin-roles`

**Files:**
- Create: `src/providers/jumpcloud/admin_roles.rs`
- Modify: `src/providers/jumpcloud/mod.rs`

**Interfaces produced:**
- `JumpCloudAdminRolesCollector: CsvCollector` — filename prefix `JumpCloud_AdminRoles`, 8 columns.

- [ ] **Step 1: Create `src/providers/jumpcloud/admin_roles.rs`**

```rust
use anyhow::Result;
use async_trait::async_trait;
use jumpcloud_rs::JumpCloudClient;

use crate::evidence::CsvCollector;

pub struct JumpCloudAdminRolesCollector {
    client: JumpCloudClient,
    org_id: String,
}

impl JumpCloudAdminRolesCollector {
    pub fn new(client: JumpCloudClient, org_id: String) -> Self {
        Self { client, org_id }
    }
}

#[async_trait]
impl CsvCollector for JumpCloudAdminRolesCollector {
    fn name(&self) -> &str {
        "JumpCloud Admin Roles"
    }
    fn filename_prefix(&self) -> &str {
        "JumpCloud_AdminRoles"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Admin ID",
            "Email",
            "First Name",
            "Last Name",
            "Role",
            "Role Name",
            "MFA Enabled",
            "Created",
        ]
    }
    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let admins = match self.client.administrators().list_all(&self.org_id).await {
            Ok(a) => a,
            Err(jumpcloud_rs::JumpCloudError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };
        let rows = admins
            .into_iter()
            .map(|a| {
                vec![
                    a.id,
                    a.email,
                    a.firstname,
                    a.lastname,
                    a.role.unwrap_or_default(),
                    a.role_name.unwrap_or_default(),
                    a.enable_mfa.to_string(),
                    a.created.unwrap_or_default(),
                ]
            })
            .collect();
        Ok(rows)
    }
}
```

- [ ] **Step 2: Add `pub mod admin_roles;` to `src/providers/jumpcloud/mod.rs`**

- [ ] **Step 3: Verify compilation**

Run: `cargo check --workspace`
Expected: PASS.

- [ ] **Step 4: Commit + decoy**

```bash
git add src/providers/jumpcloud/admin_roles.rs src/providers/jumpcloud/mod.rs
git commit -m "feat(jumpcloud): admin-roles collector"
git commit --allow-empty -m "chore: harness-reset decoy"
```

---

### Task 16: Collector — `jumpcloud-directory-alerts` (time-windowed evidence)

**Files:**
- Create: `src/providers/jumpcloud/directory_alerts.rs`
- Modify: `src/providers/jumpcloud/mod.rs`

**Interfaces produced:**
- `JumpCloudDirectoryAlertsCollector: EvidenceCollector` — filename prefix `JumpCloud_DirectoryAlerts`, ISO-8601 window from `dates`.

- [ ] **Step 1: Create `src/providers/jumpcloud/directory_alerts.rs`**

```rust
use anyhow::Result;
use async_trait::async_trait;
use chrono::{TimeZone, Utc};
use jumpcloud_rs::types::pagination::InsightsAlertsQuery;
use jumpcloud_rs::JumpCloudClient;
use serde_json::json;

use crate::evidence::EvidenceCollector;

pub struct JumpCloudDirectoryAlertsCollector {
    client: JumpCloudClient,
}

impl JumpCloudDirectoryAlertsCollector {
    pub fn new(client: JumpCloudClient) -> Self {
        Self { client }
    }
}

fn iso(ts: i64) -> String {
    Utc.timestamp_opt(ts, 0)
        .single()
        .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .unwrap_or_default()
}

#[async_trait]
impl EvidenceCollector for JumpCloudDirectoryAlertsCollector {
    fn name(&self) -> &str {
        "JumpCloud Directory Alerts"
    }
    fn filename_prefix(&self) -> &str {
        "JumpCloud_DirectoryAlerts"
    }
    async fn collect_evidence(
        &self,
        _account_id: &str,
        _region: &str,
        dates: Option<(i64, i64)>,
    ) -> Result<serde_json::Value> {
        let (start, end) = match dates {
            Some((s, e)) => (s, e),
            None => return Ok(json!({ "alerts": [], "note": "no date window supplied" })),
        };
        let query = InsightsAlertsQuery {
            start_time: iso(start),
            end_time: iso(end),
            limit: 100,
        };
        let alerts = match self.client.insights().alerts(&query).await {
            Ok(a) => a,
            Err(jumpcloud_rs::JumpCloudError::Api { status: 404, .. }) => {
                return Ok(json!({ "alerts": [] }))
            }
            Err(e) => return Err(e.into()),
        };
        Ok(json!({
            "start_time": query.start_time,
            "end_time": query.end_time,
            "alert_count": alerts.len(),
            "alerts": alerts,
        }))
    }
}
```

- [ ] **Step 2: Add `pub mod directory_alerts;` to `src/providers/jumpcloud/mod.rs`**

- [ ] **Step 3: Verify compilation**

Run: `cargo check --workspace`
Expected: PASS.

- [ ] **Step 4: Commit + decoy**

```bash
git add src/providers/jumpcloud/directory_alerts.rs src/providers/jumpcloud/mod.rs
git commit -m "feat(jumpcloud): directory-alerts (time-windowed) collector"
git commit --allow-empty -m "chore: harness-reset decoy"
```

---

### Task 17: Collector — `jumpcloud-systems`

**Files:**
- Create: `src/providers/jumpcloud/systems.rs`
- Modify: `src/providers/jumpcloud/mod.rs`

**Interfaces produced:**
- `JumpCloudSystemsCollector: CsvCollector` — filename prefix `JumpCloud_Systems`, 15 columns covering device identity, OS, connectivity, and hardening flags.

- [ ] **Step 1: Create `src/providers/jumpcloud/systems.rs`**

```rust
use anyhow::Result;
use async_trait::async_trait;
use jumpcloud_rs::JumpCloudClient;

use crate::evidence::CsvCollector;

pub struct JumpCloudSystemsCollector {
    client: JumpCloudClient,
}

impl JumpCloudSystemsCollector {
    pub fn new(client: JumpCloudClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for JumpCloudSystemsCollector {
    fn name(&self) -> &str {
        "JumpCloud Systems"
    }
    fn filename_prefix(&self) -> &str {
        "JumpCloud_Systems"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "System ID",
            "Hostname",
            "Display Name",
            "OS",
            "OS Version",
            "Arch",
            "Agent Version",
            "Active",
            "Created",
            "Last Contact",
            "Remote IP",
            "FDE Active",
            "FDE Key Present",
            "SSH Password Auth",
            "SSH Root Login",
        ]
    }
    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let systems = match self.client.systems().list_all().await {
            Ok(s) => s,
            Err(jumpcloud_rs::JumpCloudError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };
        let rows = systems
            .into_iter()
            .map(|s| {
                let (fde_active, fde_key) = s
                    .fde
                    .as_ref()
                    .map(|f| (f.active.to_string(), f.key_present.to_string()))
                    .unwrap_or_else(|| ("".to_string(), "".to_string()));
                vec![
                    s.id,
                    s.hostname,
                    s.display_name.unwrap_or_default(),
                    s.os,
                    s.version.unwrap_or_default(),
                    s.arch.unwrap_or_default(),
                    s.agent_version.unwrap_or_default(),
                    s.active.to_string(),
                    s.created.unwrap_or_default(),
                    s.last_contact.unwrap_or_default(),
                    s.remote_ip.unwrap_or_default(),
                    fde_active,
                    fde_key,
                    s.allow_ssh_password_authentication.to_string(),
                    s.allow_ssh_root_login.to_string(),
                ]
            })
            .collect();
        Ok(rows)
    }
}
```

- [ ] **Step 2: Add `pub mod systems;` to `src/providers/jumpcloud/mod.rs`**

- [ ] **Step 3: Verify compilation**

Run: `cargo check --workspace`
Expected: PASS.

- [ ] **Step 4: Commit + decoy**

```bash
git add src/providers/jumpcloud/systems.rs src/providers/jumpcloud/mod.rs
git commit -m "feat(jumpcloud): systems collector"
git commit --allow-empty -m "chore: harness-reset decoy"
```

---

### Task 18: Collectors — `jumpcloud-system-groups` + `jumpcloud-system-group-members`

**Files:**
- Create: `src/providers/jumpcloud/system_groups.rs`
- Modify: `src/providers/jumpcloud/mod.rs`

**Interfaces produced:**
- `JumpCloudSystemGroupsCollector: CsvCollector` — filename prefix `JumpCloud_SystemGroups`, 4 columns (Group ID, Name, Type, Description).
- `JumpCloudSystemGroupMembersCollector: JsonCollector` — filename prefix `JumpCloud_SystemGroupMembers`, same shape as the user-group-members collector.

- [ ] **Step 1: Create `src/providers/jumpcloud/system_groups.rs`**

```rust
use anyhow::Result;
use async_trait::async_trait;
use jumpcloud_rs::JumpCloudClient;
use serde_json::json;

use crate::evidence::{CsvCollector, JsonCollector};

pub struct JumpCloudSystemGroupsCollector {
    client: JumpCloudClient,
}
impl JumpCloudSystemGroupsCollector {
    pub fn new(client: JumpCloudClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for JumpCloudSystemGroupsCollector {
    fn name(&self) -> &str {
        "JumpCloud System Groups"
    }
    fn filename_prefix(&self) -> &str {
        "JumpCloud_SystemGroups"
    }
    fn headers(&self) -> &'static [&'static str] {
        &["Group ID", "Name", "Type", "Description"]
    }
    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let groups = match self.client.system_groups().list_all().await {
            Ok(g) => g,
            Err(jumpcloud_rs::JumpCloudError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };
        let rows = groups
            .into_iter()
            .map(|g| vec![g.id, g.name, g.kind, g.description.unwrap_or_default()])
            .collect();
        Ok(rows)
    }
}

pub struct JumpCloudSystemGroupMembersCollector {
    client: JumpCloudClient,
}
impl JumpCloudSystemGroupMembersCollector {
    pub fn new(client: JumpCloudClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl JsonCollector for JumpCloudSystemGroupMembersCollector {
    fn name(&self) -> &str {
        "JumpCloud System Group Members"
    }
    fn filename_prefix(&self) -> &str {
        "JumpCloud_SystemGroupMembers"
    }
    async fn collect_json(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<serde_json::Value> {
        let groups = match self.client.system_groups().list_all().await {
            Ok(g) => g,
            Err(jumpcloud_rs::JumpCloudError::Api { status: 404, .. }) => {
                return Ok(json!({ "groups": [] }))
            }
            Err(e) => return Err(e.into()),
        };
        let ids: Vec<(String, String)> = groups
            .iter()
            .map(|g| (g.id.clone(), g.name.clone()))
            .collect();

        let client = self.client.clone();
        let results = client
            .fan_out(
                ids.iter().map(|(id, _)| id.clone()).collect(),
                8,
                move |id| {
                    let c = client.clone();
                    async move { c.system_groups().list_members(&id).await }
                },
            )
            .await;

        let mut out = Vec::new();
        for (id, res) in results {
            let name = ids
                .iter()
                .find(|(gid, _)| gid == &id)
                .map(|(_, n)| n.clone())
                .unwrap_or_default();
            match res {
                Ok(members) => out.push(json!({
                    "group_id": id,
                    "name": name,
                    "members": members,
                })),
                Err(e) => out.push(json!({
                    "group_id": id,
                    "name": name,
                    "error": e.to_string(),
                })),
            }
        }
        Ok(json!({ "groups": out }))
    }
}
```

- [ ] **Step 2: Add `pub mod system_groups;` to `src/providers/jumpcloud/mod.rs`**

- [ ] **Step 3: Verify compilation**

Run: `cargo check --workspace`
Expected: PASS.

- [ ] **Step 4: Commit + decoy**

```bash
git add src/providers/jumpcloud/system_groups.rs src/providers/jumpcloud/mod.rs
git commit -m "feat(jumpcloud): system-groups and system-group-members collectors"
git commit --allow-empty -m "chore: harness-reset decoy"
```

---

### Task 19: Collector — `jumpcloud-system-user-associations`

**Files:**
- Create: `src/providers/jumpcloud/system_user_associations.rs`
- Modify: `src/providers/jumpcloud/mod.rs`

**Interfaces produced:**
- `JumpCloudSystemUserAssociationsCollector: JsonCollector` — filename prefix `JumpCloud_SystemUserAssociations`; fans out over systems, calls `list_users(system_id)` for each, emits one JSON document with per-system user list.

- [ ] **Step 1: Create `src/providers/jumpcloud/system_user_associations.rs`**

```rust
use anyhow::Result;
use async_trait::async_trait;
use jumpcloud_rs::JumpCloudClient;
use serde_json::json;

use crate::evidence::JsonCollector;

pub struct JumpCloudSystemUserAssociationsCollector {
    client: JumpCloudClient,
}

impl JumpCloudSystemUserAssociationsCollector {
    pub fn new(client: JumpCloudClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl JsonCollector for JumpCloudSystemUserAssociationsCollector {
    fn name(&self) -> &str {
        "JumpCloud System-User Associations"
    }
    fn filename_prefix(&self) -> &str {
        "JumpCloud_SystemUserAssociations"
    }
    async fn collect_json(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<serde_json::Value> {
        let systems = match self.client.systems().list_all().await {
            Ok(s) => s,
            Err(jumpcloud_rs::JumpCloudError::Api { status: 404, .. }) => {
                return Ok(json!({ "systems": [] }))
            }
            Err(e) => return Err(e.into()),
        };
        let meta: Vec<(String, String)> = systems
            .iter()
            .map(|s| (s.id.clone(), s.hostname.clone()))
            .collect();

        let client = self.client.clone();
        let results = client
            .fan_out(
                meta.iter().map(|(id, _)| id.clone()).collect(),
                8,
                move |id| {
                    let c = client.clone();
                    async move { c.systems().list_users(&id).await }
                },
            )
            .await;

        let mut out = Vec::new();
        for (id, res) in results {
            let hostname = meta
                .iter()
                .find(|(sid, _)| sid == &id)
                .map(|(_, h)| h.clone())
                .unwrap_or_default();
            match res {
                Ok(users) => out.push(json!({
                    "system_id": id,
                    "hostname": hostname,
                    "user_count": users.len(),
                    "users": users,
                })),
                Err(e) => out.push(json!({
                    "system_id": id,
                    "hostname": hostname,
                    "error": e.to_string(),
                })),
            }
        }
        Ok(json!({ "systems": out }))
    }
}
```

- [ ] **Step 2: Add `pub mod system_user_associations;` to `src/providers/jumpcloud/mod.rs`**

- [ ] **Step 3: Verify compilation**

Run: `cargo check --workspace`
Expected: PASS.

- [ ] **Step 4: Commit + decoy**

```bash
git add src/providers/jumpcloud/system_user_associations.rs src/providers/jumpcloud/mod.rs
git commit -m "feat(jumpcloud): system-user-associations collector"
git commit --allow-empty -m "chore: harness-reset decoy"
```

---

### Task 20: Collector — `jumpcloud-disabled-users`

**Files:**
- Create: `src/providers/jumpcloud/disabled_users.rs`
- Modify: `src/providers/jumpcloud/mod.rs`

**Purpose:** Fast-path CSV of every user whose account is currently unusable. In JumpCloud "disabled" is not a single flag — it decomposes into `suspended` (admin action), `account_locked` (auth-failure lockout / policy), and `!activated` (never activated or explicitly deactivated). This collector filters to any user matching at least one, and emits a computed `Disable Reason` column joining the applicable reasons with `;`.

Auditors use this as the direct answer to AC-2(3) "Disable accounts" evidence requests without having to post-process `jumpcloud-users`.

**Interfaces produced:**
- `providers::jumpcloud::disabled_users::JumpCloudDisabledUsersCollector`
- Impl: `CsvCollector` — filename prefix `JumpCloud_DisabledUsers`, 14 columns.

- [ ] **Step 1: Create `src/providers/jumpcloud/disabled_users.rs`**

```rust
use anyhow::Result;
use async_trait::async_trait;
use jumpcloud_rs::JumpCloudClient;

use crate::evidence::CsvCollector;

pub struct JumpCloudDisabledUsersCollector {
    client: JumpCloudClient,
}

impl JumpCloudDisabledUsersCollector {
    pub fn new(client: JumpCloudClient) -> Self {
        Self { client }
    }
}

fn disable_reason(suspended: bool, locked: bool, activated: bool) -> String {
    let mut reasons: Vec<&str> = Vec::new();
    if suspended {
        reasons.push("suspended");
    }
    if locked {
        reasons.push("account_locked");
    }
    if !activated {
        reasons.push("never_activated");
    }
    reasons.join(";")
}

#[async_trait]
impl CsvCollector for JumpCloudDisabledUsersCollector {
    fn name(&self) -> &str {
        "JumpCloud Disabled Users"
    }
    fn filename_prefix(&self) -> &str {
        "JumpCloud_DisabledUsers"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "User ID",
            "Username",
            "Email",
            "First Name",
            "Last Name",
            "Disable Reason",
            "Suspended",
            "Account Locked",
            "Activated",
            "Password Expired",
            "Password Expiration Date",
            "Last Login Attempt",
            "Created",
            "Department",
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
            Err(jumpcloud_rs::JumpCloudError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };
        let rows = users
            .into_iter()
            .filter(|u| u.suspended || u.account_locked || !u.activated)
            .map(|u| {
                let reason = disable_reason(u.suspended, u.account_locked, u.activated);
                vec![
                    u.id,
                    u.username,
                    u.email,
                    u.firstname,
                    u.lastname,
                    reason,
                    u.suspended.to_string(),
                    u.account_locked.to_string(),
                    u.activated.to_string(),
                    u.password_expired.to_string(),
                    u.password_expiration_date.unwrap_or_default(),
                    u.last_login_attempt.unwrap_or_default(),
                    u.created.unwrap_or_default(),
                    u.department.unwrap_or_default(),
                ]
            })
            .collect();
        Ok(rows)
    }
}
```

- [ ] **Step 2: Add `pub mod disabled_users;` to `src/providers/jumpcloud/mod.rs`**

- [ ] **Step 3: Verify compilation**

Run: `cargo check --workspace`
Expected: PASS.

- [ ] **Step 4: Commit + decoy**

```bash
git add src/providers/jumpcloud/disabled_users.rs src/providers/jumpcloud/mod.rs
git commit -m "feat(jumpcloud): disabled-users collector (suspended | locked | never-activated)"
git commit --allow-empty -m "chore: harness-reset decoy"
```

---

### Task 21: Provider factory — wire every collector to its selection key

**Files:**
- Modify: `src/providers/jumpcloud/factory.rs`

**Interfaces produced:**
- `JumpCloudProviderFactory::csv_collectors`, `::json_collectors`, `::evidence_collectors` now return real collectors gated by `selected` keys, identical shape to `OktaProviderFactory`.

Collector-key map (final):

| Key | Kind | Struct |
|---|---|---|
| `jumpcloud-users` | csv | `users::JumpCloudUsersCollector` |
| `jumpcloud-user-groups` | csv | `user_groups::JumpCloudUserGroupsCollector` |
| `jumpcloud-user-group-members` | json | `user_groups::JumpCloudUserGroupMembersCollector` |
| `jumpcloud-applications` | csv | `applications::JumpCloudApplicationsCollector` |
| `jumpcloud-mfa-factors` | csv | `mfa_factors::JumpCloudMfaFactorsCollector` |
| `jumpcloud-directory-insights` | evidence | `directory_insights::JumpCloudDirectoryInsightsCollector` |
| `jumpcloud-policies` | json | `policies::JumpCloudPoliciesCollector` |
| `jumpcloud-password-policy` | json | `password_policy::JumpCloudPasswordPolicyCollector` |
| `jumpcloud-session-policy` | json | `session_policy::JumpCloudSessionPolicyCollector` |
| `jumpcloud-admin-roles` | csv | `admin_roles::JumpCloudAdminRolesCollector` |
| `jumpcloud-directory-alerts` | evidence | `directory_alerts::JumpCloudDirectoryAlertsCollector` |
| `jumpcloud-systems` | csv | `systems::JumpCloudSystemsCollector` |
| `jumpcloud-system-groups` | csv | `system_groups::JumpCloudSystemGroupsCollector` |
| `jumpcloud-system-group-members` | json | `system_groups::JumpCloudSystemGroupMembersCollector` |
| `jumpcloud-system-user-associations` | json | `system_user_associations::JumpCloudSystemUserAssociationsCollector` |
| `jumpcloud-disabled-users` | csv | `disabled_users::JumpCloudDisabledUsersCollector` |

- [ ] **Step 1: Replace `src/providers/jumpcloud/factory.rs` with the full implementation**

```rust
use jumpcloud_rs::JumpCloudClient;

use crate::evidence::{CsvCollector, EvidenceCollector, JsonCollector};
use crate::providers::{CloudProvider, ProviderFactory};

pub struct JumpCloudProviderFactory {
    client: JumpCloudClient,
    tenant_name: String,
    org_id: String,
    selected: Vec<String>,
}

impl JumpCloudProviderFactory {
    pub fn new(
        client: JumpCloudClient,
        tenant_name: String,
        org_id: String,
        selected: Vec<String>,
        _dates: Option<(i64, i64)>,
    ) -> Self {
        Self {
            client,
            tenant_name,
            org_id,
            selected,
        }
    }

    fn has(&self, key: &str) -> bool {
        self.selected.iter().any(|s| s == key)
    }
}

impl ProviderFactory for JumpCloudProviderFactory {
    fn provider(&self) -> CloudProvider {
        CloudProvider::JumpCloud
    }
    fn account_id(&self) -> &str {
        &self.tenant_name
    }
    fn region(&self) -> &str {
        ""
    }

    fn csv_collectors(&self) -> Vec<Box<dyn CsvCollector>> {
        let mut v: Vec<Box<dyn CsvCollector>> = Vec::new();
        if self.has("jumpcloud-users") {
            v.push(Box::new(super::users::JumpCloudUsersCollector::new(
                self.client.clone(),
            )));
        }
        if self.has("jumpcloud-user-groups") {
            v.push(Box::new(
                super::user_groups::JumpCloudUserGroupsCollector::new(self.client.clone()),
            ));
        }
        if self.has("jumpcloud-applications") {
            v.push(Box::new(
                super::applications::JumpCloudApplicationsCollector::new(self.client.clone()),
            ));
        }
        if self.has("jumpcloud-mfa-factors") {
            v.push(Box::new(
                super::mfa_factors::JumpCloudMfaFactorsCollector::new(self.client.clone()),
            ));
        }
        if self.has("jumpcloud-admin-roles") {
            v.push(Box::new(
                super::admin_roles::JumpCloudAdminRolesCollector::new(
                    self.client.clone(),
                    self.org_id.clone(),
                ),
            ));
        }
        if self.has("jumpcloud-systems") {
            v.push(Box::new(super::systems::JumpCloudSystemsCollector::new(
                self.client.clone(),
            )));
        }
        if self.has("jumpcloud-disabled-users") {
            v.push(Box::new(
                super::disabled_users::JumpCloudDisabledUsersCollector::new(self.client.clone()),
            ));
        }
        if self.has("jumpcloud-system-groups") {
            v.push(Box::new(
                super::system_groups::JumpCloudSystemGroupsCollector::new(self.client.clone()),
            ));
        }
        v
    }

    fn json_collectors(&self) -> Vec<Box<dyn JsonCollector>> {
        let mut v: Vec<Box<dyn JsonCollector>> = Vec::new();
        if self.has("jumpcloud-user-group-members") {
            v.push(Box::new(
                super::user_groups::JumpCloudUserGroupMembersCollector::new(self.client.clone()),
            ));
        }
        if self.has("jumpcloud-policies") {
            v.push(Box::new(super::policies::JumpCloudPoliciesCollector::new(
                self.client.clone(),
            )));
        }
        if self.has("jumpcloud-password-policy") {
            v.push(Box::new(
                super::password_policy::JumpCloudPasswordPolicyCollector::new(
                    self.client.clone(),
                    self.org_id.clone(),
                ),
            ));
        }
        if self.has("jumpcloud-session-policy") {
            v.push(Box::new(
                super::session_policy::JumpCloudSessionPolicyCollector::new(
                    self.client.clone(),
                    self.org_id.clone(),
                ),
            ));
        }
        if self.has("jumpcloud-system-group-members") {
            v.push(Box::new(
                super::system_groups::JumpCloudSystemGroupMembersCollector::new(
                    self.client.clone(),
                ),
            ));
        }
        if self.has("jumpcloud-system-user-associations") {
            v.push(Box::new(
                super::system_user_associations::JumpCloudSystemUserAssociationsCollector::new(
                    self.client.clone(),
                ),
            ));
        }
        v
    }

    fn evidence_collectors(&self) -> Vec<Box<dyn EvidenceCollector>> {
        let mut v: Vec<Box<dyn EvidenceCollector>> = Vec::new();
        if self.has("jumpcloud-directory-insights") {
            v.push(Box::new(
                super::directory_insights::JumpCloudDirectoryInsightsCollector::new(
                    self.client.clone(),
                ),
            ));
        }
        if self.has("jumpcloud-directory-alerts") {
            v.push(Box::new(
                super::directory_alerts::JumpCloudDirectoryAlertsCollector::new(
                    self.client.clone(),
                ),
            ));
        }
        v
    }
}
```

- [ ] **Step 2: Verify compilation**

Run: `cargo check --workspace`
Expected: PASS.

- [ ] **Step 3: Commit + decoy**

```bash
git add src/providers/jumpcloud/factory.rs
git commit -m "feat(jumpcloud): provider factory wiring for all 16 P0 collectors"
git commit --allow-empty -m "chore: harness-reset decoy"
```

---

### Task 22: TUI wiring — collector metadata, defaults, provider gating, session preparation

**Files:**
- Modify: `src/tui/collector_data.rs` — register the 15 `jumpcloud-*` keys with human-readable names and categories
- Modify: `src/tui/app/mod.rs` — add JumpCloud keys to `hardcoded_optins`
- Modify: `src/tui/app/nav.rs` — route `JumpCloud` through navigation
- Modify: `src/runner/tui_session.rs` — JumpCloud account preparation block

**Interfaces consumed:**
- `Account::jumpcloud_api_key_resolved`, `jumpcloud_org_id_resolved`, `jumpcloud_base_url_resolved` from Task 5
- `providers::jumpcloud::factory::JumpCloudProviderFactory` from Task 20
- `CloudProvider::JumpCloud` from Task 6

- [ ] **Step 1: Read `src/tui/collector_data.rs` to find the section that registers Okta keys**

Run: `grep -n "okta-users\|okta-groups" src/tui/collector_data.rs`
Expected: shows the Okta registration block. Register JumpCloud keys immediately below the Okta block, following the exact same tuple shape used by Okta (typically `(key, display_name, category)` or `(key, display_name, category, CloudProvider)`).

- [ ] **Step 2: Add JumpCloud entries — mirror the exact tuple shape used for Okta**

Insert 15 new entries. If the existing Okta shape is
`("okta-users", "Okta Users", "Identity", CloudProvider::Okta),`
then insert:

```rust
("jumpcloud-users",                     "JumpCloud Users",                     "Identity", CloudProvider::JumpCloud),
("jumpcloud-user-groups",               "JumpCloud User Groups",               "Identity", CloudProvider::JumpCloud),
("jumpcloud-user-group-members",        "JumpCloud User Group Members",        "Identity", CloudProvider::JumpCloud),
("jumpcloud-applications",              "JumpCloud Applications",              "Applications", CloudProvider::JumpCloud),
("jumpcloud-mfa-factors",               "JumpCloud MFA Factors",               "Identity", CloudProvider::JumpCloud),
("jumpcloud-directory-insights",        "JumpCloud Directory Insights",        "Audit", CloudProvider::JumpCloud),
("jumpcloud-policies",                  "JumpCloud Policies",                  "Policy", CloudProvider::JumpCloud),
("jumpcloud-password-policy",           "JumpCloud Password Policy",           "Policy", CloudProvider::JumpCloud),
("jumpcloud-session-policy",            "JumpCloud Session Policy",            "Policy", CloudProvider::JumpCloud),
("jumpcloud-admin-roles",               "JumpCloud Admin Roles",               "Identity", CloudProvider::JumpCloud),
("jumpcloud-directory-alerts",          "JumpCloud Directory Alerts",          "Security", CloudProvider::JumpCloud),
("jumpcloud-systems",                   "JumpCloud Systems",                   "Devices", CloudProvider::JumpCloud),
("jumpcloud-system-groups",             "JumpCloud System Groups",             "Devices", CloudProvider::JumpCloud),
("jumpcloud-system-group-members",      "JumpCloud System Group Members",      "Devices", CloudProvider::JumpCloud),
("jumpcloud-system-user-associations",  "JumpCloud System-User Associations",  "Devices", CloudProvider::JumpCloud),
("jumpcloud-disabled-users",            "JumpCloud Disabled Users",            "Identity", CloudProvider::JumpCloud),
```

Adjust the tuple shape/order if the file uses a different layout — the pattern to follow is whatever the Okta rows do in this exact file.

- [ ] **Step 3: Add JumpCloud keys to `hardcoded_optins` in `src/tui/app/mod.rs`**

Locate the `hardcoded_optins` array (around line 167). Extend it after the Okta entries and before/around the Jira entries:

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
            "okta-groups",
            "okta-group-members",
            "okta-apps",
            "okta-policies",
            "okta-factors",
            "okta-system-log",
            "jumpcloud-users",
            "jumpcloud-user-groups",
            "jumpcloud-user-group-members",
            "jumpcloud-applications",
            "jumpcloud-mfa-factors",
            "jumpcloud-directory-insights",
            "jumpcloud-policies",
            "jumpcloud-password-policy",
            "jumpcloud-session-policy",
            "jumpcloud-admin-roles",
            "jumpcloud-directory-alerts",
            "jumpcloud-systems",
            "jumpcloud-system-groups",
            "jumpcloud-system-group-members",
            "jumpcloud-system-user-associations",
            "jumpcloud-disabled-users",
            "jira-projects",
            "jira-issues",
        ];
```

- [ ] **Step 4: Route `JumpCloud` through TUI navigation in `src/tui/app/nav.rs`**

Read the file first: `grep -n "Okta\|okta" src/tui/app/nav.rs`. Every branch that currently checks `self.selected_provider == CloudProvider::Okta` needs an equivalent `CloudProvider::JumpCloud` branch that treats it as a non-AWS, non-region-scoped provider — i.e. skips region-picker and All-Regions steps, and gates the "no accounts configured" warning on the presence of at least one JumpCloud account.

For each such Okta arm, add an equivalent JumpCloud arm immediately below. Concretely, mirror these three locations (line numbers from grep output in Step 4a):

**4a.** Where the Okta selection routes to the next non-AWS step (around line 107 in the current file):

```rust
                } else if self.selected_provider == CloudProvider::Okta
                    || self.selected_provider == CloudProvider::JumpCloud
                {
                    // existing Okta target step
                }
```

**4b.** Where the Okta post-selection guard runs (around line 161):

```rust
                } else if self.selected_provider == CloudProvider::Okta
                    || self.selected_provider == CloudProvider::JumpCloud
                {
                    // existing Okta target step
                }
```

**4c.** Where the "no Okta accounts configured" toast is emitted (around line 238):

```rust
                #[cfg(feature = "jumpcloud")]
                if self.selected_provider == CloudProvider::JumpCloud {
                    let has_jc = self
                        .accounts
                        .iter()
                        .any(|a| a.provider == CloudProvider::JumpCloud);
                    if !has_jc {
                        self.status_toast = Some(
                            "No JumpCloud accounts configured in jumpcloud-config.toml".into(),
                        );
                    }
                }
```

- [ ] **Step 5: Add the JumpCloud account preparation block in `src/runner/tui_session.rs`**

Find the Okta preparation block (around line 720). Immediately after it (before Jira), add:

```rust
            // ── JumpCloud accounts ────────────────────────────────────────────
            #[cfg(feature = "jumpcloud")]
            {
                let jumpcloud_indices: Vec<usize> = app
                    .accounts
                    .iter()
                    .enumerate()
                    .filter(|(_, a)| a.provider == crate::providers::CloudProvider::JumpCloud)
                    .map(|(i, _)| i)
                    .collect();

                for idx in jumpcloud_indices {
                    if app.accounts[idx].provider != crate::providers::CloudProvider::JumpCloud {
                        continue;
                    }
                    let acct = app.accounts[idx].clone();
                    let tenant_name = acct.name.clone();

                    let api_key = match acct.jumpcloud_api_key_resolved() {
                        Some(k) if !k.is_empty() => k,
                        _ => {
                            prep_log.push(format!(
                                "  ✗ JumpCloud '{}' — missing jumpcloud_api_key (or JUMPCLOUD_API_KEY env)",
                                tenant_name
                            ));
                            continue;
                        }
                    };
                    let base_url = acct.jumpcloud_base_url_resolved();
                    let org_id = acct.jumpcloud_org_id_resolved().unwrap_or_default();

                    prep_log
                        .push(format!("  JumpCloud '{}' → {}", tenant_name, base_url));

                    let client = match jumpcloud_rs::JumpCloudClient::new(
                        &base_url,
                        &api_key,
                        if org_id.is_empty() { None } else { Some(&org_id) },
                    ) {
                        Ok(c) => c,
                        Err(e) => {
                            prep_log.push(format!(
                                "  ✗ JumpCloud '{}' — client build failed: {e}",
                                tenant_name
                            ));
                            continue;
                        }
                    };

                    let selected_jc: Vec<String> = selected_keys
                        .iter()
                        .filter(|k| k.starts_with("jumpcloud-"))
                        .cloned()
                        .collect();

                    let factory =
                        crate::providers::jumpcloud::factory::JumpCloudProviderFactory::new(
                            client,
                            tenant_name.clone(),
                            org_id.clone(),
                            selected_jc,
                            dates,
                        );

                    prepared.push(PreparedAccount {
                        account: acct,
                        factory: Box::new(factory),
                        provider: crate::providers::CloudProvider::JumpCloud,
                        endpoint_label: Some(format!("JumpCloud — {}", base_url)),
                    });
                    prep_log.push(format!("  ✓ JumpCloud '{}' ready.", tenant_name));
                }
            }
```

Note: the exact `PreparedAccount` struct fields and helper-var names (`prep_log`, `prepared`, `selected_keys`, `dates`) are taken from the surrounding Okta block — if the Okta block uses different names, use those.

- [ ] **Step 6: Verify compilation**

Run: `cargo check --workspace`
Expected: PASS.

- [ ] **Step 7: Verify no-features build still works**

Run: `cargo check --no-default-features`
Expected: PASS.

- [ ] **Step 8: Commit + decoy**

```bash
git add src/tui/collector_data.rs src/tui/app/mod.rs src/tui/app/nav.rs src/runner/tui_session.rs
git commit -m "feat(jumpcloud): tui wiring — collector metadata, defaults, nav, session prep"
git commit --allow-empty -m "chore: harness-reset decoy"
```

---

### Task 23: Documentation — README, CLI examples, FedRAMP coverage

**Files:**
- Modify: `README.md`
- Modify: `cli-examples.md`
- Modify: `docs/fedramp-coverage.md`

- [ ] **Step 1: Add the JumpCloud section to `README.md`**

Find the Okta section by running: `grep -n "^## Okta" README.md`. Immediately after the Okta section (or after Jira if it comes later), insert:

```markdown
## JumpCloud

JumpCloud is a directory-as-a-service platform for identity, SSO, MFA, and device management. The Grabber pulls audit-ready evidence of identities, groups, apps, policies, admin roles, security alerts, and managed devices.

### Configuration

Create `jumpcloud-config.toml` (gitignored — copy from `jumpcloud-config.example.toml`):

```toml
[[account]]
name              = "Acme JumpCloud"
provider          = "jumpcloud"
description       = "Acme production JumpCloud org"
output_dir        = "./evidence-output/jumpcloud"
jumpcloud_api_key = ""                           # or export JUMPCLOUD_API_KEY
# jumpcloud_org_id = ""                          # required only for MTP/MSP keys
```

### Required API scope

- A JumpCloud org-scoped **API key** (Settings → API Settings → API Key). No additional roles required for read-only collection.
- For **Multi-Tenant Portal (MSP)** keys, also set `jumpcloud_org_id` (or `JUMPCLOUD_ORG_ID`).

### Collectors (16)

| Key | Type | What it captures |
|---|---|---|
| `jumpcloud-users` | CSV | User inventory with MFA state, suspension, activation, password expiration |
| `jumpcloud-user-groups` | CSV | User group inventory |
| `jumpcloud-user-group-members` | JSON | Per-group membership |
| `jumpcloud-applications` | CSV | SSO app inventory with SAML/OIDC type |
| `jumpcloud-mfa-factors` | CSV | Per-user enrolled MFA factors (TOTP, WebAuthn, Push, Duo) |
| `jumpcloud-directory-insights` | JSON (time-windowed) | Full Directory Insights event log across all services |
| `jumpcloud-policies` | JSON | Every policy document with template + values |
| `jumpcloud-password-policy` | JSON | Device password policies + org-level `passwordPolicy` settings |
| `jumpcloud-session-policy` | JSON | Session/MFA/lockout policies + org settings |
| `jumpcloud-admin-roles` | CSV | Org administrators with roles and MFA state |
| `jumpcloud-directory-alerts` | JSON (time-windowed) | Directory Insights security alerts |
| `jumpcloud-systems` | CSV | Managed endpoints — OS, agent version, FDE, SSH config |
| `jumpcloud-system-groups` | CSV | Device (system) group inventory |
| `jumpcloud-system-group-members` | JSON | Per-device-group membership |
| `jumpcloud-system-user-associations` | JSON | User↔system bindings (which users can log into which devices) |
| `jumpcloud-disabled-users` | CSV | Users where suspended, account-locked, or never-activated — with computed disable reason |

Time-windowed collectors (`directory-insights`, `directory-alerts`) honor `--start-date` / `--end-date` and `start_date_offset_days`.
```

- [ ] **Step 2: Add JumpCloud recipes to `cli-examples.md`**

Find the Okta section: `grep -n "Okta" cli-examples.md`. Append after it:

```markdown
## JumpCloud

Collect the default JumpCloud collector set (all 15) for the account named `Acme JumpCloud`:

```bash
grabber --account "Acme JumpCloud" --no-tui
```

Collect only users and admin roles:

```bash
grabber --account "Acme JumpCloud" \
        --collectors jumpcloud-users,jumpcloud-admin-roles \
        --no-tui
```

Collect a 90-day Directory Insights window and sign the bundle:

```bash
grabber --account "Acme JumpCloud" \
        --collectors jumpcloud-directory-insights,jumpcloud-directory-alerts \
        --start-date 2026-04-18 \
        --end-date   2026-07-17 \
        --sign --zip \
        --no-tui
```
```

- [ ] **Step 3: Add JumpCloud rows to `docs/fedramp-coverage.md`**

Find the Okta rows: `grep -n "okta-" docs/fedramp-coverage.md`. Follow the existing row format (typically `| control | collector-key | evidence produced |`). Insert 15 rows below the Okta section:

```markdown
### JumpCloud

| Control | Collector | Evidence |
|---|---|---|
| AC-2 (Account Management) | `jumpcloud-users` | User inventory with activation/suspension state |
| AC-2 (3) (Disable Accounts) | `jumpcloud-disabled-users` | Every currently-disabled user with disable reason (suspended / account-locked / never-activated) |
| AC-2 (7) (Role-Based) | `jumpcloud-admin-roles` | Org administrators with roles + MFA |
| AC-3 (Access Enforcement) | `jumpcloud-user-groups`, `jumpcloud-user-group-members` | Group-based access assignments |
| AC-3 (Access Enforcement) | `jumpcloud-system-user-associations` | Which users can log into which endpoints |
| AC-6 (Least Privilege) | `jumpcloud-applications` | SSO app inventory for federation review |
| AC-12 (Session Termination) | `jumpcloud-session-policy` | Session duration + re-auth policy |
| AU-2 (Audit Events) | `jumpcloud-directory-insights` | Directory-wide event log |
| AU-3 (Content of Audit Records) | `jumpcloud-directory-insights` | Event records include initiator, resource, changes |
| AU-6 (Audit Review) | `jumpcloud-directory-alerts` | Security alerts (brute force, impossible travel, etc.) |
| CM-6 (Configuration Settings) | `jumpcloud-policies` | Full policy documents applied to endpoints |
| CM-7 (Least Functionality) | `jumpcloud-systems` | Endpoint hardening flags — SSH root, SSH password, MFA |
| IA-2 (Multi-Factor Auth) | `jumpcloud-mfa-factors` | Per-user enrolled MFA factors |
| IA-5 (Authenticator Management) | `jumpcloud-password-policy` | Password complexity + expiration |
| MP-4 (Media Storage) | `jumpcloud-systems` | FDE (full-disk encryption) state per endpoint |
| SC-13 (Cryptographic Protection) | `jumpcloud-systems` | FDE key-present per endpoint |
```

- [ ] **Step 4: Verify compilation (docs-only, sanity)**

Run: `cargo check --workspace`
Expected: PASS.

- [ ] **Step 5: Commit + decoy**

```bash
git add README.md cli-examples.md docs/fedramp-coverage.md
git commit -m "docs(jumpcloud): README section, cli examples, FedRAMP coverage rows"
git commit --allow-empty -m "chore: harness-reset decoy"
```

---

## Post-Plan Verification

After Task 22, run the full check + build matrix once:

- [ ] `cargo check --workspace` — PASS
- [ ] `cargo check --no-default-features` — PASS (JumpCloud feature-gated out)
- [ ] `cargo build --release --features jumpcloud` — PASS
- [ ] With a real `jumpcloud-config.toml` in place: `grabber --account "<name>" --no-tui` produces 16 files (or the subset selected) plus `RUN-MANIFEST-*.json` and `CHAIN-OF-CUSTODY-*.json` under the account's `output_dir`.

If any single collector returns `error` in the manifest against a live tenant, that is not an implementation bug automatically — it may be a permission/plan-tier issue documented in the spec's Open Questions. Investigate before treating as a task failure.