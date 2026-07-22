# Add GitHub Evidence Provider Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add GitHub as a first-class evidence-collection provider — a workspace crate for the GitHub REST API plus collectors for org members, teams, security settings, repositories, branch protection, the org audit log, and Dependabot/secret-scanning/code-scanning alerts — wired into the existing TUI/CLI plumbing.

**Architecture:** Mirror the existing Okta/Jira/Tenable integrations exactly. A new `crates/github-rs` workspace crate wraps the GitHub REST API (`Authorization: Bearer <PAT>` auth, RFC 5988 Link-header pagination, rate-limit-aware retry). A new `src/providers/github` module implements `ProviderFactory` and produces ten `CsvCollector` implementations — **not** `JsonCollector`/`EvidenceCollector`, which the current codebase reserves for AWS only (every non-AWS provider — Okta's 24 collectors, Jira's 27, Tenable's 5 — is a flat `CsvCollector`, with the `dates: Option<(i64,i64)>` parameter handling time-windowed data generically). GitHub-specific config lives in `github-config.toml` (gitignored), merged into the main `AppConfig` at startup like `okta-config.toml`. The TUI gains a `Github` variant on `CloudProvider`; no endpoint- or project-selection screen is needed because a GitHub account entry is scoped to exactly one org (config-driven), exactly like Okta's per-tenant domain.

**Tech Stack:** Rust 1.75+, `reqwest` (rustls), `serde`/`serde_json`, `tokio`, `async_trait`, `wiremock` for HTTP tests. Optional Cargo feature `github`, added to the `default` feature set alongside `tenable`/`okta`/`jira`.

**Reference patterns mirrored throughout this plan:**
- API client, Link-header pagination, rate-limit retry: `crates/okta-rs/src/client.rs` (verified against the actual shipped file, not an earlier draft — its `next_link`/`split_link_entries` bracket-aware comma splitting is ported directly)
- Provider factory + flat collector registration by string key: `src/providers/okta/factory.rs`
- Self-contained nested collector (fetches its own parent list, doesn't depend on a sibling collector being selected): `src/providers/okta/groups.rs` (`OktaGroupMembersCollector`)
- Graceful 404-degrades-to-empty pattern: `src/providers/okta/system_log.rs`
- TUI collector menu: `src/tui/menus/okta.rs` + `src/tui/menus/mod.rs`
- Account config fields + resolvers + config-file merge: `src/app_config.rs` Okta fields (lines 182–189), resolvers (lines 235–249), merge block (lines 311–319)
- TUI session account-prep block: `src/runner/tui_session.rs` Okta block (lines 721–829)
- Provider-switch nav wiring: `src/tui/app/nav.rs` (whole file read; Okta arms at lines 107, 161, 239)
- Provider list (must stay in sync, order-for-order, with the tile list below): `src/tui/events.rs` `handle_provider_selection` (lines 727–745)
- Provider tile: `src/tui/ui/account_screens.rs` `draw_provider_selection` (lines 17–58)

**Out of scope (see `docs/superpowers/specs/2026-07-19-github-provider-design.md` for rationale):**
- GitHub App authentication — PAT only.
- Multi-org fan-out from one account/token — one `[[account]]` = one org.
- FedRAMP requirement/control-ID mapping in `assets/fedramp-map.json` — every baseline collector for every existing provider ships unmapped; mapping only happens in later, requirement-driven follow-up plans.
- GitHub GraphQL API (e.g. SAML SSO identity provider config).
- Branch protection for non-default branches, or repository rulesets.
- A repo/team picker TUI screen — collectors that need repo or team lists enumerate every repo/team in the org automatically.

## Global Constraints

- Rust 1.75+, edition 2021, matching every other crate in this workspace.
- `reqwest` with `rustls-tls`, `default-features = false` (no native-tls / OpenSSL dependency) — matches `okta-rs`/`tenable-rs`/`jira-rs`.
- Every collector is a `CsvCollector` (`src/evidence.rs`) — never `JsonCollector`/`EvidenceCollector`.
- Auth: `Authorization: Bearer <token>` + `Accept: application/vnd.github+json` + `X-GitHub-Api-Version: 2022-11-28` on every request.
- `github_base_url` is the **full REST API root** the caller provides (`https://api.github.com` by default, or `https://HOST/api/v3` for GitHub Enterprise Server) — the client never guesses or rewrites it.
- Every endpoint gated behind a GitHub plan/feature (audit log, the three alert types, the `2fa_disabled` member filter) degrades to an empty/unknown result on 403/404 instead of failing the whole collection run.
- No `assets/fedramp-map.json` changes in this plan.
- No new tests are written at the `src/providers/github/*.rs` collector-wrapper layer — matching the established pattern where `wiremock` tests live only at the crate API layer (`crates/*-rs/tests/`) and the thin provider wrapper is exercised end-to-end by the TUI/CLI, not unit-tested.

---

## File Structure

**New files (crate):**
- `crates/github-rs/Cargo.toml`
- `crates/github-rs/src/lib.rs`
- `crates/github-rs/src/client.rs` — auth, base URL + org, retry, `next_link` pagination helper
- `crates/github-rs/src/error.rs` — `GithubError` enum
- `crates/github-rs/src/api/mod.rs`
- `crates/github-rs/src/api/members.rs` — `MembersApi::list_by_role`, `MembersApi::list_2fa_disabled`
- `crates/github-rs/src/api/teams.rs` — `TeamsApi::list_all`, `TeamsApi::list_members`
- `crates/github-rs/src/api/orgs.rs` — `OrgsApi::get`
- `crates/github-rs/src/api/repos.rs` — `ReposApi::list_all`, `ReposApi::get_branch_protection`
- `crates/github-rs/src/api/audit_log.rs` — `AuditLogApi::events`
- `crates/github-rs/src/api/alerts.rs` — `AlertsApi::dependabot_alerts`, `secret_scanning_alerts`, `code_scanning_alerts`
- `crates/github-rs/src/types/mod.rs`
- `crates/github-rs/src/types/user.rs`
- `crates/github-rs/src/types/team.rs`
- `crates/github-rs/src/types/org.rs`
- `crates/github-rs/src/types/repo.rs`
- `crates/github-rs/src/types/audit_log.rs`
- `crates/github-rs/src/types/alert.rs`

**New files (provider + config):**
- `src/providers/github/mod.rs`
- `src/providers/github/factory.rs` — `GithubProviderFactory: ProviderFactory`
- `src/providers/github/members.rs` — `GithubMembersCollector: CsvCollector`
- `src/providers/github/teams.rs` — `GithubTeamsCollector`, `GithubTeamMembersCollector`
- `src/providers/github/security_settings.rs` — `GithubSecuritySettingsCollector`
- `src/providers/github/repos.rs` — `GithubReposCollector`
- `src/providers/github/branch_protection.rs` — `GithubBranchProtectionCollector`
- `src/providers/github/audit_log.rs` — `GithubAuditLogCollector`
- `src/providers/github/alerts.rs` — `GithubDependabotAlertsCollector`, `GithubSecretScanningAlertsCollector`, `GithubCodeScanningAlertsCollector`
- `src/tui/menus/github.rs`
- `github-config.example.toml`

**Modified files:**
- `Cargo.toml` — workspace member, optional `github-rs` dep, `github` feature
- `.gitignore` — ignore `github-config.toml`
- `src/providers/mod.rs` — `Github` variant on `CloudProvider`, `pub mod github` behind feature
- `src/app_config.rs` — GitHub fields on `Account`, resolvers, `github-config.toml` merge
- `src/tui/menus/mod.rs` — register `GITHUB_CATEGORIES`
- `src/tui/app/mod.rs` — add plan-gated GitHub keys to `hardcoded_optins`
- `src/tui/app/nav.rs` — `ProviderSelection ↔ SelectCollectors` transition + validation arms for `Github`
- `src/tui/events.rs` — add `CloudProvider::Github` to the provider list
- `src/tui/ui/account_screens.rs` — add the GitHub tile
- `src/runner/tui_session.rs` — GitHub account-prep block
- `README.md` — new `## GitHub` section + provider-count/feature-list updates
- `cli-examples.md` — GitHub examples
- `docs/cli-reference.md` — add `github-*` to the provider-prefix note
- `evidence-list.md` — ten new `EV203`–`EV212` rows

---

## Self-Review Notes (run after writing, before handoff)

- Spec coverage: all four evidence categories from the design spec (org access control, repo config & branch protection, org audit log, code security alerts) map to Tasks 12–17.
- No placeholders: every step below shows real code, not descriptions of code.
- Type/method names referenced from later tasks (`GithubClient::members()`, `GithubError::Api`, `GithubUser`, etc.) match what earlier tasks define — verified by a final pass after drafting all 20 tasks.

---

### Task 1: Workspace + github-rs crate skeleton

**Files:**
- Create: `crates/github-rs/Cargo.toml`
- Create: `crates/github-rs/src/lib.rs`
- Create: `crates/github-rs/src/error.rs`
- Create: `crates/github-rs/src/client.rs` (stub)
- Create: `crates/github-rs/src/api/mod.rs` (stub)
- Create: `crates/github-rs/src/types/mod.rs` (stub)
- Modify: `Cargo.toml`
- Modify: `.gitignore`

**Interfaces:**
- Produces: `github_rs::GithubClient`, `github_rs::GithubError` (empty shells — Task 2 fills in real behavior)

- [ ] **Step 1: Add the new crate to the workspace and as an optional dep**

Edit `Cargo.toml`:

```toml
[workspace]
members  = [".", "crates/tenable-rs", "crates/okta-rs", "crates/jira-rs", "crates/github-rs"]
resolver = "2"
```

In `[dependencies]`, add (near the other provider crates):

```toml
# GitHub — only compiled with `--features github`
github-rs = { path = "crates/github-rs", optional = true }
```

In `[features]`:

```toml
[features]
default = ["tenable", "okta", "jira", "github"]
azure   = ["dep:azure_identity", "dep:azure_mgmt_monitor", "dep:azure_mgmt_resources"]
gcp     = ["dep:google-cloud-auth"]
tenable = ["dep:tenable-rs"]
okta    = ["dep:okta-rs"]
jira    = ["dep:jira-rs"]
github  = ["dep:github-rs"]
```

- [ ] **Step 2: Create `crates/github-rs/Cargo.toml`**

```toml
[package]
name        = "github-rs"
version     = "0.1.0"
edition     = "2021"
description = "Async Rust client for the GitHub REST API"
license     = "MIT OR Apache-2.0"

[dependencies]
reqwest    = { version = "0.12", features = ["json", "rustls-tls"], default-features = false }
serde      = { version = "1", features = ["derive"] }
serde_json = "1"
tokio      = { version = "1", features = ["time"] }
thiserror  = "2"
anyhow     = "1"
chrono     = { version = "0.4", features = ["serde"] }

[dev-dependencies]
tokio    = { version = "1", features = ["full"] }
wiremock = "0.6"
```

- [ ] **Step 3: Create `crates/github-rs/src/error.rs`**

```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum GithubError {
    #[error("HTTP transport error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("invalid header value: {0}")]
    Header(#[from] reqwest::header::InvalidHeaderValue),

    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("GitHub API error: HTTP {status} — {message}")]
    Api { status: u16, message: String },

    #[error("invalid client configuration: {0}")]
    InvalidBaseUrl(String),
}
```

- [ ] **Step 4: Create `crates/github-rs/src/lib.rs`**

```rust
//! Async Rust client for the GitHub REST API.
//!
//! # Quick start
//!
//! ```no_run
//! use github_rs::GithubClient;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let client = GithubClient::new("https://api.github.com", "ghp_...", "my-org")?;
//!     let admins = client.members().list_by_role("admin").await?;
//!     println!("{} admins", admins.len());
//!     Ok(())
//! }
//! ```

mod client;
mod error;

pub mod api;
pub mod types;

pub use client::GithubClient;
pub use error::GithubError;

#[doc(hidden)]
pub use client::next_link as __test_next_link;
```

- [ ] **Step 5: Create stub `client.rs`, `api/mod.rs`, `types/mod.rs` so the workspace compiles**

`crates/github-rs/src/client.rs`:

```rust
use crate::error::GithubError;

#[derive(Clone)]
pub struct GithubClient;

impl GithubClient {
    pub fn new(_base_url: &str, _token: &str, _org: &str) -> Result<Self, GithubError> {
        Ok(Self)
    }
}

#[doc(hidden)]
pub fn next_link(_resp: &reqwest::Response) -> Option<String> {
    None
}
```

`crates/github-rs/src/api/mod.rs`:

```rust
// (empty for now — Task 2 populates this)
```

`crates/github-rs/src/types/mod.rs`:

```rust
// (empty for now — Task 3+ populates this)
```

- [ ] **Step 6: Verify the workspace compiles**

Run: `cargo check --workspace`
Expected: PASS.

- [ ] **Step 7: Update `.gitignore`**

Append after the Jira block:

```
# GitHub credentials — never commit
github-config.toml
```

- [ ] **Step 8: Commit**

```bash
git add Cargo.toml .gitignore crates/github-rs
git commit -m "feat(github): scaffold github-rs workspace crate and feature flag"
```

---

### Task 2: HTTP client with Bearer auth, rate-limit retry, Link pagination

**Files:**
- Modify: `crates/github-rs/src/client.rs`
- Modify: `crates/github-rs/src/api/mod.rs`
- Create: `crates/github-rs/src/api/members.rs` (stub)
- Create: `crates/github-rs/src/api/teams.rs` (stub)
- Create: `crates/github-rs/src/api/orgs.rs` (stub)
- Create: `crates/github-rs/src/api/repos.rs` (stub)
- Create: `crates/github-rs/src/api/audit_log.rs` (stub)
- Create: `crates/github-rs/src/api/alerts.rs` (stub)
- Create: `crates/github-rs/tests/client_test.rs`

**Interfaces:**
- Produces: `GithubClient::new(base_url, token, org)`, `GithubClient::get`/`get_absolute` (crate-internal), `GithubClient::url`, `GithubClient::members()`/`teams()`/`orgs()`/`repos()`/`audit_log()`/`alerts()` accessors, `next_link(&Response) -> Option<String>`

- [ ] **Step 1: Write the failing test for Bearer auth headers**

Create `crates/github-rs/tests/client_test.rs`:

```rust
use github_rs::GithubClient;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn injects_bearer_auth_and_api_version_headers() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/orgs/acme/members"))
        .and(header("Authorization", "Bearer test-token"))
        .and(header("X-GitHub-Api-Version", "2022-11-28"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
        .expect(1)
        .mount(&server)
        .await;

    let client = GithubClient::new(&server.uri(), "test-token", "acme").unwrap();
    let resp = client.raw_get("/orgs/acme/members").await.unwrap();
    assert_eq!(resp.status(), 200);
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p github-rs --test client_test injects_bearer_auth_and_api_version_headers`
Expected: FAIL (no `raw_get` method yet).

- [ ] **Step 3: Implement `GithubClient` fully in `crates/github-rs/src/client.rs`**

Replace the stub entirely:

```rust
use reqwest::{header, Client, Response};
use tokio::time::{sleep, Duration};

use crate::api::{AlertsApi, AuditLogApi, MembersApi, OrgsApi, ReposApi, TeamsApi};
use crate::error::GithubError;

const MAX_RETRIES: u32 = 5;
const DEFAULT_RETRY_SECS: u64 = 60;

/// Async HTTP client for the GitHub REST API, scoped to one org.
///
/// Auth: `Authorization: Bearer <token>` is injected on every request, along
/// with `Accept: application/vnd.github+json` and
/// `X-GitHub-Api-Version: 2022-11-28`.
///
/// Retries only on rate-limit signals (429, or 403 carrying `Retry-After` or
/// `X-RateLimit-Remaining: 0`) — a bare 403 (missing scope, or the org's plan
/// doesn't have this feature) returns immediately instead of burning through
/// retries on a request that will never succeed.
///
/// `GithubClient` is cheaply cloneable — `reqwest::Client` is arc-pooled.
#[derive(Clone)]
pub struct GithubClient {
    pub(crate) http: Client,
    pub(crate) base_url: String,
    pub(crate) org: String,
}

impl GithubClient {
    /// Build a client for one org. `base_url` is the full REST API root —
    /// `https://api.github.com` for GitHub.com, or `https://HOST/api/v3` for
    /// GitHub Enterprise Server. The caller provides it verbatim; this client
    /// never rewrites or guesses a path suffix.
    pub fn new(base_url: &str, token: &str, org: &str) -> Result<Self, GithubError> {
        let trimmed = base_url.trim().trim_end_matches('/');
        if trimmed.is_empty() {
            return Err(GithubError::InvalidBaseUrl(base_url.to_string()));
        }
        let org_trimmed = org.trim();
        if org_trimmed.is_empty() {
            return Err(GithubError::InvalidBaseUrl("org must not be empty".to_string()));
        }

        let auth = format!("Bearer {token}");
        let mut headers = header::HeaderMap::new();
        headers.insert(header::AUTHORIZATION, header::HeaderValue::from_str(&auth)?);
        headers.insert(
            header::ACCEPT,
            header::HeaderValue::from_static("application/vnd.github+json"),
        );
        headers.insert(
            header::HeaderName::from_static("x-github-api-version"),
            header::HeaderValue::from_static("2022-11-28"),
        );

        let http = Client::builder().default_headers(headers).build()?;
        Ok(Self {
            http,
            base_url: trimmed.to_string(),
            org: org_trimmed.to_string(),
        })
    }

    /// The org this client is scoped to.
    pub fn org(&self) -> &str {
        &self.org
    }

    /// Absolute URL for a path beginning with `/`.
    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    /// GET a relative path. Internal helper.
    pub(crate) async fn get(&self, path: &str) -> Result<Response, GithubError> {
        let url = self.url(path);
        self.send_with_retry(|| self.http.get(&url).send()).await
    }

    /// GET an absolute URL (used for Link-pagination follow-ups). Internal.
    pub(crate) async fn get_absolute(&self, url: &str) -> Result<Response, GithubError> {
        let owned = url.to_string();
        self.send_with_retry(|| self.http.get(&owned).send()).await
    }

    /// Public escape hatch used by integration tests.
    #[doc(hidden)]
    pub async fn raw_get(&self, path: &str) -> Result<Response, GithubError> {
        self.get(path).await
    }

    async fn send_with_retry<F, Fut>(&self, make_req: F) -> Result<Response, GithubError>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<Response, reqwest::Error>>,
    {
        let mut backoff = 1u64;
        for attempt in 0..=MAX_RETRIES {
            let resp = make_req().await?;
            if !is_rate_limited(&resp) || attempt == MAX_RETRIES {
                return Ok(resp);
            }
            let wait = retry_wait(&resp).max(backoff);
            sleep(Duration::from_secs(wait)).await;
            backoff = (backoff * 2).min(DEFAULT_RETRY_SECS);
        }
        unreachable!()
    }

    // API accessors -------------------------------------------------------
    pub fn members(&self) -> MembersApi<'_> {
        MembersApi(self)
    }
    pub fn teams(&self) -> TeamsApi<'_> {
        TeamsApi(self)
    }
    pub fn orgs(&self) -> OrgsApi<'_> {
        OrgsApi(self)
    }
    pub fn repos(&self) -> ReposApi<'_> {
        ReposApi(self)
    }
    pub fn audit_log(&self) -> AuditLogApi<'_> {
        AuditLogApi(self)
    }
    pub fn alerts(&self) -> AlertsApi<'_> {
        AlertsApi(self)
    }
}

/// A 429 is always a rate limit. A 403 only counts as one if it carries a
/// `Retry-After` header (secondary/abuse limit) or `X-RateLimit-Remaining: 0`
/// (primary limit exhausted) — a bare 403 is a permission/plan error that
/// will never succeed on retry.
fn is_rate_limited(resp: &Response) -> bool {
    if resp.status() == 429 {
        return true;
    }
    if resp.status() != 403 {
        return false;
    }
    if resp.headers().contains_key("retry-after") {
        return true;
    }
    resp.headers()
        .get("x-ratelimit-remaining")
        .and_then(|v| v.to_str().ok())
        == Some("0")
}

/// Seconds to wait before retrying. Prefers the explicit `Retry-After` header
/// (secondary/abuse limit — always short, capped defensively at
/// `DEFAULT_RETRY_SECS`), falling back to the primary limit's
/// `X-RateLimit-Reset` (Unix epoch seconds). That fallback is deliberately
/// NOT capped — a primary-limit reset can legitimately be up to an hour away,
/// and returning early would just draw another 403.
fn retry_wait(resp: &Response) -> u64 {
    if let Some(v) = resp.headers().get("retry-after") {
        if let Ok(s) = v.to_str() {
            if let Ok(secs) = s.parse::<u64>() {
                return secs.min(DEFAULT_RETRY_SECS);
            }
        }
    }
    if let Some(v) = resp.headers().get("x-ratelimit-reset") {
        if let Ok(s) = v.to_str() {
            if let Ok(reset_epoch) = s.parse::<i64>() {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                return (reset_epoch - now).max(1) as u64;
            }
        }
    }
    DEFAULT_RETRY_SECS
}

/// Parse RFC 5988 `Link` headers and return the URL with `rel="next"` if any.
///
/// Splits multi-link headers on `,` only when outside `<...>` brackets, so
/// URLs containing commas (e.g. `?phrase=a,b`) are preserved intact.
#[doc(hidden)]
pub fn next_link(resp: &Response) -> Option<String> {
    for v in resp.headers().get_all("link").iter() {
        let s = match v.to_str() {
            Ok(s) => s,
            Err(_) => continue,
        };
        for entry in split_link_entries(s) {
            let trimmed = entry.trim();
            let Some(open) = trimmed.find('<') else {
                continue;
            };
            let Some(close_rel) = trimmed[open + 1..].find('>') else {
                continue;
            };
            let close = open + 1 + close_rel;
            let url = &trimmed[open + 1..close];
            let rest = &trimmed[close + 1..];
            if rest.contains("rel=\"next\"") {
                return Some(url.to_string());
            }
        }
    }
    None
}

/// Split a Link header value into individual entries, treating `,` as a
/// separator only when outside `<...>` brackets.
fn split_link_entries(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut depth = 0;
    let mut start = 0;
    for (i, c) in s.char_indices() {
        match c {
            '<' => depth += 1,
            '>' => {
                if depth > 0 {
                    depth -= 1;
                }
            }
            ',' if depth == 0 => {
                out.push(&s[start..i]);
                start = i + c.len_utf8();
            }
            _ => {}
        }
    }
    out.push(&s[start..]);
    out
}
```

- [ ] **Step 4: Create stub API modules so `client.rs` compiles**

`crates/github-rs/src/api/mod.rs`:

```rust
pub mod alerts;
pub mod audit_log;
pub mod members;
pub mod orgs;
pub mod repos;
pub mod teams;

pub use alerts::AlertsApi;
pub use audit_log::AuditLogApi;
pub use members::MembersApi;
pub use orgs::OrgsApi;
pub use repos::ReposApi;
pub use teams::TeamsApi;
```

Each stub file (e.g. `crates/github-rs/src/api/members.rs`) exports just the accessor struct — Tasks 3–8 fill in the real methods:

```rust
use crate::client::GithubClient;
pub struct MembersApi<'c>(pub(crate) &'c GithubClient);
```

Repeat for `teams.rs` (`TeamsApi`), `orgs.rs` (`OrgsApi`), `repos.rs` (`ReposApi`), `audit_log.rs` (`AuditLogApi`), `alerts.rs` (`AlertsApi`) with the matching struct name.

- [ ] **Step 5: Run the auth-header test to verify it passes**

Run: `cargo test -p github-rs --test client_test injects_bearer_auth_and_api_version_headers`
Expected: PASS.

- [ ] **Step 6: Write a test for Link-header pagination parsing**

Append to `crates/github-rs/tests/client_test.rs`:

```rust
#[tokio::test]
async fn follows_link_header_pagination_next_rel() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};

    let server = MockServer::start().await;
    let next_url = format!("{}/orgs/acme/members?page=2", server.uri());
    Mock::given(method("GET"))
        .and(path("/orgs/acme/members"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("link", format!("<{}>; rel=\"next\"", next_url).as_str())
                .set_body_json(serde_json::json!([])),
        )
        .mount(&server)
        .await;

    let client = GithubClient::new(&server.uri(), "test-token", "acme").unwrap();
    let resp = client.raw_get("/orgs/acme/members").await.unwrap();
    let link = github_rs::__test_next_link(&resp);
    assert_eq!(link, Some(next_url));
}
```

- [ ] **Step 7: Run to verify it passes**

Run: `cargo test -p github-rs --test client_test`
Expected: BOTH tests PASS.

- [ ] **Step 8: Write a test for rate-limit retry on 429**

Append to `crates/github-rs/tests/client_test.rs`:

```rust
#[tokio::test]
async fn retries_after_429_with_retry_after_header() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};

    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/orgs/acme/members"))
        .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "1"))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/orgs/acme/members"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
        .mount(&server)
        .await;

    let client = GithubClient::new(&server.uri(), "test-token", "acme").unwrap();
    let resp = client.raw_get("/orgs/acme/members").await.unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn does_not_retry_a_bare_403() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/orgs/acme/dependabot/alerts"))
        .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
            "message": "Dependabot alerts are disabled for this repository."
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = GithubClient::new(&server.uri(), "test-token", "acme").unwrap();
    let resp = client.raw_get("/orgs/acme/dependabot/alerts").await.unwrap();
    assert_eq!(resp.status(), 403);
}
```

- [ ] **Step 9: Run to verify both pass**

Run: `cargo test -p github-rs --test client_test`
Expected: ALL FOUR tests PASS. (`retries_after_429_with_retry_after_header` takes ~1 real second because of the `sleep(1s)` in the retry path — that's expected.)

- [ ] **Step 10: Commit**

```bash
git add crates/github-rs
git commit -m "feat(github): http client with bearer auth, rate-limit retry, link pagination"
```

---

### Task 3: Members API + types

**Files:**
- Create: `crates/github-rs/src/types/user.rs`
- Modify: `crates/github-rs/src/types/mod.rs`
- Modify: `crates/github-rs/src/api/members.rs`
- Create: `crates/github-rs/tests/members_test.rs`

**Interfaces:**
- Produces: `GithubUser { login, id, user_type, site_admin }`, `MembersApi::list_by_role(&self, role: &str) -> Result<Vec<GithubUser>, GithubError>`, `MembersApi::list_2fa_disabled(&self) -> Result<Vec<GithubUser>, GithubError>`

- [ ] **Step 1: Write the failing test**

Create `crates/github-rs/tests/members_test.rs`:

```rust
use github_rs::GithubClient;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn list_by_role_filters_and_paginates() {
    let server = MockServer::start().await;
    let page2 = format!("{}/orgs/acme/members?role=admin&per_page=100&page=2", server.uri());

    Mock::given(method("GET"))
        .and(path("/orgs/acme/members"))
        .and(query_param("role", "admin"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("link", format!("<{}>; rel=\"next\"", page2).as_str())
                .set_body_json(serde_json::json!([
                    {"login": "alice", "id": 1, "type": "User", "site_admin": false}
                ])),
        )
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/orgs/acme/members"))
        .and(query_param("page", "2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            {"login": "bob", "id": 2, "type": "User", "site_admin": true}
        ])))
        .mount(&server)
        .await;

    let client = GithubClient::new(&server.uri(), "tok", "acme").unwrap();
    let admins = client.members().list_by_role("admin").await.unwrap();
    assert_eq!(admins.len(), 2);
    assert_eq!(admins[0].login, "alice");
    assert!(admins[1].site_admin);
}

#[tokio::test]
async fn list_2fa_disabled_returns_users() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/orgs/acme/members"))
        .and(query_param("filter", "2fa_disabled"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            {"login": "carol", "id": 3, "type": "User", "site_admin": false}
        ])))
        .mount(&server)
        .await;

    let client = GithubClient::new(&server.uri(), "tok", "acme").unwrap();
    let users = client.members().list_2fa_disabled().await.unwrap();
    assert_eq!(users.len(), 1);
    assert_eq!(users[0].login, "carol");
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p github-rs --test members_test`
Expected: FAIL — `list_by_role`/`list_2fa_disabled` missing.

- [ ] **Step 3: Define `GithubUser` in `crates/github-rs/src/types/user.rs`**

```rust
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct GithubUser {
    pub login: String,
    pub id: i64,
    #[serde(default, rename = "type")]
    pub user_type: String,
    #[serde(default)]
    pub site_admin: bool,
}
```

- [ ] **Step 4: Export from `crates/github-rs/src/types/mod.rs`**

```rust
pub mod alert;
pub mod audit_log;
pub mod org;
pub mod repo;
pub mod team;
pub mod user;
```

Create empty placeholders for the not-yet-written files so this compiles — `crates/github-rs/src/types/team.rs`, `org.rs`, `repo.rs`, `audit_log.rs`, `alert.rs` each containing just:

```rust
// Filled in by Task 4 (team), Task 5 (org), Task 6 (repo), Task 7 (audit_log), Task 8 (alert).
```

- [ ] **Step 5: Implement `MembersApi` in `crates/github-rs/src/api/members.rs`**

```rust
use crate::client::{next_link, GithubClient};
use crate::error::GithubError;
use crate::types::user::GithubUser;

pub struct MembersApi<'c>(pub(crate) &'c GithubClient);

impl<'c> MembersApi<'c> {
    /// GET /orgs/{org}/members?role={role} — "admin" or "member". Paginated.
    pub async fn list_by_role(&self, role: &str) -> Result<Vec<GithubUser>, GithubError> {
        let first = self.0.url(&format!(
            "/orgs/{}/members?role={}&per_page=100",
            self.0.org(),
            role
        ));
        self.paginate(first).await
    }

    /// GET /orgs/{org}/members?filter=2fa_disabled — requires an org-owner
    /// token; callers should treat a 403 here as "unknown", not a hard error.
    pub async fn list_2fa_disabled(&self) -> Result<Vec<GithubUser>, GithubError> {
        let first = self.0.url(&format!(
            "/orgs/{}/members?filter=2fa_disabled&per_page=100",
            self.0.org()
        ));
        self.paginate(first).await
    }

    async fn paginate(&self, first_url: String) -> Result<Vec<GithubUser>, GithubError> {
        let mut all = Vec::new();
        let mut next: Option<String> = Some(first_url);
        while let Some(url) = next {
            let resp = self.0.get_absolute(&url).await?;
            if !resp.status().is_success() {
                let status = resp.status().as_u16();
                let message = resp.text().await.unwrap_or_default();
                return Err(GithubError::Api { status, message });
            }
            let link = next_link(&resp);
            let page: Vec<GithubUser> = resp.json().await?;
            all.extend(page);
            next = link;
        }
        Ok(all)
    }
}
```

- [ ] **Step 6: Run to verify it passes**

Run: `cargo test -p github-rs --test members_test`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add crates/github-rs
git commit -m "feat(github): members api (role-filtered list, 2fa-disabled list)"
```

---

### Task 4: Teams API + types

**Files:**
- Create: `crates/github-rs/src/types/team.rs`
- Modify: `crates/github-rs/src/api/teams.rs`
- Create: `crates/github-rs/tests/teams_test.rs`

**Interfaces:**
- Produces: `GithubTeam { id, name, slug, description, privacy, permission }`, `TeamsApi::list_all(&self) -> Result<Vec<GithubTeam>, GithubError>`, `TeamsApi::list_members(&self, team_slug: &str) -> Result<Vec<GithubUser>, GithubError>`

- [ ] **Step 1: Write the failing test**

Create `crates/github-rs/tests/teams_test.rs`:

```rust
use github_rs::GithubClient;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn list_all_teams_parses_fields() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/orgs/acme/teams"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            {
                "id": 1,
                "name": "Platform",
                "slug": "platform",
                "description": "Platform team",
                "privacy": "closed",
                "permission": "push"
            }
        ])))
        .mount(&server)
        .await;

    let client = GithubClient::new(&server.uri(), "tok", "acme").unwrap();
    let teams = client.teams().list_all().await.unwrap();
    assert_eq!(teams.len(), 1);
    assert_eq!(teams[0].slug, "platform");
}

#[tokio::test]
async fn list_members_returns_users() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/orgs/acme/teams/platform/members"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            {"login": "alice", "id": 1, "type": "User", "site_admin": false}
        ])))
        .mount(&server)
        .await;

    let client = GithubClient::new(&server.uri(), "tok", "acme").unwrap();
    let members = client.teams().list_members("platform").await.unwrap();
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].login, "alice");
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p github-rs --test teams_test`
Expected: FAIL.

- [ ] **Step 3: Define `GithubTeam` in `crates/github-rs/src/types/team.rs`**

```rust
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct GithubTeam {
    pub id: i64,
    pub name: String,
    pub slug: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub privacy: String,
    #[serde(default)]
    pub permission: String,
}
```

- [ ] **Step 4: Implement `TeamsApi` in `crates/github-rs/src/api/teams.rs`**

```rust
use crate::client::{next_link, GithubClient};
use crate::error::GithubError;
use crate::types::team::GithubTeam;
use crate::types::user::GithubUser;

pub struct TeamsApi<'c>(pub(crate) &'c GithubClient);

impl<'c> TeamsApi<'c> {
    /// GET /orgs/{org}/teams — paginated.
    pub async fn list_all(&self) -> Result<Vec<GithubTeam>, GithubError> {
        let mut all = Vec::new();
        let mut next: Option<String> =
            Some(self.0.url(&format!("/orgs/{}/teams?per_page=100", self.0.org())));
        while let Some(url) = next {
            let resp = self.0.get_absolute(&url).await?;
            if !resp.status().is_success() {
                let status = resp.status().as_u16();
                let message = resp.text().await.unwrap_or_default();
                return Err(GithubError::Api { status, message });
            }
            let link = next_link(&resp);
            let page: Vec<GithubTeam> = resp.json().await?;
            all.extend(page);
            next = link;
        }
        Ok(all)
    }

    /// GET /orgs/{org}/teams/{team_slug}/members — paginated.
    pub async fn list_members(&self, team_slug: &str) -> Result<Vec<GithubUser>, GithubError> {
        let mut all = Vec::new();
        let mut next: Option<String> = Some(self.0.url(&format!(
            "/orgs/{}/teams/{}/members?per_page=100",
            self.0.org(),
            team_slug
        )));
        while let Some(url) = next {
            let resp = self.0.get_absolute(&url).await?;
            if !resp.status().is_success() {
                let status = resp.status().as_u16();
                let message = resp.text().await.unwrap_or_default();
                return Err(GithubError::Api { status, message });
            }
            let link = next_link(&resp);
            let page: Vec<GithubUser> = resp.json().await?;
            all.extend(page);
            next = link;
        }
        Ok(all)
    }
}
```

- [ ] **Step 5: Run to verify it passes**

Run: `cargo test -p github-rs --test teams_test`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/github-rs
git commit -m "feat(github): teams api (list + members)"
```

---

### Task 5: Orgs API + types

**Files:**
- Create: `crates/github-rs/src/types/org.rs`
- Modify: `crates/github-rs/src/api/orgs.rs`
- Create: `crates/github-rs/tests/orgs_test.rs`

**Interfaces:**
- Produces: `GithubOrg { login, two_factor_requirement_enabled, default_repository_permission, members_can_create_repositories, members_can_create_private_repositories }`, `OrgsApi::get(&self) -> Result<GithubOrg, GithubError>`

- [ ] **Step 1: Write the failing test**

Create `crates/github-rs/tests/orgs_test.rs`:

```rust
use github_rs::GithubClient;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn get_org_parses_security_settings() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/orgs/acme"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "login": "acme",
            "two_factor_requirement_enabled": true,
            "default_repository_permission": "read",
            "members_can_create_repositories": false,
            "members_can_create_private_repositories": true
        })))
        .mount(&server)
        .await;

    let client = GithubClient::new(&server.uri(), "tok", "acme").unwrap();
    let org = client.orgs().get().await.unwrap();
    assert_eq!(org.login, "acme");
    assert_eq!(org.two_factor_requirement_enabled, Some(true));
    assert_eq!(org.default_repository_permission.as_deref(), Some("read"));
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p github-rs --test orgs_test`
Expected: FAIL.

- [ ] **Step 3: Define `GithubOrg` in `crates/github-rs/src/types/org.rs`**

```rust
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct GithubOrg {
    pub login: String,
    #[serde(default)]
    pub two_factor_requirement_enabled: Option<bool>,
    #[serde(default)]
    pub default_repository_permission: Option<String>,
    #[serde(default)]
    pub members_can_create_repositories: Option<bool>,
    #[serde(default)]
    pub members_can_create_private_repositories: Option<bool>,
}
```

- [ ] **Step 4: Implement `OrgsApi` in `crates/github-rs/src/api/orgs.rs`**

```rust
use crate::client::GithubClient;
use crate::error::GithubError;
use crate::types::org::GithubOrg;

pub struct OrgsApi<'c>(pub(crate) &'c GithubClient);

impl<'c> OrgsApi<'c> {
    /// GET /orgs/{org} — single-record org settings snapshot.
    pub async fn get(&self) -> Result<GithubOrg, GithubError> {
        let path = format!("/orgs/{}", self.0.org());
        let resp = self.0.get(&path).await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let message = resp.text().await.unwrap_or_default();
            return Err(GithubError::Api { status, message });
        }
        Ok(resp.json().await?)
    }
}
```

- [ ] **Step 5: Run to verify it passes**

Run: `cargo test -p github-rs --test orgs_test`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/github-rs
git commit -m "feat(github): orgs api (security settings snapshot)"
```

---

### Task 6: Repos + Branch Protection API + types

**Files:**
- Create: `crates/github-rs/src/types/repo.rs`
- Modify: `crates/github-rs/src/api/repos.rs`
- Create: `crates/github-rs/tests/repos_test.rs`

**Interfaces:**
- Produces: `GithubRepo { id, name, full_name, private, visibility, default_branch, archived, created_at, pushed_at }`, `GithubBranchProtection { enforce_admins, required_pull_request_reviews, required_status_checks, allow_force_pushes }`, `ReposApi::list_all(&self) -> Result<Vec<GithubRepo>, GithubError>`, `ReposApi::get_branch_protection(&self, repo_name: &str, branch: &str) -> Result<GithubBranchProtection, GithubError>`

- [ ] **Step 1: Write the failing test**

Create `crates/github-rs/tests/repos_test.rs`:

```rust
use github_rs::{GithubClient, GithubError};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn list_all_repos_parses_fields() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/orgs/acme/repos"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            {
                "id": 1,
                "name": "widget",
                "full_name": "acme/widget",
                "private": false,
                "visibility": "public",
                "default_branch": "main",
                "archived": false,
                "created_at": "2020-01-01T00:00:00Z",
                "pushed_at": "2026-01-01T00:00:00Z"
            }
        ])))
        .mount(&server)
        .await;

    let client = GithubClient::new(&server.uri(), "tok", "acme").unwrap();
    let repos = client.repos().list_all().await.unwrap();
    assert_eq!(repos.len(), 1);
    assert_eq!(repos[0].default_branch, "main");
}

#[tokio::test]
async fn get_branch_protection_parses_review_settings() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/widget/branches/main/protection"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "enforce_admins": {"enabled": true},
            "required_pull_request_reviews": {
                "required_approving_review_count": 2,
                "require_code_owner_reviews": true,
                "dismiss_stale_reviews": true
            },
            "required_status_checks": {"strict": true, "contexts": ["ci"]},
            "allow_force_pushes": {"enabled": false}
        })))
        .mount(&server)
        .await;

    let client = GithubClient::new(&server.uri(), "tok", "acme").unwrap();
    let protection = client
        .repos()
        .get_branch_protection("widget", "main")
        .await
        .unwrap();
    assert_eq!(
        protection
            .required_pull_request_reviews
            .unwrap()
            .required_approving_review_count,
        Some(2)
    );
}

#[tokio::test]
async fn get_branch_protection_404_is_an_api_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/widget/branches/main/protection"))
        .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
            "message": "Branch not protected"
        })))
        .mount(&server)
        .await;

    let client = GithubClient::new(&server.uri(), "tok", "acme").unwrap();
    let err = client
        .repos()
        .get_branch_protection("widget", "main")
        .await
        .unwrap_err();
    assert!(matches!(err, GithubError::Api { status: 404, .. }));
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p github-rs --test repos_test`
Expected: FAIL.

- [ ] **Step 3: Define repo + branch-protection types in `crates/github-rs/src/types/repo.rs`**

```rust
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct GithubRepo {
    pub id: i64,
    pub name: String,
    pub full_name: String,
    #[serde(default)]
    pub private: bool,
    #[serde(default)]
    pub visibility: String,
    #[serde(default)]
    pub default_branch: String,
    #[serde(default)]
    pub archived: bool,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub pushed_at: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct GithubBranchProtection {
    #[serde(default)]
    pub enforce_admins: Option<EnforceAdmins>,
    #[serde(default)]
    pub required_pull_request_reviews: Option<RequiredPullRequestReviews>,
    #[serde(default)]
    pub required_status_checks: Option<RequiredStatusChecks>,
    #[serde(default)]
    pub allow_force_pushes: Option<ToggleSetting>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EnforceAdmins {
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ToggleSetting {
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RequiredPullRequestReviews {
    #[serde(default)]
    pub required_approving_review_count: Option<i64>,
    #[serde(default)]
    pub require_code_owner_reviews: Option<bool>,
    #[serde(default)]
    pub dismiss_stale_reviews: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RequiredStatusChecks {
    #[serde(default)]
    pub strict: bool,
    #[serde(default)]
    pub contexts: Vec<String>,
}
```

- [ ] **Step 4: Implement `ReposApi` in `crates/github-rs/src/api/repos.rs`**

```rust
use crate::client::{next_link, GithubClient};
use crate::error::GithubError;
use crate::types::repo::{GithubBranchProtection, GithubRepo};

pub struct ReposApi<'c>(pub(crate) &'c GithubClient);

impl<'c> ReposApi<'c> {
    /// GET /orgs/{org}/repos?type=all — paginated.
    pub async fn list_all(&self) -> Result<Vec<GithubRepo>, GithubError> {
        let mut all = Vec::new();
        let mut next: Option<String> = Some(self.0.url(&format!(
            "/orgs/{}/repos?type=all&per_page=100",
            self.0.org()
        )));
        while let Some(url) = next {
            let resp = self.0.get_absolute(&url).await?;
            if !resp.status().is_success() {
                let status = resp.status().as_u16();
                let message = resp.text().await.unwrap_or_default();
                return Err(GithubError::Api { status, message });
            }
            let link = next_link(&resp);
            let page: Vec<GithubRepo> = resp.json().await?;
            all.extend(page);
            next = link;
        }
        Ok(all)
    }

    /// GET /repos/{org}/{repo_name}/branches/{branch}/protection.
    /// Returns `Err(GithubError::Api { status: 404, .. })` when the branch has
    /// no protection configured — callers decide how to represent that.
    pub async fn get_branch_protection(
        &self,
        repo_name: &str,
        branch: &str,
    ) -> Result<GithubBranchProtection, GithubError> {
        let path = format!(
            "/repos/{}/{}/branches/{}/protection",
            self.0.org(),
            repo_name,
            branch
        );
        let resp = self.0.get(&path).await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let message = resp.text().await.unwrap_or_default();
            return Err(GithubError::Api { status, message });
        }
        Ok(resp.json().await?)
    }
}
```

- [ ] **Step 5: Run to verify it passes**

Run: `cargo test -p github-rs --test repos_test`
Expected: ALL THREE tests PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/github-rs
git commit -m "feat(github): repos api (list + branch protection)"
```

---

### Task 7: Audit Log API + types

**Files:**
- Create: `crates/github-rs/src/types/audit_log.rs`
- Modify: `crates/github-rs/src/api/audit_log.rs`
- Create: `crates/github-rs/tests/audit_log_test.rs`

**Interfaces:**
- Produces: `GithubAuditLogEvent { action, actor, user, org, created_at, document_id }`, `AuditLogApi::events(&self, since: &str, until: &str) -> Result<Vec<GithubAuditLogEvent>, GithubError>`

**Note:** `GET /orgs/{org}/audit-log` requires GitHub Enterprise Cloud. On any other plan it 403s/404s — the collector in Task 16 handles that, not this API layer, matching how `get_branch_protection` returns the raw `Err` for its caller to interpret.

- [ ] **Step 1: Write the failing test**

Create `crates/github-rs/tests/audit_log_test.rs`:

```rust
use github_rs::GithubClient;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn events_sends_created_range_phrase_and_parses_epoch_millis() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/orgs/acme/audit-log"))
        .and(query_param(
            "phrase",
            "created:2026-01-01T00:00:00Z..2026-02-01T00:00:00Z",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            {
                "action": "team.create",
                "actor": "alice",
                "user": "alice",
                "org": "acme",
                "created_at": 1_735_689_600_000i64,
                "_document_id": "doc-1"
            }
        ])))
        .mount(&server)
        .await;

    let client = GithubClient::new(&server.uri(), "tok", "acme").unwrap();
    let events = client
        .audit_log()
        .events("2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z")
        .await
        .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].action, "team.create");
    assert_eq!(events[0].created_at, Some(1_735_689_600_000));
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p github-rs --test audit_log_test`
Expected: FAIL.

- [ ] **Step 3: Define `GithubAuditLogEvent` in `crates/github-rs/src/types/audit_log.rs`**

```rust
use serde::Deserialize;

/// `created_at` is Unix epoch **milliseconds** on this endpoint — unlike every
/// other timestamp field in this crate, which GitHub sends as an RFC 3339
/// string. Do not assume ISO-string parsing works here.
#[derive(Debug, Clone, Deserialize)]
pub struct GithubAuditLogEvent {
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub actor: Option<String>,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub org: Option<String>,
    #[serde(default)]
    pub created_at: Option<i64>,
    #[serde(default, rename = "_document_id")]
    pub document_id: Option<String>,
}
```

- [ ] **Step 4: Implement `AuditLogApi` in `crates/github-rs/src/api/audit_log.rs`**

```rust
use crate::client::{next_link, GithubClient};
use crate::error::GithubError;
use crate::types::audit_log::GithubAuditLogEvent;

pub struct AuditLogApi<'c>(pub(crate) &'c GithubClient);

impl<'c> AuditLogApi<'c> {
    /// GET /orgs/{org}/audit-log?phrase=created:{since}..{until} — paginated
    /// via Link headers. `since`/`until` are RFC 3339 timestamps.
    /// Requires GitHub Enterprise Cloud; on any other plan this 403s/404s.
    pub async fn events(
        &self,
        since: &str,
        until: &str,
    ) -> Result<Vec<GithubAuditLogEvent>, GithubError> {
        let phrase = format!("created:{}..{}", since, until);
        let first = self.0.url(&format!(
            "/orgs/{}/audit-log?phrase={}&per_page=100",
            self.0.org(),
            urlencode(&phrase)
        ));
        let mut all = Vec::new();
        let mut next: Option<String> = Some(first);
        while let Some(url) = next {
            let resp = self.0.get_absolute(&url).await?;
            if !resp.status().is_success() {
                let status = resp.status().as_u16();
                let message = resp.text().await.unwrap_or_default();
                return Err(GithubError::Api { status, message });
            }
            let link = next_link(&resp);
            let page: Vec<GithubAuditLogEvent> = resp.json().await?;
            all.extend(page);
            next = link;
        }
        Ok(all)
    }
}

/// Minimal RFC 3986 percent-encode for the `phrase` query parameter — the
/// only characters we need to escape are `:` and `Z` context punctuation from
/// RFC 3339 timestamps. Kept dependency-free rather than pulling in `url`.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}
```

- [ ] **Step 5: Run to verify it passes**

Run: `cargo test -p github-rs --test audit_log_test`
Expected: PASS. (wiremock's `query_param` matcher compares decoded values, so the percent-encoded `phrase` sent on the wire still matches the plain-text expectation in the test.)

- [ ] **Step 6: Commit**

```bash
git add crates/github-rs
git commit -m "feat(github): audit log api with time-window phrase filter"
```

---

### Task 8: Alerts API (Dependabot / secret scanning / code scanning) + types

**Files:**
- Create: `crates/github-rs/src/types/alert.rs`
- Modify: `crates/github-rs/src/api/alerts.rs`
- Create: `crates/github-rs/tests/alerts_test.rs`

**Interfaces:**
- Produces: `GithubAlertRepo { full_name }`, `GithubDependabotAlert`, `GithubSecretScanningAlert`, `GithubCodeScanningAlert`, `AlertsApi::dependabot_alerts`, `AlertsApi::secret_scanning_alerts`, `AlertsApi::code_scanning_alerts` — each `(&self) -> Result<Vec<T>, GithubError>`

- [ ] **Step 1: Write the failing test**

Create `crates/github-rs/tests/alerts_test.rs`:

```rust
use github_rs::GithubClient;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn dependabot_alerts_parses_advisory_and_package() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/orgs/acme/dependabot/alerts"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            {
                "number": 2,
                "state": "open",
                "dependency": {
                    "package": {"ecosystem": "pip", "name": "django"},
                    "manifest_path": "requirements.txt"
                },
                "security_advisory": {
                    "ghsa_id": "GHSA-xxxx",
                    "cve_id": "CVE-2018-6188",
                    "severity": "low",
                    "summary": "Denial of service"
                },
                "created_at": "2022-06-15T07:43:03Z",
                "updated_at": "2022-08-23T14:29:47Z",
                "repository": {"full_name": "acme/widget"}
            }
        ])))
        .mount(&server)
        .await;

    let client = GithubClient::new(&server.uri(), "tok", "acme").unwrap();
    let alerts = client.alerts().dependabot_alerts().await.unwrap();
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].dependency.package.name, "django");
    assert_eq!(
        alerts[0].security_advisory.as_ref().unwrap().ghsa_id,
        "GHSA-xxxx"
    );
}

#[tokio::test]
async fn secret_scanning_alerts_parses_fields() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/orgs/acme/secret-scanning/alerts"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            {
                "number": 5,
                "created_at": "2020-11-06T18:48:51Z",
                "state": "resolved",
                "resolution": "false_positive",
                "secret_type": "adafruit_io_key",
                "secret_type_display_name": "Adafruit IO Key",
                "push_protection_bypassed": false,
                "repository": {"full_name": "acme/widget"}
            }
        ])))
        .mount(&server)
        .await;

    let client = GithubClient::new(&server.uri(), "tok", "acme").unwrap();
    let alerts = client.alerts().secret_scanning_alerts().await.unwrap();
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].secret_type, "adafruit_io_key");
}

#[tokio::test]
async fn code_scanning_alerts_parses_rule() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/orgs/acme/code-scanning/alerts"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            {
                "number": 4,
                "created_at": "2020-02-13T12:29:18Z",
                "state": "open",
                "rule": {
                    "id": "js/trivial-conditional",
                    "severity": "warning",
                    "security_severity_level": "high",
                    "description": "Useless conditional"
                },
                "repository": {"full_name": "acme/widget"}
            }
        ])))
        .mount(&server)
        .await;

    let client = GithubClient::new(&server.uri(), "tok", "acme").unwrap();
    let alerts = client.alerts().code_scanning_alerts().await.unwrap();
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].rule.id, "js/trivial-conditional");
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p github-rs --test alerts_test`
Expected: FAIL.

- [ ] **Step 3: Define alert types in `crates/github-rs/src/types/alert.rs`**

```rust
use serde::Deserialize;

#[derive(Debug, Clone, Default, Deserialize)]
pub struct GithubAlertRepo {
    #[serde(default)]
    pub full_name: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct DependabotPackage {
    #[serde(default)]
    pub ecosystem: String,
    #[serde(default)]
    pub name: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DependabotDependency {
    #[serde(default)]
    pub package: DependabotPackage,
    #[serde(default)]
    pub manifest_path: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DependabotAdvisory {
    #[serde(default)]
    pub ghsa_id: String,
    #[serde(default)]
    pub cve_id: Option<String>,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub summary: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GithubDependabotAlert {
    pub number: i64,
    #[serde(default)]
    pub state: String,
    pub dependency: DependabotDependency,
    #[serde(default)]
    pub security_advisory: Option<DependabotAdvisory>,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub updated_at: Option<String>,
    #[serde(default)]
    pub repository: GithubAlertRepo,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GithubSecretScanningAlert {
    pub number: i64,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub resolution: Option<String>,
    #[serde(default)]
    pub secret_type: String,
    #[serde(default)]
    pub secret_type_display_name: Option<String>,
    #[serde(default)]
    pub push_protection_bypassed: bool,
    #[serde(default)]
    pub repository: GithubAlertRepo,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CodeScanningRule {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub security_severity_level: Option<String>,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GithubCodeScanningAlert {
    pub number: i64,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub state: String,
    pub rule: CodeScanningRule,
    #[serde(default)]
    pub repository: GithubAlertRepo,
}
```

- [ ] **Step 4: Implement `AlertsApi` in `crates/github-rs/src/api/alerts.rs`**

```rust
use crate::client::{next_link, GithubClient};
use crate::error::GithubError;
use crate::types::alert::{GithubCodeScanningAlert, GithubDependabotAlert, GithubSecretScanningAlert};

pub struct AlertsApi<'c>(pub(crate) &'c GithubClient);

impl<'c> AlertsApi<'c> {
    /// GET /orgs/{org}/dependabot/alerts — paginated. Requires Dependabot
    /// alerts enabled for at least one repo in the org.
    pub async fn dependabot_alerts(&self) -> Result<Vec<GithubDependabotAlert>, GithubError> {
        self.paginate(self.0.url(&format!(
            "/orgs/{}/dependabot/alerts?per_page=100",
            self.0.org()
        )))
        .await
    }

    /// GET /orgs/{org}/secret-scanning/alerts — paginated. Requires secret
    /// scanning enabled for at least one repo in the org.
    pub async fn secret_scanning_alerts(
        &self,
    ) -> Result<Vec<GithubSecretScanningAlert>, GithubError> {
        self.paginate(self.0.url(&format!(
            "/orgs/{}/secret-scanning/alerts?per_page=100",
            self.0.org()
        )))
        .await
    }

    /// GET /orgs/{org}/code-scanning/alerts — paginated. Requires code
    /// scanning (e.g. CodeQL) configured for at least one repo in the org.
    pub async fn code_scanning_alerts(&self) -> Result<Vec<GithubCodeScanningAlert>, GithubError> {
        self.paginate(self.0.url(&format!(
            "/orgs/{}/code-scanning/alerts?per_page=100",
            self.0.org()
        )))
        .await
    }

    async fn paginate<T: serde::de::DeserializeOwned>(
        &self,
        first_url: String,
    ) -> Result<Vec<T>, GithubError> {
        let mut all = Vec::new();
        let mut next: Option<String> = Some(first_url);
        while let Some(url) = next {
            let resp = self.0.get_absolute(&url).await?;
            if !resp.status().is_success() {
                let status = resp.status().as_u16();
                let message = resp.text().await.unwrap_or_default();
                return Err(GithubError::Api { status, message });
            }
            let link = next_link(&resp);
            let page: Vec<T> = resp.json().await?;
            all.extend(page);
            next = link;
        }
        Ok(all)
    }
}
```

- [ ] **Step 5: Run to verify it passes**

Run: `cargo test -p github-rs --test alerts_test`
Expected: ALL THREE tests PASS.

- [ ] **Step 6: Run the full crate test suite**

Run: `cargo test -p github-rs`
Expected: ALL tests across `client_test`, `members_test`, `teams_test`, `orgs_test`, `repos_test`, `audit_log_test`, `alerts_test` PASS.

- [ ] **Step 7: Commit**

```bash
git add crates/github-rs
git commit -m "feat(github): alerts api (dependabot, secret scanning, code scanning)"
```

---

### Task 9: `providers/github` skeleton + `GithubProviderFactory`

**Note on ordering:** this task creates `src/providers/github/` but does **not** touch `src/providers/mod.rs` — the directory is not yet part of the compiled crate (nothing declares `pub mod github;` for it yet), so every file below can reference `CloudProvider::Github` before that variant exists without causing a compile error: none of this code is reachable from the crate root until Task 11 wires it in. This ordering (children fully exist before the parent's `mod` declaration references them) avoids a broken intermediate state — declaring `pub mod github;` first, before the directory exists, would be a hard "unresolved module" error the instant that line landed.

**Files:**
- Create: `src/providers/github/mod.rs`
- Create: `src/providers/github/factory.rs`
- Create: `src/providers/github/members.rs` (stub)
- Create: `src/providers/github/teams.rs` (stub)
- Create: `src/providers/github/security_settings.rs` (stub)
- Create: `src/providers/github/repos.rs` (stub)
- Create: `src/providers/github/branch_protection.rs` (stub)
- Create: `src/providers/github/audit_log.rs` (stub)
- Create: `src/providers/github/alerts.rs` (stub)

**Interfaces:**
- Produces: `GithubProviderFactory::new(client: github_rs::GithubClient, org_name: String, selected: Vec<String>) -> Self`, implementing `ProviderFactory`

- [ ] **Step 1: Create the module declaration**

`src/providers/github/mod.rs`:

```rust
pub mod alerts;
pub mod audit_log;
pub mod branch_protection;
pub mod factory;
pub mod members;
pub mod repos;
pub mod security_settings;
pub mod teams;

// Authentication:
//   Authorization: Bearer <personal_access_token>
//
// Base URL: full REST API root, per-account (e.g. https://api.github.com for
// GitHub.com, or https://HOST/api/v3 for GitHub Enterprise Server). Supplied
// via the `github_base_url` config field or the `GITHUB_BASE_URL` env var.
```

- [ ] **Step 2: Create per-collector stub files so the factory compiles**

`src/providers/github/members.rs`:

```rust
use github_rs::GithubClient;

pub struct GithubMembersCollector {
    pub(crate) client: GithubClient,
}
impl GithubMembersCollector {
    pub fn new(client: GithubClient) -> Self {
        Self { client }
    }
}
```

`src/providers/github/teams.rs`:

```rust
use github_rs::GithubClient;

pub struct GithubTeamsCollector {
    pub(crate) client: GithubClient,
}
impl GithubTeamsCollector {
    pub fn new(client: GithubClient) -> Self {
        Self { client }
    }
}

pub struct GithubTeamMembersCollector {
    pub(crate) client: GithubClient,
}
impl GithubTeamMembersCollector {
    pub fn new(client: GithubClient) -> Self {
        Self { client }
    }
}
```

`src/providers/github/security_settings.rs`:

```rust
use github_rs::GithubClient;

pub struct GithubSecuritySettingsCollector {
    pub(crate) client: GithubClient,
}
impl GithubSecuritySettingsCollector {
    pub fn new(client: GithubClient) -> Self {
        Self { client }
    }
}
```

`src/providers/github/repos.rs`:

```rust
use github_rs::GithubClient;

pub struct GithubReposCollector {
    pub(crate) client: GithubClient,
}
impl GithubReposCollector {
    pub fn new(client: GithubClient) -> Self {
        Self { client }
    }
}
```

`src/providers/github/branch_protection.rs`:

```rust
use github_rs::GithubClient;

pub struct GithubBranchProtectionCollector {
    pub(crate) client: GithubClient,
}
impl GithubBranchProtectionCollector {
    pub fn new(client: GithubClient) -> Self {
        Self { client }
    }
}
```

`src/providers/github/audit_log.rs`:

```rust
use github_rs::GithubClient;

pub struct GithubAuditLogCollector {
    pub(crate) client: GithubClient,
}
impl GithubAuditLogCollector {
    pub fn new(client: GithubClient) -> Self {
        Self { client }
    }
}
```

`src/providers/github/alerts.rs`:

```rust
use github_rs::GithubClient;

pub struct GithubDependabotAlertsCollector {
    pub(crate) client: GithubClient,
}
impl GithubDependabotAlertsCollector {
    pub fn new(client: GithubClient) -> Self {
        Self { client }
    }
}

pub struct GithubSecretScanningAlertsCollector {
    pub(crate) client: GithubClient,
}
impl GithubSecretScanningAlertsCollector {
    pub fn new(client: GithubClient) -> Self {
        Self { client }
    }
}

pub struct GithubCodeScanningAlertsCollector {
    pub(crate) client: GithubClient,
}
impl GithubCodeScanningAlertsCollector {
    pub fn new(client: GithubClient) -> Self {
        Self { client }
    }
}
```

- [ ] **Step 3: Create `src/providers/github/factory.rs`**

```rust
use github_rs::GithubClient;

use crate::evidence::{CsvCollector, EvidenceCollector, JsonCollector};
use crate::providers::{CloudProvider, ProviderFactory};

use super::alerts::{
    GithubCodeScanningAlertsCollector, GithubDependabotAlertsCollector,
    GithubSecretScanningAlertsCollector,
};
use super::audit_log::GithubAuditLogCollector;
use super::branch_protection::GithubBranchProtectionCollector;
use super::members::GithubMembersCollector;
use super::repos::GithubReposCollector;
use super::security_settings::GithubSecuritySettingsCollector;
use super::teams::{GithubTeamMembersCollector, GithubTeamsCollector};

pub struct GithubProviderFactory {
    client: GithubClient,
    org_name: String,
    selected: Vec<String>,
}

impl GithubProviderFactory {
    pub fn new(client: GithubClient, org_name: String, selected: Vec<String>) -> Self {
        Self {
            client,
            org_name,
            selected,
        }
    }

    fn has(&self, key: &str) -> bool {
        self.selected.iter().any(|s| s == key)
    }
}

impl ProviderFactory for GithubProviderFactory {
    fn provider(&self) -> CloudProvider {
        CloudProvider::Github
    }
    fn account_id(&self) -> &str {
        &self.org_name
    }
    fn region(&self) -> &str {
        ""
    }

    fn csv_collectors(&self) -> Vec<Box<dyn CsvCollector>> {
        let mut v: Vec<Box<dyn CsvCollector>> = Vec::new();
        if self.has("github-members") {
            v.push(Box::new(GithubMembersCollector::new(self.client.clone())));
        }
        if self.has("github-teams") {
            v.push(Box::new(GithubTeamsCollector::new(self.client.clone())));
        }
        if self.has("github-team-members") {
            v.push(Box::new(GithubTeamMembersCollector::new(
                self.client.clone(),
            )));
        }
        if self.has("github-security-settings") {
            v.push(Box::new(GithubSecuritySettingsCollector::new(
                self.client.clone(),
            )));
        }
        if self.has("github-repos") {
            v.push(Box::new(GithubReposCollector::new(self.client.clone())));
        }
        if self.has("github-branch-protection") {
            v.push(Box::new(GithubBranchProtectionCollector::new(
                self.client.clone(),
            )));
        }
        if self.has("github-audit-log") {
            v.push(Box::new(GithubAuditLogCollector::new(self.client.clone())));
        }
        if self.has("github-dependabot-alerts") {
            v.push(Box::new(GithubDependabotAlertsCollector::new(
                self.client.clone(),
            )));
        }
        if self.has("github-secret-scanning-alerts") {
            v.push(Box::new(GithubSecretScanningAlertsCollector::new(
                self.client.clone(),
            )));
        }
        if self.has("github-code-scanning-alerts") {
            v.push(Box::new(GithubCodeScanningAlertsCollector::new(
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

- [ ] **Step 4: Verify the workspace still compiles cleanly**

Run: `cargo check --workspace --features github`
Expected: PASS with no new errors — none of the files created in this task are part of the compiled crate yet (`src/providers/mod.rs` doesn't declare `pub mod github;` until Task 11), so this step only confirms the rest of the workspace is undisturbed.

- [ ] **Step 5: Commit**

```bash
git add src/providers/github
git commit -m "feat(github): providers/github skeleton + GithubProviderFactory"
```

---

### Task 10: Account config fields + `github-config.toml` merge + env resolvers

**Files:**
- Modify: `src/app_config.rs`
- Create: `github-config.example.toml`

- [ ] **Step 1: Add GitHub fields to `Account` in `src/app_config.rs`**

After the Jira fields block (after line 203, before the "Collector filtering" comment at line 205):

```rust
    // ------------------------------------------------------------------
    // GitHub fields
    // ------------------------------------------------------------------
    /// GitHub org login (e.g. "acme").
    pub github_org: Option<String>,

    /// GitHub Personal Access Token (fine-grained or classic).
    /// Can also be supplied via `GITHUB_TOKEN` env var (env wins over TOML).
    pub github_token: Option<String>,

    /// Full REST API root. Defaults to `https://api.github.com` for
    /// GitHub.com. For GitHub Enterprise Server, set to
    /// `https://HOST/api/v3`.
    /// Can also be supplied via `GITHUB_BASE_URL` env var (env wins over TOML).
    pub github_base_url: Option<String>,
```

- [ ] **Step 2: Add resolver methods in the existing `impl Account` block**

After the `jira_domain_resolved` method (after line 272, before the closing `}` of `impl Account`):

```rust
    /// Resolve the GitHub org: env var takes precedence over TOML.
    pub fn github_org_resolved(&self) -> Option<String> {
        std::env::var("GITHUB_ORG")
            .ok()
            .or_else(|| self.github_org.clone())
            .filter(|s| !s.trim().is_empty())
    }

    /// Resolve the GitHub PAT: env var takes precedence over TOML.
    pub fn github_token_resolved(&self) -> Option<String> {
        std::env::var("GITHUB_TOKEN")
            .ok()
            .or_else(|| self.github_token.clone())
    }

    /// Resolve the GitHub REST API base URL, defaulting to GitHub.com.
    pub fn github_base_url_resolved(&self) -> String {
        std::env::var("GITHUB_BASE_URL")
            .ok()
            .or_else(|| self.github_base_url.clone())
            .map(|s| s.trim().trim_end_matches('/').to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "https://api.github.com".to_string())
    }
```

- [ ] **Step 3: Merge `github-config.toml` in `load_config`**

In `src/app_config.rs`, after the `jira-config.toml` merge block (after line 328):

```rust
    // Merge github-config.toml accounts if present
    let github_path = PathBuf::from("github-config.toml");
    if github_path.exists() {
        if let Ok(contents) = fs::read_to_string(&github_path) {
            if let Ok(github_cfg) = toml::from_str::<AppConfig>(&contents) {
                cfg.account.extend(github_cfg.account);
            }
        }
    }
```

Update the doc comment above `load_config` (lines 275–280):

```rust
/// Best-effort load of config, checking in order:
///   1. `./config.toml`  (project-local)
///   2. `~/.config/evidence/config.toml`  (user-global)
///
/// After loading the primary config, `./tenable-config.toml`,
/// `./okta-config.toml`, `./jira-config.toml`, and `./github-config.toml`
/// are merged in (accounts only) if those files exist.
```

- [ ] **Step 4: Create `github-config.example.toml`**

```toml
# GitHub credentials — keep this file out of version control
# Add to .gitignore: github-config.toml
#
# Merged automatically into config.toml at startup when present.
# Env vars override TOML values: GITHUB_ORG, GITHUB_TOKEN, GITHUB_BASE_URL

[[account]]
name             = "GitHub"
provider         = "github"
description      = "GitHub.com organization"
output_dir       = "./evidence-output/github"
github_org       = "acme"
github_token     = ""
# For GitHub Enterprise Server, uncomment and point at your instance:
# github_base_url = "https://github.acme.internal/api/v3"
```

- [ ] **Step 5: Verify it compiles**

Run: `cargo check`
Expected: PASS cleanly — `src/providers/github` (Task 9) still isn't wired into the module tree (`pub mod github;` isn't added until Task 11), so this step only confirms `app_config.rs` itself has no errors.

- [ ] **Step 6: Commit**

```bash
git add src/app_config.rs github-config.example.toml
git commit -m "feat(github): account config fields + github-config.toml merge"
```

---

### Task 11: Add `Github` variant to `CloudProvider`

**Files:**
- Modify: `src/providers/mod.rs`

**Note on ordering:** this is the task that wires the whole `src/providers/github` subtree (built in Task 9) into the crate. Both changes below — the `pub mod github;` declaration and the `CloudProvider::Github` variant — land in the same `src/providers/mod.rs` edit, so the module and the enum variant its `factory.rs` depends on become valid at the same instant.

- [ ] **Step 1: Add the module declaration and enum variant**

In `src/providers/mod.rs`, add the module declaration after the `jira` one:

```rust
#[cfg(feature = "jira")]
pub mod jira;

#[cfg(feature = "github")]
pub mod github;
```

Update `CloudProvider` and its `Display` impl:

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
    Github,
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
            CloudProvider::Github => write!(f, "GitHub"),
        }
    }
}
```

- [ ] **Step 2: Build to see the whole subtree come online**

Run: `cargo check --workspace --features github`
Expected: the `src/providers/github` subtree from Task 9 is now part of the compiled crate for the first time. Errors surface for exactly the ten `Github*Collector` stubs not yet implementing `CsvCollector` (Tasks 12–17 add those impls one at a time), plus every other `match` on `CloudProvider` elsewhere in `src/` that doesn't cover `Github` yet (Tasks 18–19 add those arms). If a non-exhaustive match turns up somewhere not listed in this plan, add a `Github` arm mirroring the nearest non-AWS provider's arm (Okta's, unless the match is Jira-specific like project-key handling).

- [ ] **Step 3: Commit**

```bash
git add src/providers/mod.rs
git commit -m "feat(github): add Github variant to CloudProvider, wire in providers/github"
```

---

### Task 12: Org Members collector (`github-members`)

**Files:**
- Modify: `src/providers/github/members.rs`

**Interfaces:**
- Consumes: `github_rs::GithubClient::members()`, `MembersApi::list_by_role`, `MembersApi::list_2fa_disabled`, `GithubError::Api`
- Produces: `GithubMembersCollector: CsvCollector`, `filename_prefix() == "Github_Org_Members"`

- [ ] **Step 1: Implement `CsvCollector` for `GithubMembersCollector`**

Replace `src/providers/github/members.rs` entirely:

```rust
use anyhow::Result;
use async_trait::async_trait;
use github_rs::{GithubClient, GithubError};
use std::collections::HashMap;

use crate::evidence::CsvCollector;

pub struct GithubMembersCollector {
    pub(crate) client: GithubClient,
}

impl GithubMembersCollector {
    pub fn new(client: GithubClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for GithubMembersCollector {
    fn name(&self) -> &str {
        "GitHub Org Members"
    }
    fn filename_prefix(&self) -> &str {
        "Github_Org_Members"
    }
    fn headers(&self) -> &'static [&'static str] {
        &["Login", "User ID", "Role", "Site Admin", "2FA Disabled"]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let admins = self.client.members().list_by_role("admin").await?;
        let members = self.client.members().list_by_role("member").await?;

        let mut role_by_login: HashMap<String, &'static str> = HashMap::new();
        for u in &admins {
            role_by_login.insert(u.login.clone(), "admin");
        }
        for u in &members {
            role_by_login.entry(u.login.clone()).or_insert("member");
        }

        // 2FA-disabled requires an org-owner token — a 403 here means "we
        // can't tell", not "collection failed"; every row gets "unknown".
        let disabled_2fa: Option<std::collections::HashSet<String>> =
            match self.client.members().list_2fa_disabled().await {
                Ok(users) => Some(users.into_iter().map(|u| u.login).collect()),
                Err(GithubError::Api { status: 403, .. }) => None,
                Err(GithubError::Api { status: 404, .. }) => None,
                Err(e) => return Err(e.into()),
            };

        let mut merged: HashMap<String, (i64, bool)> = HashMap::new();
        for u in admins.into_iter().chain(members.into_iter()) {
            merged.entry(u.login).or_insert((u.id, u.site_admin));
        }

        let mut rows: Vec<Vec<String>> = merged
            .into_iter()
            .map(|(login, (id, site_admin))| {
                let role = role_by_login.get(&login).copied().unwrap_or("member");
                let two_fa = match &disabled_2fa {
                    Some(set) => if set.contains(&login) { "true" } else { "false" },
                    None => "unknown",
                };
                vec![
                    login,
                    id.to_string(),
                    role.to_string(),
                    site_admin.to_string(),
                    two_fa.to_string(),
                ]
            })
            .collect();
        rows.sort_by(|a, b| a[0].cmp(&b[0]));
        Ok(rows)
    }
}
```

- [ ] **Step 2: Verify it compiles**

Run: `cargo check --features github`
Expected: `GithubMembersCollector` no longer errors; remaining errors are only the other nine still-stub collectors (expected until Tasks 13–17).

- [ ] **Step 3: Commit**

```bash
git add src/providers/github/members.rs
git commit -m "feat(github): org members collector"
```

---

### Task 13: Org Teams + Team Membership collectors (`github-teams`, `github-team-members`)

**Files:**
- Modify: `src/providers/github/teams.rs`

**Interfaces:**
- Consumes: `GithubClient::teams()`, `TeamsApi::list_all`, `TeamsApi::list_members`
- Produces: `GithubTeamsCollector: CsvCollector` (`filename_prefix() == "Github_Teams"`), `GithubTeamMembersCollector: CsvCollector` (`filename_prefix() == "Github_Team_Members"`) — the latter is self-contained: it calls `list_all()` itself rather than depending on `github-teams` being separately selected, matching `OktaGroupMembersCollector`

- [ ] **Step 1: Implement both collectors**

Replace `src/providers/github/teams.rs` entirely:

```rust
use anyhow::Result;
use async_trait::async_trait;
use github_rs::GithubClient;

use crate::evidence::CsvCollector;

pub struct GithubTeamsCollector {
    pub(crate) client: GithubClient,
}

impl GithubTeamsCollector {
    pub fn new(client: GithubClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for GithubTeamsCollector {
    fn name(&self) -> &str {
        "GitHub Teams"
    }
    fn filename_prefix(&self) -> &str {
        "Github_Teams"
    }
    fn headers(&self) -> &'static [&'static str] {
        &["Team ID", "Slug", "Name", "Privacy", "Permission", "Description"]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let teams = self.client.teams().list_all().await?;
        Ok(teams
            .into_iter()
            .map(|t| {
                vec![
                    t.id.to_string(),
                    t.slug,
                    t.name,
                    t.privacy,
                    t.permission,
                    t.description.unwrap_or_default(),
                ]
            })
            .collect())
    }
}

pub struct GithubTeamMembersCollector {
    pub(crate) client: GithubClient,
}

impl GithubTeamMembersCollector {
    pub fn new(client: GithubClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for GithubTeamMembersCollector {
    fn name(&self) -> &str {
        "GitHub Team Members"
    }
    fn filename_prefix(&self) -> &str {
        "Github_Team_Members"
    }
    fn headers(&self) -> &'static [&'static str] {
        &["Team Slug", "Team Name", "Member Login", "Member ID"]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let teams = self.client.teams().list_all().await?;
        let mut rows: Vec<Vec<String>> = Vec::new();
        for t in teams {
            let members = self.client.teams().list_members(&t.slug).await?;
            if members.is_empty() {
                rows.push(vec![t.slug.clone(), t.name.clone(), String::new(), String::new()]);
                continue;
            }
            for m in members {
                rows.push(vec![
                    t.slug.clone(),
                    t.name.clone(),
                    m.login,
                    m.id.to_string(),
                ]);
            }
        }
        Ok(rows)
    }
}
```

- [ ] **Step 2: Verify it compiles**

Run: `cargo check --features github`
Expected: `GithubTeamsCollector` and `GithubTeamMembersCollector` no longer error.

- [ ] **Step 3: Commit**

```bash
git add src/providers/github/teams.rs
git commit -m "feat(github): teams + team membership collectors"
```

---

### Task 14: Org Security Settings collector (`github-security-settings`)

**Files:**
- Modify: `src/providers/github/security_settings.rs`

**Interfaces:**
- Consumes: `GithubClient::orgs()`, `OrgsApi::get`
- Produces: `GithubSecuritySettingsCollector: CsvCollector`, `filename_prefix() == "Github_Org_Security_Settings"`, single-row output

- [ ] **Step 1: Implement `CsvCollector`**

Replace `src/providers/github/security_settings.rs` entirely:

```rust
use anyhow::Result;
use async_trait::async_trait;
use github_rs::GithubClient;

use crate::evidence::CsvCollector;

pub struct GithubSecuritySettingsCollector {
    pub(crate) client: GithubClient,
}

impl GithubSecuritySettingsCollector {
    pub fn new(client: GithubClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for GithubSecuritySettingsCollector {
    fn name(&self) -> &str {
        "GitHub Org Security Settings"
    }
    fn filename_prefix(&self) -> &str {
        "Github_Org_Security_Settings"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Org Login",
            "Two-Factor Requirement Enabled",
            "Default Repository Permission",
            "Members Can Create Repositories",
            "Members Can Create Private Repositories",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let org = self.client.orgs().get().await?;
        Ok(vec![vec![
            org.login,
            org.two_factor_requirement_enabled
                .map(|b| b.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            org.default_repository_permission.unwrap_or_default(),
            org.members_can_create_repositories
                .map(|b| b.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            org.members_can_create_private_repositories
                .map(|b| b.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
        ]])
    }
}
```

- [ ] **Step 2: Verify it compiles**

Run: `cargo check --features github`
Expected: `GithubSecuritySettingsCollector` no longer errors.

- [ ] **Step 3: Commit**

```bash
git add src/providers/github/security_settings.rs
git commit -m "feat(github): org security settings collector"
```

---

### Task 15: Repositories + Branch Protection collectors (`github-repos`, `github-branch-protection`)

**Files:**
- Modify: `src/providers/github/repos.rs`
- Modify: `src/providers/github/branch_protection.rs`

**Interfaces:**
- Consumes: `GithubClient::repos()`, `ReposApi::list_all`, `ReposApi::get_branch_protection`, `GithubError::Api`
- Produces: `GithubReposCollector: CsvCollector` (`filename_prefix() == "Github_Repositories"`), `GithubBranchProtectionCollector: CsvCollector` (`filename_prefix() == "Github_Branch_Protection"`) — the latter is self-contained: calls `list_all()` itself

- [ ] **Step 1: Implement `GithubReposCollector`**

Replace `src/providers/github/repos.rs` entirely:

```rust
use anyhow::Result;
use async_trait::async_trait;
use github_rs::GithubClient;

use crate::evidence::CsvCollector;

pub struct GithubReposCollector {
    pub(crate) client: GithubClient,
}

impl GithubReposCollector {
    pub fn new(client: GithubClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for GithubReposCollector {
    fn name(&self) -> &str {
        "GitHub Repositories"
    }
    fn filename_prefix(&self) -> &str {
        "Github_Repositories"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Repo ID",
            "Name",
            "Full Name",
            "Visibility",
            "Private",
            "Default Branch",
            "Archived",
            "Created At",
            "Pushed At",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let repos = self.client.repos().list_all().await?;
        Ok(repos
            .into_iter()
            .map(|r| {
                vec![
                    r.id.to_string(),
                    r.name,
                    r.full_name,
                    r.visibility,
                    r.private.to_string(),
                    r.default_branch,
                    r.archived.to_string(),
                    r.created_at.unwrap_or_default(),
                    r.pushed_at.unwrap_or_default(),
                ]
            })
            .collect())
    }
}
```

- [ ] **Step 2: Implement `GithubBranchProtectionCollector`**

Replace `src/providers/github/branch_protection.rs` entirely:

```rust
use anyhow::Result;
use async_trait::async_trait;
use github_rs::{GithubClient, GithubError};

use crate::evidence::CsvCollector;

pub struct GithubBranchProtectionCollector {
    pub(crate) client: GithubClient,
}

impl GithubBranchProtectionCollector {
    pub fn new(client: GithubClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for GithubBranchProtectionCollector {
    fn name(&self) -> &str {
        "GitHub Branch Protection"
    }
    fn filename_prefix(&self) -> &str {
        "Github_Branch_Protection"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Repository",
            "Branch",
            "Protected",
            "Enforce Admins",
            "Required Approving Review Count",
            "Require Code Owner Reviews",
            "Required Status Checks Strict",
            "Allow Force Pushes",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let repos = self.client.repos().list_all().await?;
        let mut rows = Vec::with_capacity(repos.len());
        for r in repos {
            if r.default_branch.is_empty() {
                continue;
            }
            let protection = match self
                .client
                .repos()
                .get_branch_protection(&r.name, &r.default_branch)
                .await
            {
                Ok(p) => Some(p),
                Err(GithubError::Api { status: 404, .. }) => None,
                Err(e) => return Err(e.into()),
            };

            match protection {
                None => rows.push(vec![
                    r.full_name,
                    r.default_branch,
                    "false".to_string(),
                    "unknown".to_string(),
                    String::new(),
                    "unknown".to_string(),
                    "unknown".to_string(),
                    "unknown".to_string(),
                ]),
                Some(p) => {
                    let reviews = p.required_pull_request_reviews;
                    rows.push(vec![
                        r.full_name,
                        r.default_branch,
                        "true".to_string(),
                        p.enforce_admins
                            .map(|e| e.enabled.to_string())
                            .unwrap_or_else(|| "unknown".to_string()),
                        reviews
                            .as_ref()
                            .and_then(|rv| rv.required_approving_review_count)
                            .map(|n| n.to_string())
                            .unwrap_or_default(),
                        reviews
                            .as_ref()
                            .and_then(|rv| rv.require_code_owner_reviews)
                            .map(|b| b.to_string())
                            .unwrap_or_else(|| "unknown".to_string()),
                        p.required_status_checks
                            .map(|c| c.strict.to_string())
                            .unwrap_or_else(|| "unknown".to_string()),
                        p.allow_force_pushes
                            .map(|f| f.enabled.to_string())
                            .unwrap_or_else(|| "unknown".to_string()),
                    ]);
                }
            }
        }
        Ok(rows)
    }
}
```

- [ ] **Step 3: Verify it compiles**

Run: `cargo check --features github`
Expected: `GithubReposCollector` and `GithubBranchProtectionCollector` no longer error.

- [ ] **Step 4: Commit**

```bash
git add src/providers/github/repos.rs src/providers/github/branch_protection.rs
git commit -m "feat(github): repositories + branch protection collectors"
```

---

### Task 16: Org Audit Log collector (`github-audit-log`)

**Files:**
- Modify: `src/providers/github/audit_log.rs`

**Interfaces:**
- Consumes: `GithubClient::audit_log()`, `AuditLogApi::events`
- Produces: `GithubAuditLogCollector: CsvCollector`, `filename_prefix() == "Github_Org_Audit_Log"` — degrades to empty on 403/404 (not GitHub Enterprise Cloud)

- [ ] **Step 1: Implement `CsvCollector`**

Replace `src/providers/github/audit_log.rs` entirely:

```rust
use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use github_rs::{GithubClient, GithubError};

use crate::evidence::CsvCollector;

pub struct GithubAuditLogCollector {
    pub(crate) client: GithubClient,
}

impl GithubAuditLogCollector {
    pub fn new(client: GithubClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for GithubAuditLogCollector {
    fn name(&self) -> &str {
        "GitHub Org Audit Log"
    }
    fn filename_prefix(&self) -> &str {
        "Github_Org_Audit_Log"
    }
    fn headers(&self) -> &'static [&'static str] {
        &["Action", "Actor", "User", "Org", "Created At", "Document ID"]
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

        // Requires GitHub Enterprise Cloud — any other plan 403s/404s here.
        let events = match self.client.audit_log().events(&since, &until).await {
            Ok(e) => e,
            Err(GithubError::Api { status: 403, .. }) => return Ok(vec![]),
            Err(GithubError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };

        Ok(events
            .into_iter()
            .map(|e| {
                let created_at = e
                    .created_at
                    .and_then(|ms| DateTime::<Utc>::from_timestamp_millis(ms))
                    .map(|dt| dt.to_rfc3339())
                    .unwrap_or_default();
                vec![
                    e.action,
                    e.actor.unwrap_or_default(),
                    e.user.unwrap_or_default(),
                    e.org.unwrap_or_default(),
                    created_at,
                    e.document_id.unwrap_or_default(),
                ]
            })
            .collect())
    }
}
```

- [ ] **Step 2: Verify it compiles**

Run: `cargo check --features github`
Expected: `GithubAuditLogCollector` no longer errors.

- [ ] **Step 3: Commit**

```bash
git add src/providers/github/audit_log.rs
git commit -m "feat(github): org audit log collector"
```

---

### Task 17: Security Alerts collectors (`github-dependabot-alerts`, `github-secret-scanning-alerts`, `github-code-scanning-alerts`)

**Files:**
- Modify: `src/providers/github/alerts.rs`

**Interfaces:**
- Consumes: `GithubClient::alerts()`, `AlertsApi::dependabot_alerts`/`secret_scanning_alerts`/`code_scanning_alerts`, `GithubError::Api`
- Produces: `GithubDependabotAlertsCollector: CsvCollector` (`"Github_Dependabot_Alerts"`), `GithubSecretScanningAlertsCollector: CsvCollector` (`"Github_Secret_Scanning_Alerts"`), `GithubCodeScanningAlertsCollector: CsvCollector` (`"Github_Code_Scanning_Alerts"`) — each degrades to empty on 403/404 and client-side filters by `created_at` when `dates` is provided

- [ ] **Step 1: Implement all three collectors**

Replace `src/providers/github/alerts.rs` entirely:

```rust
use anyhow::Result;
use async_trait::async_trait;
use chrono::DateTime;
use github_rs::{GithubClient, GithubError};

use crate::evidence::CsvCollector;

/// Parse an RFC 3339 `created_at` and check it against an optional
/// `(start_secs, end_secs)` Unix-timestamp range. Unparseable timestamps are
/// kept (fail open) rather than silently dropped.
fn in_range(created_at: &str, dates: Option<(i64, i64)>) -> bool {
    let Some((start, end)) = dates else {
        return true;
    };
    match DateTime::parse_from_rfc3339(created_at) {
        Ok(dt) => {
            let ts = dt.timestamp();
            ts >= start && ts <= end
        }
        Err(_) => true,
    }
}

pub struct GithubDependabotAlertsCollector {
    pub(crate) client: GithubClient,
}

impl GithubDependabotAlertsCollector {
    pub fn new(client: GithubClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for GithubDependabotAlertsCollector {
    fn name(&self) -> &str {
        "GitHub Dependabot Alerts"
    }
    fn filename_prefix(&self) -> &str {
        "Github_Dependabot_Alerts"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Repository",
            "Alert Number",
            "State",
            "Package Ecosystem",
            "Package Name",
            "Severity",
            "GHSA ID",
            "CVE ID",
            "Summary",
            "Created At",
            "Updated At",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let alerts = match self.client.alerts().dependabot_alerts().await {
            Ok(a) => a,
            Err(GithubError::Api { status: 403, .. }) => return Ok(vec![]),
            Err(GithubError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };
        Ok(alerts
            .into_iter()
            .filter(|a| in_range(&a.created_at, dates))
            .map(|a| {
                let advisory = a.security_advisory;
                vec![
                    a.repository.full_name,
                    a.number.to_string(),
                    a.state,
                    a.dependency.package.ecosystem,
                    a.dependency.package.name,
                    advisory.as_ref().map(|s| s.severity.clone()).unwrap_or_default(),
                    advisory.as_ref().map(|s| s.ghsa_id.clone()).unwrap_or_default(),
                    advisory
                        .as_ref()
                        .and_then(|s| s.cve_id.clone())
                        .unwrap_or_default(),
                    advisory.as_ref().map(|s| s.summary.clone()).unwrap_or_default(),
                    a.created_at,
                    a.updated_at.unwrap_or_default(),
                ]
            })
            .collect())
    }
}

pub struct GithubSecretScanningAlertsCollector {
    pub(crate) client: GithubClient,
}

impl GithubSecretScanningAlertsCollector {
    pub fn new(client: GithubClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for GithubSecretScanningAlertsCollector {
    fn name(&self) -> &str {
        "GitHub Secret Scanning Alerts"
    }
    fn filename_prefix(&self) -> &str {
        "Github_Secret_Scanning_Alerts"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Repository",
            "Alert Number",
            "State",
            "Secret Type",
            "Secret Type Display Name",
            "Resolution",
            "Push Protection Bypassed",
            "Created At",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let alerts = match self.client.alerts().secret_scanning_alerts().await {
            Ok(a) => a,
            Err(GithubError::Api { status: 403, .. }) => return Ok(vec![]),
            Err(GithubError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };
        Ok(alerts
            .into_iter()
            .filter(|a| in_range(&a.created_at, dates))
            .map(|a| {
                vec![
                    a.repository.full_name,
                    a.number.to_string(),
                    a.state,
                    a.secret_type,
                    a.secret_type_display_name.unwrap_or_default(),
                    a.resolution.unwrap_or_default(),
                    a.push_protection_bypassed.to_string(),
                    a.created_at,
                ]
            })
            .collect())
    }
}

pub struct GithubCodeScanningAlertsCollector {
    pub(crate) client: GithubClient,
}

impl GithubCodeScanningAlertsCollector {
    pub fn new(client: GithubClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for GithubCodeScanningAlertsCollector {
    fn name(&self) -> &str {
        "GitHub Code Scanning Alerts"
    }
    fn filename_prefix(&self) -> &str {
        "Github_Code_Scanning_Alerts"
    }
    fn headers(&self) -> &'static [&'static str] {
        &[
            "Repository",
            "Alert Number",
            "State",
            "Rule ID",
            "Severity",
            "Security Severity Level",
            "Description",
            "Created At",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let alerts = match self.client.alerts().code_scanning_alerts().await {
            Ok(a) => a,
            Err(GithubError::Api { status: 403, .. }) => return Ok(vec![]),
            Err(GithubError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };
        Ok(alerts
            .into_iter()
            .filter(|a| in_range(&a.created_at, dates))
            .map(|a| {
                vec![
                    a.repository.full_name,
                    a.number.to_string(),
                    a.state,
                    a.rule.id,
                    a.rule.severity.unwrap_or_default(),
                    a.rule.security_severity_level.unwrap_or_default(),
                    a.rule.description,
                    a.created_at,
                ]
            })
            .collect())
    }
}
```

- [ ] **Step 2: Verify the whole workspace compiles**

Run: `cargo check --workspace --features github`
Expected: PASS — this is the first fully clean build since Task 11 introduced the `Github` variant; every collector now has a real `CsvCollector` impl.

- [ ] **Step 3: Commit**

```bash
git add src/providers/github/alerts.rs
git commit -m "feat(github): security alerts collectors (dependabot, secret scanning, code scanning)"
```

---

### Task 18: TUI collector menu

**Files:**
- Create: `src/tui/menus/github.rs`
- Modify: `src/tui/menus/mod.rs`

- [ ] **Step 1: Create `src/tui/menus/github.rs`**

```rust
//! GitHub collector menu. 10 collectors across 3 categories.

use super::ProviderCategory;

pub const GITHUB_CATEGORIES: &[ProviderCategory] = &[
    ProviderCategory {
        name: "Access Control",
        items: &[
            ("github-members", "Org Members            "),
            ("github-teams", "Org Teams              "),
            ("github-team-members", "Team Membership        "),
            ("github-security-settings", "Org Security Settings  "),
        ],
    },
    ProviderCategory {
        name: "Repositories & Change Control",
        items: &[
            ("github-repos", "Repositories           "),
            ("github-branch-protection", "Branch Protection      "),
        ],
    },
    ProviderCategory {
        name: "Audit & Security Alerts",
        items: &[
            ("github-audit-log", "Org Audit Log          "),
            ("github-dependabot-alerts", "Dependabot Alerts      "),
            ("github-secret-scanning-alerts", "Secret Scanning Alerts "),
            ("github-code-scanning-alerts", "Code Scanning Alerts   "),
        ],
    },
];
```

- [ ] **Step 2: Register in `src/tui/menus/mod.rs`**

Add the module declaration:

```rust
pub mod aws;
pub mod github;
pub mod jira;
pub mod okta;
pub mod tenable;
```

Add the entry to `PROVIDER_MENUS`:

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
        provider: CloudProvider::Github,
        categories: github::GITHUB_CATEGORIES,
    },
];
```

- [ ] **Step 3: Verify it compiles**

Run: `cargo check --features github`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add src/tui/menus/github.rs src/tui/menus/mod.rs
git commit -m "feat(github): tui collector menu"
```

---

### Task 19: TUI wiring — provider list, tile, navigation, defaults, session prep

**Files:**
- Modify: `src/tui/events.rs`
- Modify: `src/tui/ui/account_screens.rs`
- Modify: `src/tui/app/nav.rs`
- Modify: `src/tui/app/mod.rs`
- Modify: `src/runner/tui_session.rs`

- [ ] **Step 1: Add `Github` to the provider list in `src/tui/events.rs`**

In `handle_provider_selection` (around line 730), add after the `jira` push:

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
        #[cfg(feature = "github")]
        v.push(CloudProvider::Github);
        v
    };
```

- [ ] **Step 2: Add the GitHub tile in `src/tui/ui/account_screens.rs`**

In `draw_provider_selection` (around line 50), add after the `jira` push, in the same relative order as Step 1:

```rust
        #[cfg(feature = "github")]
        v.push((
            CloudProvider::Github,
            "◆  GitHub",
            "Collect org members, teams, repos, branch protection, audit log, and security alerts",
        ));
```

- [ ] **Step 3: Add `Github` nav arms in `src/tui/app/nav.rs`**

In `next_screen`, the `Screen::ProviderSelection` match arm (line 102–120): add a `Github` branch alongside `Okta`/`Jira` (both already return `Screen::SelectCollectors` with the same auto-select behavior — mirror that exactly):

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
                } else if self.selected_provider == CloudProvider::Github {
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

In `prev_screen`, the `Screen::SelectCollectors` arm (line 158–168): add `Github` to the same `ProviderSelection`-returning condition as `Okta`/`Jira`:

```rust
            Screen::SelectCollectors => {
                if self.selected_provider == CloudProvider::Tenable {
                    Screen::TenableEndpoint
                } else if self.selected_provider == CloudProvider::Okta
                    || self.selected_provider == CloudProvider::Jira
                    || self.selected_provider == CloudProvider::Github
                {
                    Screen::ProviderSelection
                } else {
                    Screen::SetDates
                }
            }
```

In `validate_current`, the `Screen::ProviderSelection` arm (line 225–262): add a `Github` block after the `jira` one:

```rust
                #[cfg(feature = "github")]
                if self.selected_provider == CloudProvider::Github {
                    let has_github = self
                        .accounts
                        .iter()
                        .any(|a| a.provider == CloudProvider::Github);
                    if !has_github {
                        self.error_msg =
                            Some("No GitHub accounts configured in github-config.toml".into());
                        return false;
                    }
                }
```

- [ ] **Step 4: Add plan-gated GitHub keys to `hardcoded_optins` in `src/tui/app/mod.rs`**

At line 167–188, append after `"jira-issues",`:

```rust
            "jira-projects",
            "jira-issues",
            "github-audit-log",
            "github-dependabot-alerts",
            "github-secret-scanning-alerts",
            "github-code-scanning-alerts",
        ];
```

(`github-members`, `github-teams`, `github-team-members`, `github-security-settings`, `github-repos`, `github-branch-protection` are intentionally **not** added — they work on any GitHub plan and stay enabled by default.)

- [ ] **Step 5: Add the GitHub account-prep block in `src/runner/tui_session.rs`**

After the Jira account-prep block (after line 946 or wherever it closes — locate the closing `}` that matches `#[cfg(feature = "jira")] if !app.selected_accounts.is_empty() {` before the next section), add:

```rust
            // ── GitHub accounts ──────────────────────────────────────────────────
            #[cfg(feature = "github")]
            if !app.selected_accounts.is_empty() {
                use crate::providers::ProviderFactory as _;

                let sorted_all: Vec<usize> = {
                    let mut v: Vec<usize> = app.selected_accounts.iter().copied().collect();
                    v.sort();
                    v
                };
                for &idx in &sorted_all {
                    if app.accounts[idx].provider != crate::providers::CloudProvider::Github {
                        continue;
                    }
                    let acct = &app.accounts[idx];
                    let account_name = acct.name.clone();

                    let org = match acct.github_org_resolved() {
                        Some(o) => o,
                        None => {
                            app.prep_log.push(format!(
                                "  ✗ GitHub '{}' — missing github_org (or GITHUB_ORG env)",
                                account_name,
                            ));
                            terminal.draw(|f| crate::tui::ui::draw(f, &app))?;
                            continue;
                        }
                    };
                    let token = match acct.github_token_resolved() {
                        Some(t) => t,
                        None => {
                            app.prep_log.push(format!(
                                "  ✗ GitHub '{}' — missing github_token (or GITHUB_TOKEN env)",
                                account_name,
                            ));
                            terminal.draw(|f| crate::tui::ui::draw(f, &app))?;
                            continue;
                        }
                    };
                    let base_url = acct.github_base_url_resolved();

                    app.prep_log
                        .push(format!("  GitHub '{}' → {} ({})", account_name, org, base_url));
                    terminal.draw(|f| crate::tui::ui::draw(f, &app))?;

                    let client = match github_rs::GithubClient::new(&base_url, &token, &org) {
                        Ok(c) => c,
                        Err(e) => {
                            app.prep_log.push(format!(
                                "  ✗ GitHub '{}' — client build failed: {e}",
                                account_name,
                            ));
                            terminal.draw(|f| crate::tui::ui::draw(f, &app))?;
                            continue;
                        }
                    };

                    let selected_keys: Vec<String> = app
                        .selected_collectors()
                        .into_iter()
                        .filter(|k| k.starts_with("github-"))
                        .collect();

                    let factory = crate::providers::github::factory::GithubProviderFactory::new(
                        client,
                        org.clone(),
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
                        account_id: org.clone(),
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
                        endpoint_label: Some(format!("GitHub — {}", org)),
                    });

                    app.prep_log
                        .push(format!("  ✓ GitHub '{}' ready.", account_name));
                    terminal.draw(|f| crate::tui::ui::draw(f, &app))?;
                }
            }
```

- [ ] **Step 6: Verify the whole workspace compiles**

Run: `cargo check --workspace --features github`
Expected: PASS with no warnings about unhandled `CloudProvider::Github` match arms anywhere in `src/`.

Run: `cargo build --workspace`
Expected: PASS (default features include `github`).

- [ ] **Step 7: Commit**

```bash
git add src/tui/events.rs src/tui/ui/account_screens.rs src/tui/app/nav.rs src/tui/app/mod.rs src/runner/tui_session.rs
git commit -m "feat(github): wire GitHub into TUI provider selection, nav, and session prep"
```

---

### Task 20: Documentation

**Files:**
- Modify: `README.md`
- Modify: `cli-examples.md`
- Modify: `docs/cli-reference.md`
- Modify: `evidence-list.md`

- [ ] **Step 1: Update README's top-level provider mentions**

Line 3, update the description:

```markdown
The Grabber. Collects current-state snapshots and time-windowed audit records from AWS, Okta, Jira, Tenable, and GitHub, writing them as CSV and JSON. Supports exporting inventory and POA&M artifacts using FedRAMP-aligned templates, suitable for FedRAMP, SOC 2, HIPAA, or internal audits.
```

Line 13, update the collector count bullet:

```markdown
- **200+ collectors across five providers** — 144 AWS, 24 Okta, 28 Jira, 5 Tenable, 10 GitHub (see `evidence-list.md` for the current catalog)
```

Line 178, update the non-AWS provider mention:

```markdown
A scrollable checklist of 144 AWS collectors grouped into categories (IAM, EC2/Networking, Storage, RDS, KMS, CloudTrail, Config, Security Services, SSM, Monitoring, Containers, etc.). Non-AWS providers (Okta, Jira, Tenable, GitHub) surface their own per-provider collector menus with only the keys relevant to that provider.
```

Line 319, update the `--collectors` note:

```markdown
3. `--collectors` accepts keys across every enabled provider (AWS/Okta/Jira/Tenable/GitHub); the maintained key list lives in `evidence-list.md`.
```

- [ ] **Step 2: Add a `## GitHub` section to README.md**

Insert after the `## Jira` section, before whatever section follows it (find the section following `## Jira` — likely `## Tenable` at line 818 — and insert immediately before it):

```markdown
## GitHub

Optional feature — build with `--features github` (enabled by default).

### Configuration

Create `github-config.toml` in the repo root (gitignored):

```toml
[[account]]
name             = "GitHub"
provider         = "github"
description      = "GitHub.com organization"
output_dir       = "./evidence-output/github"
github_org       = "acme"
github_token     = ""
# For GitHub Enterprise Server, uncomment and point at your instance:
# github_base_url = "https://github.acme.internal/api/v3"
```

Or set the values via environment variables (env wins over TOML):

- `GITHUB_ORG` — org login, e.g. `acme`
- `GITHUB_TOKEN` — Personal Access Token (fine-grained or classic)
- `GITHUB_BASE_URL` — REST API root; omit for GitHub.com (defaults to `https://api.github.com`), or set to `https://HOST/api/v3` for GitHub Enterprise Server

Create a token at **Settings → Developer settings → Personal access tokens**. Required scopes/permissions:

| Collector(s) | Fine-grained permission | Classic scope |
|---|---|---|
| Org Members, Teams, Team Membership | Members: Read-only | `read:org` |
| Org Security Settings | Administration: Read-only (org) | `read:org` |
| Repositories, Branch Protection | Contents: Read-only, Administration: Read-only | `repo` |
| Org Audit Log | Organization audit log: Read-only — **requires GitHub Enterprise Cloud** | `read:audit_log` |
| Dependabot Alerts | Dependabot alerts: Read-only | `security_events` |
| Secret Scanning Alerts | Secret scanning alerts: Read-only | `security_events` |
| Code Scanning Alerts | Code scanning alerts: Read-only | `security_events` |

### Collectors

| Key | Output | Description |
|-----|--------|-------------|
| `github-members` | CSV | Org members with role (admin/member), site-admin flag, and 2FA-disabled status (2FA status requires an org-owner token) |
| `github-teams` | CSV | Teams with slug, privacy, and permission level |
| `github-team-members` | CSV | Per-team membership lists |
| `github-security-settings` | CSV | Org-wide 2FA requirement, default repo permission, member repo-creation rights |
| `github-repos` | CSV | Repositories with visibility, default branch, archived status |
| `github-branch-protection` | CSV | Default-branch protection rules per repo (required reviews, status checks, force-push policy) |
| `github-audit-log` | CSV | Time-windowed org audit log events — **requires GitHub Enterprise Cloud** |
| `github-dependabot-alerts` | CSV | Dependency vulnerability alerts, time-windowed by `created_at` |
| `github-secret-scanning-alerts` | CSV | Leaked-secret alerts, time-windowed by `created_at` |
| `github-code-scanning-alerts` | CSV | Static-analysis (e.g. CodeQL) findings, time-windowed by `created_at` |

`github-audit-log`, `github-dependabot-alerts`, `github-secret-scanning-alerts`, and `github-code-scanning-alerts` are opt-in by default in the TUI (they depend on a GitHub plan/feature the org may not have) — pass them explicitly via `--collectors` or enable them in the TUI's collector-selection screen.

```

- [ ] **Step 3: Add GitHub examples to `cli-examples.md`**

Read the file's existing per-provider example format first (`Read cli-examples.md`), then append a `## GitHub` section immediately after the Jira examples section, following the same style — one non-interactive collectors-mode example and one with `--lookback` for the time-windowed collectors:

```markdown
## GitHub

```bash
# Baseline collectors (members, teams, team membership, security settings, repos, branch protection)
grabber --mode collectors --provider github \
  --collectors github-members,github-teams,github-team-members,github-security-settings,github-repos,github-branch-protection \
  --output ./evidence-output/github

# Include audit log + security alerts, last 30 days
grabber --mode collectors --provider github \
  --collectors github-members,github-teams,github-repos,github-branch-protection,github-audit-log,github-dependabot-alerts,github-secret-scanning-alerts,github-code-scanning-alerts \
  --lookback 30d \
  --output ./evidence-output/github
```
```

- [ ] **Step 4: Update `docs/cli-reference.md`**

Line 219, add `github-config.toml` to the merge-file list:

```markdown
Merge inventory from every authenticated AWS account listed in `config.toml` (and every non-AWS account listed in `tenable-config.toml` / `okta-config.toml` / `jira-config.toml` / `github-config.toml`) into a single unified CSV + XLSX, matching the TUI multi-account inventory output. Accounts whose profile cannot resolve an AWS identity (expired SSO, missing credentials) are skipped with a `WARN` and the run continues against the rest.
```

Line 439, add the `github-*` prefix:

```markdown
All 144 AWS collector keys are organized by category below. Pass any combination to `--collectors`. Non-AWS keys are namespaced with their provider prefix (`okta-*`, `jira-*`, `tenable-*`, `github-*`) — see the provider sections in the main [README](../README.md) for the canonical lists.
```

- [ ] **Step 5: Add GitHub rows to `evidence-list.md`**

Find the `### Ticketing — Jira` section (or the section immediately following the last Jira row) and insert a new subsection before whatever comes next, continuing the `EV` numbering from `EV202`:

```markdown
### Source Control — GitHub

| ID | Evidence | Filename Prefix | Key Columns |
|----|----------|-----------------|--------------|
| EV203 | GitHub Org Members | `Github_Org_Members` | Login, User ID, Role, Site Admin, 2FA Disabled |
| EV204 | GitHub Teams | `Github_Teams` | Team ID, Slug, Name, Privacy, Permission, Description |
| EV205 | GitHub Team Members | `Github_Team_Members` | Team Slug, Team Name, Member Login, Member ID |
| EV206 | GitHub Org Security Settings | `Github_Org_Security_Settings` | Org Login, Two-Factor Requirement Enabled, Default Repository Permission, Members Can Create Repositories, Members Can Create Private Repositories |
| EV207 | GitHub Repositories | `Github_Repositories` | Repo ID, Name, Full Name, Visibility, Private, Default Branch, Archived, Created At, Pushed At |
| EV208 | GitHub Branch Protection | `Github_Branch_Protection` | Repository, Branch, Protected, Enforce Admins, Required Approving Review Count, Require Code Owner Reviews, Required Status Checks Strict, Allow Force Pushes |
| EV209 | GitHub Org Audit Log | `Github_Org_Audit_Log` | Action, Actor, User, Org, Created At, Document ID |
| EV210 | GitHub Dependabot Alerts | `Github_Dependabot_Alerts` | Repository, Alert Number, State, Package Ecosystem, Package Name, Severity, GHSA ID, CVE ID, Summary, Created At, Updated At |
| EV211 | GitHub Secret Scanning Alerts | `Github_Secret_Scanning_Alerts` | Repository, Alert Number, State, Secret Type, Secret Type Display Name, Resolution, Push Protection Bypassed, Created At |
| EV212 | GitHub Code Scanning Alerts | `Github_Code_Scanning_Alerts` | Repository, Alert Number, State, Rule ID, Severity, Security Severity Level, Description, Created At |
```

- [ ] **Step 6: Verify the workspace still builds (docs changes don't affect compilation, but confirm nothing else broke)**

Run: `cargo check --workspace --features github`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add README.md cli-examples.md docs/cli-reference.md evidence-list.md
git commit -m "docs(github): document the GitHub provider, collectors, and required token permissions"
```

---

## Final Verification

- [ ] Run the full test suite: `cargo test --workspace --features github`
  Expected: every test in `crates/github-rs/tests/` plus the existing full-repo suite PASS.
- [ ] Run `cargo build --workspace` (default features)
  Expected: PASS — `github` is in `default`, so this exercises the same path a normal `cargo build` would.
- [ ] Manually smoke-test the TUI: `cargo run --features github -- ` (no other flags, launches the interactive wizard), select **Evidence Collection → GitHub**, confirm the provider tile appears, the collector menu shows the three categories from Task 18, and — with a real `github-config.toml` and a valid PAT — at least `github-members` and `github-repos` complete and write CSVs under `evidence-output/github/`.
