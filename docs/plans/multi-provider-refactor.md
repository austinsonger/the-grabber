# Plan: Multi-Provider Architecture

## Current State

88 AWS collector modules live flat in `src/`. The evidence traits (`EvidenceCollector`,
`JsonCollector`, `CsvCollector`) are already provider-agnostic. The `EvidenceSource` enum
has only 4 AWS variants. `app_config` only knows about AWS accounts. There is no `providers/`
directory yet.

### File size audit (lines)

| File | Lines | Status |
|---|---|---|
| `src/main.rs` | 4,146 | Critical — 7+ responsibilities |
| `src/tui/ui.rs` | 3,173 | Critical |
| `src/tui/mod.rs` | 2,275 | Critical |
| `src/inventory_orchestrator.rs` | 1,058 | Oversized |
| `src/inventory_xlsx.rs` | 491 | Oversized |

The 200-line guideline is violated across all five largest files. Phase 4 addresses this
independently of provider work.

---

## Bounded Context Map

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  DOMAIN LAYER  (src/evidence.rs, src/inventory_core.rs)                      │
│  Traits: EvidenceCollector, JsonCollector, CsvCollector                      │
│  Types:  EvidenceRecord, CollectParams, EvidenceSource, CloudProvider     │
│  Rule:   No SDK imports. No framework imports. Pure Rust.                    │
└──────────────┬────────────────────────────┬─────────────────────────────────┘
               │ implements                  │ implements
               ▼                             ▼
┌──────────────────────────┐   ┌─────────────────────────────────────────────────────┐
│  AWS INFRASTRUCTURE      │   │  NON-AWS INFRASTRUCTURE (future)                    │
│  src/providers/aws/      │   │  src/providers/azure/   src/providers/gcp/          │
│  (88 collector modules)  │   │  src/providers/tenable/                             │
│  SDK: aws-sdk-*          │   │  Gated by Cargo features                            │
│                          │   │  azure/gcp: cloud SDKs  tenable: reqwest REST client│
└──────────────┬───────────┘   └──────────────────────────────┬──────────────────────┘
               │                                               │
               └────────────────────┬──────────────────────────┘
                                    │ registered by
                                    ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│  APPLICATION LAYER  (src/runner/, src/cli.rs, src/aws_loader.rs)            │
│  Wires collectors → execution → output.                                      │
│  No SDK calls. No collection logic. No UI rendering.                         │
└──────────────────────────────┬───────────────────────────────────────────────┘
                                │ drives
                                ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│  PRESENTATION LAYER  (src/tui/)                                              │
│  Renders progress, feature selection, results.                               │
│  Communicates with Application via Progress channel only.                    │
└──────────────────────────────────────────────────────────────────────────────┘
```

**Rule:** Dependencies flow downward only. Domain has no imports from any other layer.
Infrastructure knows about Domain but not Application or Presentation. Application imports
Domain and Infrastructure but not Presentation. Presentation imports Application types only
through channel messages.

The `ProviderFactory` trait lives in the Domain layer (it references only domain traits).
Each provider's `factory.rs` lives in its Infrastructure module. The Application layer
calls `ProviderFactory` methods — it never imports an AWS/Azure/GCP/Tenable SDK directly.

---

## Provider Abstraction Model

### Design goal

> Any security data source — cloud platform, security scanner, SIEM, or SaaS tool —
> should be addable to grabber by touching at most four files and writing one new
> module. No existing file should need to be edited just because a new provider exists.

This goal is achieved through a **`ProviderFactory` trait** that is the single contract
every provider fulfills. The application layer asks factories for collectors; it never
needs to know which provider it is talking to.

---

### The four providers (current scope)

| Provider | Type | Auth model | Transport | Cargo feature |
|---|---|---|---|---|
| **AWS** | Cloud platform | IAM profile / role assumption | `aws-sdk-*` (built-in) | *(default — always on)* |
| **Azure** | Cloud platform | Service principal / workload identity | `azure_identity` SDK | `azure` |
| **GCP** | Cloud platform | Service account / workload identity | `google-cloud-auth` SDK | `gcp` |
| **Tenable** | Security platform | API key pair (`X-ApiKeys` header) | `tenable-rs` (custom crate, REST) | `tenable` |

Each provider lives in its own module under `src/providers/<name>/` and is compiled
only when its feature flag is enabled. **AWS is always compiled** — it is the default
and requires no feature flag.

---

### `ProviderFactory` — the universal provider contract

Every provider exposes one struct that implements this trait. The application layer
only ever calls this trait; it imports nothing provider-specific.

```rust
// src/providers/mod.rs  (alongside CloudProvider)

use async_trait::async_trait;
use anyhow::Result;
use crate::evidence::{CsvCollector, EvidenceCollector, JsonCollector};

/// A provider factory resolves credentials, constructs all SDK/HTTP clients for its
/// provider, and hands back ready-to-run collectors grouped by output type.
///
/// Implementing this trait is the entire contract for registering a new provider.
#[async_trait]
pub trait ProviderFactory: Send + Sync {
    /// The provider variant this factory represents.
    fn provider(&self) -> CloudProvider;

    /// The account/project/site identifier used to prefix output filenames.
    /// AWS: account ID   Azure: subscription ID   GCP: project ID   Tenable: site name
    fn account_id(&self) -> &str;

    /// Region, location, or scope label used in report metadata and output paths.
    /// Providers without a region concept (Tenable) return an empty string.
    fn region(&self) -> &str;

    /// Point-in-time CSV snapshot collectors (current resource state).
    fn csv_collectors(&self) -> Vec<Box<dyn CsvCollector>>;

    /// Structured JSON snapshot collectors (policy documents, configs).
    fn json_collectors(&self) -> Vec<Box<dyn JsonCollector>>;

    /// Time-windowed evidence collectors (event logs, findings).
    fn evidence_collectors(&self) -> Vec<Box<dyn EvidenceCollector>>;
}
```

#### Per-provider factory structs

```
src/providers/
├── mod.rs                     CloudProvider enum + ProviderFactory trait
├── aws/
│   └── factory.rs             AwsProviderFactory { sdk_config, account_id, region, selected }
├── azure/
│   └── factory.rs             AzureProviderFactory { credential, subscription_id, region, selected }
├── gcp/
│   └── factory.rs             GcpProviderFactory { credential, project_id, region, selected }
└── tenable/
    └── factory.rs             TenableProviderFactory { client, site_name, selected }
```

Each `factory.rs` is the only file that imports provider-specific SDKs. Everything
above the factory layer is SDK-free.

#### Factory signatures (one per provider)

```rust
// AWS
impl AwsProviderFactory {
    pub fn new(config: aws_config::SdkConfig, account_id: String,
               region: String, selected: Vec<String>) -> Self { ... }
}

// Azure  (#[cfg(feature = "azure")])
impl AzureProviderFactory {
    pub fn new(credential: Arc<dyn azure_identity::TokenCredential>,
               subscription_id: String, region: String, selected: Vec<String>) -> Self { ... }
}

// GCP  (#[cfg(feature = "gcp")])
impl GcpProviderFactory {
    pub fn new(credential: google_cloud_auth::Token,
               project_id: String, region: String, selected: Vec<String>) -> Self { ... }
}

// Tenable  (#[cfg(feature = "tenable")])
impl TenableProviderFactory {
    pub fn new(client: tenable_rs::TenableClient,
               site_name: String, selected: Vec<String>) -> Self { ... }
}
```

---

### `CollectorRegistry` — the application-layer aggregator

Once all factories are built, they are registered into a `CollectorRegistry`. The
runner only ever talks to the registry — it has zero provider-specific code.

```rust
// src/runner/collector_registry.rs

pub struct CollectorRegistry {
    factories: Vec<Box<dyn ProviderFactory>>,
}

impl CollectorRegistry {
    pub fn new() -> Self { Self { factories: Vec::new() } }

    pub fn register(&mut self, factory: impl ProviderFactory + 'static) {
        self.factories.push(Box::new(factory));
    }

    pub fn csv_collectors(&self) -> Vec<Box<dyn CsvCollector>> {
        self.factories.iter().flat_map(|f| f.csv_collectors()).collect()
    }
    pub fn json_collectors(&self) -> Vec<Box<dyn JsonCollector>> {
        self.factories.iter().flat_map(|f| f.json_collectors()).collect()
    }
    pub fn evidence_collectors(&self) -> Vec<Box<dyn EvidenceCollector>> {
        self.factories.iter().flat_map(|f| f.evidence_collectors()).collect()
    }
}
```

#### How `async_main` builds the registry (after Phase 4)

```rust
// src/main.rs  (~80 lines after Phase 4)

let mut registry = CollectorRegistry::new();

// AWS — always registered
registry.register(AwsProviderFactory::new(aws_config, account_id, region, selected.clone()));

// Azure — compiled only with --features azure
#[cfg(feature = "azure")]
if let Some(az) = azure_account {
    let cred = azure_identity::DefaultAzureCredential::default();
    registry.register(AzureProviderFactory::new(Arc::new(cred),
        az.subscription_id.clone(), az.region.clone(), selected.clone()));
}

// GCP — compiled only with --features gcp
#[cfg(feature = "gcp")]
if let Some(gcp) = gcp_account {
    registry.register(GcpProviderFactory::new(gcp_token,
        gcp.project_id.clone(), gcp.region.clone(), selected.clone()));
}

// Tenable — compiled only with --features tenable
#[cfg(feature = "tenable")]
if let Some(t) = tenable_account {
    let client = TenableClient::from_account(&t)?;
    registry.register(TenableProviderFactory::new(client,
        t.name.clone(), selected.clone()));
}

// Hand the registry to the runner — no provider logic beyond this point
runner::run(registry, params, tx).await?;
```

Adding a fifth provider means: add one `register()` block here and write one
`ProviderFactory` impl. The runner, TUI, output layer, and all existing providers
are untouched.

---

### Provider comparison: what each one looks like when complete

| Concern | AWS | Azure | GCP | Tenable |
|---|---|---|---|---|
| **Feature flag** | *(none)* | `azure` | `gcp` | `tenable` |
| **Credential source** | `~/.aws/credentials` / role ARN / env | env / workload identity / CLI | env / workload identity / `gcloud` | `tenable_access_key` + `tenable_secret_key` in config or env |
| **SDK / transport** | `aws-sdk-*` | `azure_identity` + `azure_mgmt_*` | `google-cloud-auth` | `tenable-rs` (custom, REST) |
| **Client reuse** | `SdkConfig` cloned per collector | `Arc<dyn TokenCredential>` shared | Token shared | `TenableClient` cloned (arc pool) |
| **Bulk data pattern** | paginated list APIs | paginated / event export | paginated / Pub/Sub export | async export job → poll → chunks |
| **Region concept** | `us-east-1`, multi-region scans | Azure location (`eastus`) | GCP region (`us-central1`) | none (global) |
| **Account identifier** | 12-digit account ID | subscription UUID | project ID string | site name from config |
| **`EvidenceSource` prefix** | *(existing)* | `Azure*` | `Gcp*` | `Tenable*` |

---

### Checklist: adding a brand-new provider

These are the complete, exhaustive steps. No step outside this list should ever be
needed.

**In the monorepo:**
- [ ] `cargo new --lib crates/<provider>-rs` if a custom SDK crate is needed (as with Tenable)
- [ ] Add `<provider>-rs = { path = "crates/<provider>-rs", optional = true }` to root `Cargo.toml`
- [ ] Add `<provider> = ["dep:<provider>-rs"]` to `[features]`

**In `src/providers/`:**
- [ ] `mkdir src/providers/<provider>`
- [ ] Create `src/providers/<provider>/mod.rs` (submodule stubs + service mapping comments)
- [ ] Create `src/providers/<provider>/factory.rs` implementing `ProviderFactory`
- [ ] Add `pub mod <provider>;` to `src/providers/mod.rs` inside `#[cfg(feature = "<provider>")]`
- [ ] Add variant to `CloudProvider` enum in `src/providers/mod.rs`

**In `src/evidence.rs`:**
- [ ] Add `<Provider>*` variants to `EvidenceSource` as new data is collected

**In `src/app_config.rs`:**
- [ ] Add credential fields for the new provider to `Account`
- [ ] Add env-var fallback pattern for any sensitive fields

**In `src/main.rs` (or `src/runner/collector_registry.rs` after Phase 4):**
- [ ] Add one `#[cfg(feature = "<provider>")] registry.register(...)` block

**No other files change.**

---

## Phases Overview

### Phase sequence

| Phase | What | Risk | Enables |
|---|---|---|---|
| **0** | `CloudProvider` enum · `ProviderFactory` trait · workspace conversion · Cargo feature flags | Zero — additive only | The stable contract all providers implement |
| **1** | Provider module stubs (`azure/`, `gcp/`, `tenable/`) · `EvidenceSource` variants | Zero — no existing files move | Collector development can start in any provider module |
| **1.5** | `app_config` multi-provider credentials · env-var fallback | Low — additive, backward-compatible | Loading credentials for Azure, GCP, Tenable from config |
| **2** | Move 88 AWS files into `src/providers/aws/` · create `AwsProviderFactory` | Medium — mechanical; many import paths change | Full provider symmetry; AWS as first `ProviderFactory` impl |
| **3** | TUI provider routing · per-provider badges · output filename prefix | Low — isolated to `tui/` | TUI shows all four providers in the collector list |
| **4** | Application layer decomposition (`main.rs` → `runner/` · `tui/` → screens) | Medium — no behavior change; many files created | `main.rs` becomes the thin wire-up described in the abstraction model |

### Target state (all phases complete)

```
Four live providers: AWS · Azure · GCP · Tenable
Adding a fifth provider: 8 checklist items, 0 existing-file edits outside app_config + main.rs
main.rs: ~80 lines
Largest file: under 200 lines
```

---

## Phase 0 — `CloudProvider` Foundation

> **Naming:** The original name `CloudProvider` is no longer accurate now that Tenable
> (a security platform, not a cloud) is a supported provider. The enum is renamed to
> `CloudProvider`. All references throughout `providers/mod.rs`, `app_config.rs`,
> `evidence.rs`, and `tui/` use the new name from the start.

Phase 0 creates the two building blocks everything else depends on: the `CloudProvider`
enum and the `ProviderFactory` trait. It also converts the project to a Cargo workspace
and adds the feature flags. No existing behavior changes.

### `src/providers/mod.rs`

```rust
pub mod aws;

#[cfg(feature = "azure")]
pub mod azure;

#[cfg(feature = "gcp")]
pub mod gcp;

#[cfg(feature = "tenable")]
pub mod tenable;

use std::fmt;
use async_trait::async_trait;
use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::evidence::{CsvCollector, EvidenceCollector, JsonCollector};

// ---------------------------------------------------------------------------
// CloudProvider — identifies which system a collector belongs to
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CloudProvider {
    Aws,
    Azure,
    Gcp,
    Tenable,
}

impl fmt::Display for CloudProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CloudProvider::Aws     => write!(f, "AWS"),
            CloudProvider::Azure   => write!(f, "Azure"),
            CloudProvider::Gcp     => write!(f, "GCP"),
            CloudProvider::Tenable => write!(f, "Tenable"),
        }
    }
}

// ---------------------------------------------------------------------------
// ProviderFactory — the single contract every provider must implement
// ---------------------------------------------------------------------------

/// Implement this trait once per provider.  The application layer calls these
/// methods to obtain collectors; it never imports provider-specific SDKs.
pub trait ProviderFactory: Send + Sync {
    fn provider(&self)   -> CloudProvider;
    fn account_id(&self) -> &str;
    fn region(&self)     -> &str;

    fn csv_collectors(&self)      -> Vec<Box<dyn CsvCollector>>;
    fn json_collectors(&self)     -> Vec<Box<dyn JsonCollector>>;
    fn evidence_collectors(&self) -> Vec<Box<dyn EvidenceCollector>>;
}
```

`Display` drives TUI labels, filename prefixes (`AWS_`, `Azure_`, `GCP_`, `Tenable_`),
and report metadata. `Serialize`/`Deserialize` lets it appear cleanly in JSON output
and `app_config` TOML.

### `src/providers/aws/factory.rs` (stub — filled out in Phase 2)

```rust
use crate::evidence::{CsvCollector, EvidenceCollector, JsonCollector};
use crate::providers::{CloudProvider, ProviderFactory};

pub struct AwsProviderFactory {
    config:       aws_config::SdkConfig,
    account_id:   String,
    region:       String,
    selected:     Vec<String>,
}

impl AwsProviderFactory {
    pub fn new(config: aws_config::SdkConfig, account_id: String,
               region: String, selected: Vec<String>) -> Self {
        Self { config, account_id, region, selected }
    }
}

impl ProviderFactory for AwsProviderFactory {
    fn provider(&self)   -> CloudProvider { CloudProvider::Aws }
    fn account_id(&self) -> &str             { &self.account_id }
    fn region(&self)     -> &str             { &self.region }

    fn csv_collectors(&self)      -> Vec<Box<dyn CsvCollector>>      { todo!("Phase 2") }
    fn json_collectors(&self)     -> Vec<Box<dyn JsonCollector>>     { todo!("Phase 2") }
    fn evidence_collectors(&self) -> Vec<Box<dyn EvidenceCollector>> { todo!("Phase 2") }
}
```

### `src/main.rs` addition

Append one line to the existing `mod` block (after line 91):

```rust
mod providers;
```

### `Cargo.toml` — workspace conversion + optional feature flags

Grabber is currently a single-package project. Adding the Tenable SDK crate requires
converting it to a **Cargo workspace**. The root package (`src/`, `[[bin]]`) stays exactly
where it is — **no files move**. The workspace declaration is prepended to the existing
`Cargo.toml`.

**The only change to the existing `Cargo.toml`:**

```toml
# Cargo.toml  (prepend this block — everything else is unchanged)
[workspace]
members  = [".", "crates/tenable-rs"]
resolver = "2"

# ---------- everything below this line is the existing [package] / [dependencies] ----------
[package]
name    = "the-grabber"
version = "0.1.0"
# ... unchanged ...
```

The `.` member means the root package is also a workspace member — `src/main.rs` stays at
`src/main.rs`, all existing build commands continue to work.

**Add the Tenable feature flag to the existing `[features]` / `[dependencies]` blocks:**

```toml
[features]
default = []
azure   = ["dep:azure_identity", "dep:azure_mgmt_monitor", "dep:azure_mgmt_resources"]
gcp     = ["dep:google-cloud-auth"]
tenable = ["dep:tenable-rs"]          # ← add this line

[dependencies]
# ... all existing aws-sdk-* deps unchanged ...

# Azure — only compiled with `--features azure`
azure_identity        = { version = "0.20", optional = true }
azure_mgmt_monitor    = { version = "0.20", optional = true }
azure_mgmt_resources  = { version = "0.20", optional = true }

# GCP — only compiled with `--features gcp`
google-cloud-auth = { version = "0.7", optional = true }

# Tenable — only compiled with `--features tenable`
tenable-rs = { path = "crates/tenable-rs", optional = true }   # ← add this line
```

**Build commands (unchanged from user perspective):**
```sh
cargo build                                   # AWS only (unchanged)
cargo build --features azure                  # AWS + Azure
cargo build --features azure,gcp             # AWS + Azure + GCP
cargo build --features tenable               # AWS + Tenable SDK
cargo build --features azure,gcp,tenable     # all four

# Target the binary package explicitly from workspace root
cargo build -p the-grabber --features tenable
# Or build just the SDK in isolation
cargo build -p tenable-rs
cargo test  -p tenable-rs
```

---

## Tenable Rust SDK Crate (`tenable-rs`)

> **When to build:** Before writing any Tenable collector in `src/providers/tenable/`.
> The SDK crate is the stable API boundary; collectors never touch `reqwest` directly.

### Purpose and scope

`tenable-rs` is a standalone async Rust client for the Tenable REST API. It covers both
**Tenable.io** (cloud-hosted, `https://cloud.tenable.com`) and **Tenable.sc**
(on-premises Security Center, configurable base URL). Grabber depends on it as a local
workspace crate but it is designed to be publishable to crates.io independently.

### Monorepo layout

```
grabber/                         ← repo root (workspace root + binary package)
├── Cargo.toml                   # [workspace] + [package] for the-grabber
├── Cargo.lock
├── src/                         # binary source — nothing moves
│   ├── main.rs
│   ├── evidence.rs
│   ├── providers/
│   │   └── tenable/             # grabber's collectors, depend on tenable-rs
│   └── ...
└── crates/
    └── tenable-rs/              # the standalone Rust SDK crate
        ├── Cargo.toml
        └── src/
            ├── lib.rs           # re-exports: TenableClient, Error, api::*, types::*
            ├── client.rs        # TenableClient, auth header injection, base URL, rate-limit retry
            ├── error.rs         # TenableError enum (Api, Auth, RateLimit, Transport, Parse)
            ├── export.rs        # shared export-job abstraction (poll + chunk download)
            ├── api/
            │   ├── mod.rs
            │   ├── vulns.rs     # /vulns/export  — async export of vulnerability findings
            │   ├── assets.rs    # /assets/export — async export of asset inventory
            │   ├── scans.rs     # /scans         — scan history, scan details
            │   ├── audit_log.rs # /audit-log/events
            │   └── compliance.rs# /compliance/export
            └── types/
                ├── mod.rs
                ├── vulnerability.rs  # VulnFinding, Severity, Plugin, Asset ref
                ├── asset.rs          # AssetRecord, Fqdn, NetworkInterface, Tags
                ├── scan.rs           # ScanSummary, ScanDetails, ScanStatus
                ├── audit.rs          # AuditEvent, Actor, Target
                └── compliance.rs     # ComplianceFinding, CheckStatus, Policy
```

### `crates/tenable-rs/Cargo.toml`

```toml
[package]
name        = "tenable-rs"
version     = "0.1.0"
edition     = "2021"
description = "Async Rust client for the Tenable.io and Tenable.sc REST APIs"
license     = "MIT OR Apache-2.0"
repository  = "https://github.com/your-org/grabber"   # update when published

[dependencies]
reqwest   = { version = "0.12", features = ["json", "rustls-tls"], default-features = false }
serde     = { version = "1", features = ["derive"] }
serde_json = "1"
tokio     = { version = "1", features = ["time"] }    # for sleep in rate-limit backoff
thiserror = "2"
anyhow    = "1"

[dev-dependencies]
tokio     = { version = "1", features = ["full"] }
wiremock  = "0.6"    # for HTTP mock tests
```

### Public API surface

```rust
// crates/tenable-rs/src/lib.rs
pub use client::{TenableClient, TenableClientBuilder};
pub use error::TenableError;
pub mod api;
pub mod types;
```

```rust
// crates/tenable-rs/src/client.rs

pub struct TenableClient {
    http:     reqwest::Client,
    base_url: String,
}

impl TenableClient {
    /// Tenable.io — uses https://cloud.tenable.com
    pub fn tenable_io(access_key: &str, secret_key: &str) -> Result<Self, TenableError> { ... }

    /// Tenable.sc — supply your on-premises base URL
    pub fn tenable_sc(base_url: &str, access_key: &str, secret_key: &str) -> Result<Self, TenableError> { ... }

    /// Access API groups
    pub fn vulns(&self)      -> api::VulnsApi<'_>      { api::VulnsApi(self) }
    pub fn assets(&self)     -> api::AssetsApi<'_>     { api::AssetsApi(self) }
    pub fn scans(&self)      -> api::ScansApi<'_>      { api::ScansApi(self) }
    pub fn audit_log(&self)  -> api::AuditLogApi<'_>   { api::AuditLogApi(self) }
    pub fn compliance(&self) -> api::ComplianceApi<'_> { api::ComplianceApi(self) }
}
```

```rust
// crates/tenable-rs/src/error.rs

#[derive(Debug, thiserror::Error)]
pub enum TenableError {
    #[error("HTTP transport error: {0}")]
    Transport(#[from] reqwest::Error),

    #[error("API error {status}: {message}")]
    Api { status: u16, message: String },

    #[error("authentication failed — check access_key and secret_key")]
    Auth,

    #[error("rate limited — retry after {retry_after_secs}s")]
    RateLimit { retry_after_secs: u64 },

    #[error("export job failed with status: {status}")]
    ExportFailed { status: String },

    #[error("JSON parse error: {0}")]
    Parse(#[from] serde_json::Error),
}
```

```rust
// crates/tenable-rs/src/export.rs
// Shared pattern: POST export → poll status → stream chunks
// All three bulk APIs (vulns, assets, compliance) use this same flow.

pub struct ExportJob<T> {
    client: TenableClient,
    export_uuid: String,
    _phantom: std::marker::PhantomData<T>,
}

impl<T: serde::de::DeserializeOwned> ExportJob<T> {
    /// Poll until ready, then download and deserialize all chunks.
    pub async fn collect_all(self) -> Result<Vec<T>, TenableError> { ... }

    /// Stream chunks one at a time (lower peak memory for large exports).
    pub async fn chunks(self) -> impl futures::Stream<Item = Result<Vec<T>, TenableError>> { ... }
}
```

```rust
// crates/tenable-rs/src/api/vulns.rs  (example API group)

pub struct VulnsApi<'c>(pub(crate) &'c TenableClient);

impl<'c> VulnsApi<'c> {
    /// Start a vulnerability export.  `filters` follows the Tenable export filter schema.
    pub async fn export(
        &self,
        filters: Option<serde_json::Value>,
    ) -> Result<ExportJob<VulnFinding>, TenableError> { ... }

    /// Convenience: export and collect in one call.
    pub async fn export_all(
        &self,
        filters: Option<serde_json::Value>,
    ) -> Result<Vec<VulnFinding>, TenableError> {
        self.export(filters).await?.collect_all().await
    }
}
```

### Rate-limit handling

Tenable.io enforces per-minute rate limits and returns `429 Too Many Requests` with a
`Retry-After` header. The SDK handles this transparently in the HTTP layer:

```rust
// Pattern inside client's request dispatcher
if response.status() == 429 {
    let retry_after = response.headers()
        .get("Retry-After")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(60);
    tokio::time::sleep(Duration::from_secs(retry_after)).await;
    // retry once
}
```

Grabber collectors never see 429s — the SDK absorbs them.

### How grabber collectors use the SDK

```rust
// src/providers/tenable/vulnerabilities.rs  (grabber crate)
// Requires: --features tenable

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;

use tenable_rs::TenableClient;
use crate::evidence::JsonCollector;

pub struct VulnerabilitiesCollector {
    client: TenableClient,  // cheaply cloneable arc-wrapped client
}

impl VulnerabilitiesCollector {
    pub fn new(client: TenableClient) -> Self { Self { client } }
}

#[async_trait]
impl JsonCollector for VulnerabilitiesCollector {
    fn name(&self) -> &str { "Tenable Vulnerabilities" }
    fn filename_prefix(&self) -> &str { "Tenable_Vulnerabilities" }

    async fn collect_records(&self, _account_id: &str, _region: &str) -> Result<Vec<Value>> {
        let findings = self.client.vulns().export_all(None).await?;
        Ok(findings.into_iter()
            .map(|f| serde_json::to_value(f).unwrap())
            .collect())
    }
}
```

The collector is 20 lines. All HTTP, polling, chunking, and rate-limit logic lives in
`tenable-rs`, not in grabber.

### Publishing strategy

The crate ships as a local path dep first:
```toml
tenable-rs = { path = "../crates/tenable-rs", optional = true }
```

When the API is stable, publish to crates.io:
```toml
tenable-rs = { version = "0.1", optional = true }
```

No changes needed in `src/providers/tenable/` — the import path is the same either way.

---

## Phase 1 — Provider Stubs + `EvidenceSource` variants

Zero existing files move. Only additions and small edits.

### Files created / changed

| File | Action |
|---|---|
| `src/providers/mod.rs` | **Create** — see Phase 0 above |
| `src/providers/aws/mod.rs` | **Create** — stub (collectors arrive in Phase 2) |
| `src/providers/aws/factory.rs` | **Create** — `AwsProviderFactory` stub (see Phase 0) |
| `src/providers/azure/mod.rs` | **Create** — collector stubs |
| `src/providers/azure/factory.rs` | **Create** — `AzureProviderFactory` stub |
| `src/providers/gcp/mod.rs` | **Create** — collector stubs |
| `src/providers/gcp/factory.rs` | **Create** — `GcpProviderFactory` stub |
| `src/providers/tenable/mod.rs` | **Create** — collector stubs |
| `src/providers/tenable/factory.rs` | **Create** — `TenableProviderFactory` stub |
| `src/main.rs` | Add `mod providers;` |
| `src/evidence.rs` | Add Azure/GCP/Tenable variants to `EvidenceSource` |

### `src/providers/azure/mod.rs`

```rust
// Azure collector submodules go here, e.g.:
//   pub mod activity_log;
//   pub mod defender;
//   pub mod entra_id;
//   pub mod key_vault;
//   pub mod storage;
//   pub mod virtual_machines;
//   pub mod policy;
//
// Azure → AWS service equivalents:
//   activity_log      → CloudTrail
//   defender          → SecurityHub / GuardDuty
//   entra_id          → IAM
//   key_vault         → KMS / SecretsManager
//   storage           → S3
//   virtual_machines  → EC2
//   policy            → AWS Config / SCPs
```

### `src/providers/gcp/mod.rs`

```rust
// GCP collector submodules go here, e.g.:
//   pub mod cloud_audit_logs;
//   pub mod security_command_center;
//   pub mod iam;
//   pub mod cloud_kms;
//   pub mod cloud_storage;
//   pub mod compute;
//   pub mod cloud_logging;
//
// GCP → AWS service equivalents:
//   cloud_audit_logs          → CloudTrail
//   security_command_center   → SecurityHub / GuardDuty
//   iam                       → IAM
//   cloud_kms                 → KMS
//   cloud_storage             → S3
//   compute                   → EC2
//   cloud_logging             → CloudWatch Logs
```

### `src/providers/azure/factory.rs` (stub)

```rust
// #[cfg(feature = "azure")]
use crate::evidence::{CsvCollector, EvidenceCollector, JsonCollector};
use crate::providers::{CloudProvider, ProviderFactory};

pub struct AzureProviderFactory {
    subscription_id: String,
    region:          String,
    selected:        Vec<String>,
    // credential: Arc<dyn azure_identity::TokenCredential>  — added when first collector ships
}

impl ProviderFactory for AzureProviderFactory {
    fn provider(&self)   -> CloudProvider { CloudProvider::Azure }
    fn account_id(&self) -> &str             { &self.subscription_id }
    fn region(&self)     -> &str             { &self.region }

    fn csv_collectors(&self)      -> Vec<Box<dyn CsvCollector>>      { vec![] }
    fn json_collectors(&self)     -> Vec<Box<dyn JsonCollector>>     { vec![] }
    fn evidence_collectors(&self) -> Vec<Box<dyn EvidenceCollector>> { vec![] }
}
```

### `src/providers/gcp/factory.rs` (stub)

```rust
// #[cfg(feature = "gcp")]
use crate::evidence::{CsvCollector, EvidenceCollector, JsonCollector};
use crate::providers::{CloudProvider, ProviderFactory};

pub struct GcpProviderFactory {
    project_id: String,
    region:     String,
    selected:   Vec<String>,
    // credential: google_cloud_auth::Token  — added when first collector ships
}

impl ProviderFactory for GcpProviderFactory {
    fn provider(&self)   -> CloudProvider { CloudProvider::Gcp }
    fn account_id(&self) -> &str             { &self.project_id }
    fn region(&self)     -> &str             { &self.region }

    fn csv_collectors(&self)      -> Vec<Box<dyn CsvCollector>>      { vec![] }
    fn json_collectors(&self)     -> Vec<Box<dyn JsonCollector>>     { vec![] }
    fn evidence_collectors(&self) -> Vec<Box<dyn EvidenceCollector>> { vec![] }
}
```

### `src/providers/tenable/mod.rs`

```rust
// Tenable collector submodules go here, e.g.:
//   pub mod vulnerabilities;
//   pub mod assets;
//   pub mod scans;
//   pub mod audit_log;
//   pub mod compliance;
//   pub mod plugins;
//
// Tenable → AWS service equivalents:
//   vulnerabilities   → Inspector2 / SecurityHub findings
//   assets            → EC2 inventory / resource tagging
//   scans             → Inspector scan history
//   audit_log         → CloudTrail
//   compliance        → AWS Config rules / Security Hub standards
//   plugins           → Inspector rule packages
//
// Authentication:
//   Tenable.io  — X-ApiKeys header: "accessKey=<key>; secretKey=<key>"
//   Tenable.sc  — X-SecurityCenter-Token or username/password session
//
// Base URLs:
//   Tenable.io  — https://cloud.tenable.com  (fixed)
//   Tenable.sc  — configurable (on-premises deployment)
```

### `src/providers/tenable/factory.rs` (stub)

```rust
// #[cfg(feature = "tenable")]
use tenable_rs::TenableClient;
use crate::evidence::{CsvCollector, EvidenceCollector, JsonCollector};
use crate::providers::{CloudProvider, ProviderFactory};

pub struct TenableProviderFactory {
    client:    TenableClient,
    site_name: String,
    selected:  Vec<String>,
}

impl TenableProviderFactory {
    pub fn new(client: TenableClient, site_name: String, selected: Vec<String>) -> Self {
        Self { client, site_name, selected }
    }
}

impl ProviderFactory for TenableProviderFactory {
    fn provider(&self)   -> CloudProvider { CloudProvider::Tenable }
    fn account_id(&self) -> &str             { &self.site_name }
    fn region(&self)     -> &str             { "" }   // Tenable has no region concept

    fn csv_collectors(&self)      -> Vec<Box<dyn CsvCollector>>      { vec![] }
    fn json_collectors(&self)     -> Vec<Box<dyn JsonCollector>>     { vec![] }
    fn evidence_collectors(&self) -> Vec<Box<dyn EvidenceCollector>> { vec![] }
}
```

As each Tenable collector module is written, its stub is replaced:

```rust
// Once vulnerabilities.rs is written:
fn json_collectors(&self) -> Vec<Box<dyn JsonCollector>> {
    if self.selected.iter().any(|s| s == "tenable-vulns") {
        vec![Box::new(VulnerabilitiesCollector::new(self.client.clone()))]
    } else {
        vec![]
    }
}
```

### `src/evidence.rs` — `EvidenceSource` diff

```rust
// BEFORE
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSource {
    CloudTrail,
    BackupApi,
    RdsApi,
    CloudTrailS3,
}

// AFTER
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
}
```

No existing serialized output changes — only new variants are added.

---

## Phase 1.5 — Multi-Provider Credential Support in `app_config`

Required before any non-AWS collector can be registered. Currently `Account` in
`src/app_config.rs` has only AWS fields (profile, role ARN, region). Non-AWS accounts
need different credential fields.

### Strategy: tagged union in TOML

```toml
# ~/.config/grabber/config.toml

[[accounts]]
name = "prod-aws"
provider = "aws"
profile = "prod"
region = "us-east-1"

[[accounts]]
name = "prod-azure"
provider = "azure"
tenant_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
subscription_id = "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy"
# credential resolution order: env AZURE_CLIENT_ID/SECRET, workload identity, CLI

[[accounts]]
name = "prod-gcp"
provider = "gcp"
project_id = "my-project-123"
# credential resolution order: GOOGLE_APPLICATION_CREDENTIALS, workload identity, gcloud CLI

# Tenable.io (cloud-hosted)
[[accounts]]
name = "tenable-io"
provider = "tenable"
tenable_access_key = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
tenable_secret_key = "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy"
# tenable_url is omitted → defaults to https://cloud.tenable.com

# Tenable.sc (on-premises Security Center)
[[accounts]]
name = "tenable-sc-prod"
provider = "tenable"
tenable_url = "https://sc.internal.example.com"
tenable_access_key = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
tenable_secret_key = "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy"
```

> **Credential sensitivity:** `tenable_access_key` and `tenable_secret_key` can also be
> supplied via environment variables `TENABLE_ACCESS_KEY` and `TENABLE_SECRET_KEY` so that
> keys are never written to disk. If both TOML and env vars are present, env vars win.

### `app_config.rs` change

Add a `provider` field and credential variants:

```rust
use crate::providers::CloudProvider;

#[derive(Debug, Clone, Deserialize)]
pub struct Account {
    pub name: String,
    #[serde(default = "default_provider")]
    pub provider: CloudProvider,

    // AWS fields (ignored for non-AWS)
    pub profile: Option<String>,
    pub role_arn: Option<String>,
    pub region: Option<String>,

    // Azure fields
    pub tenant_id: Option<String>,
    pub subscription_id: Option<String>,

    // GCP fields
    pub project_id: Option<String>,

    // Tenable fields (Tenable.io and Tenable.sc share the same key format)
    pub tenable_access_key: Option<String>,
    pub tenable_secret_key: Option<String>,
    /// Defaults to "https://cloud.tenable.com" when absent (Tenable.io).
    /// Set to your Tenable.sc base URL for on-premises deployments.
    pub tenable_url: Option<String>,
}

fn default_provider() -> CloudProvider {
    CloudProvider::Aws
}
```

Existing TOML files with no `provider` key default to `Aws` — zero migration needed.

### Error handling for unconfigured providers

When a non-AWS collector is instantiated without the required credential fields, return a
descriptive error at collection time rather than panicking:

```rust
// Pattern inside a Tenable collector's `new()`:
pub fn new(account: &Account) -> Result<Self> {
    let access_key = std::env::var("TENABLE_ACCESS_KEY")
        .ok()
        .or_else(|| account.tenable_access_key.clone())
        .ok_or_else(|| anyhow::anyhow!(
            "Tenable collector requires tenable_access_key in config or TENABLE_ACCESS_KEY env var"
        ))?;
    let secret_key = std::env::var("TENABLE_SECRET_KEY")
        .ok()
        .or_else(|| account.tenable_secret_key.clone())
        .ok_or_else(|| anyhow::anyhow!(
            "Tenable collector requires tenable_secret_key in config or TENABLE_SECRET_KEY env var"
        ))?;
    let base_url = account.tenable_url
        .clone()
        .unwrap_or_else(|| "https://cloud.tenable.com".to_string());
    // ...
}
```

---

## Phase 2 — AWS Provider Completion (deferred)

Phase 2 does two things together because they touch the same files:

1. **Move** 88 AWS collector modules into `src/providers/aws/` (mechanical, no logic changes)
2. **Implement** `AwsProviderFactory` — replace the `todo!()` stubs with the actual
   `build_csv_collectors` / `build_json_collectors` / `build_evidence_collectors` logic
   extracted from `main.rs`

After Phase 2, AWS is the first fully working `ProviderFactory` implementation. The
`build_*` functions in `main.rs` are deleted — the factory takes over.

### Prerequisites

Phase 0 and Phase 1 must be complete and on a green `cargo build`.

### Files changed

| File | Action |
|---|---|
| `src/providers/aws/mod.rs` | **Create** — 88 `pub mod` declarations |
| `src/providers/aws/*.rs` | **Move** — `git mv src/<name>.rs src/providers/aws/<name>.rs` |
| `src/main.rs` | Remove 88 `mod` declarations; replace `mod providers;` with nothing (providers handles it); update ~120 `use crate::` imports |
| `src/tui/mod.rs` / `src/tui/ui.rs` | Update any `use crate::` imports that reference moved modules |

### Migration script

Run from repo root after verifying Phase 1 is green:

```sh
#!/usr/bin/env bash
set -euo pipefail

mkdir -p src/providers/aws

# Move all non-special collector files
for f in src/*.rs; do
  base=$(basename "$f" .rs)
  case "$base" in
    main|evidence|providers|app_config|audit_log|inventory_core|inventory_orchestrator|inventory_xlsx|poam|signing|zip_bundle)
      # Keep these in src/ — they are infrastructure, not collectors
      ;;
    tui)
      # Directory module — skip
      ;;
    *)
      git mv "$f" "src/providers/aws/${base}.rs"
      ;;
  esac
done
```

After running, create `src/providers/aws/mod.rs` from the list of moved files:

```sh
ls src/providers/aws/*.rs \
  | sed 's|src/providers/aws/||;s|\.rs||' \
  | sort \
  | sed 's/^/pub mod /' \
  | sed 's/$/ ;/' \
  > src/providers/aws/mod.rs
```

Add `pub mod aws;` to `src/providers/mod.rs`.

### Import path update

After moving files, fix all `use crate::<name>` references in `main.rs` and `tui/`:

```sh
# Dry-run — shows what would change
grep -rn 'use crate::' src/main.rs src/tui/ | head -30

# Replace (adjust the sed pattern to match your shell)
sed -i '' 's|use crate::\([a-z_]*\)::|use crate::providers::aws::\1::|g' src/main.rs
sed -i '' 's|use crate::\([a-z_]*\)::|use crate::providers::aws::\1::|g' src/tui/mod.rs
sed -i '' 's|use crate::\([a-z_]*\)::|use crate::providers::aws::\1::|g' src/tui/ui.rs
```

> **Note:** The sed above is approximate. Run `cargo check` after and fix any remaining
> path errors manually — they will be obvious compile errors, not silent.

### Infrastructure files that stay in `src/`

These are not collectors and must NOT be moved:

| File | Reason |
|---|---|
| `src/evidence.rs` | Core trait definitions |
| `src/app_config.rs` | Account configuration |
| `src/inventory_core.rs` | Shared CSV schema |
| `src/inventory_orchestrator.rs` | Multi-service inventory runner |
| `src/inventory_xlsx.rs` | XLSX output formatter |
| `src/audit_log.rs` | Cross-provider audit logging |
| `src/poam.rs` | POA&M generation |
| `src/signing.rs` | HMAC signing |
| `src/zip_bundle.rs` | Output bundling |

---

## Phase 3 — TUI Provider Routing

Required when the first non-AWS collector is registered in `main.rs`.

### Changes needed

1. **Feature/collector screen** — Display a provider badge next to each collector name.
   The `CollectorInfo` struct (or equivalent in `tui/`) gains a `provider: CloudProvider` field.

2. **Credential initialization** — `main.rs` currently builds one `aws_config::SdkConfig`
   and passes it to all collectors. After Phase 3, collector initialization is grouped
   by provider:

   ```rust
   // Pseudocode — actual structure depends on how app_config evolves
   for account in &accounts {
       match account.provider {
           CloudProvider::Aws     => { /* existing AWS SDK init */ }
           CloudProvider::Azure   => { /* azure_identity credential init */ }
           CloudProvider::Gcp     => { /* google-cloud-auth credential init */ }
           CloudProvider::Tenable => { /* TenableClient::new(keys, url) */ }
       }
   }
   ```

3. **Output file prefix** — Currently collectors prefix their files with the AWS account ID.
   Non-AWS collectors should prefix with a provider-scoped identifier
   (Azure subscription ID, GCP project ID, or Tenable site name).

4. **POAM / audit log provider tag** — `poam.rs` and `audit_log.rs` should record the
   `CloudProvider` variant on each finding/log entry for multi-cloud reports.

---

## Concrete Collector Skeleton (non-AWS)

When writing the first Azure or GCP collector, use this skeleton to stay consistent
with existing AWS collectors:

```rust
// src/providers/azure/activity_log.rs
// Requires: --features azure

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;

use crate::evidence::JsonCollector;

pub struct ActivityLogCollector {
    subscription_id: String,
    // azure_identity::DefaultAzureCredential or similar
}

impl ActivityLogCollector {
    pub fn new(subscription_id: impl Into<String>) -> Result<Self> {
        Ok(Self {
            subscription_id: subscription_id.into(),
        })
    }
}

#[async_trait]
impl JsonCollector for ActivityLogCollector {
    fn name(&self) -> &str {
        "Azure Activity Log"
    }

    fn filename_prefix(&self) -> &str {
        "Azure_Activity_Log"
    }

    async fn collect_records(&self, account_id: &str, region: &str) -> Result<Vec<Value>> {
        // account_id = subscription_id, region = Azure region name
        todo!("implement Azure Monitor / Activity Log API call")
    }
}
```

Registration in `main.rs` (Phase 1.5+):

```rust
// Conditionally compiled — only present with `--features azure`
#[cfg(feature = "azure")]
{
    use crate::providers::azure::activity_log::ActivityLogCollector;
    let azure_collector = ActivityLogCollector::new(&azure_account.subscription_id)?;
    // push to json_collectors vec
}
```

### Tenable collector skeleton

Tenable has no Rust SDK — collectors call the REST API directly using `reqwest`.
The shared HTTP client (with auth headers pre-set) is constructed once and cloned into
each collector.

```rust
// src/providers/tenable/client.rs
// Requires: --features tenable

use anyhow::Result;
use reqwest::{Client, header};

/// Thin wrapper around reqwest that injects Tenable auth headers on every request.
#[derive(Clone)]
pub struct TenableClient {
    pub(crate) http: Client,
    pub(crate) base_url: String,
}

impl TenableClient {
    pub fn new(access_key: &str, secret_key: &str, base_url: &str) -> Result<Self> {
        let auth_value = format!("accessKey={access_key}; secretKey={secret_key}");
        let mut headers = header::HeaderMap::new();
        headers.insert("X-ApiKeys", header::HeaderValue::from_str(&auth_value)?);

        let http = Client::builder()
            .default_headers(headers)
            .build()?;

        Ok(Self { http, base_url: base_url.to_string() })
    }

    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }
}
```

```rust
// src/providers/tenable/vulnerabilities.rs
// Requires: --features tenable

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;

use crate::evidence::JsonCollector;
use crate::providers::tenable::client::TenableClient;

pub struct VulnerabilitiesCollector {
    client: TenableClient,
}

impl VulnerabilitiesCollector {
    pub fn new(client: TenableClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl JsonCollector for VulnerabilitiesCollector {
    fn name(&self) -> &str { "Tenable Vulnerabilities" }
    fn filename_prefix(&self) -> &str { "Tenable_Vulnerabilities" }

    async fn collect_records(&self, _account_id: &str, _region: &str) -> Result<Vec<Value>> {
        // POST /vulns/export  →  poll  GET /vulns/export/{export_uuid}/status
        // →  GET /vulns/export/{export_uuid}/chunks/{chunk_id}
        todo!("implement Tenable vuln export API")
    }
}
```

```rust
// src/providers/tenable/mod.rs  (after first collector is added)
pub mod client;
pub mod vulnerabilities;
pub mod assets;
pub mod scans;
pub mod audit_log;
pub mod compliance;
```

Registration in `main.rs` (Phase 1.5+):

```rust
#[cfg(feature = "tenable")]
{
    use crate::providers::tenable::client::TenableClient;
    use crate::providers::tenable::vulnerabilities::VulnerabilitiesCollector;

    let tenable_client = TenableClient::new(&access_key, &secret_key, &base_url)?;
    json_collectors.push(Box::new(VulnerabilitiesCollector::new(tenable_client.clone())));
    // add more Tenable collectors by cloning the same client
}
```

> **`TenableClient` cloning:** `reqwest::Client` is cheaply cloneable (arc-wrapped
> connection pool). Building it once and cloning into each collector avoids redundant
> TLS handshake overhead across parallel collectors.

---

## How to Add a New Provider Collector After Phase 1

**For cloud SDK providers (Azure, GCP):**

1. Create `src/providers/<provider>/<service>.rs` implementing `EvidenceCollector`,
   `JsonCollector`, or `CsvCollector` from `crate::evidence`.
2. Add `pub mod <service>;` to `src/providers/<provider>/mod.rs`.
3. Add the feature gate (`#[cfg(feature = "<provider>")]`) around the module.
4. Import and instantiate in `src/main.rs` inside a `#[cfg(feature = "<provider>")]` block.
5. Add the new `EvidenceSource` variant to `src/evidence.rs` if needed.

**For REST-only providers (Tenable):**

Steps 1–5 above, plus:

6. Construct a `TenableClient` once from `app_config` credentials (env var fallback).
7. Clone the client into each collector that needs it — do **not** create a new client
   per collector (connection pool reuse).
8. Implement the export/poll pattern for bulk endpoints (Tenable uses async export jobs,
   not paginated lists): POST export → poll status → download chunks.

No other files change.

---

## Phase 4 — Application Layer Decomposition

`main.rs` is 4,146 lines with seven distinct responsibilities. This phase breaks it into
focused modules without changing any behavior.

### Target file tree

```
grabber/                           ← repo root (workspace root)
├── Cargo.toml                     # [workspace] + [package]
├── crates/
│   └── tenable-rs/                # see "Tenable Rust SDK Crate" section
└── src/
    ├── main.rs                    # ~80 lines — fn main() + async_main dispatcher only
    ├── cli.rs                     # Cli struct, argument definitions, parse_lookback
    ├── aws_loader.rs              # load_cli_config, load_cli_probe_and_work_configs,
    │                              # discover_regions, print_identity, print_cli_identity
    ├── platform.rs                # redirect_stderr_to_file / restore_stderr (unix/stub)
    ├── runner/
    │   ├── mod.rs                 # Re-exports; CollectionContext struct
    │   ├── collector_registry.rs  # build_csv_collectors, build_json_collectors,
    │   │                          # build_json_inv_collectors, all_inventory_type_keys,
    │   │                          # resolve_inventory_types
    │   ├── output.rs              # write_csv_bytes, write_inventory_outputs,
    │   │                          # format_path_with_osc8, date_path_suffix
    │   ├── tui_runners.rs         # run_tui_csv_collector, run_tui_inv_collector,
    │   │                          # run_tui_json_collector, run_tui_poam
    │   ├── multi_account.rs       # run_tui_multi_account
    │   └── cli_runners.rs         # run_inventory_cli, run_poam_cli
    └── tui/
        ├── mod.rs                 # Re-exports; run(), setup_terminal, restore_terminal
        ├── state.rs               # App, CollectorStatus, CollectorState, Feature,
        │                          # PoamSummary, Progress — all pure state types
        ├── events.rs              # Key event handlers extracted from the main loop
        ├── screens/
        │   ├── mod.rs
        │   ├── feature_select.rs  # draw_feature_select
        │   ├── collector_select.rs# draw_collectors, search bar, filtered panels
        │   ├── running.rs         # draw_running, progress display
        │   └── results.rs         # draw_results, file list, signing summary
        └── widgets.rs             # Any custom ratatui Widget impls
```

### Decomposition order (lowest risk first)

1. **Extract `src/platform.rs`** — two cfg-gated functions with no dependencies on
   anything else. Zero risk.

2. **Extract `src/cli.rs`** — the `Cli` struct and `parse_lookback`. Remove the 220-line
   block from `main.rs`. Update `use` in `main.rs`: `use crate::cli::Cli;`.

3. **Extract `src/aws_loader.rs`** — `load_cli_config`, `load_cli_probe_and_work_configs`,
   `discover_regions`, `print_identity`. These have no collectors as dependencies; they
   only use `aws_config` and `aws_sdk_sts`.

4. **Create `src/runner/output.rs`** — `write_csv_bytes`, `write_inventory_outputs`,
   `date_path_suffix`, `format_path_with_osc8`. All are pure functions with no state.

5. **Create `src/runner/collector_registry.rs`** — the three `build_*_collectors`
   functions + `all_inventory_type_keys` + `resolve_inventory_types`. This is the
   collector factory. It takes `&aws_config::SdkConfig` and a name slice, returns
   `Vec<Box<dyn *Collector>>`. No business logic — just wiring.

   ```rust
   // Pattern: keyed factory replacing the giant if-chain
   pub fn build_csv_collectors(
       names: &[&str],
       config: &aws_config::SdkConfig,
   ) -> Vec<Box<dyn CsvCollector>> {
       // same body as today, but in its own file
   }
   ```

   > Future: once the provider system is in place, this becomes a `CollectorRegistry`
   > that also accepts Azure/GCP configs and produces provider-tagged collectors.

6. **Create `src/runner/cli_runners.rs`** — `run_inventory_cli`, `run_poam_cli`.

7. **Create `src/runner/tui_runners.rs`** — `run_tui_csv_collector`,
   `run_tui_inv_collector`, `run_tui_json_collector`, `run_tui_poam`.

8. **Create `src/runner/multi_account.rs`** — `run_tui_multi_account` (currently
   ~550 lines on its own).

9. **`tui/` decomposition** — Split `tui/mod.rs` (2,275 lines) and `tui/ui.rs`
   (3,173 lines) following the screen/state separation in the target tree above.
   Extract state types to `tui/state.rs` first (zero behavior change), then screens
   one at a time, verifying TUI renders correctly after each.

### `CollectorRegistry` — future-ready design

Once Phase 2 and Phase 4 are both complete, `collector_registry.rs` can evolve into a
proper registry that produces collectors for any provider:

```rust
pub struct CollectorRegistry {
    csv:      Vec<Box<dyn CsvCollector>>,
    json_inv: Vec<Box<dyn JsonCollector>>,
    evidence: Vec<Box<dyn EvidenceCollector>>,
}

impl CollectorRegistry {
    pub fn from_aws(names: &[&str], config: &aws_config::SdkConfig) -> Self { ... }

    #[cfg(feature = "azure")]
    pub fn add_azure(&mut self, names: &[&str], creds: &AzureCredential) { ... }

    #[cfg(feature = "gcp")]
    pub fn add_gcp(&mut self, names: &[&str], creds: &GcpCredential) { ... }
}
```

This replaces all three `build_*` functions and the fragmented `#[cfg]` blocks in
`main.rs` with a single registry that `async_main` builds once and passes to runners.

### `inventory_orchestrator.rs` decomposition

At 1,058 lines, this file also exceeds the guideline. After Phase 2 moves AWS collectors
into `src/providers/aws/`, split the per-service collection helpers out of
`inventory_orchestrator.rs`:

```
src/providers/aws/
├── inventory/
│   ├── mod.rs           # InventoryCollector struct + CsvCollector impl
│   ├── kms.rs           # collect_kms_keys
│   ├── s3.rs            # collect_s3_buckets
│   ├── lambda.rs        # collect_lambda_functions
│   ├── ec2.rs           # collect_ec2_instances
│   ├── alb.rs           # collect_albs
│   ├── rds.rs           # collect_rds_instances
│   ├── elasticache.rs   # collect_elasticache_clusters
│   └── containers.rs    # collect_containers, collect_ecs_cluster_names, collect_eks_cluster_names
```

Each file will be under 200 lines. `mod.rs` delegates to them:

```rust
mod kms; mod s3; mod lambda; mod ec2; mod alb; mod rds; mod elasticache; mod containers;
use self::{kms::*, s3::*, lambda::*, ec2::*, alb::*, rds::*, elasticache::*, containers::*};
```

### Phase 4 verification

1. `cargo build` — no errors
2. `cargo test` — all tests pass
3. TUI smoke test: launch, navigate, run one collector, verify output file exists
4. `git diff --stat HEAD` confirms no `.rs` file content changes — only moves/renames

---

## What Never Changes (any phase)

- Trait definitions in `src/evidence.rs` (`EvidenceCollector`, `JsonCollector`, `CsvCollector`, `CollectParams`)
- Collector logic inside any `.rs` file (Phase 2 moves files; content is untouched)
- Output formats, signing, POA&M, TUI behavior
- Existing AWS `cargo build` — no features required, default build stays all-AWS

---

## Verification

### Phase 0 / Phase 1

1. `cargo build` compiles with no errors or warnings from new modules
2. `cargo check` passes
3. `crate::providers::azure`, `crate::providers::gcp`, and `crate::providers::tenable`
   are reachable from any module
4. `cargo build --features tenable` compiles (once `reqwest` dep is uncommented)
5. `cargo build --features azure` compiles (once Azure SDK deps are uncommented)
6. Existing TUI run against AWS collects normally — no regression

### Phase 1.5

1. Existing TOML config files with no `provider` key load without error
2. An account with `provider = "azure"` but no `tenant_id` returns a descriptive error,
   not a panic
3. An account with `provider = "tenable"` but no keys and no env vars returns a
   descriptive error, not a panic
4. `TENABLE_ACCESS_KEY` / `TENABLE_SECRET_KEY` env vars override TOML values

### Phase 2

1. `cargo build` after file moves and import updates — zero errors
2. `cargo test` — all existing tests pass
3. Full TUI run: AWS evidence collection produces the same files as before the move
4. `git diff --stat HEAD~1` confirms only renames + import updates (no logic changes)
