# Plan: Multi-Provider Architecture

## Current State

88 AWS collector modules live flat in `src/`. The evidence traits (`EvidenceCollector`,
`JsonCollector`, `CsvCollector`) are already provider-agnostic. The `EvidenceSource` enum
has only 4 AWS variants. `app_config` only knows about AWS accounts. There is no `providers/`
directory yet.

---

## Phases Overview

| Phase | What | Risk | When |
|---|---|---|---|
| 0 | `CloudProvider` enum + Cargo feature flags | Zero — additive only | Now |
| 1 | Provider stubs + `EvidenceSource` variants | Zero — no existing files move | Now |
| 1.5 | `app_config` multi-provider credential support | Low — additive | Before first non-AWS collector |
| 2 | Move 88 AWS files into provider tree | Medium — mechanical; many import paths change | Whenever flat `src/` becomes inconvenient |
| 3 | TUI provider routing | Low — isolated to `tui/` | When first non-AWS collector is registered |

---

## Phase 0 — `CloudProvider` Foundation

### `src/providers/mod.rs`

```rust
pub mod azure;
pub mod gcp;

use std::fmt;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CloudProvider {
    Aws,
    Azure,
    Gcp,
}

impl fmt::Display for CloudProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CloudProvider::Aws => write!(f, "AWS"),
            CloudProvider::Azure => write!(f, "Azure"),
            CloudProvider::Gcp => write!(f, "GCP"),
        }
    }
}
```

`Display` drives TUI labels, filename prefixes (`AWS_`, `Azure_`, `GCP_`), and report metadata.
`Serialize`/`Deserialize` lets it appear cleanly in JSON output and `app_config` TOML.

### `src/main.rs` addition

Append one line to the existing `mod` block (after line 91):

```rust
mod providers;
```

### `Cargo.toml` — optional feature flags

Add these sections. No Azure/GCP SDK is pulled in until the feature is enabled.

```toml
[features]
default = []
azure = ["dep:azure_identity", "dep:azure_mgmt_monitor", "dep:azure_mgmt_resources"]
gcp   = ["dep:google-cloud-auth"]

[dependencies]
# ... existing deps unchanged ...

# Azure — only compiled with `--features azure`
azure_identity        = { version = "0.20", optional = true }
azure_mgmt_monitor    = { version = "0.20", optional = true }
azure_mgmt_resources  = { version = "0.20", optional = true }

# GCP — only compiled with `--features gcp`
google-cloud-auth = { version = "0.7", optional = true }
```

**Build commands:**
```sh
cargo build                         # AWS only (current behavior unchanged)
cargo build --features azure        # AWS + Azure
cargo build --features azure,gcp    # all three
```

---

## Phase 1 — Provider Stubs + `EvidenceSource` variants

Zero existing files move. Only additions and small edits.

### Files created / changed

| File | Action |
|---|---|
| `src/providers/mod.rs` | **Create** — see Phase 0 above |
| `src/providers/azure/mod.rs` | **Create** — stub |
| `src/providers/gcp/mod.rs` | **Create** — stub |
| `src/main.rs` | Add `mod providers;` |
| `src/evidence.rs` | Add Azure/GCP variants to `EvidenceSource` |

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
```

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
// Pattern inside an Azure collector's `new()`:
pub fn new(account: &Account) -> Result<Self> {
    let tenant_id = account.tenant_id.as_deref()
        .ok_or_else(|| anyhow::anyhow!("Azure collector requires tenant_id in config"))?;
    // ...
}
```

---

## Phase 2 — Full AWS Cleanup (deferred)

Move the 88 AWS files into `src/providers/aws/`. This is purely mechanical —
no behavior changes.

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
           CloudProvider::Aws => { /* existing AWS SDK init */ }
           CloudProvider::Azure => { /* azure_identity credential init */ }
           CloudProvider::Gcp => { /* google-cloud-auth credential init */ }
       }
   }
   ```

3. **Output file prefix** — Currently collectors prefix their files with the AWS account ID.
   Non-AWS collectors should prefix with a provider-scoped identifier
   (Azure subscription ID or GCP project ID).

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

---

## How to Add a New Provider Collector After Phase 1

1. Create `src/providers/<provider>/<service>.rs` implementing `EvidenceCollector`,
   `JsonCollector`, or `CsvCollector` from `crate::evidence`.
2. Add `pub mod <service>;` to `src/providers/<provider>/mod.rs`.
3. Add the feature gate (`#[cfg(feature = "<provider>")]`) around the module and any SDK deps.
4. Import and instantiate in `src/main.rs` inside a `#[cfg(feature = "<provider>")]` block.
5. Add the new `EvidenceSource` variant to `src/evidence.rs` if needed.

No other files change.

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
3. `crate::providers::azure` and `crate::providers::gcp` are reachable from any module
4. `cargo build --features azure` (once Azure SDK deps are uncommented) compiles
5. Existing TUI run against AWS collects normally — no regression

### Phase 1.5

1. Existing TOML config files with no `provider` key load without error
2. An account with `provider = "azure"` but no `tenant_id` returns a descriptive error,
   not a panic

### Phase 2

1. `cargo build` after file moves and import updates — zero errors
2. `cargo test` — all existing tests pass
3. Full TUI run: AWS evidence collection produces the same files as before the move
4. `git diff --stat HEAD~1` confirms only renames + import updates (no logic changes)
