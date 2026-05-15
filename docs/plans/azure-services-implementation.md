# Azure Services Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement Azure feature-parity with the existing 88+ AWS collectors by building out `src/providers/azure/` submodules, completing `AzureProviderFactory`, and wiring credential resolution via `DefaultAzureCredential`.

**Architecture:** Each Azure service maps to a named submodule under `src/providers/azure/` and implements one of the three collector traits (`EvidenceCollector`, `JsonCollector`, `CsvCollector`) from `crate::evidence`. The `AzureProviderFactory` in `src/providers/azure/factory.rs` holds an `Arc<DefaultAzureCredential>` shared across all collectors; `subscription_id` maps to `account_id` and Azure `location` maps to `region` on the `ProviderFactory` trait. All Azure code compiles only under `--features azure`.

**Tech Stack:** `azure_identity` 0.20, `azure_mgmt_monitor` 0.20, `azure_mgmt_resources` 0.20, `azure_mgmt_security` (to be added), `azure_mgmt_compute` (to be added), `azure_mgmt_storage` (to be added), `azure_mgmt_keyvault` (to be added), `azure_mgmt_authorization` (to be added), `azure_mgmt_policyinsights` (to be added), `tokio`, `serde_json`, `async-trait`, `anyhow`.

---

## Service Mapping: Azure → AWS Equivalents

| Azure Service | Module | AWS Equivalent(s) | Trait |
|---|---|---|---|
| Activity Log | `activity_log` | CloudTrail | `EvidenceCollector` |
| Defender for Cloud | `defender` | SecurityHub + GuardDuty | `CsvCollector` |
| Entra ID (Users, Groups, Apps) | `entra_id` | IAM (users, roles, policies) | `JsonCollector` |
| Key Vault (keys, secrets, certs) | `key_vault` | KMS + SecretsManager | `JsonCollector` |
| Blob Storage | `storage` | S3 | `CsvCollector` |
| Virtual Machines | `virtual_machines` | EC2 | `CsvCollector` |
| Azure Policy | `policy` | AWS Config Rules + SCPs | `JsonCollector` |
| Network Security Groups | `nsg` | Security Groups + NACLs | `CsvCollector` |
| Azure AD Conditional Access | `conditional_access` | IAM Conditions / SCPs | `JsonCollector` |
| Azure Monitor Alerts | `monitor_alerts` | CloudWatch Alarms | `CsvCollector` |
| Role Assignments (RBAC) | `rbac` | IAM Policies + Trust Policies | `JsonCollector` |
| SQL Database | `sql` | RDS | `CsvCollector` |
| AKS (Kubernetes) | `aks` | EKS | `CsvCollector` |
| Container Registry | `acr` | ECR | `CsvCollector` |
| App Service | `app_service` | ECS / Lambda | `CsvCollector` |

---

## File Structure

### Files Created

```
src/providers/azure/
├── mod.rs                   (modify — uncomment pub mod declarations)
├── factory.rs               (modify — add Arc<DefaultAzureCredential> + wire collectors)
│
│── Phase 1: Identity & Logging
├── activity_log.rs          (create — EvidenceCollector, azure_mgmt_monitor)
├── entra_id.rs              (create — JsonCollector, MS Graph REST via reqwest)
├── rbac.rs                  (create — JsonCollector, azure_mgmt_authorization)
├── conditional_access.rs    (create — JsonCollector, MS Graph REST via reqwest)
│
│── Phase 2: Compute & Storage
├── virtual_machines.rs      (create — CsvCollector, azure_mgmt_compute)
├── storage.rs               (create — CsvCollector, azure_mgmt_storage)
├── sql.rs                   (create — CsvCollector, azure_mgmt_sql)
├── aks.rs                   (create — CsvCollector, azure_mgmt_containerservice)
├── acr.rs                   (create — CsvCollector, azure_mgmt_containerregistry)
├── app_service.rs           (create — CsvCollector, azure_mgmt_web)
│
│── Phase 3: Security & Compliance
├── defender.rs              (create — CsvCollector, azure_mgmt_security)
├── key_vault.rs             (create — JsonCollector, azure_mgmt_keyvault)
├── policy.rs                (create — JsonCollector, azure_mgmt_policyinsights)
├── nsg.rs                   (create — CsvCollector, azure_mgmt_network)
└── monitor_alerts.rs        (create — CsvCollector, azure_mgmt_monitor)
```

### Files Modified

```
Cargo.toml                          — add 10 azure_mgmt_* optional deps
src/evidence.rs                     — add AzureActivityLog, AzureMonitor EvidenceSource variants
src/providers/azure/mod.rs          — uncomment pub mod declarations as each phase ships
src/providers/azure/factory.rs      — add credential field, build collector vecs
src/app_config.rs                   — already has Azure fields; verify region field
```

---

## Dependency Management

### Task 0: Add Azure SDK Crates to `Cargo.toml`

**Files:**
- Modify: `Cargo.toml`

- [ ] **Step 1: Read current Cargo.toml `[features]` and `[dependencies]` azure section**

Run: `grep -A5 'azure' Cargo.toml`

Expected: shows `azure_identity`, `azure_mgmt_monitor`, `azure_mgmt_resources` already present.

- [ ] **Step 2: Add missing azure_mgmt_* crates to Cargo.toml**

In `Cargo.toml`, replace the existing azure optional deps block:

```toml
# Azure — only compiled with `--features azure`
azure_identity              = { version = "0.20", optional = true }
azure_mgmt_monitor          = { version = "0.20", optional = true }
azure_mgmt_resources        = { version = "0.20", optional = true }
azure_mgmt_security         = { version = "0.20", optional = true }
azure_mgmt_compute          = { version = "0.20", optional = true }
azure_mgmt_storage          = { version = "0.20", optional = true }
azure_mgmt_keyvault         = { version = "0.20", optional = true }
azure_mgmt_authorization    = { version = "0.20", optional = true }
azure_mgmt_policyinsights   = { version = "0.20", optional = true }
azure_mgmt_network          = { version = "0.20", optional = true }
azure_mgmt_sql              = { version = "0.20", optional = true }
azure_mgmt_containerservice = { version = "0.20", optional = true }
azure_mgmt_containerregistry= { version = "0.20", optional = true }
azure_mgmt_web              = { version = "0.20", optional = true }
```

- [ ] **Step 3: Update the `[features]` azure entry to include all new crates**

```toml
[features]
azure = [
    "dep:azure_identity",
    "dep:azure_mgmt_monitor",
    "dep:azure_mgmt_resources",
    "dep:azure_mgmt_security",
    "dep:azure_mgmt_compute",
    "dep:azure_mgmt_storage",
    "dep:azure_mgmt_keyvault",
    "dep:azure_mgmt_authorization",
    "dep:azure_mgmt_policyinsights",
    "dep:azure_mgmt_network",
    "dep:azure_mgmt_sql",
    "dep:azure_mgmt_containerservice",
    "dep:azure_mgmt_containerregistry",
    "dep:azure_mgmt_web",
]
```

- [ ] **Step 4: Verify the feature gate compiles before writing any collectors**

Run: `cargo check --features azure 2>&1 | head -20`

Expected: zero errors (the empty stubs in `factory.rs` already compile).

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml
git commit -m "chore(azure): add azure_mgmt_* optional deps for all planned collectors"
```

---

## Credential Handling: `AzureProviderFactory`

### Task 1: Wire `DefaultAzureCredential` into the Factory

**Files:**
- Modify: `src/providers/azure/factory.rs`

The factory must hold an `Arc<DefaultAzureCredential>` that is cloned into every collector.
`DefaultAzureCredential` tries, in order: environment variables (`AZURE_CLIENT_ID`,
`AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID`), workload identity, managed identity, Azure CLI.
This means no explicit credential configuration is needed in most environments.

`subscription_id` → `ProviderFactory::account_id()`.
`region` (Azure location, e.g. `"eastus"`) → `ProviderFactory::region()`.

- [ ] **Step 1: Write the failing compile-check test**

Create `src/providers/azure/factory.rs` with the updated struct. The test is a compile
test — if it builds with `--features azure`, it passes.

```rust
// src/providers/azure/factory.rs
use std::sync::Arc;

use azure_identity::DefaultAzureCredential;

use crate::evidence::{CsvCollector, EvidenceCollector, JsonCollector};
use crate::providers::{CloudProvider, ProviderFactory};

pub struct AzureProviderFactory {
    credential:      Arc<DefaultAzureCredential>,
    subscription_id: String,
    region:          String,
    selected:        Vec<String>,
}

impl AzureProviderFactory {
    pub fn new(
        credential: Arc<DefaultAzureCredential>,
        subscription_id: String,
        region: String,
        selected: Vec<String>,
    ) -> Self {
        Self { credential, subscription_id, region, selected }
    }

    fn is_selected(&self, key: &str) -> bool {
        self.selected.is_empty() || self.selected.iter().any(|s| s == key)
    }
}

impl ProviderFactory for AzureProviderFactory {
    fn provider(&self)   -> CloudProvider { CloudProvider::Azure }
    fn account_id(&self) -> &str          { &self.subscription_id }
    fn region(&self)     -> &str          { &self.region }

    fn csv_collectors(&self)      -> Vec<Box<dyn CsvCollector>>      { vec![] }
    fn json_collectors(&self)     -> Vec<Box<dyn JsonCollector>>     { vec![] }
    fn evidence_collectors(&self) -> Vec<Box<dyn EvidenceCollector>> { vec![] }
}
```

- [ ] **Step 2: Verify it compiles**

Run: `cargo check --features azure 2>&1`

Expected: zero errors.

- [ ] **Step 3: Commit**

```bash
git add src/providers/azure/factory.rs
git commit -m "feat(azure): add DefaultAzureCredential to AzureProviderFactory"
```

---

## Phase 1: Identity and Logging

### Task 2: `activity_log` — Azure Activity Log Collector

**Maps to:** AWS CloudTrail (`EvidenceCollector`)

**Files:**
- Create: `src/providers/azure/activity_log.rs`
- Modify: `src/providers/azure/mod.rs`
- Modify: `src/providers/azure/factory.rs`
- Modify: `src/evidence.rs`

The Azure Activity Log API is under `azure_mgmt_monitor`. It exposes
`GET /subscriptions/{subscriptionId}/providers/Microsoft.Insights/eventtypes/management/values`
with `$filter=eventTimestamp ge '<ISO8601>' and eventTimestamp le '<ISO8601>'`.

- [ ] **Step 1: Add `AzureActivityLog` variant to `EvidenceSource`**

In `src/evidence.rs`, find the `EvidenceSource` enum and add:

```rust
pub enum EvidenceSource {
    // existing AWS variants ...
    CloudTrail,
    BackupApi,
    RdsApi,
    CloudTrailS3,
    // Azure
    AzureActivityLog,
    AzureMonitor,
}
```

Run: `cargo check 2>&1 | grep 'error'`

Expected: only warnings about unused variants — no errors.

- [ ] **Step 2: Create `src/providers/azure/activity_log.rs`**

```rust
use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use azure_identity::DefaultAzureCredential;
use azure_mgmt_monitor::Client as MonitorClient;

use crate::evidence::{CollectParams, EvidenceCollector, EvidenceRecord, EvidenceSource};

pub struct ActivityLogCollector {
    client:          MonitorClient,
    subscription_id: String,
}

impl ActivityLogCollector {
    pub fn new(credential: Arc<DefaultAzureCredential>, subscription_id: String) -> Self {
        let client = MonitorClient::new(Arc::clone(&credential));
        Self { client, subscription_id }
    }
}

#[async_trait]
impl EvidenceCollector for ActivityLogCollector {
    fn name(&self) -> &str { "Azure Activity Log" }
    fn filename_prefix(&self) -> &str { "Azure_Activity_Log" }

    async fn collect(&self, params: &CollectParams) -> Result<Vec<EvidenceRecord>> {
        let start = params.start_time.to_rfc3339();
        let end   = params.end_time.to_rfc3339();
        let filter = format!(
            "eventTimestamp ge '{}' and eventTimestamp le '{}'",
            start, end
        );

        let mut records = Vec::new();
        let mut response = self.client
            .activity_logs_client()
            .list(&self.subscription_id, &filter)
            .into_stream();

        while let Some(page) = futures::StreamExt::next(&mut response).await {
            let page = page.context("Azure Activity Log page fetch failed")?;
            for event in page.value {
                records.push(EvidenceRecord {
                    source:               EvidenceSource::AzureActivityLog,
                    event_name:           event.operation_name
                        .as_ref()
                        .and_then(|o| o.value.clone())
                        .unwrap_or_default(),
                    timestamp:            event.event_timestamp
                        .map(|t| t.to_rfc3339())
                        .unwrap_or_default(),
                    job_id:               None,
                    plan_id:              event.correlation_id.clone(),
                    resource_arn:         event.resource_id.clone(),
                    resource_type:        event.resource_type
                        .as_ref()
                        .and_then(|r| r.value.clone()),
                    status:               event.status
                        .as_ref()
                        .and_then(|s| s.value.clone()),
                    completion_timestamp: None,
                    raw:                  if params.include_raw {
                        serde_json::to_value(&event).ok()
                    } else {
                        None
                    },
                });
            }
        }

        Ok(records)
    }
}
```

- [ ] **Step 3: Add `pub mod activity_log;` to `src/providers/azure/mod.rs`**

```rust
pub mod factory;
pub mod activity_log;
```

- [ ] **Step 4: Wire into `AzureProviderFactory::evidence_collectors()`**

In `src/providers/azure/factory.rs`, update the `evidence_collectors` method:

```rust
use crate::providers::azure::activity_log::ActivityLogCollector;

fn evidence_collectors(&self) -> Vec<Box<dyn EvidenceCollector>> {
    let mut out: Vec<Box<dyn EvidenceCollector>> = vec![];
    if self.is_selected("azure-activity-log") {
        out.push(Box::new(ActivityLogCollector::new(
            Arc::clone(&self.credential),
            self.subscription_id.clone(),
        )));
    }
    out
}
```

- [ ] **Step 5: Verify it compiles**

Run: `cargo check --features azure 2>&1 | grep 'error'`

Expected: zero errors.

- [ ] **Step 6: Commit**

```bash
git add src/providers/azure/activity_log.rs src/providers/azure/mod.rs \
        src/providers/azure/factory.rs src/evidence.rs
git commit -m "feat(azure): add ActivityLog EvidenceCollector (maps to CloudTrail)"
```

---

### Task 3: `entra_id` — Entra ID (Users, Groups, Service Principals)

**Maps to:** AWS IAM (`JsonCollector`)

**Files:**
- Create: `src/providers/azure/entra_id.rs`
- Modify: `src/providers/azure/mod.rs`
- Modify: `src/providers/azure/factory.rs`

Entra ID (formerly Azure AD) is accessed via the Microsoft Graph REST API
(`https://graph.microsoft.com/v1.0/`), not an azure_mgmt_* SDK. Use `reqwest` directly
with a bearer token obtained from the credential. This follows the same pattern as the
Tenable client — construct an HTTP client once, share it across collector methods.

- [ ] **Step 1: Create `src/providers/azure/entra_id.rs`**

```rust
use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use azure_identity::DefaultAzureCredential;
use azure_core::auth::TokenCredential;
use serde_json::Value;

use crate::evidence::JsonCollector;

const GRAPH_URL: &str = "https://graph.microsoft.com/v1.0";

pub struct EntraIdCollector {
    credential: Arc<DefaultAzureCredential>,
    http:       reqwest::Client,
}

impl EntraIdCollector {
    pub fn new(credential: Arc<DefaultAzureCredential>) -> Self {
        Self {
            credential,
            http: reqwest::Client::new(),
        }
    }

    async fn bearer_token(&self) -> Result<String> {
        let scopes = &["https://graph.microsoft.com/.default"];
        let token  = self.credential
            .get_token(scopes)
            .await
            .context("EntraID: failed to obtain Graph API token")?;
        Ok(token.token.secret().to_string())
    }

    async fn get_all(&self, path: &str, token: &str) -> Result<Vec<Value>> {
        let mut results = Vec::new();
        let mut url = format!("{GRAPH_URL}{path}");

        loop {
            let resp: Value = self.http
                .get(&url)
                .bearer_auth(token)
                .send()
                .await
                .context("Graph API request failed")?
                .json()
                .await
                .context("Graph API JSON parse failed")?;

            if let Some(arr) = resp.get("value").and_then(|v| v.as_array()) {
                results.extend(arr.iter().cloned());
            }

            match resp.get("@odata.nextLink").and_then(|v| v.as_str()) {
                Some(next) => url = next.to_string(),
                None       => break,
            }
        }

        Ok(results)
    }
}

#[async_trait]
impl JsonCollector for EntraIdCollector {
    fn name(&self) -> &str { "Azure Entra ID" }
    fn filename_prefix(&self) -> &str { "Azure_Entra_ID" }

    async fn collect_records(&self, _account_id: &str, _region: &str) -> Result<Vec<Value>> {
        let token = self.bearer_token().await?;
        let mut records = Vec::new();

        let users = self.get_all("/users?$select=id,displayName,userPrincipalName,accountEnabled,createdDateTime,lastSignInDateTime", &token).await?;
        let groups = self.get_all("/groups?$select=id,displayName,groupTypes,securityEnabled,createdDateTime", &token).await?;
        let service_principals = self.get_all("/servicePrincipals?$select=id,displayName,appId,servicePrincipalType,createdDateTime", &token).await?;

        records.push(serde_json::json!({
            "entity_type": "users",
            "count": users.len(),
            "records": users,
        }));
        records.push(serde_json::json!({
            "entity_type": "groups",
            "count": groups.len(),
            "records": groups,
        }));
        records.push(serde_json::json!({
            "entity_type": "service_principals",
            "count": service_principals.len(),
            "records": service_principals,
        }));

        Ok(records)
    }
}
```

- [ ] **Step 2: Add `pub mod entra_id;` to `src/providers/azure/mod.rs`**

```rust
pub mod factory;
pub mod activity_log;
pub mod entra_id;
```

- [ ] **Step 3: Wire into `AzureProviderFactory::json_collectors()`**

In `src/providers/azure/factory.rs`:

```rust
use crate::providers::azure::entra_id::EntraIdCollector;

fn json_collectors(&self) -> Vec<Box<dyn JsonCollector>> {
    let mut out: Vec<Box<dyn JsonCollector>> = vec![];
    if self.is_selected("azure-entra-id") {
        out.push(Box::new(EntraIdCollector::new(Arc::clone(&self.credential))));
    }
    out
}
```

- [ ] **Step 4: Verify it compiles**

Run: `cargo check --features azure 2>&1 | grep 'error'`

Expected: zero errors.

- [ ] **Step 5: Commit**

```bash
git add src/providers/azure/entra_id.rs src/providers/azure/mod.rs \
        src/providers/azure/factory.rs
git commit -m "feat(azure): add EntraID JsonCollector (maps to IAM)"
```

---

### Task 4: `rbac` — Azure Role Assignments

**Maps to:** AWS IAM Policies + Trust Policies (`JsonCollector`)

**Files:**
- Create: `src/providers/azure/rbac.rs`
- Modify: `src/providers/azure/mod.rs`
- Modify: `src/providers/azure/factory.rs`

Uses `azure_mgmt_authorization`. Lists all role assignments at subscription scope, then
resolves role definitions for each unique `roleDefinitionId`.

- [ ] **Step 1: Create `src/providers/azure/rbac.rs`**

```rust
use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use azure_identity::DefaultAzureCredential;
use azure_mgmt_authorization::Client as AuthzClient;
use serde_json::{json, Value};

use crate::evidence::JsonCollector;

pub struct RbacCollector {
    client:          AuthzClient,
    subscription_id: String,
}

impl RbacCollector {
    pub fn new(credential: Arc<DefaultAzureCredential>, subscription_id: String) -> Self {
        Self {
            client: AuthzClient::new(Arc::clone(&credential)),
            subscription_id,
        }
    }
}

#[async_trait]
impl JsonCollector for RbacCollector {
    fn name(&self) -> &str { "Azure RBAC Role Assignments" }
    fn filename_prefix(&self) -> &str { "Azure_RBAC_Role_Assignments" }

    async fn collect_records(&self, _account_id: &str, _region: &str) -> Result<Vec<Value>> {
        let scope = format!("/subscriptions/{}", self.subscription_id);

        let assignments: Vec<Value> = self.client
            .role_assignments_client()
            .list_for_scope(&scope, None)
            .into_stream()
            .collect_all()
            .await
            .context("Azure RBAC: list_role_assignments failed")?
            .into_iter()
            .map(|a| serde_json::to_value(a).unwrap_or(Value::Null))
            .collect();

        let definitions: Vec<Value> = self.client
            .role_definitions_client()
            .list(&scope, None)
            .into_stream()
            .collect_all()
            .await
            .context("Azure RBAC: list_role_definitions failed")?
            .into_iter()
            .map(|d| serde_json::to_value(d).unwrap_or(Value::Null))
            .collect();

        Ok(vec![
            json!({ "entity_type": "role_assignments", "count": assignments.len(), "records": assignments }),
            json!({ "entity_type": "role_definitions",  "count": definitions.len(),  "records": definitions }),
        ])
    }
}
```

- [ ] **Step 2: Add `pub mod rbac;` to `src/providers/azure/mod.rs`**

```rust
pub mod factory;
pub mod activity_log;
pub mod entra_id;
pub mod rbac;
```

- [ ] **Step 3: Wire into `AzureProviderFactory::json_collectors()`**

```rust
use crate::providers::azure::rbac::RbacCollector;

// in json_collectors():
if self.is_selected("azure-rbac") {
    out.push(Box::new(RbacCollector::new(
        Arc::clone(&self.credential),
        self.subscription_id.clone(),
    )));
}
```

- [ ] **Step 4: Compile check**

Run: `cargo check --features azure 2>&1 | grep 'error'`

Expected: zero errors.

- [ ] **Step 5: Commit**

```bash
git add src/providers/azure/rbac.rs src/providers/azure/mod.rs \
        src/providers/azure/factory.rs
git commit -m "feat(azure): add RBAC role assignments JsonCollector (maps to IAM Policies)"
```

---

### Task 5: `conditional_access` — Azure AD Conditional Access Policies

**Maps to:** IAM Conditions / Permission Boundaries (`JsonCollector`)

**Files:**
- Create: `src/providers/azure/conditional_access.rs`
- Modify: `src/providers/azure/mod.rs`
- Modify: `src/providers/azure/factory.rs`

Uses the Microsoft Graph API (`/identity/conditionalAccess/policies`). Reuses the same
`bearer_token()` + paged `get_all()` pattern established in `entra_id.rs` — but as a
separate collector struct to keep responsibilities clear.

- [ ] **Step 1: Create `src/providers/azure/conditional_access.rs`**

```rust
use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use azure_identity::DefaultAzureCredential;
use azure_core::auth::TokenCredential;
use serde_json::Value;

use crate::evidence::JsonCollector;

const GRAPH_URL: &str = "https://graph.microsoft.com/v1.0";

pub struct ConditionalAccessCollector {
    credential: Arc<DefaultAzureCredential>,
    http:       reqwest::Client,
}

impl ConditionalAccessCollector {
    pub fn new(credential: Arc<DefaultAzureCredential>) -> Self {
        Self { credential, http: reqwest::Client::new() }
    }

    async fn bearer_token(&self) -> Result<String> {
        let token = self.credential
            .get_token(&["https://graph.microsoft.com/.default"])
            .await
            .context("ConditionalAccess: failed to obtain token")?;
        Ok(token.token.secret().to_string())
    }
}

#[async_trait]
impl JsonCollector for ConditionalAccessCollector {
    fn name(&self) -> &str { "Azure Conditional Access Policies" }
    fn filename_prefix(&self) -> &str { "Azure_Conditional_Access_Policies" }

    async fn collect_records(&self, _account_id: &str, _region: &str) -> Result<Vec<Value>> {
        let token = self.bearer_token().await?;
        let mut policies = Vec::new();
        let mut url = format!("{GRAPH_URL}/identity/conditionalAccess/policies");

        loop {
            let resp: Value = self.http
                .get(&url)
                .bearer_auth(&token)
                .send()
                .await
                .context("Conditional Access: HTTP request failed")?
                .json()
                .await
                .context("Conditional Access: JSON parse failed")?;

            if let Some(arr) = resp.get("value").and_then(|v| v.as_array()) {
                policies.extend(arr.iter().cloned());
            }

            match resp.get("@odata.nextLink").and_then(|v| v.as_str()) {
                Some(next) => url = next.to_string(),
                None       => break,
            }
        }

        Ok(policies)
    }
}
```

- [ ] **Step 2: Add `pub mod conditional_access;` to `src/providers/azure/mod.rs`**

- [ ] **Step 3: Wire into `AzureProviderFactory::json_collectors()`**

```rust
use crate::providers::azure::conditional_access::ConditionalAccessCollector;

if self.is_selected("azure-conditional-access") {
    out.push(Box::new(ConditionalAccessCollector::new(Arc::clone(&self.credential))));
}
```

- [ ] **Step 4: Compile check and commit**

Run: `cargo check --features azure 2>&1 | grep 'error'`

```bash
git add src/providers/azure/conditional_access.rs src/providers/azure/mod.rs \
        src/providers/azure/factory.rs
git commit -m "feat(azure): add ConditionalAccess JsonCollector (maps to IAM Conditions)"
```

---

## Phase 2: Compute and Storage

### Task 6: `virtual_machines` — Azure VM Inventory

**Maps to:** AWS EC2 (`CsvCollector`)

**Files:**
- Create: `src/providers/azure/virtual_machines.rs`
- Modify: `src/providers/azure/mod.rs`
- Modify: `src/providers/azure/factory.rs`

Uses `azure_mgmt_compute`. Lists all VMs in the subscription across all resource groups.
Pagination is handled by the SDK's `into_stream()` async iterator.

- [ ] **Step 1: Create `src/providers/azure/virtual_machines.rs`**

```rust
use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use azure_identity::DefaultAzureCredential;
use azure_mgmt_compute::Client as ComputeClient;

use crate::evidence::CsvCollector;

pub struct VirtualMachinesCollector {
    client:          ComputeClient,
    subscription_id: String,
}

impl VirtualMachinesCollector {
    pub fn new(credential: Arc<DefaultAzureCredential>, subscription_id: String) -> Self {
        Self {
            client: ComputeClient::new(Arc::clone(&credential)),
            subscription_id,
        }
    }
}

#[async_trait]
impl CsvCollector for VirtualMachinesCollector {
    fn name(&self) -> &str { "Azure Virtual Machines" }
    fn filename_prefix(&self) -> &str { "Azure_Virtual_Machines" }

    fn headers(&self) -> &'static [&'static str] {
        &[
            "VM Name",
            "Resource Group",
            "Location",
            "VM Size",
            "OS Type",
            "OS Disk",
            "Provisioning State",
            "VM ID",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        let mut stream = self.client
            .virtual_machines_client()
            .list_all(&self.subscription_id, None, None)
            .into_stream();

        while let Some(page) = futures::StreamExt::next(&mut stream).await {
            let page = page.context("Azure VMs: list_all page failed")?;
            for vm in page.value {
                let props = vm.properties.as_ref();
                rows.push(vec![
                    vm.name.clone().unwrap_or_default(),
                    vm.id.as_deref()
                        .and_then(|id| id.split("/resourceGroups/").nth(1))
                        .and_then(|s| s.split('/').next())
                        .unwrap_or("")
                        .to_string(),
                    vm.location.clone().unwrap_or_default(),
                    props.and_then(|p| p.hardware_profile.as_ref())
                        .and_then(|h| h.vm_size.as_ref())
                        .map(|s| format!("{:?}", s))
                        .unwrap_or_default(),
                    props.and_then(|p| p.storage_profile.as_ref())
                        .and_then(|s| s.os_disk.as_ref())
                        .and_then(|d| d.os_type.as_ref())
                        .map(|t| format!("{:?}", t))
                        .unwrap_or_default(),
                    props.and_then(|p| p.storage_profile.as_ref())
                        .and_then(|s| s.os_disk.as_ref())
                        .and_then(|d| d.name.clone())
                        .unwrap_or_default(),
                    props.and_then(|p| p.provisioning_state.clone())
                        .unwrap_or_default(),
                    vm.id.clone().unwrap_or_default(),
                ]);
            }
        }

        Ok(rows)
    }
}
```

- [ ] **Step 2: Add `pub mod virtual_machines;` to `src/providers/azure/mod.rs`**

- [ ] **Step 3: Wire into `AzureProviderFactory::csv_collectors()`**

In `src/providers/azure/factory.rs`:

```rust
use crate::providers::azure::virtual_machines::VirtualMachinesCollector;

fn csv_collectors(&self) -> Vec<Box<dyn CsvCollector>> {
    let mut out: Vec<Box<dyn CsvCollector>> = vec![];
    if self.is_selected("azure-virtual-machines") {
        out.push(Box::new(VirtualMachinesCollector::new(
            Arc::clone(&self.credential),
            self.subscription_id.clone(),
        )));
    }
    out
}
```

- [ ] **Step 4: Compile check**

Run: `cargo check --features azure 2>&1 | grep 'error'`

Expected: zero errors.

- [ ] **Step 5: Commit**

```bash
git add src/providers/azure/virtual_machines.rs src/providers/azure/mod.rs \
        src/providers/azure/factory.rs
git commit -m "feat(azure): add VirtualMachines CsvCollector (maps to EC2)"
```

---

### Task 7: `storage` — Azure Blob Storage Accounts

**Maps to:** AWS S3 (`CsvCollector`)

**Files:**
- Create: `src/providers/azure/storage.rs`
- Modify: `src/providers/azure/mod.rs`
- Modify: `src/providers/azure/factory.rs`

Uses `azure_mgmt_storage`. Lists all storage accounts in the subscription, capturing
public access, replication, TLS version, and HTTPS enforcement — the Azure equivalents
of S3 bucket-level security settings.

- [ ] **Step 1: Create `src/providers/azure/storage.rs`**

```rust
use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use azure_identity::DefaultAzureCredential;
use azure_mgmt_storage::Client as StorageClient;

use crate::evidence::CsvCollector;

pub struct StorageCollector {
    client:          StorageClient,
    subscription_id: String,
}

impl StorageCollector {
    pub fn new(credential: Arc<DefaultAzureCredential>, subscription_id: String) -> Self {
        Self {
            client: StorageClient::new(Arc::clone(&credential)),
            subscription_id,
        }
    }
}

#[async_trait]
impl CsvCollector for StorageCollector {
    fn name(&self) -> &str { "Azure Storage Accounts" }
    fn filename_prefix(&self) -> &str { "Azure_Storage_Accounts" }

    fn headers(&self) -> &'static [&'static str] {
        &[
            "Account Name",
            "Resource Group",
            "Location",
            "SKU",
            "Kind",
            "HTTPS Only",
            "Min TLS Version",
            "Allow Blob Public Access",
            "Blob Soft Delete Enabled",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        let mut stream = self.client
            .storage_accounts_client()
            .list(&self.subscription_id)
            .into_stream();

        while let Some(page) = futures::StreamExt::next(&mut stream).await {
            let page = page.context("Azure Storage: list page failed")?;
            for acct in page.value {
                let props = acct.properties.as_ref();
                let rg = acct.id.as_deref()
                    .and_then(|id| id.split("/resourceGroups/").nth(1))
                    .and_then(|s| s.split('/').next())
                    .unwrap_or("")
                    .to_string();
                rows.push(vec![
                    acct.name.clone().unwrap_or_default(),
                    rg,
                    acct.location.clone().unwrap_or_default(),
                    acct.sku.as_ref()
                        .and_then(|s| s.name.as_ref())
                        .map(|n| format!("{:?}", n))
                        .unwrap_or_default(),
                    acct.kind.as_ref()
                        .map(|k| format!("{:?}", k))
                        .unwrap_or_default(),
                    props.and_then(|p| p.enable_https_traffic_only)
                        .map(|b| b.to_string())
                        .unwrap_or_default(),
                    props.and_then(|p| p.minimum_tls_version.as_ref())
                        .map(|t| format!("{:?}", t))
                        .unwrap_or_default(),
                    props.and_then(|p| p.allow_blob_public_access)
                        .map(|b| b.to_string())
                        .unwrap_or("false".to_string()),
                    props.and_then(|p| p.blob_restore_status.as_ref())
                        .map(|_| "true".to_string())
                        .unwrap_or("unknown".to_string()),
                ]);
            }
        }

        Ok(rows)
    }
}
```

- [ ] **Step 2: Add `pub mod storage;` to `src/providers/azure/mod.rs`**

- [ ] **Step 3: Wire into `AzureProviderFactory::csv_collectors()`**

```rust
use crate::providers::azure::storage::StorageCollector;

// in csv_collectors():
if self.is_selected("azure-storage") {
    out.push(Box::new(StorageCollector::new(
        Arc::clone(&self.credential),
        self.subscription_id.clone(),
    )));
}
```

- [ ] **Step 4: Compile check and commit**

Run: `cargo check --features azure 2>&1 | grep 'error'`

```bash
git add src/providers/azure/storage.rs src/providers/azure/mod.rs \
        src/providers/azure/factory.rs
git commit -m "feat(azure): add Storage Accounts CsvCollector (maps to S3)"
```

---

### Task 8: `sql` — Azure SQL Databases

**Maps to:** AWS RDS (`CsvCollector`)

**Files:**
- Create: `src/providers/azure/sql.rs`
- Modify: `src/providers/azure/mod.rs`
- Modify: `src/providers/azure/factory.rs`

Uses `azure_mgmt_sql`. Lists all SQL servers and their databases across the subscription.

- [ ] **Step 1: Create `src/providers/azure/sql.rs`**

```rust
use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use azure_identity::DefaultAzureCredential;
use azure_mgmt_sql::Client as SqlClient;

use crate::evidence::CsvCollector;

pub struct SqlCollector {
    client:          SqlClient,
    subscription_id: String,
}

impl SqlCollector {
    pub fn new(credential: Arc<DefaultAzureCredential>, subscription_id: String) -> Self {
        Self {
            client: SqlClient::new(Arc::clone(&credential)),
            subscription_id,
        }
    }
}

#[async_trait]
impl CsvCollector for SqlCollector {
    fn name(&self) -> &str { "Azure SQL Databases" }
    fn filename_prefix(&self) -> &str { "Azure_SQL_Databases" }

    fn headers(&self) -> &'static [&'static str] {
        &[
            "Server Name",
            "Database Name",
            "Resource Group",
            "Location",
            "SKU",
            "Status",
            "Max Size (GB)",
            "Zone Redundant",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        let mut server_stream = self.client
            .servers_client()
            .list(&self.subscription_id)
            .into_stream();

        while let Some(page) = futures::StreamExt::next(&mut server_stream).await {
            let page = page.context("Azure SQL: server list page failed")?;
            for server in page.value {
                let server_name = server.name.clone().unwrap_or_default();
                let rg = server.id.as_deref()
                    .and_then(|id| id.split("/resourceGroups/").nth(1))
                    .and_then(|s| s.split('/').next())
                    .unwrap_or("")
                    .to_string();

                let mut db_stream = self.client
                    .databases_client()
                    .list_by_server(&self.subscription_id, &rg, &server_name)
                    .into_stream();

                while let Some(db_page) = futures::StreamExt::next(&mut db_stream).await {
                    let db_page = db_page.context("Azure SQL: db list page failed")?;
                    for db in db_page.value {
                        let props = db.properties.as_ref();
                        rows.push(vec![
                            server_name.clone(),
                            db.name.clone().unwrap_or_default(),
                            rg.clone(),
                            db.location.clone().unwrap_or_default(),
                            db.sku.as_ref()
                                .and_then(|s| s.name.clone())
                                .unwrap_or_default(),
                            props.and_then(|p| p.status.as_ref())
                                .map(|s| format!("{:?}", s))
                                .unwrap_or_default(),
                            props.and_then(|p| p.max_size_bytes)
                                .map(|b| (b / 1_073_741_824).to_string())
                                .unwrap_or_default(),
                            props.and_then(|p| p.zone_redundant)
                                .map(|z| z.to_string())
                                .unwrap_or_default(),
                        ]);
                    }
                }
            }
        }

        Ok(rows)
    }
}
```

- [ ] **Step 2: Add `pub mod sql;` to `src/providers/azure/mod.rs`**

- [ ] **Step 3: Wire into `AzureProviderFactory::csv_collectors()`**

```rust
use crate::providers::azure::sql::SqlCollector;

if self.is_selected("azure-sql") {
    out.push(Box::new(SqlCollector::new(
        Arc::clone(&self.credential),
        self.subscription_id.clone(),
    )));
}
```

- [ ] **Step 4: Compile check and commit**

```bash
git add src/providers/azure/sql.rs src/providers/azure/mod.rs \
        src/providers/azure/factory.rs
git commit -m "feat(azure): add SQL Databases CsvCollector (maps to RDS)"
```

---

### Task 9: `aks` — Azure Kubernetes Service

**Maps to:** AWS EKS (`CsvCollector`)

**Files:**
- Create: `src/providers/azure/aks.rs`
- Modify: `src/providers/azure/mod.rs`
- Modify: `src/providers/azure/factory.rs`

Uses `azure_mgmt_containerservice`.

- [ ] **Step 1: Create `src/providers/azure/aks.rs`**

```rust
use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use azure_identity::DefaultAzureCredential;
use azure_mgmt_containerservice::Client as ContainerClient;

use crate::evidence::CsvCollector;

pub struct AksCollector {
    client:          ContainerClient,
    subscription_id: String,
}

impl AksCollector {
    pub fn new(credential: Arc<DefaultAzureCredential>, subscription_id: String) -> Self {
        Self {
            client: ContainerClient::new(Arc::clone(&credential)),
            subscription_id,
        }
    }
}

#[async_trait]
impl CsvCollector for AksCollector {
    fn name(&self) -> &str { "Azure Kubernetes Service (AKS)" }
    fn filename_prefix(&self) -> &str { "Azure_AKS_Clusters" }

    fn headers(&self) -> &'static [&'static str] {
        &[
            "Cluster Name",
            "Resource Group",
            "Location",
            "Kubernetes Version",
            "Provisioning State",
            "RBAC Enabled",
            "Node Count",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        let mut stream = self.client
            .managed_clusters_client()
            .list(&self.subscription_id)
            .into_stream();

        while let Some(page) = futures::StreamExt::next(&mut stream).await {
            let page = page.context("AKS: list page failed")?;
            for cluster in page.value {
                let props = cluster.properties.as_ref();
                let node_count: i32 = props
                    .and_then(|p| p.agent_pool_profiles.as_ref())
                    .map(|pools| pools.iter().filter_map(|p| p.count).sum())
                    .unwrap_or(0);
                let rg = cluster.id.as_deref()
                    .and_then(|id| id.split("/resourceGroups/").nth(1))
                    .and_then(|s| s.split('/').next())
                    .unwrap_or("")
                    .to_string();

                rows.push(vec![
                    cluster.name.clone().unwrap_or_default(),
                    rg,
                    cluster.location.clone().unwrap_or_default(),
                    props.and_then(|p| p.kubernetes_version.clone()).unwrap_or_default(),
                    props.and_then(|p| p.provisioning_state.clone()).unwrap_or_default(),
                    props.and_then(|p| p.enable_rbac)
                        .map(|b| b.to_string())
                        .unwrap_or_default(),
                    node_count.to_string(),
                ]);
            }
        }

        Ok(rows)
    }
}
```

- [ ] **Step 2: Add `pub mod aks;` to `src/providers/azure/mod.rs`**

- [ ] **Step 3: Wire into `AzureProviderFactory::csv_collectors()`**

```rust
use crate::providers::azure::aks::AksCollector;

if self.is_selected("azure-aks") {
    out.push(Box::new(AksCollector::new(
        Arc::clone(&self.credential),
        self.subscription_id.clone(),
    )));
}
```

- [ ] **Step 4: Compile check and commit**

```bash
git add src/providers/azure/aks.rs src/providers/azure/mod.rs \
        src/providers/azure/factory.rs
git commit -m "feat(azure): add AKS CsvCollector (maps to EKS)"
```

---

### Task 10: `acr` — Azure Container Registry

**Maps to:** AWS ECR (`CsvCollector`)

**Files:**
- Create: `src/providers/azure/acr.rs`
- Modify: `src/providers/azure/mod.rs`
- Modify: `src/providers/azure/factory.rs`

Uses `azure_mgmt_containerregistry`.

- [ ] **Step 1: Create `src/providers/azure/acr.rs`**

```rust
use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use azure_identity::DefaultAzureCredential;
use azure_mgmt_containerregistry::Client as AcrClient;

use crate::evidence::CsvCollector;

pub struct AcrCollector {
    client:          AcrClient,
    subscription_id: String,
}

impl AcrCollector {
    pub fn new(credential: Arc<DefaultAzureCredential>, subscription_id: String) -> Self {
        Self {
            client: AcrClient::new(Arc::clone(&credential)),
            subscription_id,
        }
    }
}

#[async_trait]
impl CsvCollector for AcrCollector {
    fn name(&self) -> &str { "Azure Container Registry" }
    fn filename_prefix(&self) -> &str { "Azure_Container_Registries" }

    fn headers(&self) -> &'static [&'static str] {
        &[
            "Registry Name",
            "Resource Group",
            "Location",
            "SKU",
            "Admin User Enabled",
            "Login Server",
            "Provisioning State",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        let mut stream = self.client
            .registries_client()
            .list(&self.subscription_id)
            .into_stream();

        while let Some(page) = futures::StreamExt::next(&mut stream).await {
            let page = page.context("ACR: list page failed")?;
            for reg in page.value {
                let props = reg.properties.as_ref();
                let rg = reg.id.as_deref()
                    .and_then(|id| id.split("/resourceGroups/").nth(1))
                    .and_then(|s| s.split('/').next())
                    .unwrap_or("")
                    .to_string();

                rows.push(vec![
                    reg.name.clone().unwrap_or_default(),
                    rg,
                    reg.location.clone().unwrap_or_default(),
                    reg.sku.as_ref()
                        .and_then(|s| s.name.as_ref())
                        .map(|n| format!("{:?}", n))
                        .unwrap_or_default(),
                    props.and_then(|p| p.admin_user_enabled)
                        .map(|b| b.to_string())
                        .unwrap_or_default(),
                    props.and_then(|p| p.login_server.clone()).unwrap_or_default(),
                    props.and_then(|p| p.provisioning_state.as_ref())
                        .map(|s| format!("{:?}", s))
                        .unwrap_or_default(),
                ]);
            }
        }

        Ok(rows)
    }
}
```

- [ ] **Step 2: Add `pub mod acr;` to `src/providers/azure/mod.rs`**

- [ ] **Step 3: Wire into `AzureProviderFactory::csv_collectors()`**

```rust
use crate::providers::azure::acr::AcrCollector;

if self.is_selected("azure-acr") {
    out.push(Box::new(AcrCollector::new(
        Arc::clone(&self.credential),
        self.subscription_id.clone(),
    )));
}
```

- [ ] **Step 4: Compile check and commit**

```bash
git add src/providers/azure/acr.rs src/providers/azure/mod.rs \
        src/providers/azure/factory.rs
git commit -m "feat(azure): add Container Registry CsvCollector (maps to ECR)"
```

---

### Task 11: `app_service` — Azure App Service

**Maps to:** AWS ECS / Lambda (`CsvCollector`)

**Files:**
- Create: `src/providers/azure/app_service.rs`
- Modify: `src/providers/azure/mod.rs`
- Modify: `src/providers/azure/factory.rs`

Uses `azure_mgmt_web`. Lists Web Apps and Function Apps.

- [ ] **Step 1: Create `src/providers/azure/app_service.rs`**

```rust
use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use azure_identity::DefaultAzureCredential;
use azure_mgmt_web::Client as WebClient;

use crate::evidence::CsvCollector;

pub struct AppServiceCollector {
    client:          WebClient,
    subscription_id: String,
}

impl AppServiceCollector {
    pub fn new(credential: Arc<DefaultAzureCredential>, subscription_id: String) -> Self {
        Self {
            client: WebClient::new(Arc::clone(&credential)),
            subscription_id,
        }
    }
}

#[async_trait]
impl CsvCollector for AppServiceCollector {
    fn name(&self) -> &str { "Azure App Service" }
    fn filename_prefix(&self) -> &str { "Azure_App_Service" }

    fn headers(&self) -> &'static [&'static str] {
        &[
            "App Name",
            "Resource Group",
            "Location",
            "Kind",
            "State",
            "HTTPS Only",
            "Default Host Name",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        let mut stream = self.client
            .web_apps_client()
            .list(&self.subscription_id)
            .into_stream();

        while let Some(page) = futures::StreamExt::next(&mut stream).await {
            let page = page.context("App Service: list page failed")?;
            for app in page.value {
                let props = app.properties.as_ref();
                let rg = app.id.as_deref()
                    .and_then(|id| id.split("/resourceGroups/").nth(1))
                    .and_then(|s| s.split('/').next())
                    .unwrap_or("")
                    .to_string();

                rows.push(vec![
                    app.name.clone().unwrap_or_default(),
                    rg,
                    app.location.clone().unwrap_or_default(),
                    app.kind.clone().unwrap_or_default(),
                    props.and_then(|p| p.state.clone()).unwrap_or_default(),
                    props.and_then(|p| p.https_only)
                        .map(|b| b.to_string())
                        .unwrap_or_default(),
                    props.and_then(|p| p.default_host_name.clone()).unwrap_or_default(),
                ]);
            }
        }

        Ok(rows)
    }
}
```

- [ ] **Step 2: Add `pub mod app_service;` to `src/providers/azure/mod.rs`**

- [ ] **Step 3: Wire into `AzureProviderFactory::csv_collectors()`**

```rust
use crate::providers::azure::app_service::AppServiceCollector;

if self.is_selected("azure-app-service") {
    out.push(Box::new(AppServiceCollector::new(
        Arc::clone(&self.credential),
        self.subscription_id.clone(),
    )));
}
```

- [ ] **Step 4: Compile check and commit**

```bash
git add src/providers/azure/app_service.rs src/providers/azure/mod.rs \
        src/providers/azure/factory.rs
git commit -m "feat(azure): add App Service CsvCollector (maps to ECS/Lambda)"
```

---

## Phase 3: Security and Compliance

### Task 12: `defender` — Microsoft Defender for Cloud

**Maps to:** AWS SecurityHub + GuardDuty (`CsvCollector`)

**Files:**
- Create: `src/providers/azure/defender.rs`
- Modify: `src/providers/azure/mod.rs`
- Modify: `src/providers/azure/factory.rs`

Uses `azure_mgmt_security`. Lists security assessments (findings) and alerts.

- [ ] **Step 1: Create `src/providers/azure/defender.rs`**

```rust
use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use azure_identity::DefaultAzureCredential;
use azure_mgmt_security::Client as SecurityClient;

use crate::evidence::CsvCollector;

pub struct DefenderCollector {
    client:          SecurityClient,
    subscription_id: String,
}

impl DefenderCollector {
    pub fn new(credential: Arc<DefaultAzureCredential>, subscription_id: String) -> Self {
        Self {
            client: SecurityClient::new(Arc::clone(&credential)),
            subscription_id,
        }
    }
}

#[async_trait]
impl CsvCollector for DefenderCollector {
    fn name(&self) -> &str { "Microsoft Defender for Cloud" }
    fn filename_prefix(&self) -> &str { "Azure_Defender_Assessments" }

    fn headers(&self) -> &'static [&'static str] {
        &[
            "Assessment Name",
            "Resource ID",
            "Resource Type",
            "Status",
            "Severity",
            "Category",
            "Description",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();
        let scope = format!("/subscriptions/{}", self.subscription_id);

        let mut stream = self.client
            .assessments_client()
            .list(&scope)
            .into_stream();

        while let Some(page) = futures::StreamExt::next(&mut stream).await {
            let page = page.context("Defender: assessments list page failed")?;
            for assessment in page.value {
                let props = assessment.properties.as_ref();
                let status = props.and_then(|p| p.status.as_ref());
                let metadata = props.and_then(|p| p.metadata.as_ref());

                rows.push(vec![
                    assessment.name.clone().unwrap_or_default(),
                    props.and_then(|p| p.resource_details.as_ref())
                        .and_then(|r| r.id.clone())
                        .unwrap_or_default(),
                    props.and_then(|p| p.resource_details.as_ref())
                        .and_then(|r| r.source.as_ref())
                        .map(|s| format!("{:?}", s))
                        .unwrap_or_default(),
                    status.and_then(|s| s.code.as_ref())
                        .map(|c| format!("{:?}", c))
                        .unwrap_or_default(),
                    metadata.and_then(|m| m.severity.as_ref())
                        .map(|s| format!("{:?}", s))
                        .unwrap_or_default(),
                    metadata.and_then(|m| m.categories.as_ref())
                        .map(|c| c.iter().map(|x| format!("{:?}", x)).collect::<Vec<_>>().join(", "))
                        .unwrap_or_default(),
                    metadata.and_then(|m| m.description.clone()).unwrap_or_default(),
                ]);
            }
        }

        Ok(rows)
    }
}
```

- [ ] **Step 2: Add `pub mod defender;` to `src/providers/azure/mod.rs`**

- [ ] **Step 3: Wire into `AzureProviderFactory::csv_collectors()`**

```rust
use crate::providers::azure::defender::DefenderCollector;

if self.is_selected("azure-defender") {
    out.push(Box::new(DefenderCollector::new(
        Arc::clone(&self.credential),
        self.subscription_id.clone(),
    )));
}
```

- [ ] **Step 4: Compile check and commit**

```bash
git add src/providers/azure/defender.rs src/providers/azure/mod.rs \
        src/providers/azure/factory.rs
git commit -m "feat(azure): add Defender for Cloud CsvCollector (maps to SecurityHub/GuardDuty)"
```

---

### Task 13: `key_vault` — Azure Key Vault

**Maps to:** AWS KMS + SecretsManager (`JsonCollector`)

**Files:**
- Create: `src/providers/azure/key_vault.rs`
- Modify: `src/providers/azure/mod.rs`
- Modify: `src/providers/azure/factory.rs`

Uses `azure_mgmt_keyvault` to list vaults and `azure_mgmt_resources` to enumerate
resources within each vault.

- [ ] **Step 1: Create `src/providers/azure/key_vault.rs`**

```rust
use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use azure_identity::DefaultAzureCredential;
use azure_mgmt_keyvault::Client as KeyVaultClient;
use serde_json::{json, Value};

use crate::evidence::JsonCollector;

pub struct KeyVaultCollector {
    client:          KeyVaultClient,
    subscription_id: String,
}

impl KeyVaultCollector {
    pub fn new(credential: Arc<DefaultAzureCredential>, subscription_id: String) -> Self {
        Self {
            client: KeyVaultClient::new(Arc::clone(&credential)),
            subscription_id,
        }
    }
}

#[async_trait]
impl JsonCollector for KeyVaultCollector {
    fn name(&self) -> &str { "Azure Key Vault" }
    fn filename_prefix(&self) -> &str { "Azure_Key_Vaults" }

    async fn collect_records(&self, _account_id: &str, _region: &str) -> Result<Vec<Value>> {
        let mut records = Vec::new();

        let mut stream = self.client
            .vaults_client()
            .list_by_subscription(&self.subscription_id, None)
            .into_stream();

        while let Some(page) = futures::StreamExt::next(&mut stream).await {
            let page = page.context("Key Vault: list page failed")?;
            for vault in page.value {
                let vault_val = serde_json::to_value(&vault).unwrap_or(Value::Null);
                records.push(json!({
                    "vault": vault_val,
                }));
            }
        }

        Ok(records)
    }
}
```

- [ ] **Step 2: Add `pub mod key_vault;` to `src/providers/azure/mod.rs`**

- [ ] **Step 3: Wire into `AzureProviderFactory::json_collectors()`**

```rust
use crate::providers::azure::key_vault::KeyVaultCollector;

if self.is_selected("azure-key-vault") {
    out.push(Box::new(KeyVaultCollector::new(
        Arc::clone(&self.credential),
        self.subscription_id.clone(),
    )));
}
```

- [ ] **Step 4: Compile check and commit**

```bash
git add src/providers/azure/key_vault.rs src/providers/azure/mod.rs \
        src/providers/azure/factory.rs
git commit -m "feat(azure): add Key Vault JsonCollector (maps to KMS/SecretsManager)"
```

---

### Task 14: `policy` — Azure Policy Assignments and Compliance

**Maps to:** AWS Config Rules + SCPs (`JsonCollector`)

**Files:**
- Create: `src/providers/azure/policy.rs`
- Modify: `src/providers/azure/mod.rs`
- Modify: `src/providers/azure/factory.rs`

Uses `azure_mgmt_policyinsights` for compliance state and `azure_mgmt_resources`
(policy client) for policy assignments and definitions.

- [ ] **Step 1: Create `src/providers/azure/policy.rs`**

```rust
use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use azure_identity::DefaultAzureCredential;
use azure_mgmt_policyinsights::Client as PolicyInsightsClient;
use serde_json::{json, Value};

use crate::evidence::JsonCollector;

pub struct PolicyCollector {
    client:          PolicyInsightsClient,
    subscription_id: String,
}

impl PolicyCollector {
    pub fn new(credential: Arc<DefaultAzureCredential>, subscription_id: String) -> Self {
        Self {
            client: PolicyInsightsClient::new(Arc::clone(&credential)),
            subscription_id,
        }
    }
}

#[async_trait]
impl JsonCollector for PolicyCollector {
    fn name(&self) -> &str { "Azure Policy Compliance" }
    fn filename_prefix(&self) -> &str { "Azure_Policy_Compliance" }

    async fn collect_records(&self, _account_id: &str, _region: &str) -> Result<Vec<Value>> {
        let mut records = Vec::new();

        // Query latest non-compliant policy states at subscription scope
        let mut stream = self.client
            .policy_states_client()
            .list_query_results_for_subscription(
                "latest",
                &self.subscription_id,
                None, None, None, None, None, None, None,
            )
            .into_stream();

        while let Some(page) = futures::StreamExt::next(&mut stream).await {
            let page = page.context("Azure Policy: compliance query failed")?;
            for state in page.value {
                let val = serde_json::to_value(&state).unwrap_or(Value::Null);
                records.push(val);
            }
        }

        Ok(records)
    }
}
```

- [ ] **Step 2: Add `pub mod policy;` to `src/providers/azure/mod.rs`**

- [ ] **Step 3: Wire into `AzureProviderFactory::json_collectors()`**

```rust
use crate::providers::azure::policy::PolicyCollector;

if self.is_selected("azure-policy") {
    out.push(Box::new(PolicyCollector::new(
        Arc::clone(&self.credential),
        self.subscription_id.clone(),
    )));
}
```

- [ ] **Step 4: Compile check and commit**

```bash
git add src/providers/azure/policy.rs src/providers/azure/mod.rs \
        src/providers/azure/factory.rs
git commit -m "feat(azure): add Policy Compliance JsonCollector (maps to Config Rules/SCPs)"
```

---

### Task 15: `nsg` — Network Security Groups

**Maps to:** AWS Security Groups + NACLs (`CsvCollector`)

**Files:**
- Create: `src/providers/azure/nsg.rs`
- Modify: `src/providers/azure/mod.rs`
- Modify: `src/providers/azure/factory.rs`

Uses `azure_mgmt_network`.

- [ ] **Step 1: Create `src/providers/azure/nsg.rs`**

```rust
use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use azure_identity::DefaultAzureCredential;
use azure_mgmt_network::Client as NetworkClient;

use crate::evidence::CsvCollector;

pub struct NsgCollector {
    client:          NetworkClient,
    subscription_id: String,
}

impl NsgCollector {
    pub fn new(credential: Arc<DefaultAzureCredential>, subscription_id: String) -> Self {
        Self {
            client: NetworkClient::new(Arc::clone(&credential)),
            subscription_id,
        }
    }
}

#[async_trait]
impl CsvCollector for NsgCollector {
    fn name(&self) -> &str { "Azure Network Security Groups" }
    fn filename_prefix(&self) -> &str { "Azure_Network_Security_Groups" }

    fn headers(&self) -> &'static [&'static str] {
        &[
            "NSG Name",
            "Resource Group",
            "Location",
            "Rule Name",
            "Direction",
            "Protocol",
            "Source",
            "Destination",
            "Destination Port",
            "Access",
            "Priority",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        let mut stream = self.client
            .network_security_groups_client()
            .list_all(&self.subscription_id)
            .into_stream();

        while let Some(page) = futures::StreamExt::next(&mut stream).await {
            let page = page.context("NSG: list_all page failed")?;
            for nsg in page.value {
                let nsg_name = nsg.name.clone().unwrap_or_default();
                let location = nsg.location.clone().unwrap_or_default();
                let rg = nsg.id.as_deref()
                    .and_then(|id| id.split("/resourceGroups/").nth(1))
                    .and_then(|s| s.split('/').next())
                    .unwrap_or("")
                    .to_string();

                let rules = nsg.properties
                    .as_ref()
                    .and_then(|p| p.security_rules.as_ref())
                    .cloned()
                    .unwrap_or_default();

                for rule in &rules {
                    let rp = rule.properties.as_ref();
                    rows.push(vec![
                        nsg_name.clone(),
                        rg.clone(),
                        location.clone(),
                        rule.name.clone().unwrap_or_default(),
                        rp.and_then(|p| p.direction.as_ref()).map(|d| format!("{:?}", d)).unwrap_or_default(),
                        rp.and_then(|p| p.protocol.as_ref()).map(|p| format!("{:?}", p)).unwrap_or_default(),
                        rp.and_then(|p| p.source_address_prefix.clone()).unwrap_or_default(),
                        rp.and_then(|p| p.destination_address_prefix.clone()).unwrap_or_default(),
                        rp.and_then(|p| p.destination_port_range.clone()).unwrap_or_default(),
                        rp.and_then(|p| p.access.as_ref()).map(|a| format!("{:?}", a)).unwrap_or_default(),
                        rp.and_then(|p| p.priority).map(|p| p.to_string()).unwrap_or_default(),
                    ]);
                }
            }
        }

        Ok(rows)
    }
}
```

- [ ] **Step 2: Add `pub mod nsg;` to `src/providers/azure/mod.rs`**

- [ ] **Step 3: Wire into `AzureProviderFactory::csv_collectors()`**

```rust
use crate::providers::azure::nsg::NsgCollector;

if self.is_selected("azure-nsg") {
    out.push(Box::new(NsgCollector::new(
        Arc::clone(&self.credential),
        self.subscription_id.clone(),
    )));
}
```

- [ ] **Step 4: Compile check and commit**

```bash
git add src/providers/azure/nsg.rs src/providers/azure/mod.rs \
        src/providers/azure/factory.rs
git commit -m "feat(azure): add NSG CsvCollector (maps to Security Groups/NACLs)"
```

---

### Task 16: `monitor_alerts` — Azure Monitor Alerts

**Maps to:** AWS CloudWatch Alarms (`CsvCollector`)

**Files:**
- Create: `src/providers/azure/monitor_alerts.rs`
- Modify: `src/providers/azure/mod.rs`
- Modify: `src/providers/azure/factory.rs`

Uses `azure_mgmt_monitor` (same SDK crate as `activity_log`).

- [ ] **Step 1: Create `src/providers/azure/monitor_alerts.rs`**

```rust
use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use azure_identity::DefaultAzureCredential;
use azure_mgmt_monitor::Client as MonitorClient;

use crate::evidence::CsvCollector;

pub struct MonitorAlertsCollector {
    client:          MonitorClient,
    subscription_id: String,
}

impl MonitorAlertsCollector {
    pub fn new(credential: Arc<DefaultAzureCredential>, subscription_id: String) -> Self {
        Self {
            client: MonitorClient::new(Arc::clone(&credential)),
            subscription_id,
        }
    }
}

#[async_trait]
impl CsvCollector for MonitorAlertsCollector {
    fn name(&self) -> &str { "Azure Monitor Alert Rules" }
    fn filename_prefix(&self) -> &str { "Azure_Monitor_Alert_Rules" }

    fn headers(&self) -> &'static [&'static str] {
        &[
            "Alert Name",
            "Resource Group",
            "Location",
            "Severity",
            "Enabled",
            "Description",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let mut rows = Vec::new();

        let mut stream = self.client
            .metric_alerts_client()
            .list_by_subscription(&self.subscription_id)
            .into_stream();

        while let Some(page) = futures::StreamExt::next(&mut stream).await {
            let page = page.context("Monitor Alerts: list page failed")?;
            for alert in page.value {
                let props = alert.properties.as_ref();
                let rg = alert.id.as_deref()
                    .and_then(|id| id.split("/resourceGroups/").nth(1))
                    .and_then(|s| s.split('/').next())
                    .unwrap_or("")
                    .to_string();

                rows.push(vec![
                    alert.name.clone().unwrap_or_default(),
                    rg,
                    alert.location.clone().unwrap_or_default(),
                    props.and_then(|p| p.severity)
                        .map(|s| s.to_string())
                        .unwrap_or_default(),
                    props.and_then(|p| p.enabled)
                        .map(|e| e.to_string())
                        .unwrap_or_default(),
                    props.and_then(|p| p.description.clone()).unwrap_or_default(),
                ]);
            }
        }

        Ok(rows)
    }
}
```

- [ ] **Step 2: Add `pub mod monitor_alerts;` to `src/providers/azure/mod.rs`**

- [ ] **Step 3: Wire into `AzureProviderFactory::csv_collectors()`**

```rust
use crate::providers::azure::monitor_alerts::MonitorAlertsCollector;

if self.is_selected("azure-monitor-alerts") {
    out.push(Box::new(MonitorAlertsCollector::new(
        Arc::clone(&self.credential),
        self.subscription_id.clone(),
    )));
}
```

- [ ] **Step 4: Compile check and commit**

```bash
git add src/providers/azure/monitor_alerts.rs src/providers/azure/mod.rs \
        src/providers/azure/factory.rs
git commit -m "feat(azure): add Monitor Alert Rules CsvCollector (maps to CloudWatch Alarms)"
```

---

## Final Wiring: `app_config.rs` and Registration

### Task 17: Verify `app_config.rs` Azure Fields

**Files:**
- Read: `src/app_config.rs`

- [ ] **Step 1: Check that `Account` already has `tenant_id`, `subscription_id`, `region` for Azure**

Run: `grep -n 'tenant_id\|subscription_id\|region\|provider' src/app_config.rs`

Expected: all three fields exist under the Azure section. If any are missing, add them following the pattern from Phase 1.5 in `docs/plans/multi-provider-refactor.md`.

- [ ] **Step 2: Verify `provider` field defaults to `Aws` if absent**

Run: `grep -n 'default_provider\|fn default' src/app_config.rs`

Expected: `fn default_provider() -> CloudProvider { CloudProvider::Aws }` exists.

If missing, add:

```rust
#[serde(default = "default_provider")]
pub provider: CloudProvider,

fn default_provider() -> CloudProvider { CloudProvider::Aws }
```

- [ ] **Step 3: Compile check with full features**

Run: `cargo check --features azure 2>&1 | grep 'error'`

Expected: zero errors.

---

### Task 18: Full End-to-End Compile Verification

- [ ] **Step 1: Build with `--features azure`**

Run: `cargo build --features azure 2>&1 | tail -5`

Expected: `Finished` line, zero errors.

- [ ] **Step 2: Build without `--features azure` (verify no regression)**

Run: `cargo build 2>&1 | tail -5`

Expected: `Finished` line, zero errors.

- [ ] **Step 3: Run clippy on azure feature**

Run: `cargo clippy --features azure -- -D warnings 2>&1 | head -40`

Fix any warnings before committing. Common issues: unused imports, dead code from stubs.

- [ ] **Step 4: Final commit**

```bash
git add src/providers/azure/mod.rs src/providers/azure/factory.rs
git commit -m "feat(azure): complete Phase 1-3 Azure collector wiring in AzureProviderFactory"
```

---

## Verification Checklist

### Per-Phase Checks

**Phase 1 (Identity & Logging) — after Tasks 2–5:**
- `cargo build --features azure` is green
- `activity_log` produces `Azure_Activity_Log` JSON output file when run against a test subscription
- `entra_id` produces `Azure_Entra_ID` JSON with `users`, `groups`, `service_principals` sections
- `rbac` produces `Azure_RBAC_Role_Assignments` JSON with both assignments and definitions
- `conditional_access` produces `Azure_Conditional_Access_Policies` JSON

**Phase 2 (Compute & Storage) — after Tasks 6–11:**
- `virtual_machines` CSV has all 8 columns, one row per VM
- `storage` CSV includes `HTTPS Only` and `Allow Blob Public Access` columns
- `sql` CSV lists databases nested under servers
- `aks` CSV includes `RBAC Enabled` column
- `acr` CSV includes `Admin User Enabled` column

**Phase 3 (Security & Compliance) — after Tasks 12–16:**
- `defender` CSV matches assessments visible in Azure Portal > Defender for Cloud
- `key_vault` JSON wraps vault properties
- `policy` JSON lists non-compliant resource states
- `nsg` CSV has one row per security rule (not per NSG)
- `monitor_alerts` CSV includes all metric alert rules

### Regression Guard
- `cargo build` (no features) is green after every task
- AWS collectors produce identical output before and after all Azure work — they share no code paths

---

## Collector Key Reference

| Selector Key | Module | Trait | Maps To |
|---|---|---|---|
| `azure-activity-log` | `activity_log` | `EvidenceCollector` | CloudTrail |
| `azure-entra-id` | `entra_id` | `JsonCollector` | IAM |
| `azure-rbac` | `rbac` | `JsonCollector` | IAM Policies |
| `azure-conditional-access` | `conditional_access` | `JsonCollector` | IAM Conditions |
| `azure-virtual-machines` | `virtual_machines` | `CsvCollector` | EC2 |
| `azure-storage` | `storage` | `CsvCollector` | S3 |
| `azure-sql` | `sql` | `CsvCollector` | RDS |
| `azure-aks` | `aks` | `CsvCollector` | EKS |
| `azure-acr` | `acr` | `CsvCollector` | ECR |
| `azure-app-service` | `app_service` | `CsvCollector` | ECS/Lambda |
| `azure-defender` | `defender` | `CsvCollector` | SecurityHub + GuardDuty |
| `azure-key-vault` | `key_vault` | `JsonCollector` | KMS + SecretsManager |
| `azure-policy` | `policy` | `JsonCollector` | Config Rules + SCPs |
| `azure-nsg` | `nsg` | `CsvCollector` | Security Groups + NACLs |
| `azure-monitor-alerts` | `monitor_alerts` | `CsvCollector` | CloudWatch Alarms |
