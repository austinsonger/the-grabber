# GCP Collector Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement GCP provider support in The Grabber, bringing it to feature parity with the existing 84-collector AWS provider for FedRAMP-aligned compliance evidence collection.

**Architecture:** `GcpProviderFactory` (already stubbed at `src/providers/gcp/factory.rs`) is promoted from an empty shell to a fully wired factory: it authenticates via `google-cloud-auth` Application Default Credentials, constructs a shared `GcpClient` (thin `reqwest` wrapper with Bearer-token injection), and hands collector instances to the `CollectorRegistry`. All GCP code is gated behind `#[cfg(feature = "gcp")]`. Collectors call GCP REST APIs directly; no per-service GCP SDK crates are added.

**Tech Stack:** `google-cloud-auth 0.7` (ADC / service account token acquisition), `reqwest 0.12` (HTTP, already a transitive dep), `serde_json 1` (response deserialization), `async-trait 0.1`, `anyhow 1`.

---

## Service Mapping Table

Maps each of the 84 existing AWS collector modules to its GCP equivalent service, REST API, and planned GCP module name.

| AWS Collector | GCP Equivalent Service | GCP REST API Base | GCP Module Name |
|---|---|---|---|
| `access_analyzer` | IAM Policy Analyzer / SCC | `iam.googleapis.com/v1` | `iam_policy_analyzer` |
| `account_config` | Cloud Resource Manager | `cloudresourcemanager.googleapis.com/v3` | `resource_manager` |
| `acm` | Certificate Manager | `certificatemanager.googleapis.com/v1` | `certificate_manager` |
| `alb_logs` | Cloud Load Balancing Logs | `logging.googleapis.com/v2` | `lb_logs` |
| `apigateway` | API Gateway / Cloud Endpoints | `apigateway.googleapis.com/v1` | `api_gateway` |
| `autoscaling` | Managed Instance Groups | `compute.googleapis.com/compute/v1` | `managed_instance_groups` |
| `backup` | Backup and DR Service | `backupdr.googleapis.com/v1` | `backup` |
| `backup_config` | Backup Plans / policies | `backupdr.googleapis.com/v1` | `backup_config` |
| `cloudformation_drift` | Cloud Deployment Manager | `deploymentmanager.googleapis.com/v2` | `deployment_manager` |
| `cloudfront` | Cloud CDN + Cloud Armor | `compute.googleapis.com/compute/v1` | `cloud_cdn` |
| `cloudtrail` | Cloud Audit Logs (Admin Activity) | `logging.googleapis.com/v2` | `cloud_audit_logs` |
| `cloudtrail_config` | Audit Logs config / log sinks | `logging.googleapis.com/v2` | `audit_logs_config` |
| `cloudtrail_iam` | Audit Logs — IAM events filter | `logging.googleapis.com/v2` | `audit_logs_iam` |
| `cloudtrail_inventory` | Cloud Asset Inventory | `cloudasset.googleapis.com/v1` | `asset_inventory` |
| `cloudtrail_s3` | Audit Logs via GCS export | `logging.googleapis.com/v2` | `audit_logs_gcs` |
| `cloudwatch` | Cloud Monitoring metrics | `monitoring.googleapis.com/v3` | `cloud_monitoring` |
| `cloudwatch_alarms` | Alerting policies | `monitoring.googleapis.com/v3` | `alerting_policies` |
| `cloudwatch_config` | Monitoring notification channels | `monitoring.googleapis.com/v3` | `monitoring_config` |
| `cloudwatch_resources` | Monitored resource descriptors | `monitoring.googleapis.com/v3` | `monitoring_resources` |
| `config_history` | Asset Inventory — change history | `cloudasset.googleapis.com/v1` | `asset_change_history` |
| `config_rules` | Org Policy constraints | `orgpolicy.googleapis.com/v2` | `org_policy` |
| `config_timeline` | Asset Inventory — temporal assets | `cloudasset.googleapis.com/v1` | `asset_timeline` |
| `dynamodb` | Firestore / Spanner / Bigtable | `firestore.googleapis.com/v1` | `firestore` |
| `ebs` | Persistent Disk | `compute.googleapis.com/compute/v1` | `persistent_disk` |
| `ec2_config` | Compute Engine instance config | `compute.googleapis.com/compute/v1` | `compute_config` |
| `ec2_detailed` | Compute Engine detailed instances | `compute.googleapis.com/compute/v1` | `compute_detailed` |
| `ec2_inventory` | Compute Engine inventory | `compute.googleapis.com/compute/v1` | `compute_inventory` |
| `ecr` | Artifact Registry repositories | `artifactregistry.googleapis.com/v1` | `artifact_registry` |
| `ecr_config` | Artifact Registry config | `artifactregistry.googleapis.com/v1` | `artifact_registry_config` |
| `ecs` | Cloud Run services | `run.googleapis.com/v2` | `cloud_run` |
| `efs` | Filestore instances | `file.googleapis.com/v1` | `filestore` |
| `eks` | GKE clusters | `container.googleapis.com/v1` | `gke` |
| `elasticache` | Memorystore (Redis) | `redis.googleapis.com/v1` | `memorystore` |
| `elb` | Cloud Load Balancing | `compute.googleapis.com/compute/v1` | `load_balancing` |
| `elb_config` | Load Balancing config | `compute.googleapis.com/compute/v1` | `load_balancing_config` |
| `guardduty` | Security Command Center — threats | `securitycenter.googleapis.com/v1` | `scc_findings` |
| `guardduty_config` | SCC settings | `securitycenter.googleapis.com/v1` | `scc_config` |
| `iam_certs` | Service account keys | `iam.googleapis.com/v1` | `iam_service_account_keys` |
| `iam_inventory` | IAM bindings & members | `cloudresourcemanager.googleapis.com/v1` | `iam_inventory` |
| `iam_policies` | IAM policies (project + org) | `cloudresourcemanager.googleapis.com/v1` | `iam_policies` |
| `iam_trusts` | Service accounts (workload identity) | `iam.googleapis.com/v1` | `iam_service_accounts` |
| `inspector` | SCC vulnerabilities / Container Analysis | `securitycenter.googleapis.com/v1` | `scc_vulnerabilities` |
| `inspector_config` | SCC notification config | `securitycenter.googleapis.com/v1` | `scc_notification_config` |
| `inspector_ecr` | Artifact Registry vulnerability scanning | `artifactregistry.googleapis.com/v1` | `artifact_registry_scanning` |
| `inspector_history` | SCC findings history | `securitycenter.googleapis.com/v1` | `scc_findings_history` |
| `inspector_sbom` | Software Delivery Shield SBOM | `containeranalysis.googleapis.com/v1` | `sbom` |
| `kms` | Cloud KMS key rings and keys | `cloudkms.googleapis.com/v1` | `kms` |
| `kms_config` | Cloud KMS config | `cloudkms.googleapis.com/v1` | `kms_config` |
| `kms_policies` | Cloud KMS IAM policies | `cloudkms.googleapis.com/v1` | `kms_policies` |
| `lambda_config` | Cloud Functions config | `cloudfunctions.googleapis.com/v2` | `cloud_functions` |
| `launch_templates` | Compute instance templates | `compute.googleapis.com/compute/v1` | `instance_templates` |
| `macie` | Cloud DLP inspect templates | `dlp.googleapis.com/v2` | `cloud_dlp` |
| `network_gateways` | Cloud NAT / VPN / Cloud Router | `compute.googleapis.com/compute/v1` | `network_gateways` |
| `org_config` | Resource Manager org policies | `orgpolicy.googleapis.com/v2` | `org_config` |
| `organizations` | Resource Manager org structure | `cloudresourcemanager.googleapis.com/v3` | `organizations` |
| `public_resources` | VPC Service Controls / public assets | `accesscontextmanager.googleapis.com/v1` | `vpc_service_controls` |
| `rds` | Cloud SQL instances | `sqladmin.googleapis.com/sql/v1beta4` | `cloud_sql` |
| `rds_inventory` | Cloud SQL inventory | `sqladmin.googleapis.com/sql/v1beta4` | `cloud_sql_inventory` |
| `rds_snapshots` | Cloud SQL backups | `sqladmin.googleapis.com/sql/v1beta4` | `cloud_sql_backups` |
| `route53_config` | Cloud DNS managed zones | `dns.googleapis.com/dns/v1` | `cloud_dns` |
| `s3_config` | Cloud Storage bucket config | `storage.googleapis.com/storage/v1` | `cloud_storage_config` |
| `s3_detail` | Cloud Storage bucket details | `storage.googleapis.com/storage/v1` | `cloud_storage_detail` |
| `s3_inventory` | Cloud Storage inventory | `storage.googleapis.com/storage/v1` | `cloud_storage_inventory` |
| `s3_policies` | Cloud Storage IAM / bucket policies | `storage.googleapis.com/storage/v1` | `cloud_storage_policies` |
| `secrets_extended` | Secret Manager extended metadata | `secretmanager.googleapis.com/v1` | `secret_manager_extended` |
| `secretsmanager` | Secret Manager secrets | `secretmanager.googleapis.com/v1` | `secret_manager` |
| `security_svc_config` | SCC organization settings | `securitycenter.googleapis.com/v1` | `scc_org_settings` |
| `securityhub` | SCC findings (all categories) | `securitycenter.googleapis.com/v1` | `scc_all_findings` |
| `securityhub_standards` | SCC compliance standards | `securitycenter.googleapis.com/v1` | `scc_standards` |
| `sns` | Pub/Sub topics | `pubsub.googleapis.com/v1` | `pubsub_topics` |
| `sns_eventbridge` | Pub/Sub + Eventarc triggers | `eventarc.googleapis.com/v1` | `eventarc` |
| `ssm` | OS Config patch management | `osconfig.googleapis.com/v1` | `os_config` |
| `ssm_extended` | OS Config extended inventory | `osconfig.googleapis.com/v1` | `os_config_extended` |
| `ssm_patch_detail` | OS patch compliance details | `osconfig.googleapis.com/v1` | `os_patch_detail` |
| `tagging_config` | Cloud Asset Inventory labels | `cloudasset.googleapis.com/v1` | `asset_labels` |
| `vpc` | VPC networks | `compute.googleapis.com/compute/v1` | `vpc` |
| `vpc_endpoints` | Private Service Connect | `compute.googleapis.com/compute/v1` | `private_service_connect` |
| `vpcflowlogs` | VPC Flow Logs | `logging.googleapis.com/v2` | `vpc_flow_logs` |
| `waf` | Cloud Armor security policies | `compute.googleapis.com/compute/v1` | `cloud_armor` |
| `waf_full_config` | Cloud Armor full config | `compute.googleapis.com/compute/v1` | `cloud_armor_config` |
| `waf_logging` | Cloud Armor request logging | `logging.googleapis.com/v2` | `cloud_armor_logs` |

---

## File Structure

### New files (all under `#[cfg(feature = "gcp")]`)

```
src/providers/gcp/
├── mod.rs                      ← already exists; add submodule declarations as collectors land
├── factory.rs                  ← already exists; promote from stub to real implementation
├── client.rs                   ← NEW: GcpClient (reqwest + Bearer token injection)
│
│── Phase 2 — Core Infrastructure (high-impact, FedRAMP-aligned)
├── iam_policies.rs             ← IAM policy bindings (getIamPolicy)
├── iam_service_accounts.rs     ← Service account enumeration
├── iam_service_account_keys.rs ← Service account key enumeration
├── iam_inventory.rs            ← Full IAM binding inventory
├── compute_inventory.rs        ← Compute Engine instance list (all zones)
├── compute_config.rs           ← Compute instance config detail
├── cloud_storage_config.rs     ← GCS bucket config (versioning, logging, retention)
├── cloud_storage_policies.rs   ← GCS bucket IAM policies
├── cloud_storage_inventory.rs  ← GCS bucket inventory
├── cloud_audit_logs.rs         ← Admin Activity log entries (EvidenceCollector)
├── audit_logs_config.rs        ← Log sinks, exclusions, bucket config
├── kms.rs                      ← KMS key rings and keys
├── kms_policies.rs             ← KMS key IAM policies
│
│── Phase 3 — Extended Coverage
├── scc_findings.rs             ← Security Command Center all findings
├── scc_config.rs               ← SCC org settings + notification config
├── scc_vulnerabilities.rs      ← SCC vulnerability findings
├── scc_standards.rs            ← SCC compliance standard activations
├── cloud_sql.rs                ← Cloud SQL instance inventory
├── cloud_sql_backups.rs        ← Cloud SQL backup inventory
├── gke.rs                      ← GKE cluster list
├── secret_manager.rs           ← Secret Manager secret list
├── secret_manager_extended.rs  ← Secret Manager versions + metadata
├── cloud_functions.rs          ← Cloud Functions v2 inventory
├── cloud_run.rs                ← Cloud Run services
├── org_policy.rs               ← Org Policy constraints
├── organizations.rs            ← Resource Manager org/folder/project structure
├── vpc.rs                      ← VPC networks and subnets
├── vpc_flow_logs.rs            ← VPC Flow Log configuration
├── cloud_dns.rs                ← Cloud DNS managed zones
├── pubsub_topics.rs            ← Pub/Sub topics
├── cloud_armor.rs              ← Cloud Armor security policies
├── asset_inventory.rs          ← Cloud Asset Inventory bulk export
└── cloud_monitoring.rs         ← Cloud Monitoring alerting policies
```

### Modified files

| File | Change |
|---|---|
| `src/providers/gcp/factory.rs` | Replace stub with `GcpClient`-bearing real factory |
| `src/providers/gcp/mod.rs` | Add `pub mod` for each collector as it lands |
| `src/evidence.rs` | Add `GcpIam`, `GcpCompute`, `GcpStorage`, etc. variants to `EvidenceSource` |
| `src/app_config.rs` | Already has `project_id`; add `organization_id`, `location` fields |
| `src/cli.rs` | Add `--provider` flag, `--gcp-project`, `--gcp-location` |
| `src/runner/multi_account.rs` | Add GCP branch to account dispatch |

---

## Phase 1 — Foundation: Credential Loading & GCP HTTP Client

### Task 1: Add `reqwest` as explicit GCP dependency and verify `google-cloud-auth` API

**Files:**
- Modify: `Cargo.toml`

The `google-cloud-auth` crate's token source requires knowing the API scope. Verify the 0.7 interface before writing collectors.

- [ ] **Step 1.1: Check what `google-cloud-auth 0.7` actually exports**

```bash
cd /Users/austin-songer/code/grabber
cargo add google-cloud-auth --optional --features default 2>/dev/null || true
cargo metadata --features gcp --format-version 1 | python3 -c "
import sys, json
m = json.load(sys.stdin)
for p in m['packages']:
    if 'google-cloud-auth' in p['name']:
        print(p['name'], p['version'])
        for t in p['targets']:
            print(' ', t['name'])
" 2>/dev/null || echo "check crate manually"
```

- [ ] **Step 1.2: Update `Cargo.toml` — add `reqwest` as an explicit optional GCP dep**

The `reqwest` crate is already a transitive dependency. Make it explicit so GCP code can depend on it:

```toml
# Cargo.toml — in the [dependencies] block, add inside the GCP comment block:
# GCP — only compiled with `--features gcp`
google-cloud-auth = { version = "0.7", optional = true }
reqwest = { version = "0.12", features = ["json", "rustls-tls"], default-features = false, optional = true }
```

Update `[features]`:
```toml
gcp = ["dep:google-cloud-auth", "dep:reqwest"]
```

> **Note:** If `reqwest` is already a non-optional dep (check the `[dependencies]` block), skip the `optional = true` — it is already available to all features.

- [ ] **Step 1.3: Verify build with no regressions**

```bash
cargo build --features gcp 2>&1 | head -30
```

Expected: compiles (GCP modules are empty stubs).

- [ ] **Step 1.4: Commit**

```bash
git add Cargo.toml Cargo.lock
git commit -m "feat(gcp): make reqwest explicit optional dep for gcp feature"
```

---

### Task 2: Implement `GcpClient` — shared HTTP client with token injection

**Files:**
- Create: `src/providers/gcp/client.rs`
- Modify: `src/providers/gcp/mod.rs`

This client is the GCP equivalent of Tenable's `TenableClient`. All GCP collectors receive a cloned `GcpClient` and never touch `google-cloud-auth` or `reqwest` directly.

- [ ] **Step 2.1: Create `src/providers/gcp/client.rs`**

```rust
//! Shared GCP HTTP client: handles Application Default Credentials and Bearer
//! token injection for all GCP REST API calls.

use anyhow::{Context, Result};
use reqwest::{Client, Response};
use std::sync::Arc;
use tokio::sync::RwLock;

#[cfg(feature = "gcp")]
use google_cloud_auth::{
    project::Config,
    token::DefaultTokenSourceProvider,
    TokenSourceProvider,
};

/// Cheaply cloneable (Arc-wrapped) HTTP client pre-configured with GCP auth.
#[derive(Clone)]
pub struct GcpClient {
    inner: Arc<GcpClientInner>,
}

struct GcpClientInner {
    http: Client,
    /// Cached Bearer token — refreshed when expired.
    token: RwLock<Option<String>>,
    #[cfg(feature = "gcp")]
    token_source: Box<dyn google_cloud_auth::TokenSource + Send + Sync>,
}

impl GcpClient {
    /// Build from Application Default Credentials (env GOOGLE_APPLICATION_CREDENTIALS,
    /// workload identity, or `gcloud auth application-default login`).
    pub async fn from_adc() -> Result<Self> {
        let config = Config {
            audience: None,
            scopes: Some(&["https://www.googleapis.com/auth/cloud-platform"]),
            sub: None,
        };
        let provider = DefaultTokenSourceProvider::new(config)
            .await
            .context("Failed to initialize GCP Application Default Credentials. \
                      Run `gcloud auth application-default login` or set \
                      GOOGLE_APPLICATION_CREDENTIALS to a service account key file.")?;
        let token_source = provider.token_source();
        let http = Client::builder()
            .user_agent("the-grabber/gcp")
            .build()
            .context("Failed to build reqwest client")?;

        Ok(Self {
            inner: Arc::new(GcpClientInner {
                http,
                token: RwLock::new(None),
                token_source,
            }),
        })
    }

    /// Fetch a fresh Bearer token (cached; refreshed automatically when None).
    async fn bearer_token(&self) -> Result<String> {
        // Fast path: token already cached
        {
            let guard = self.inner.token.read().await;
            if let Some(t) = guard.as_deref() {
                return Ok(t.to_owned());
            }
        }
        // Slow path: fetch new token
        let token = self.inner.token_source.token().await
            .context("Failed to acquire GCP Bearer token")?;
        let access = token.access_token.clone();
        *self.inner.token.write().await = Some(access.clone());
        Ok(access)
    }

    /// GET `url` with a GCP Bearer token. Returns the raw `Response`.
    pub async fn get(&self, url: &str) -> Result<Response> {
        let token = self.bearer_token().await?;
        self.inner.http
            .get(url)
            .bearer_auth(&token)
            .send()
            .await
            .with_context(|| format!("GET {url} failed"))
    }

    /// POST `url` with a JSON body. Returns the raw `Response`.
    pub async fn post(&self, url: &str, body: &serde_json::Value) -> Result<Response> {
        let token = self.bearer_token().await?;
        self.inner.http
            .post(url)
            .bearer_auth(&token)
            .json(body)
            .send()
            .await
            .with_context(|| format!("POST {url} failed"))
    }

    /// Paginate a GCP list endpoint. Calls `url` repeatedly, following `nextPageToken`
    /// until exhausted. Returns all JSON items from the `items_key` array field.
    ///
    /// # Example
    /// ```rust,no_run
    /// let buckets = client.paginate(
    ///     "https://storage.googleapis.com/storage/v1/b?project=my-proj",
    ///     "items",
    /// ).await?;
    /// ```
    pub async fn paginate(
        &self,
        base_url: &str,
        items_key: &str,
    ) -> Result<Vec<serde_json::Value>> {
        let mut results = Vec::new();
        let mut page_token: Option<String> = None;

        loop {
            let url = match &page_token {
                Some(tok) => format!("{base_url}&pageToken={tok}"),
                None => base_url.to_owned(),
            };

            let resp = self.get(&url).await?;
            let status = resp.status();
            let body: serde_json::Value = resp.json().await
                .with_context(|| format!("Failed to parse JSON from GET {url}"))?;

            if !status.is_success() {
                let msg = body.get("error")
                    .and_then(|e| e.get("message"))
                    .and_then(|m| m.as_str())
                    .unwrap_or("unknown error");
                anyhow::bail!("GCP API error {status} for {url}: {msg}");
            }

            if let Some(arr) = body.get(items_key).and_then(|v| v.as_array()) {
                results.extend(arr.iter().cloned());
            }

            match body.get("nextPageToken").and_then(|t| t.as_str()) {
                Some(tok) => page_token = Some(tok.to_owned()),
                None => break,
            }
        }

        Ok(results)
    }
}
```

> **Note on token caching:** The `RwLock<Option<String>>` above caches the token for the duration of a run. GCP access tokens expire after 1 hour. For runs longer than 1 hour, extend `GcpClientInner` to store the expiry time (`token_expiry: Option<Instant>`) and re-fetch when `Instant::now() >= token_expiry - 60s`. This is deferred until a collector triggers the timeout in practice.

- [ ] **Step 2.2: Add `pub mod client;` to `src/providers/gcp/mod.rs`**

```rust
pub mod client;
pub mod factory;

// Collector submodules — add here as each lands:
// pub mod iam_policies;
// pub mod iam_service_accounts;
// ... (see plan for full list)
```

- [ ] **Step 2.3: Verify the module compiles**

```bash
cargo check --features gcp 2>&1 | grep -E "^error" | head -20
```

Expected: zero errors. Warnings about unused imports are acceptable at this stage.

- [ ] **Step 2.4: Commit**

```bash
git add src/providers/gcp/client.rs src/providers/gcp/mod.rs
git commit -m "feat(gcp): add GcpClient — shared reqwest client with ADC Bearer-token injection"
```

---

### Task 3: Promote `GcpProviderFactory` from stub to real credential-loading factory

**Files:**
- Modify: `src/providers/gcp/factory.rs`

- [ ] **Step 3.1: Rewrite `src/providers/gcp/factory.rs`**

```rust
//! GCP provider factory — resolves ADC credentials and constructs all GCP collectors.

use anyhow::Result;

use crate::evidence::{CsvCollector, EvidenceCollector, JsonCollector};
use crate::providers::{CloudProvider, ProviderFactory};
use crate::providers::gcp::client::GcpClient;

pub struct GcpProviderFactory {
    client:     GcpClient,
    project_id: String,
    /// GCP region/location (e.g. "us-central1") or "global" for global resources.
    location:   String,
    /// Org ID (e.g. "123456789012") — required for org-scoped collectors (SCC, Org Policy).
    /// None when only project-scoped collectors are needed.
    org_id:     Option<String>,
    selected:   Vec<String>,
}

impl GcpProviderFactory {
    /// Async constructor — resolves Application Default Credentials before returning.
    pub async fn new(
        project_id: String,
        location: String,
        org_id: Option<String>,
        selected: Vec<String>,
    ) -> Result<Self> {
        let client = GcpClient::from_adc().await?;
        Ok(Self { client, project_id, location, org_id, selected })
    }
}

impl ProviderFactory for GcpProviderFactory {
    fn provider(&self) -> CloudProvider {
        CloudProvider::Gcp
    }

    fn account_id(&self) -> &str {
        &self.project_id
    }

    fn region(&self) -> &str {
        &self.location
    }

    fn csv_collectors(&self) -> Vec<Box<dyn CsvCollector>> {
        // Phase 2+ collectors registered here as they land.
        // Pattern (once iam_policies.rs is written):
        //   if self.selected.iter().any(|s| s == "gcp-iam-policies") {
        //       vec![Box::new(crate::providers::gcp::iam_policies::IamPoliciesCollector::new(
        //           self.client.clone(), self.project_id.clone(),
        //       ))]
        //   } else { vec![] }
        vec![]
    }

    fn json_collectors(&self) -> Vec<Box<dyn JsonCollector>> {
        vec![]
    }

    fn evidence_collectors(&self) -> Vec<Box<dyn EvidenceCollector>> {
        vec![]
    }
}
```

- [ ] **Step 3.2: Verify build**

```bash
cargo check --features gcp 2>&1 | grep "^error" | head -20
```

- [ ] **Step 3.3: Commit**

```bash
git add src/providers/gcp/factory.rs
git commit -m "feat(gcp): promote GcpProviderFactory from stub to credential-loading factory"
```

---

### Task 4: Extend `EvidenceSource` with GCP variants for time-windowed collectors

**Files:**
- Modify: `src/evidence.rs`

Currently only `GcpCloudAuditLogs` and `GcpCloudMonitoring` exist. Add variants for all GCP evidence collector types that will be implemented.

- [ ] **Step 4.1: Read the current `EvidenceSource` enum**

Open `src/evidence.rs` around line 136 to see the exact current state before editing.

- [ ] **Step 4.2: Add GCP variants**

In `src/evidence.rs`, replace the two existing GCP lines:
```rust
    // GCP
    GcpCloudAuditLogs,
    GcpCloudMonitoring,
```

with:
```rust
    // GCP — time-windowed evidence (EvidenceCollector impls)
    GcpCloudAuditLogs,
    GcpCloudMonitoring,
    GcpSccFindings,
    GcpVpcFlowLogs,
    GcpAuditLogsIam,
    GcpAuditLogsGcs,
    GcpCloudArmorLogs,
```

- [ ] **Step 4.3: Verify no existing match arms break**

```bash
cargo check --features gcp 2>&1 | grep "^error" | head -20
```

Expected: zero errors. The enum is `#[non_exhaustive]`-free, so existing `match` arms on `EvidenceSource` will produce compile errors if non-exhaustive — fix each by adding `_` arms or the new variants as appropriate.

- [ ] **Step 4.4: Commit**

```bash
git add src/evidence.rs
git commit -m "feat(gcp): add GCP EvidenceSource variants for time-windowed collectors"
```

---

### Task 5: Extend `app_config` with GCP-specific account fields

**Files:**
- Modify: `src/app_config.rs`

The existing `Account` struct already has `project_id: Option<String>`. Add `organization_id` and `location` so org-scoped collectors (SCC, Org Policy) and multi-region scans can be configured.

- [ ] **Step 5.1: Find the GCP block in `Account`**

```bash
grep -n "project_id\|gcp\|GCP\|organization" /Users/austin-songer/code/grabber/src/app_config.rs | head -20
```

- [ ] **Step 5.2: Add fields to the `Account` struct in `src/app_config.rs`**

In the GCP section of `Account`, add after `project_id`:
```rust
    // GCP fields
    pub project_id:      Option<String>,
    /// GCP organization ID (numeric, e.g. "123456789012").
    /// Required for org-scoped collectors: SCC findings, Org Policy, org IAM.
    pub organization_id: Option<String>,
    /// GCP location / region (e.g. "us-central1", "us", "global").
    /// Defaults to "us-central1" when absent.
    pub location:        Option<String>,
```

- [ ] **Step 5.3: Verify backward compatibility**

Existing TOML files with no `organization_id` or `location` keys must still deserialize without error (both fields are `Option`).

```bash
cargo test --features gcp 2>&1 | tail -20
```

- [ ] **Step 5.4: Update `config.toml` example in `README.md`**

Add a GCP account example block:
```toml
[[account]]
name            = "GCP-Production"
provider        = "gcp"
project_id      = "my-project-123"
organization_id = "123456789012"   # required for SCC / Org Policy collectors
location        = "us-central1"    # defaults to "us-central1" if omitted
```

- [ ] **Step 5.5: Commit**

```bash
git add src/app_config.rs README.md
git commit -m "feat(gcp): add organization_id and location fields to Account config"
```

---

## Phase 2 — Core Infrastructure Collectors (IAM, Compute, Storage, Audit Logs, KMS)

All Phase 2 collectors follow the same skeleton. The first collector (IAM policies) is shown in full. Subsequent collectors use the same pattern with only the URL, `items_key`, module name, and CSV headers differing.

---

### Task 6: IAM — Policy bindings, service accounts, service account keys

**Files:**
- Create: `src/providers/gcp/iam_policies.rs`
- Create: `src/providers/gcp/iam_service_accounts.rs`
- Create: `src/providers/gcp/iam_service_account_keys.rs`
- Modify: `src/providers/gcp/mod.rs` (add 3 `pub mod` lines)
- Modify: `src/providers/gcp/factory.rs` (register 3 collectors)

- [ ] **Step 6.1: Create `src/providers/gcp/iam_policies.rs`**

```rust
//! GCP IAM policy bindings — equivalent to AWS IAM policies.
//! Calls projects.getIamPolicy and returns all role–member bindings as CSV rows.

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde_json::json;

use crate::evidence::CsvCollector;
use crate::providers::gcp::client::GcpClient;

pub struct IamPoliciesCollector {
    client:     GcpClient,
    project_id: String,
}

impl IamPoliciesCollector {
    pub fn new(client: GcpClient, project_id: impl Into<String>) -> Self {
        Self { client, project_id: project_id.into() }
    }
}

#[async_trait]
impl CsvCollector for IamPoliciesCollector {
    fn name(&self) -> &str {
        "GCP IAM Policies"
    }

    fn filename_prefix(&self) -> &str {
        "GCP_IAM_Policies"
    }

    fn headers(&self) -> &'static [&'static str] {
        &["project_id", "role", "member", "member_type", "condition"]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let url = format!(
            "https://cloudresourcemanager.googleapis.com/v1/projects/{}:getIamPolicy",
            self.project_id
        );
        let resp = self.client.post(&url, &json!({"options": {"requestedPolicyVersion": 3}})).await?;
        let body: serde_json::Value = resp.json().await
            .context("Failed to parse IAM policy response")?;

        let bindings = body
            .get("bindings")
            .and_then(|b| b.as_array())
            .cloned()
            .unwrap_or_default();

        let mut rows = Vec::new();
        for binding in &bindings {
            let role = binding.get("role").and_then(|r| r.as_str()).unwrap_or("").to_owned();
            let condition = binding.get("condition")
                .map(|c| serde_json::to_string(c).unwrap_or_default())
                .unwrap_or_default();

            if let Some(members) = binding.get("members").and_then(|m| m.as_array()) {
                for member in members {
                    let m_str = member.as_str().unwrap_or("").to_owned();
                    let member_type = m_str.split(':').next().unwrap_or("").to_owned();
                    rows.push(vec![
                        self.project_id.clone(),
                        role.clone(),
                        m_str,
                        member_type,
                        condition.clone(),
                    ]);
                }
            }
        }

        Ok(rows)
    }
}
```

- [ ] **Step 6.2: Create `src/providers/gcp/iam_service_accounts.rs`**

```rust
//! GCP IAM service accounts — equivalent to AWS IAM roles (machine identities).

use anyhow::Result;
use async_trait::async_trait;

use crate::evidence::CsvCollector;
use crate::providers::gcp::client::GcpClient;

pub struct IamServiceAccountsCollector {
    client:     GcpClient,
    project_id: String,
}

impl IamServiceAccountsCollector {
    pub fn new(client: GcpClient, project_id: impl Into<String>) -> Self {
        Self { client, project_id: project_id.into() }
    }
}

#[async_trait]
impl CsvCollector for IamServiceAccountsCollector {
    fn name(&self) -> &str { "GCP IAM Service Accounts" }
    fn filename_prefix(&self) -> &str { "GCP_IAM_Service_Accounts" }
    fn headers(&self) -> &'static [&'static str] {
        &["project_id", "name", "email", "display_name", "disabled", "description"]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let url = format!(
            "https://iam.googleapis.com/v1/projects/{}/serviceAccounts?pageSize=100",
            self.project_id
        );
        let items = self.client.paginate(&url, "accounts").await?;

        Ok(items.iter().map(|sa| vec![
            self.project_id.clone(),
            sa.get("name").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
            sa.get("email").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
            sa.get("displayName").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
            sa.get("disabled").and_then(|v| v.as_bool()).unwrap_or(false).to_string(),
            sa.get("description").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
        ]).collect())
    }
}
```

- [ ] **Step 6.3: Create `src/providers/gcp/iam_service_account_keys.rs`**

```rust
//! GCP service account keys — equivalent to AWS IAM access keys.
//! Lists all user-managed keys across all service accounts in the project.

use anyhow::Result;
use async_trait::async_trait;

use crate::evidence::CsvCollector;
use crate::providers::gcp::client::GcpClient;

pub struct IamServiceAccountKeysCollector {
    client:     GcpClient,
    project_id: String,
}

impl IamServiceAccountKeysCollector {
    pub fn new(client: GcpClient, project_id: impl Into<String>) -> Self {
        Self { client, project_id: project_id.into() }
    }
}

#[async_trait]
impl CsvCollector for IamServiceAccountKeysCollector {
    fn name(&self) -> &str { "GCP IAM Service Account Keys" }
    fn filename_prefix(&self) -> &str { "GCP_IAM_SA_Keys" }
    fn headers(&self) -> &'static [&'static str] {
        &["project_id", "service_account_email", "key_name", "key_type",
          "key_algorithm", "valid_after", "valid_before"]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        // First: list all service accounts
        let sa_url = format!(
            "https://iam.googleapis.com/v1/projects/{}/serviceAccounts?pageSize=100",
            self.project_id
        );
        let accounts = self.client.paginate(&sa_url, "accounts").await?;

        let mut rows = Vec::new();
        for sa in &accounts {
            let email = sa.get("email").and_then(|v| v.as_str()).unwrap_or("").to_owned();
            let sa_name = sa.get("name").and_then(|v| v.as_str()).unwrap_or("").to_owned();

            // List keys for this service account — user-managed only
            let keys_url = format!(
                "https://iam.googleapis.com/v1/{}/keys?keyTypes=USER_MANAGED",
                sa_name
            );
            let keys_resp = self.client.get(&keys_url).await?;
            let keys_body: serde_json::Value = keys_resp.json().await?;

            if let Some(keys) = keys_body.get("keys").and_then(|k| k.as_array()) {
                for key in keys {
                    rows.push(vec![
                        self.project_id.clone(),
                        email.clone(),
                        key.get("name").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
                        key.get("keyType").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
                        key.get("keyAlgorithm").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
                        key.get("validAfterTime").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
                        key.get("validBeforeTime").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
                    ]);
                }
            }
        }

        Ok(rows)
    }
}
```

- [ ] **Step 6.4: Register the three IAM collectors in `GcpProviderFactory::csv_collectors()`**

In `src/providers/gcp/factory.rs`, replace the `csv_collectors` method:

```rust
    fn csv_collectors(&self) -> Vec<Box<dyn CsvCollector>> {
        use crate::providers::gcp::{
            iam_policies::IamPoliciesCollector,
            iam_service_accounts::IamServiceAccountsCollector,
            iam_service_account_keys::IamServiceAccountKeysCollector,
        };

        let mut out: Vec<Box<dyn CsvCollector>> = Vec::new();
        let all = self.selected.is_empty();

        macro_rules! push_csv {
            ($key:expr, $collector:expr) => {
                if all || self.selected.iter().any(|s| s == $key) {
                    out.push(Box::new($collector));
                }
            };
        }

        push_csv!("gcp-iam-policies",
            IamPoliciesCollector::new(self.client.clone(), &self.project_id));
        push_csv!("gcp-iam-service-accounts",
            IamServiceAccountsCollector::new(self.client.clone(), &self.project_id));
        push_csv!("gcp-iam-sa-keys",
            IamServiceAccountKeysCollector::new(self.client.clone(), &self.project_id));

        out
    }
```

- [ ] **Step 6.5: Add `pub mod` declarations to `src/providers/gcp/mod.rs`**

```rust
pub mod client;
pub mod factory;
pub mod iam_policies;
pub mod iam_service_accounts;
pub mod iam_service_account_keys;
```

- [ ] **Step 6.6: Verify build**

```bash
cargo check --features gcp 2>&1 | grep "^error" | head -30
```

- [ ] **Step 6.7: Commit**

```bash
git add src/providers/gcp/iam_policies.rs \
        src/providers/gcp/iam_service_accounts.rs \
        src/providers/gcp/iam_service_account_keys.rs \
        src/providers/gcp/mod.rs \
        src/providers/gcp/factory.rs
git commit -m "feat(gcp/iam): implement IAM policy bindings, service accounts, SA keys collectors"
```

---

### Task 7: Compute Engine collectors

**Files:**
- Create: `src/providers/gcp/compute_inventory.rs`
- Create: `src/providers/gcp/compute_config.rs`

- [ ] **Step 7.1: Create `src/providers/gcp/compute_inventory.rs`**

Calls the aggregated list API to enumerate instances across all zones in one request.

```rust
//! GCP Compute Engine instance inventory (all zones) — equivalent to AWS EC2 inventory.

use anyhow::Result;
use async_trait::async_trait;

use crate::evidence::CsvCollector;
use crate::providers::gcp::client::GcpClient;

pub struct ComputeInventoryCollector {
    client:     GcpClient,
    project_id: String,
}

impl ComputeInventoryCollector {
    pub fn new(client: GcpClient, project_id: impl Into<String>) -> Self {
        Self { client, project_id: project_id.into() }
    }
}

#[async_trait]
impl CsvCollector for ComputeInventoryCollector {
    fn name(&self) -> &str { "GCP Compute Engine Inventory" }
    fn filename_prefix(&self) -> &str { "GCP_Compute_Inventory" }
    fn headers(&self) -> &'static [&'static str] {
        &["project_id", "zone", "name", "machine_type", "status",
          "creation_timestamp", "network", "internal_ip", "external_ip",
          "service_account", "labels"]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        // aggregatedList returns instances across all zones
        let url = format!(
            "https://compute.googleapis.com/compute/v1/projects/{}/aggregated/instances?maxResults=500",
            self.project_id
        );
        let resp = self.client.get(&url).await?;
        let body: serde_json::Value = resp.json().await?;

        let mut rows = Vec::new();
        if let Some(items) = body.get("items").and_then(|v| v.as_object()) {
            for (zone_key, zone_data) in items {
                let zone = zone_key.trim_start_matches("zones/");
                if let Some(instances) = zone_data.get("instances").and_then(|v| v.as_array()) {
                    for inst in instances {
                        let name = inst.get("name").and_then(|v| v.as_str()).unwrap_or("");
                        let machine_type = inst.get("machineType").and_then(|v| v.as_str())
                            .unwrap_or("").split('/').last().unwrap_or("");
                        let status = inst.get("status").and_then(|v| v.as_str()).unwrap_or("");
                        let created = inst.get("creationTimestamp").and_then(|v| v.as_str()).unwrap_or("");

                        let (network, internal_ip, external_ip) = inst
                            .get("networkInterfaces")
                            .and_then(|ni| ni.as_array())
                            .and_then(|ni| ni.first())
                            .map(|ni| {
                                let net = ni.get("network").and_then(|v| v.as_str())
                                    .unwrap_or("").split('/').last().unwrap_or("").to_owned();
                                let iip = ni.get("networkIP").and_then(|v| v.as_str())
                                    .unwrap_or("").to_owned();
                                let eip = ni.get("accessConfigs")
                                    .and_then(|ac| ac.as_array())
                                    .and_then(|ac| ac.first())
                                    .and_then(|ac| ac.get("natIP"))
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("").to_owned();
                                (net, iip, eip)
                            })
                            .unwrap_or_default();

                        let sa = inst.get("serviceAccounts")
                            .and_then(|v| v.as_array())
                            .and_then(|v| v.first())
                            .and_then(|v| v.get("email"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("");

                        let labels = inst.get("labels")
                            .map(|l| serde_json::to_string(l).unwrap_or_default())
                            .unwrap_or_default();

                        rows.push(vec![
                            self.project_id.clone(),
                            zone.to_owned(),
                            name.to_owned(),
                            machine_type.to_owned(),
                            status.to_owned(),
                            created.to_owned(),
                            network,
                            internal_ip,
                            external_ip,
                            sa.to_owned(),
                            labels,
                        ]);
                    }
                }
            }
        }

        Ok(rows)
    }
}
```

- [ ] **Step 7.2: Create `src/providers/gcp/compute_config.rs`**

```rust
//! GCP Compute Engine per-instance configuration detail — equivalent to AWS EC2 detailed.

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;

use crate::evidence::JsonCollector;
use crate::providers::gcp::client::GcpClient;

pub struct ComputeConfigCollector {
    client:     GcpClient,
    project_id: String,
}

impl ComputeConfigCollector {
    pub fn new(client: GcpClient, project_id: impl Into<String>) -> Self {
        Self { client, project_id: project_id.into() }
    }
}

#[async_trait]
impl JsonCollector for ComputeConfigCollector {
    fn name(&self) -> &str { "GCP Compute Engine Config" }
    fn filename_prefix(&self) -> &str { "GCP_Compute_Config" }

    async fn collect_records(&self, _account_id: &str, _region: &str) -> Result<Vec<Value>> {
        let url = format!(
            "https://compute.googleapis.com/compute/v1/projects/{}/aggregated/instances?maxResults=500",
            self.project_id
        );
        let resp = self.client.get(&url).await?;
        let body: Value = resp.json().await?;

        let mut records = Vec::new();
        if let Some(items) = body.get("items").and_then(|v| v.as_object()) {
            for zone_data in items.values() {
                if let Some(instances) = zone_data.get("instances").and_then(|v| v.as_array()) {
                    records.extend(instances.iter().cloned());
                }
            }
        }
        Ok(records)
    }
}
```

- [ ] **Step 7.3: Register in factory and update mod.rs (same pattern as Task 6.4–6.5)**

Add to `src/providers/gcp/mod.rs`:
```rust
pub mod compute_inventory;
pub mod compute_config;
```

Add to `csv_collectors()` in factory:
```rust
push_csv!("gcp-compute-inventory",
    ComputeInventoryCollector::new(self.client.clone(), &self.project_id));
```

Add to `json_collectors()` in factory:
```rust
fn json_collectors(&self) -> Vec<Box<dyn JsonCollector>> {
    use crate::providers::gcp::compute_config::ComputeConfigCollector;
    let mut out: Vec<Box<dyn JsonCollector>> = Vec::new();
    let all = self.selected.is_empty();
    if all || self.selected.iter().any(|s| s == "gcp-compute-config") {
        out.push(Box::new(ComputeConfigCollector::new(self.client.clone(), &self.project_id)));
    }
    out
}
```

- [ ] **Step 7.4: Build and commit**

```bash
cargo check --features gcp 2>&1 | grep "^error" | head -20
git add src/providers/gcp/compute_inventory.rs src/providers/gcp/compute_config.rs \
        src/providers/gcp/mod.rs src/providers/gcp/factory.rs
git commit -m "feat(gcp/compute): add Compute Engine inventory and config collectors"
```

---

### Task 8: Cloud Storage collectors

**Files:**
- Create: `src/providers/gcp/cloud_storage_inventory.rs`
- Create: `src/providers/gcp/cloud_storage_config.rs`
- Create: `src/providers/gcp/cloud_storage_policies.rs`

- [ ] **Step 8.1: Create `src/providers/gcp/cloud_storage_inventory.rs`**

```rust
//! GCP Cloud Storage bucket inventory — equivalent to AWS S3 inventory.

use anyhow::Result;
use async_trait::async_trait;

use crate::evidence::CsvCollector;
use crate::providers::gcp::client::GcpClient;

pub struct CloudStorageInventoryCollector {
    client:     GcpClient,
    project_id: String,
}

impl CloudStorageInventoryCollector {
    pub fn new(client: GcpClient, project_id: impl Into<String>) -> Self {
        Self { client, project_id: project_id.into() }
    }
}

#[async_trait]
impl CsvCollector for CloudStorageInventoryCollector {
    fn name(&self) -> &str { "GCP Cloud Storage Inventory" }
    fn filename_prefix(&self) -> &str { "GCP_Cloud_Storage_Inventory" }
    fn headers(&self) -> &'static [&'static str] {
        &["project_id", "name", "location", "location_type", "storage_class",
          "time_created", "versioning_enabled", "public_access_prevention", "labels"]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let url = format!(
            "https://storage.googleapis.com/storage/v1/b?project={}&maxResults=250",
            self.project_id
        );
        let items = self.client.paginate(&url, "items").await?;

        Ok(items.iter().map(|b| {
            let versioning = b.get("versioning")
                .and_then(|v| v.get("enabled"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
                .to_string();
            let pap = b.get("iamConfiguration")
                .and_then(|v| v.get("publicAccessPrevention"))
                .and_then(|v| v.as_str())
                .unwrap_or("inherited")
                .to_owned();
            let labels = b.get("labels")
                .map(|l| serde_json::to_string(l).unwrap_or_default())
                .unwrap_or_default();
            vec![
                self.project_id.clone(),
                b.get("name").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
                b.get("location").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
                b.get("locationType").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
                b.get("storageClass").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
                b.get("timeCreated").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
                versioning,
                pap,
                labels,
            ]
        }).collect())
    }
}
```

- [ ] **Step 8.2: Create `src/providers/gcp/cloud_storage_config.rs`**

Calls `buckets.get` with full projection for versioning, retention policy, logging, lifecycle rules, and CORS config.

```rust
//! GCP Cloud Storage bucket configuration detail — equivalent to AWS S3 config.

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;

use crate::evidence::JsonCollector;
use crate::providers::gcp::client::GcpClient;

pub struct CloudStorageConfigCollector {
    client:     GcpClient,
    project_id: String,
}

impl CloudStorageConfigCollector {
    pub fn new(client: GcpClient, project_id: impl Into<String>) -> Self {
        Self { client, project_id: project_id.into() }
    }
}

#[async_trait]
impl JsonCollector for CloudStorageConfigCollector {
    fn name(&self) -> &str { "GCP Cloud Storage Config" }
    fn filename_prefix(&self) -> &str { "GCP_Cloud_Storage_Config" }

    async fn collect_records(&self, _account_id: &str, _region: &str) -> Result<Vec<Value>> {
        let url = format!(
            "https://storage.googleapis.com/storage/v1/b?project={}&maxResults=250&projection=full",
            self.project_id
        );
        self.client.paginate(&url, "items").await
    }
}
```

- [ ] **Step 8.3: Create `src/providers/gcp/cloud_storage_policies.rs`**

```rust
//! GCP Cloud Storage bucket IAM policies — equivalent to AWS S3 bucket policies.

use anyhow::Result;
use async_trait::async_trait;

use crate::evidence::CsvCollector;
use crate::providers::gcp::client::GcpClient;

pub struct CloudStoragePoliciesCollector {
    client:     GcpClient,
    project_id: String,
}

impl CloudStoragePoliciesCollector {
    pub fn new(client: GcpClient, project_id: impl Into<String>) -> Self {
        Self { client, project_id: project_id.into() }
    }
}

#[async_trait]
impl CsvCollector for CloudStoragePoliciesCollector {
    fn name(&self) -> &str { "GCP Cloud Storage IAM Policies" }
    fn filename_prefix(&self) -> &str { "GCP_Cloud_Storage_Policies" }
    fn headers(&self) -> &'static [&'static str] {
        &["project_id", "bucket", "role", "member"]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        // List buckets
        let url = format!(
            "https://storage.googleapis.com/storage/v1/b?project={}&maxResults=250",
            self.project_id
        );
        let buckets = self.client.paginate(&url, "items").await?;

        let mut rows = Vec::new();
        for bucket in &buckets {
            let bucket_name = bucket.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let iam_url = format!(
                "https://storage.googleapis.com/storage/v1/b/{}/iam",
                bucket_name
            );
            let iam_resp = self.client.get(&iam_url).await?;
            let iam_body: serde_json::Value = iam_resp.json().await?;

            if let Some(bindings) = iam_body.get("bindings").and_then(|b| b.as_array()) {
                for binding in bindings {
                    let role = binding.get("role").and_then(|v| v.as_str()).unwrap_or("").to_owned();
                    if let Some(members) = binding.get("members").and_then(|m| m.as_array()) {
                        for member in members {
                            rows.push(vec![
                                self.project_id.clone(),
                                bucket_name.to_owned(),
                                role.clone(),
                                member.as_str().unwrap_or("").to_owned(),
                            ]);
                        }
                    }
                }
            }
        }

        Ok(rows)
    }
}
```

- [ ] **Step 8.4: Register all three in factory and update mod.rs**

Add to `src/providers/gcp/mod.rs`:
```rust
pub mod cloud_storage_inventory;
pub mod cloud_storage_config;
pub mod cloud_storage_policies;
```

In `csv_collectors()` factory method, add:
```rust
push_csv!("gcp-storage-inventory",
    CloudStorageInventoryCollector::new(self.client.clone(), &self.project_id));
push_csv!("gcp-storage-policies",
    CloudStoragePoliciesCollector::new(self.client.clone(), &self.project_id));
```

In `json_collectors()` factory method, add:
```rust
if all || self.selected.iter().any(|s| s == "gcp-storage-config") {
    out.push(Box::new(CloudStorageConfigCollector::new(self.client.clone(), &self.project_id)));
}
```

- [ ] **Step 8.5: Build and commit**

```bash
cargo check --features gcp 2>&1 | grep "^error" | head -20
git add src/providers/gcp/cloud_storage_inventory.rs \
        src/providers/gcp/cloud_storage_config.rs \
        src/providers/gcp/cloud_storage_policies.rs \
        src/providers/gcp/mod.rs src/providers/gcp/factory.rs
git commit -m "feat(gcp/storage): add Cloud Storage inventory, config, and IAM policy collectors"
```

---

### Task 9: Cloud Audit Logs — time-windowed evidence collector

**Files:**
- Create: `src/providers/gcp/cloud_audit_logs.rs`

This is the GCP equivalent of AWS `cloudtrail.rs` and uses `EvidenceCollector` (time-windowed), not `CsvCollector`.

- [ ] **Step 9.1: Create `src/providers/gcp/cloud_audit_logs.rs`**

```rust
//! GCP Cloud Audit Logs — Admin Activity and Data Access log entries.
//! Equivalent to AWS CloudTrail. Uses the Cloud Logging entries.list API.
//! Implements EvidenceCollector (time-windowed).

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde_json::{json, Value};

use crate::evidence::{CollectParams, EvidenceCollector, EvidenceRecord, EvidenceSource};
use crate::providers::gcp::client::GcpClient;

pub struct CloudAuditLogsCollector {
    client:     GcpClient,
    project_id: String,
}

impl CloudAuditLogsCollector {
    pub fn new(client: GcpClient, project_id: impl Into<String>) -> Self {
        Self { client, project_id: project_id.into() }
    }
}

#[async_trait]
impl EvidenceCollector for CloudAuditLogsCollector {
    fn name(&self) -> &str { "GCP Cloud Audit Logs" }
    fn filename_prefix(&self) -> &str { "GCP_Cloud_Audit_Logs" }
    fn source(&self) -> EvidenceSource { EvidenceSource::GcpCloudAuditLogs }

    async fn collect_evidence(&self, params: &CollectParams) -> Result<Vec<EvidenceRecord>> {
        // Format RFC3339 timestamps from Unix epoch seconds
        let start = chrono::DateTime::from_timestamp(params.start_ts, 0)
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_default();
        let end = chrono::DateTime::from_timestamp(params.end_ts, 0)
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_default();

        let filter = format!(
            r#"logName=~"cloudaudit.googleapis.com" \
               AND timestamp >= "{start}" \
               AND timestamp <= "{end}""#
        );

        let body = json!({
            "resourceNames": [format!("projects/{}", self.project_id)],
            "filter": filter,
            "orderBy": "timestamp desc",
            "pageSize": 1000
        });

        let mut records = Vec::new();
        let mut page_token: Option<String> = None;

        loop {
            let mut req_body = body.clone();
            if let Some(tok) = &page_token {
                req_body["pageToken"] = Value::String(tok.clone());
            }

            let resp = self.client
                .post("https://logging.googleapis.com/v2/entries:list", &req_body)
                .await?;

            let status = resp.status();
            let resp_body: Value = resp.json().await
                .context("Failed to parse Cloud Logging response")?;

            if !status.is_success() {
                let msg = resp_body.get("error")
                    .and_then(|e| e.get("message"))
                    .and_then(|m| m.as_str())
                    .unwrap_or("unknown error");
                anyhow::bail!("Cloud Logging API error {status}: {msg}");
            }

            if let Some(entries) = resp_body.get("entries").and_then(|e| e.as_array()) {
                for entry in entries {
                    let timestamp = entry.get("timestamp")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned();
                    records.push(EvidenceRecord {
                        timestamp,
                        source: self.source(),
                        raw: if params.include_raw { Some(entry.clone()) } else { None },
                        // Other EvidenceRecord fields — match whatever the current struct requires.
                        // Inspect src/evidence.rs for the full field list.
                        ..Default::default()
                    });
                }
            }

            match resp_body.get("nextPageToken").and_then(|t| t.as_str()) {
                Some(tok) => page_token = Some(tok.to_owned()),
                None => break,
            }
        }

        Ok(records)
    }
}
```

> **Important:** `EvidenceRecord` may not have `..Default::default()` if it doesn't implement `Default`. Check `src/evidence.rs` for the exact struct fields and construct it explicitly. The `timestamp`, `source`, and `raw` fields are guaranteed to exist from the existing AWS usage.

- [ ] **Step 9.2: Add to mod.rs and register in `evidence_collectors()` in factory**

```rust
// mod.rs
pub mod cloud_audit_logs;

// factory.rs — evidence_collectors()
fn evidence_collectors(&self) -> Vec<Box<dyn EvidenceCollector>> {
    use crate::providers::gcp::cloud_audit_logs::CloudAuditLogsCollector;
    let mut out: Vec<Box<dyn EvidenceCollector>> = Vec::new();
    let all = self.selected.is_empty();
    if all || self.selected.iter().any(|s| s == "gcp-audit-logs") {
        out.push(Box::new(CloudAuditLogsCollector::new(
            self.client.clone(), &self.project_id
        )));
    }
    out
}
```

- [ ] **Step 9.3: Build and commit**

```bash
cargo check --features gcp 2>&1 | grep "^error" | head -20
git add src/providers/gcp/cloud_audit_logs.rs src/providers/gcp/mod.rs src/providers/gcp/factory.rs
git commit -m "feat(gcp/logging): add Cloud Audit Logs evidence collector (time-windowed)"
```

---

### Task 10: Cloud KMS collectors

**Files:**
- Create: `src/providers/gcp/kms.rs`
- Create: `src/providers/gcp/kms_policies.rs`

- [ ] **Step 10.1: Create `src/providers/gcp/kms.rs`**

```rust
//! GCP Cloud KMS key rings and keys — equivalent to AWS KMS.

use anyhow::Result;
use async_trait::async_trait;

use crate::evidence::CsvCollector;
use crate::providers::gcp::client::GcpClient;

pub struct KmsCollector {
    client:     GcpClient,
    project_id: String,
    location:   String,
}

impl KmsCollector {
    pub fn new(client: GcpClient, project_id: impl Into<String>, location: impl Into<String>) -> Self {
        Self { client, project_id: project_id.into(), location: location.into() }
    }
}

#[async_trait]
impl CsvCollector for KmsCollector {
    fn name(&self) -> &str { "GCP Cloud KMS" }
    fn filename_prefix(&self) -> &str { "GCP_KMS" }
    fn headers(&self) -> &'static [&'static str] {
        &["project_id", "location", "key_ring", "key_name", "purpose",
          "algorithm", "protection_level", "state", "create_time", "rotation_period",
          "next_rotation_time", "labels"]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        // Use "-" as location to list across all locations
        let loc = if self.location.is_empty() { "-" } else { &self.location };
        let rings_url = format!(
            "https://cloudkms.googleapis.com/v1/projects/{}/locations/{}/keyRings?pageSize=100",
            self.project_id, loc
        );
        let rings = self.client.paginate(&rings_url, "keyRings").await?;

        let mut rows = Vec::new();
        for ring in &rings {
            let ring_name = ring.get("name").and_then(|v| v.as_str()).unwrap_or("").to_owned();
            let ring_short = ring_name.split('/').last().unwrap_or("");

            let keys_url = format!(
                "https://cloudkms.googleapis.com/v1/{}/cryptoKeys?pageSize=100&versionView=FULL",
                ring_name
            );
            let keys = self.client.paginate(&keys_url, "cryptoKeys").await?;

            for key in &keys {
                let primary = key.get("primary");
                let algorithm = primary
                    .and_then(|p| p.get("algorithm"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let protection = primary
                    .and_then(|p| p.get("protectionLevel"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let state = primary
                    .and_then(|p| p.get("state"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                rows.push(vec![
                    self.project_id.clone(),
                    self.location.clone(),
                    ring_short.to_owned(),
                    key.get("name").and_then(|v| v.as_str()).unwrap_or("").split('/').last().unwrap_or("").to_owned(),
                    key.get("purpose").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
                    algorithm.to_owned(),
                    protection.to_owned(),
                    state.to_owned(),
                    key.get("createTime").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
                    key.get("rotationPeriod").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
                    key.get("nextRotationTime").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
                    key.get("labels").map(|l| serde_json::to_string(l).unwrap_or_default()).unwrap_or_default(),
                ]);
            }
        }

        Ok(rows)
    }
}
```

- [ ] **Step 10.2: Create `src/providers/gcp/kms_policies.rs`**

```rust
//! GCP Cloud KMS key IAM policies — equivalent to AWS KMS key policies.

use anyhow::Result;
use async_trait::async_trait;

use crate::evidence::CsvCollector;
use crate::providers::gcp::client::GcpClient;

pub struct KmsPoliciesCollector {
    client:     GcpClient,
    project_id: String,
    location:   String,
}

impl KmsPoliciesCollector {
    pub fn new(client: GcpClient, project_id: impl Into<String>, location: impl Into<String>) -> Self {
        Self { client, project_id: project_id.into(), location: location.into() }
    }
}

#[async_trait]
impl CsvCollector for KmsPoliciesCollector {
    fn name(&self) -> &str { "GCP KMS Key IAM Policies" }
    fn filename_prefix(&self) -> &str { "GCP_KMS_Policies" }
    fn headers(&self) -> &'static [&'static str] {
        &["project_id", "location", "key_ring", "key_name", "role", "member"]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let loc = if self.location.is_empty() { "-" } else { &self.location };
        let rings_url = format!(
            "https://cloudkms.googleapis.com/v1/projects/{}/locations/{}/keyRings?pageSize=100",
            self.project_id, loc
        );
        let rings = self.client.paginate(&rings_url, "keyRings").await?;

        let mut rows = Vec::new();
        for ring in &rings {
            let ring_name = ring.get("name").and_then(|v| v.as_str()).unwrap_or("").to_owned();
            let ring_short = ring_name.split('/').last().unwrap_or("").to_owned();
            let keys_url = format!(
                "https://cloudkms.googleapis.com/v1/{}/cryptoKeys?pageSize=100",
                ring_name
            );
            let keys = self.client.paginate(&keys_url, "cryptoKeys").await?;

            for key in &keys {
                let key_name = key.get("name").and_then(|v| v.as_str()).unwrap_or("").to_owned();
                let key_short = key_name.split('/').last().unwrap_or("").to_owned();
                let policy_url = format!("https://cloudkms.googleapis.com/v1/{}:getIamPolicy", key_name);
                let policy_resp = self.client.get(&policy_url).await?;
                let policy: serde_json::Value = policy_resp.json().await?;

                if let Some(bindings) = policy.get("bindings").and_then(|b| b.as_array()) {
                    for binding in bindings {
                        let role = binding.get("role").and_then(|v| v.as_str()).unwrap_or("").to_owned();
                        if let Some(members) = binding.get("members").and_then(|m| m.as_array()) {
                            for member in members {
                                rows.push(vec![
                                    self.project_id.clone(),
                                    self.location.clone(),
                                    ring_short.clone(),
                                    key_short.clone(),
                                    role.clone(),
                                    member.as_str().unwrap_or("").to_owned(),
                                ]);
                            }
                        }
                    }
                }
            }
        }

        Ok(rows)
    }
}
```

- [ ] **Step 10.3: Register and commit**

```bash
# mod.rs additions:
# pub mod kms;
# pub mod kms_policies;

# factory.rs csv_collectors — add:
# push_csv!("gcp-kms", KmsCollector::new(self.client.clone(), &self.project_id, &self.location));
# push_csv!("gcp-kms-policies", KmsPoliciesCollector::new(self.client.clone(), &self.project_id, &self.location));

cargo check --features gcp 2>&1 | grep "^error" | head -20
git add src/providers/gcp/kms.rs src/providers/gcp/kms_policies.rs \
        src/providers/gcp/mod.rs src/providers/gcp/factory.rs
git commit -m "feat(gcp/kms): add Cloud KMS key ring/key inventory and IAM policy collectors"
```

---

## Phase 3 — Extended Service Coverage

Each collector in Phase 3 follows the exact same patterns established in Phase 2. The table below gives the key parameters for each remaining collector. Implement them one at a time using the `CsvCollector` or `JsonCollector` skeleton from Phase 2.

| Module | Trait | GCP REST endpoint | `items_key` / notes |
|---|---|---|---|
| `scc_findings.rs` | `JsonCollector` | `POST securitycenter.googleapis.com/v1/organizations/{org}/sources/-/findings:list` | `findings`; requires `org_id` |
| `scc_config.rs` | `CsvCollector` | `GET securitycenter.googleapis.com/v1/organizations/{org}/organizationSettings` | single object; no pagination |
| `scc_vulnerabilities.rs` | `JsonCollector` | `POST securitycenter.googleapis.com/v1/organizations/{org}/sources/-/findings:list` with `filter: "category=\"VULNERABILITY\""` | `findings` |
| `scc_standards.rs` | `JsonCollector` | `GET securitycenter.googleapis.com/v1/organizations/{org}/securityHealthAnalyticsSettings` | single object |
| `cloud_sql.rs` | `CsvCollector` | `GET sqladmin.googleapis.com/sql/v1beta4/projects/{project}/instances` | `items` |
| `cloud_sql_backups.rs` | `CsvCollector` | `GET sqladmin.googleapis.com/sql/v1beta4/projects/{project}/instances/{instance}/backupRuns` | `items`; loop over instances |
| `gke.rs` | `CsvCollector` | `GET container.googleapis.com/v1/projects/{project}/locations/-/clusters` | `clusters` |
| `secret_manager.rs` | `CsvCollector` | `GET secretmanager.googleapis.com/v1/projects/{project}/secrets` | `secrets` |
| `secret_manager_extended.rs` | `JsonCollector` | `GET secretmanager.googleapis.com/v1/projects/{project}/secrets/{secret}/versions` | `versions`; loop |
| `cloud_functions.rs` | `CsvCollector` | `GET cloudfunctions.googleapis.com/v2/projects/{project}/locations/-/functions` | `functions` |
| `cloud_run.rs` | `CsvCollector` | `GET run.googleapis.com/v2/projects/{project}/locations/-/services` | `services` |
| `org_policy.rs` | `JsonCollector` | `GET orgpolicy.googleapis.com/v2/projects/{project}/policies` | `policies` |
| `organizations.rs` | `JsonCollector` | `GET cloudresourcemanager.googleapis.com/v3/projects?parent=organizations/{org}` | `projects` |
| `vpc.rs` | `CsvCollector` | `GET compute.googleapis.com/compute/v1/projects/{project}/global/networks` | `items` |
| `vpc_flow_logs.rs` | `CsvCollector` | `GET compute.googleapis.com/compute/v1/projects/{project}/aggregated/subnetworks` | aggregated; check `enableFlowLogs` field |
| `cloud_dns.rs` | `CsvCollector` | `GET dns.googleapis.com/dns/v1/projects/{project}/managedZones` | `managedZones` |
| `pubsub_topics.rs` | `CsvCollector` | `GET pubsub.googleapis.com/v1/projects/{project}/topics` | `topics` |
| `cloud_armor.rs` | `CsvCollector` | `GET compute.googleapis.com/compute/v1/projects/{project}/global/securityPolicies` | `items` |
| `asset_inventory.rs` | `JsonCollector` | `GET cloudasset.googleapis.com/v1/projects/{project}/assets?contentType=RESOURCE&pageSize=1000` | `assets` |
| `cloud_monitoring.rs` | `JsonCollector` | `GET monitoring.googleapis.com/v3/projects/{project}/alertPolicies` | `alertPolicies` |
| `persistent_disk.rs` | `CsvCollector` | `GET compute.googleapis.com/compute/v1/projects/{project}/aggregated/disks` | aggregated |
| `memorystore.rs` | `CsvCollector` | `GET redis.googleapis.com/v1/projects/{project}/locations/-/instances` | `instances` |
| `cloud_dlp.rs` | `JsonCollector` | `GET dlp.googleapis.com/v2/projects/{project}/inspectTemplates` | `inspectTemplates` |
| `filestore.rs` | `CsvCollector` | `GET file.googleapis.com/v1/projects/{project}/locations/-/instances` | `instances` |
| `audit_logs_config.rs` | `JsonCollector` | `GET logging.googleapis.com/v2/projects/{project}/sinks` | `sinks` |

### Phase 3 task order (highest FedRAMP impact first)

1. **SCC findings** (`scc_findings.rs`, `scc_vulnerabilities.rs`) — GuardDuty/SecurityHub parity
2. **Cloud SQL** (`cloud_sql.rs`, `cloud_sql_backups.rs`) — RDS parity
3. **GKE** (`gke.rs`) — EKS parity
4. **Secret Manager** (`secret_manager.rs`, `secret_manager_extended.rs`) — Secrets Manager parity
5. **Cloud Functions + Cloud Run** — Lambda/ECS parity
6. **Org Policy + organizations** — AWS Organizations/Config parity
7. **VPC + VPC Flow Logs** — network evidence
8. **Remaining** in any order

For each Phase 3 collector, the commit message pattern is:
```bash
git commit -m "feat(gcp/<service>): add <ServiceName> collector"
```

---

## Phase 4 — CLI and TUI Integration

### Task 11: Add `--provider` flag and GCP CLI arguments

**Files:**
- Modify: `src/cli.rs`

- [ ] **Step 11.1: Add provider and GCP-specific args to `Cli` struct**

After the last existing field in the `Cli` struct (`pub poam: ...` or whichever is last), add:

```rust
    // ------- Provider selection -------
    /// Cloud provider to collect from. Defaults to "aws".
    /// Supported values: aws, gcp (requires --features gcp).
    #[arg(long, default_value = "aws")]
    pub provider: String,

    // ------- GCP-specific options (used when --provider gcp) -------
    /// GCP project ID (e.g. "my-project-123").
    /// Falls back to the active gcloud project if omitted.
    #[arg(long)]
    pub gcp_project: Option<String>,

    /// GCP organization ID (numeric). Required for org-scoped GCP collectors
    /// (Security Command Center, Org Policy, organization structure).
    #[arg(long)]
    pub gcp_org: Option<String>,

    /// GCP location/region (e.g. "us-central1", "us", "global").
    /// Defaults to "us-central1" when omitted.
    #[arg(long, default_value = "us-central1")]
    pub gcp_location: String,
```

- [ ] **Step 11.2: Update `async_main` (or equivalent entry point) to dispatch GCP**

In `src/main.rs` (or `src/runner/multi_account.rs`), add a GCP branch inside `#[cfg(feature = "gcp")]`:

```rust
#[cfg(feature = "gcp")]
if cli.provider == "gcp" {
    let project = cli.gcp_project
        .or_else(|| std::env::var("CLOUDSDK_CORE_PROJECT").ok())
        .ok_or_else(|| anyhow::anyhow!(
            "GCP provider requires --gcp-project or CLOUDSDK_CORE_PROJECT env var"
        ))?;

    let factory = crate::providers::gcp::factory::GcpProviderFactory::new(
        project,
        cli.gcp_location.clone(),
        cli.gcp_org.clone(),
        cli.collectors.clone().unwrap_or_default(),
    ).await?;

    // Hand off to the same runner functions AWS uses — the factory hides all GCP specifics.
    let csv_collectors = factory.csv_collectors();
    let json_collectors = factory.json_collectors();
    let evidence_collectors = factory.evidence_collectors();
    // ... run them with the existing run_csv_collectors / run_json_collectors / run_evidence_collectors
}
```

- [ ] **Step 11.3: Build and commit**

```bash
cargo check --features gcp 2>&1 | grep "^error" | head -20
git add src/cli.rs src/main.rs
git commit -m "feat(cli): add --provider gcp, --gcp-project, --gcp-org, --gcp-location flags"
```

---

### Task 12: TUI provider badge and GCP account selection

**Files:**
- Modify: `src/runner/multi_account.rs`
- Modify: `src/tui/mod.rs` or `src/tui/screens/collector_select.rs` (wherever the collector list is rendered)

- [ ] **Step 12.1: Add GCP to account type dispatch in `multi_account.rs`**

In `run_tui_multi_account` (or equivalent), the account-picker loop currently only handles AWS accounts. Add a GCP branch:

```rust
#[cfg(feature = "gcp")]
crate::providers::CloudProvider::Gcp => {
    let project = account.project_id.clone()
        .ok_or_else(|| anyhow::anyhow!("GCP account '{}' missing project_id", account.name))?;
    let factory = crate::providers::gcp::factory::GcpProviderFactory::new(
        project,
        account.location.clone().unwrap_or_else(|| "us-central1".to_owned()),
        account.organization_id.clone(),
        selected.clone(),
    ).await?;
    Box::new(factory) as Box<dyn crate::providers::ProviderFactory>
}
```

- [ ] **Step 12.2: Add a `[GCP]` provider badge in the collector selection screen**

The TUI currently shows collector names without a provider label. Locate the line in `src/tui/mod.rs` or `src/tui/ui.rs` that renders collector names (search for `collector.name()` or `CollectorStatus`). Prefix the display name with the provider badge:

```rust
// Before (approximate):
let label = collector.name();

// After:
let label = match collector.provider() {
    CloudProvider::Aws     => format!("[AWS] {}", collector.name()),
    CloudProvider::Gcp     => format!("[GCP] {}", collector.name()),
    CloudProvider::Azure   => format!("[AZ]  {}", collector.name()),
    CloudProvider::Tenable => format!("[TEN] {}", collector.name()),
};
```

> **Note:** The `provider()` method lives on `ProviderFactory`, not on individual collectors. If individual collectors don't expose their provider, pass it through via a wrapper or query the registry. The existing collector structs have no `provider()` method — this may require adding a `provider: CloudProvider` field to collector display items in the TUI state.

- [ ] **Step 12.3: Build, smoke-test TUI launch with `--features gcp`**

```bash
cargo build --features gcp
# Launch TUI with a GCP config entry and verify [GCP] badges appear
```

- [ ] **Step 12.4: Commit**

```bash
git add src/runner/multi_account.rs src/tui/mod.rs
git commit -m "feat(tui): add GCP account dispatch and [GCP] provider badge in collector list"
```

---

## Phase 5 — Chain-of-Custody and Run Manifest for GCP

The chain-of-custody and run manifest features are output-layer concerns — they don't care which provider collected the data. They operate on file paths, collector names, and outcomes. **No changes to `src/audit_log.rs`, `src/signing.rs`, or `src/zip_bundle.rs` are required** as long as GCP collectors conform to the same `CsvCollector` / `JsonCollector` / `EvidenceCollector` trait contracts the AWS collectors use.

### Verification checklist

- [ ] After a GCP run, `CHAIN-OF-CUSTODY-<timestamp>.json` is written to the output directory
- [ ] `CHAIN-OF-CUSTODY.json` contains `"provider": "GCP"` (check that `CloudProvider::Gcp`'s `Display` impl produces `"GCP"`)
- [ ] `RUN-MANIFEST-<timestamp>.json` lists every GCP collector outcome (success / empty / error / timeout)
- [ ] `--zip` bundles GCP output files alongside any AWS files in `Evidence-<timestamp>.zip`
- [ ] `--sign` produces a valid HMAC manifest over GCP output files

### Output filename prefix

GCP output files must be prefixed with the project ID, not an AWS account ID. This is controlled by `ProviderFactory::account_id()`, which already returns `&self.project_id` in `GcpProviderFactory`. Verify the runner uses `factory.account_id()` as the file prefix (not a hard-coded AWS account variable).

```bash
# After a GCP test run, verify:
ls evidence-output/ | grep GCP
# Expected: GCP_IAM_Policies-<timestamp>.csv, GCP_Compute_Inventory-<timestamp>.csv, etc.
```

---

## Phase 6 — Integration Tests

### Task 13: GCP collector unit tests using mock HTTP

**Files:**
- Create: `tests/gcp_collectors.rs`

- [ ] **Step 13.1: Create `tests/gcp_collectors.rs`**

Test that `IamPoliciesCollector` correctly parses a known JSON response shape without making real network calls. Use `wiremock` (already a dev-dep of `tenable-rs`; add to root `[dev-dependencies]` if needed).

```rust
// tests/gcp_collectors.rs
#![cfg(feature = "gcp")]

// If wiremock is not yet a root dev-dep, add to Cargo.toml:
//   [dev-dependencies]
//   wiremock = "0.6"

use wiremock::{matchers::method, Mock, MockServer, ResponseTemplate};
use serde_json::json;

// We need a way to construct GcpClient pointing at a local mock server.
// This requires adding a `GcpClient::from_static_token(token, base_url)` constructor
// to client.rs for testing — see Step 13.2.

#[tokio::test]
async fn iam_policies_parses_bindings() {
    let mock = MockServer::start().await;

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "bindings": [
                {"role": "roles/owner", "members": ["user:alice@example.com"]},
                {"role": "roles/viewer", "members": ["serviceAccount:sa@project.iam.gserviceaccount.com"]}
            ],
            "version": 1
        })))
        .mount(&mock)
        .await;

    // Use test constructor (added in Step 13.2)
    let client = the_grabber::providers::gcp::client::GcpClient::from_static_token(
        "test-token",
        &mock.uri(),
    );
    let collector = the_grabber::providers::gcp::iam_policies::IamPoliciesCollector::new(
        client, "test-project"
    );

    let rows = collector.collect_rows("test-project", "us-central1", None).await.unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0][1], "roles/owner");
    assert_eq!(rows[0][2], "user:alice@example.com");
    assert_eq!(rows[1][3], "serviceAccount");  // member_type
}

#[tokio::test]
async fn compute_inventory_parses_aggregated_list() {
    let mock = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": {
                "zones/us-central1-a": {
                    "instances": [{
                        "name": "my-vm",
                        "status": "RUNNING",
                        "machineType": "zones/us-central1-a/machineTypes/n1-standard-1",
                        "creationTimestamp": "2024-01-01T00:00:00Z",
                        "networkInterfaces": [{"network": "global/networks/default", "networkIP": "10.0.0.2"}],
                        "serviceAccounts": [{"email": "sa@project.iam.gserviceaccount.com"}],
                        "labels": {}
                    }]
                }
            }
        })))
        .mount(&mock)
        .await;

    let client = the_grabber::providers::gcp::client::GcpClient::from_static_token(
        "test-token",
        &mock.uri(),
    );
    let collector = the_grabber::providers::gcp::compute_inventory::ComputeInventoryCollector::new(
        client, "test-project"
    );

    let rows = collector.collect_rows("test-project", "us-central1", None).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0][2], "my-vm");
    assert_eq!(rows[0][4], "RUNNING");
}
```

- [ ] **Step 13.2: Add `GcpClient::from_static_token` constructor to `client.rs` (test-only)**

```rust
// In src/providers/gcp/client.rs — add after `from_adc`:
#[cfg(test)]
pub fn from_static_token(token: impl Into<String>, base_url: &str) -> Self {
    // For tests: bypass ADC, inject a fixed token and override the base URL.
    // Collectors are expected to call full URLs — in tests, the mock server
    // must be mounted at the path the collector constructs.
    // This constructor is intentionally `#[cfg(test)]` only.
    todo!("implement test constructor — store token in Arc<RwLock<Option<String>>>")
}
```

> **Note:** Implementing `from_static_token` requires refactoring `GcpClientInner` to support a static token path without `google-cloud-auth`. One approach: make `token_source` an `Option` and short-circuit `bearer_token()` when a static token is set. This is test infrastructure — do it only after the main collectors are working.

- [ ] **Step 13.3: Run tests**

```bash
cargo test --features gcp -- gcp_collectors 2>&1 | tail -20
```

- [ ] **Step 13.4: Commit**

```bash
git add tests/gcp_collectors.rs Cargo.toml
git commit -m "test(gcp): add mock-HTTP unit tests for IAM policies and Compute inventory collectors"
```

---

## Feature Flag Summary

All GCP code is gated behind `#[cfg(feature = "gcp")]`. The current `Cargo.toml` already has:

```toml
gcp = ["dep:google-cloud-auth"]
```

After Task 1, this becomes:
```toml
gcp = ["dep:google-cloud-auth", "dep:reqwest"]
```

Build commands:
```bash
cargo build                    # AWS + Tenable (default features)
cargo build --features gcp     # AWS + Tenable + GCP
cargo build --no-default-features --features gcp  # GCP only (no Tenable)
```

Module gates — every collector file must start with no conditional attribute (the `mod` declaration in `providers/gcp/mod.rs` is already inside a `#[cfg(feature = "gcp")]` block inherited from `providers/mod.rs`). Do **not** add redundant `#[cfg(feature = "gcp")]` inside `src/providers/gcp/*.rs` — the parent module gate is sufficient.

---

## Collector Key Registry

The following keys are used in `--collectors` CLI flag and `selected` vec for GCP:

| Key | Module | Output type |
|---|---|---|
| `gcp-iam-policies` | `iam_policies` | CSV |
| `gcp-iam-service-accounts` | `iam_service_accounts` | CSV |
| `gcp-iam-sa-keys` | `iam_service_account_keys` | CSV |
| `gcp-compute-inventory` | `compute_inventory` | CSV |
| `gcp-compute-config` | `compute_config` | JSON |
| `gcp-storage-inventory` | `cloud_storage_inventory` | CSV |
| `gcp-storage-config` | `cloud_storage_config` | JSON |
| `gcp-storage-policies` | `cloud_storage_policies` | CSV |
| `gcp-audit-logs` | `cloud_audit_logs` | Evidence (JSON) |
| `gcp-kms` | `kms` | CSV |
| `gcp-kms-policies` | `kms_policies` | CSV |
| `gcp-scc-findings` | `scc_findings` | JSON |
| `gcp-scc-config` | `scc_config` | CSV |
| `gcp-cloud-sql` | `cloud_sql` | CSV |
| `gcp-gke` | `gke` | CSV |
| `gcp-secrets` | `secret_manager` | CSV |
| `gcp-cloud-functions` | `cloud_functions` | CSV |
| `gcp-cloud-run` | `cloud_run` | CSV |
| `gcp-org-policy` | `org_policy` | JSON |
| `gcp-vpc` | `vpc` | CSV |
| `gcp-vpc-flow-logs` | `vpc_flow_logs` | CSV |
| `gcp-cloud-dns` | `cloud_dns` | CSV |
| `gcp-pubsub` | `pubsub_topics` | CSV |
| `gcp-cloud-armor` | `cloud_armor` | CSV |
| `gcp-asset-inventory` | `asset_inventory` | JSON |
| `gcp-monitoring` | `cloud_monitoring` | JSON |

---

## Self-Review Against Requirements

| Requirement | Covered by |
|---|---|
| Service mapping table (88+ AWS → GCP equivalents) | Service Mapping Table above (84 entries) |
| `google-cloud-auth` integration | Task 1–2 (`GcpClient::from_adc`) |
| Service account / Workload Identity credentials | Task 2 — ADC resolves both automatically |
| `GcpProviderFactory` credential loading | Task 3 |
| Project / region discovery | Task 3 (`account_id()` = project_id, `region()` = location) + Task 5 |
| Phase 1: Foundation | Tasks 1–5 |
| Phase 2: Core Infrastructure (`CsvCollector`/`JsonCollector`) | Tasks 6–10 |
| Phase 3: High-impact services (IAM, Compute, Storage, Logging) | Tasks 6–9 |
| Feature flag `#[cfg(feature = "gcp")]` | Feature Flag Summary section |
| `--provider gcp` CLI flag | Task 11 |
| GCP-specific account config (`--gcp-project`, `--gcp-org`) | Tasks 5 + 11 |
| TUI `--provider gcp` routing | Task 12 |
| Chain-of-custody parity | Phase 5 |
| Run manifest parity | Phase 5 |
