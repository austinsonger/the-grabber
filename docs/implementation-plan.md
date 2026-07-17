# Implementation Plan — Architectural Refinements

> Targets four structural improvements to The Grabber:
> 1. Provider trait generalization
> 2. Collector macro/derive
> 3. Streaming CSV writer
> 4. Region-aware caching

## Status snapshot (main branch)

| Phase | Status |
|-------|--------|
| 1 — Streaming CSV writer | **Not started.** `CsvCollector::collect_rows` still returns `Vec<Vec<String>>` and `run_csv_collectors` still buffers full rows before writing. |
| 2 — Collector macro/derive | **Not started.** No `src/macros.rs`; each collector is hand-written. |
| 3 — Provider trait generalization | **Done in shape.** `src/providers/mod.rs` defines `CloudProvider` + `ProviderFactory`; `aws`, `okta`, `jira`, `tenable`, `azure`, and `gcp` all implement it. Providers are inferred from each `[[account]]` block's `provider = "…"` field, not from a `--provider` CLI flag (that idea was dropped as unnecessary once accounts became provider-tagged). |
| 4 — Region-aware caching | **Not started.** No `GlobalCache` type; every region rebuilds SDK clients and identity from scratch. |

Sections 3.x below are kept for historical reference; treat them as *how the provider trait landed*, not as pending work. Sections 1, 2, and 4 remain accurate as forward-looking plans.

---

## Recommended Sequencing

| Phase | Feature | Why This Order |
|-------|---------|----------------|
| 1 | **Streaming CSV Writer** | Changes the `CsvCollector` trait contract. Stabilizing this first prevents double-work in the macro layer. |
| 2 | **Collector Macro/Derive** | Builds on the finalized trait. Once the macro exists, migrating the 80+ simple CSV collectors becomes a mechanical search-replace. |
| 3 | **Provider Trait Generalization** | *(shipped — see status snapshot)* |
| 4 | **Region-Aware Caching** | Adds a cache layer inside the provider factory. |

---

## Phase 1 — Streaming CSV Writer

**Goal:** Eliminate `Vec<Vec<String>>` buffering so collectors with millions of rows use O(1) memory.

### 1.1 Add a streaming method to `CsvCollector`

**File:** `src/evidence.rs`

Add a default-implemented streaming method alongside the existing `collect_rows` so migration is backward-compatible:

```rust
#[async_trait]
pub trait CsvCollector: Send + Sync {
    fn name(&self) -> &str;
    fn filename_prefix(&self) -> &str;
    fn headers(&self) -> &'static [&'static str];

    // --- existing (kept for compatibility during migration) ---
    async fn collect_rows(
        &self,
        account_id: &str,
        region: &str,
        dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>>;

    // --- new streaming contract ---
    /// Write rows directly to `writer` and return the count written.
    /// Default impl delegates to `collect_rows` so existing collectors keep working.
    async fn collect_to_writer<W: std::io::Write + Send>(
        &self,
        account_id: &str,
        region: &str,
        dates: Option<(i64, i64)>,
        writer: &mut csv::Writer<W>,
    ) -> Result<usize> {
        let rows = self.collect_rows(account_id, region, dates).await?;
        let count = rows.len();
        for row in &rows {
            writer.write_record(row).context("CSV write row")?;
        }
        Ok(count)
    }
}
```

### 1.2 Rewrite `run_csv_collectors` to stream

**File:** `src/runner/collect_ops.rs`

Replace the `write_csv_bytes` call with a file-backed `csv::Writer`:

```rust
pub(crate) async fn run_csv_collectors(
    collectors: &[Box<dyn CsvCollector>],
    account_id: &str,
    region: &str,
    output_dir: &PathBuf,
    dates: Option<(i64, i64)>,
    timestamp: &str,
) -> Result<Vec<audit_log::CollectorOutcome>> {
    std::fs::create_dir_all(output_dir)?;
    let mut outcomes = Vec::new();

    for collector in collectors {
        let filename = format!("{}_{}-{}.csv", account_id, collector.filename_prefix(), timestamp);
        let path = output_dir.join(&filename);

        let file = std::fs::File::create(&path)
            .with_context(|| format!("Failed to create {}", path.display()))?;
        let mut writer = csv::Writer::from_writer(std::io::BufWriter::new(file));

        // Write headers first
        writer.write_record(collector.headers())
            .context("CSV write headers")?;

        match collector.collect_to_writer(account_id, region, dates, &mut writer).await {
            Ok(count) => {
                writer.flush().context("CSV flush")?;
                // ... outcome logic identical to today ...
            }
            Err(e) => { /* ... */ }
        }
    }
    Ok(outcomes)
}
```

### 1.3 Remove `write_csv_bytes` from the hot path

**File:** `src/runner/output.rs`

Keep `write_csv_bytes` for the inventory path (which still builds a `Vec` today), but stop using it in `collect_ops.rs`.

### 1.4 Migrate one collector to native streaming

**File:** `src/providers/aws/ebs.rs` (pilot)

Implement `collect_to_writer` directly to prove the pattern:

```rust
async fn collect_to_writer<W: std::io::Write + Send>(
    &self,
    account_id: &str,
    region: &str,
    _dates: Option<(i64, i64)>,
    writer: &mut csv::Writer<W>,
) -> Result<usize> {
    let mut count = 0;
    let mut next_token: Option<String> = None;
    loop {
        // ... pagination identical ...
        for vol in resp.volumes() {
            writer.write_record(&[
                vol_id, arn, az, enc, kms_key, region.into()
            ])?;
            count += 1;
        }
        // ...
    }
    Ok(count)
}
```

### 1.5 Remaining collector migration

Convert the other **simple** collectors (the ones that just paginate and map fields) in bulk during Phase 2 via the macro.

---

## Phase 2 — Collector Macro/Derive

**Goal:** Cut ~60% of the boilerplate in AWS collector modules.

Because the project uses a flat module structure and avoids heavy proc-macro crates, use a **declarative macro** inside `src/macros.rs` rather than a separate proc-macro crate.

### 2.1 Create `src/macros.rs`

**File:** `src/macros.rs` (new)

```rust
/// Define a CSV collector with minimal boilerplate.
///
/// Usage:
/// ```rust
/// define_csv_collector! {
///     struct EbsCollector {
///         client: Ec2Client,
///         name: "EBS Volumes",
///         prefix: "EBS",
///         headers: &["Volume ID", "Volume ARN", "AZ", "Encryption", "KMS Key ARN", "Region"],
///     }
///
///     async fn collect_to_writer(&self, account_id, region, _dates, writer) {
///         let mut count = 0;
///         let mut next_token = None;
///         loop {
///             let resp = self.client.describe_volumes()
///                 .set_next_token(next_token.clone())
///                 .send().await.context("EC2 describe_volumes")?;
///
///             for vol in resp.volumes() {
///                 let vol_id = vol.volume_id().unwrap_or("").to_string();
///                 // ...
///                 writer.write_record(&[vol_id, arn, az, enc, kms_key, region.into()])?;
///                 count += 1;
///             }
///
///             next_token = resp.next_token().map(|s| s.to_string());
///             if next_token.is_none() { break; }
///         }
///         Ok(count)
///     }
/// }
/// ```
#[macro_export]
macro_rules! define_csv_collector {
    // ... implementation expands to struct + impl CsvCollector + impl new()
}
```

The macro generates:

1. The struct definition with `client` field.
2. `impl TheStruct { pub fn new(config: &aws_config::SdkConfig) -> Self { ... } }`
3. `#[async_trait] impl CsvCollector for TheStruct` with `name()`, `filename_prefix()`, `headers()`, and `collect_to_writer()`.

### 2.2 Migrate a batch of simple collectors

Start with the most mechanical ones (no nested API calls per row):

- `ebs.rs`
- `efs.rs`
- `dynamodb.rs`
- `acm.rs`
- `cloudfront.rs`
- `ecs.rs`
- `eks.rs`
- `s3_config.rs`
- `vpc.rs`
- `nacl.rs`
- `igw.rs`
- `nat-gateways.rs`
- `alb_logs.rs`

Then tackle the ones with **per-row follow-up calls** (e.g., `kms.rs` calls `describe_key` and `get_key_rotation_status` per key). The macro can support an optional `per_item` block or these can remain hand-written until a more advanced macro is built.

### 2.3 Add a similar macro for `JsonCollector`

**File:** `src/macros.rs`

```rust
#[macro_export]
macro_rules! define_json_collector {
    // Generates struct + impl JsonCollector with collect_to_writer
    // For JSON, the macro accepts a body that yields `serde_json::Value` rows
    // and handles the `JsonInventoryReport` envelope.
}
```

For JSON, instead of buffering a `Vec<serde_json::Value>`, the collector would write values into a `serde_json::StreamWriter` (or simply buffer fewer records). The bigger win is on CSV, so JSON streaming can be Phase 2.5 if needed.

---

## Phase 3 — Provider Trait Generalization

**Goal:** The runner never imports `aws_sdk_*` directly; adding Azure/GCP is just a new module + factory registration.

### 3.1 Audit the current state

You already have:

- `ProviderFactory` trait in `src/providers/mod.rs` ✅
- `CollectorRegistry` in `src/runner/collector_registry.rs` ✅
- AWS factory in `src/providers/aws/factory.rs` ✅

The **leakage** is in three places:

1. `collector_registry.rs` hardcodes `AwsProviderFactory::new(...)` in `build_csv_collectors`, `build_json_inv_collectors`, and `build_json_collectors`.
2. `multi_region_cli.rs` hardcodes AWS config loading (`aws_config::defaults(...)`) and the global/regional split.
3. `main.rs`/`cli.rs` have no `--provider` switch.

### 3.2 Make `CollectorRegistry` the single entry point

**File:** `src/runner/collector_registry.rs`

Delete the three `build_*` free functions. The registry already has `register()` and flat-map accessors. Runner code should build a `CollectorRegistry`, register the desired provider factories, then call `registry.csv_collectors()`.

```rust
pub fn build_registry_for_provider(
    provider: CloudProvider,
    // provider-specific config object (enum wrapper)
    config: ProviderConfig,
    selected: Vec<String>,
) -> CollectorRegistry {
    let mut reg = CollectorRegistry::new();
    match provider {
        CloudProvider::Aws => {
            let factory = AwsProviderFactory::new(config.into_aws(), ..., selected);
            reg.register(factory);
        }
        #[cfg(feature = "azure")]
        CloudProvider::Azure => {
            let factory = AzureProviderFactory::new(config.into_azure(), ..., selected);
            reg.register(factory);
        }
        // ...
    }
    reg
}
```

### 3.3 Introduce `ProviderConfig` enum

**File:** `src/providers/mod.rs`

```rust
pub enum ProviderConfig {
    Aws(aws_config::SdkConfig, String /*account_id*/, String /*region*/),
    #[cfg(feature = "azure")]
    Azure(...),
    #[cfg(feature = "gcp")]
    Gcp(...),
}
```

This lets `main.rs` load credentials once per account, wrap them in `ProviderConfig`, and pass them into the generic registry builder.

### 3.4 Generic runner loops

**File:** `src/runner/multi_region_cli.rs` (rename to `multi_region.rs` or keep)

Replace the AWS-specific `run_multi_region_standard` with a provider-agnostic version:

```rust
pub(crate) async fn run_multi_region(
    cli: &Cli,
    provider: CloudProvider,
    base_config: ProviderConfig,
    // ...
) -> Result<()> {
    // Provider-specific region discovery
    let target_regions = match provider {
        CloudProvider::Aws => crate::aws_loader::discover_regions(base_config.aws_sdk()).await,
        // Azure: discover locations, etc.
    };

    // Build registry once with the base config
    let registry = build_registry_for_provider(provider, base_config.clone(), selected.to_vec());

    // Run global collectors (from registry, filtered by GLOBAL_COLLECTOR_KEYS)
    // Run regional collectors per region
}
```

Because `ProviderFactory::csv_collectors()` returns `Vec<Box<dyn CsvCollector>>`, the actual collection loop (`run_csv_collectors`) is already provider-agnostic.

### 3.5 Implement stub Azure/GCP factories

**Files:** `src/providers/azure/factory.rs`, `src/providers/gcp/factory.rs`

Even if they only return 2-3 collectors initially, having them implement `ProviderFactory` proves the abstraction:

```rust
pub struct AzureProviderFactory { ... }

impl ProviderFactory for AzureProviderFactory {
    fn provider(&self) -> CloudProvider { CloudProvider::Azure }
    fn account_id(&self) -> &str { &self.subscription_id }
    fn region(&self) -> &str { &self.location }
    fn csv_collectors(&self) -> Vec<Box<dyn CsvCollector>> { /* ... */ }
    // ...
}
```

### 3.6 CLI changes

**File:** `src/cli.rs`

Add `--provider <aws|azure|gcp|tenable>` (default `aws`). The flag drives which factory gets registered and which region-discovery path runs.

---

## Phase 4 — Region-Aware Caching

**Goal:** When `--all-regions` runs, global API results and STS identity are fetched once and shared.

### 4.1 Cache the base SDK config components

**File:** `src/aws_loader.rs` (or new `src/providers/aws/cache.rs`)

When `multi_region_cli.rs` currently does this per region:

```rust
let region_config = aws_config::defaults(BehaviorVersion::latest())
    .region(Region::new(region_name.clone()))
    .profile_name(p)
    .load().await;
```

It re-runs the full credential provider chain (SSO token refresh, IMDS, etc.) for every region. Instead:

```rust
// Load base config ONCE
let base_config = aws_config::defaults(BehaviorVersion::latest())
    .profile_name(p)
    .load().await;

// Per region, just swap the region (cheap)
let region_config = aws_config::SdkConfig::builder()
    .behavior_version(BehaviorVersion::latest())
    .region(Region::new(region_name.clone()))
    .credentials_provider(base_config.credentials_provider().unwrap())
    .http_client(base_config.http_client().unwrap())
    // copy other cheap fields
    .build();
```

This alone removes ~N credential resolutions for N regions.

### 4.2 Add a `GlobalCache` to `AwsProviderFactory`

**File:** `src/providers/aws/factory.rs`

```rust
use std::sync::{Arc, RwLock};
use std::collections::HashMap;

#[derive(Clone, Default)]
pub struct GlobalCache {
    sts_identity: Option<audit_log::AwsIdentity>,
    // Key = API name, Value = cached JSON/CSV rows
    iam_roles: Option<Vec<Vec<String>>>,
    s3_buckets: Option<Vec<Vec<String>>>,
}

pub struct AwsProviderFactory {
    config: aws_config::SdkConfig,
    account_id: String,
    region: String,
    selected: Vec<String>,
    cache: Arc<RwLock<GlobalCache>>,
}
```

When the factory builds collectors, pass `Arc<RwLock<GlobalCache>>` into constructors that need it:

```rust
// In csv_collectors():
if has("iam-roles") {
    collectors.push(Box::new(IamRoleCollector::new_cached(cfg, cache.clone())));
}
```

### 4.3 Wrap collectors with a cache decorator

**File:** `src/providers/aws/cached_collector.rs` (new)

Rather than modifying every collector, use a **decorator pattern**:

```rust
pub struct CachedCsvCollector {
    inner: Box<dyn CsvCollector>,
    cache_key: String,
    cache: Arc<RwLock<GlobalCache>>,
}

#[async_trait]
impl CsvCollector for CachedCsvCollector {
    // ...
    async fn collect_rows(&self, ...) -> Result<Vec<Vec<String>>> {
        // Check cache first
        if let Some(cached) = self.cache.read().unwrap().get(&self.cache_key) {
            return Ok(cached.clone());
        }
        let rows = self.inner.collect_rows(account_id, region, dates).await?;
        self.cache.write().unwrap().insert(self.cache_key.clone(), rows.clone());
        Ok(rows)
    }
}
```

In `AwsProviderFactory::csv_collectors()`, wrap global collectors:

```rust
if has("iam-roles") {
    let inner = IamRoleCollector::new(cfg);
    collectors.push(Box::new(CachedCsvCollector::new(
        Box::new(inner),
        "iam-roles".into(),
        self.cache.clone(),
    )));
}
```

This ensures IAM, S3, CloudFront, etc. hit the cache on the second region pass. Because the multi-region runner runs global collectors **once** already, the bigger win is for **regional collectors that reference global data** (e.g., a future collector that needs to know all IAM roles to evaluate cross-account trust).

### 4.4 Cache STS identity explicitly

**File:** `src/aws_loader.rs`

```rust
pub async fn get_cached_identity(
    config: &aws_config::SdkConfig,
    cache: &Arc<RwLock<GlobalCache>>,
) -> Result<audit_log::AwsIdentity> {
    if let Some(id) = cache.read().unwrap().sts_identity.clone() {
        return Ok(id);
    }
    let id = get_identity(config).await?; // existing function
    cache.write().unwrap().sts_identity = Some(id.clone());
    Ok(id)
}
```

---

## Testing & Rollout Strategy

| Step | Action |
|------|--------|
| **A** | Create a feature branch `feat/streaming-csv`. Migrate `ebs.rs` + `kms.rs` to `collect_to_writer`, run `cargo test`, run a live `--all-regions` test to verify byte-for-byte output parity. |
| **B** | Merge (A), then branch `feat/collector-macros`. Add `src/macros.rs`, migrate 10 simple collectors, run the full test suite. |
| **C** | Merge (B), then branch `feat/provider-trait`. Refactor `collector_registry.rs` and `multi_region_cli.rs` to use generic `CollectorRegistry`. Verify TUI and CLI both work. |
| **D** | Merge (C), then branch `feat/region-cache`. Add `GlobalCache` and the per-region config cloning. Benchmark `--all-regions` runtime before/after. |

---

## Files to Touch (Summary)

| Phase | Files |
|-------|-------|
| **1. Streaming CSV** | `src/evidence.rs`, `src/runner/collect_ops.rs`, `src/runner/output.rs`, `src/providers/aws/ebs.rs` (pilot) |
| **2. Macro/Derive** | `src/macros.rs` (new), ~40 `src/providers/aws/*.rs` modules |
| **3. Provider Trait** | `src/providers/mod.rs`, `src/providers/aws/factory.rs`, `src/runner/collector_registry.rs`, `src/runner/multi_region_cli.rs`, `src/cli.rs`, `src/main.rs`, `src/providers/azure/factory.rs`, `src/providers/gcp/factory.rs` |
| **4. Region Cache** | `src/aws_loader.rs`, `src/providers/aws/factory.rs`, `src/providers/aws/cached_collector.rs` (new), `src/runner/multi_region_cli.rs` |
