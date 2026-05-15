# Tenable Performance & New Collectors Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Speed up all Tenable bulk exports with parallel chunk downloads, add assets and compliance CSV collectors, and improve API reliability with multi-attempt retry logic.

**Architecture:** Four independent changes — (1) `ExportJob<T>::collect_all()` dispatches chunks concurrently via `futures::stream::buffer_unordered`; (2) `TenableClient::get/post` retry up to 5× with exponential backoff; (3) two new `CsvCollector` impls for assets and compliance follow the exact same pattern as `was.rs`; (4) new collector keys wired through `collector_data.rs`, `app/mod.rs`, `factory.rs`, and `mod.rs`.

**Tech Stack:** Rust, tokio, futures (already in `Cargo.toml`), reqwest, ratatui, tenable-rs local crate.

---

## Task 1: Parallel Chunk Downloads

**Files:**
- Modify: `crates/tenable-rs/src/export.rs`

The `collect_all()` method currently downloads chunks serially. This task replaces the serial `for` loop with `buffer_unordered(4)` — 4 concurrent HTTP requests — using `futures::StreamExt`. The `futures` crate is already in `Cargo.toml`; no new dependencies are needed.

### Step 1: Add import to export.rs

Open `crates/tenable-rs/src/export.rs`. Add `futures::StreamExt` to the imports:

```rust
use std::marker::PhantomData;

use futures::StreamExt;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use tokio::time::{sleep, Duration};

use crate::client::TenableClient;
use crate::error::TenableError;
```

### Step 2: Replace `collect_all` body

Replace the entire `collect_all` method (lines 62–73 in export.rs) with the parallel version:

```rust
/// Poll until the export is FINISHED, then download all chunks concurrently.
///
/// Up to 4 chunk downloads run in parallel. Ordering is preserved — results
/// are flattened in chunk-id order as they complete.
pub async fn collect_all(self) -> Result<Vec<T>, TenableError> {
    let chunks = self.wait_for_chunks().await?;

    // Shared references passed into each chunk future.
    let client = &self.client;
    let resource_path = &self.resource_path;

    let mut stream = futures::stream::iter(chunks)
        .map(|chunk_id| async move {
            let path = format!("{}/chunks/{}", resource_path, chunk_id);
            let resp = client.get(&path).await?;
            let resp = check_response(resp).await?;
            let chunk: Vec<T> = resp.json().await?;
            Ok::<Vec<T>, TenableError>(chunk)
        })
        .buffer_unordered(4);

    let mut records = Vec::new();
    while let Some(result) = stream.next().await {
        records.extend(result?);
    }
    Ok(records)
}
```

### Step 3: Verify

```bash
cargo check --features tenable 2>&1 | grep "^error"
```

Expected: no output (no errors).

### Step 4: Run tests

```bash
cargo test --features tenable 2>&1 | tail -5
```

Expected: `test result: ok.` (all existing tests pass).

### Step 5: Commit

```bash
git add crates/tenable-rs/src/export.rs
git commit -m "perf(tenable-rs): download export chunks in parallel (buffer_unordered 4)"
```

---

## Task 2: Multi-Attempt Retry with Exponential Backoff

**Files:**
- Modify: `crates/tenable-rs/src/client.rs`

Currently `get()` and `post()` retry exactly once on 429. This task adds retry loops with exponential backoff (1 s, 2 s, 4 s, 8 s, 16 s, then stop) while still honouring `Retry-After` as the minimum wait.

### Step 1: Add retry constants to client.rs

At the top of `client.rs`, replace the single constant:

```rust
const DEFAULT_RETRY_AFTER_SECS: u64 = 60;
```

with:

```rust
const DEFAULT_RETRY_AFTER_SECS: u64 = 60;
const MAX_RETRIES: u32 = 5;
```

### Step 2: Extract a shared `send_with_retry` helper

Add a private helper at the bottom of `impl TenableClient` (just before the closing `}`), above `fn parse_retry_after`:

```rust
/// Send a closure-produced request, retrying on 429 up to MAX_RETRIES times
/// with exponential backoff.  The closure is called fresh for each attempt so
/// the request body (if any) is re-serialised correctly.
async fn send_with_retry<F, Fut>(&self, make_req: F) -> Result<reqwest::Response, TenableError>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<reqwest::Response, reqwest::Error>>,
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
```

### Step 3: Replace `get` and `post` bodies to call the helper

Replace the `get` method:

```rust
pub(crate) async fn get(&self, path: &str) -> Result<reqwest::Response, TenableError> {
    let url = self.url(path);
    self.send_with_retry(|| self.http.get(&url).send()).await
}
```

Replace the `post` method:

```rust
pub(crate) async fn post(
    &self,
    path: &str,
    body: &serde_json::Value,
) -> Result<reqwest::Response, TenableError> {
    let url = self.url(path);
    self.send_with_retry(|| self.http.post(&url).json(body).send()).await
}
```

### Step 4: Verify

```bash
cargo check --features tenable 2>&1 | grep "^error"
```

Expected: no output.

### Step 5: Run tests

```bash
cargo test --features tenable 2>&1 | tail -5
```

Expected: `test result: ok.`

### Step 6: Commit

```bash
git add crates/tenable-rs/src/client.rs
git commit -m "fix(tenable-rs): retry 429 up to 5× with exponential backoff"
```

---

## Task 3: Assets Export Collector

**Files:**
- Create: `src/providers/tenable/assets.rs`
- Modify: `src/providers/tenable/mod.rs`

`tenable-rs` already has `AssetsApi::export_all()` and the `AssetRecord` type in `crates/tenable-rs/src/types/asset.rs`. This task adds a `CsvCollector` wrapper following the exact same pattern as `vulnerabilities.rs`.

The `AssetRecord` struct has these fields we care about:
- `id: String`
- `fqdn: Option<Vec<String>>`
- `ipv4: Option<Vec<String>>`
- `ipv6: Option<Vec<String>>`
- `mac_address: Option<Vec<String>>`
- `hostname: Option<Vec<String>>`
- `operating_system: Option<Vec<String>>`
- `agent_name: Option<Vec<String>>`
- `tags: Option<Vec<Tag>>` (each has `key: String`, `value: String`)
- `sources: Option<Vec<AssetSource>>` (each has `name: String`)
- `network_name: Option<String>`
- `tracking_method: Option<String>`
- `has_agent: Option<bool>`
- `is_licensed: Option<bool>`
- `exposure_score: Option<f64>`
- `first_seen: Option<String>`
- `last_seen: Option<String>`
- `created_at: Option<String>`
- `updated_at: Option<String>`

### Step 1: Create src/providers/tenable/assets.rs

Create the file with this exact content:

```rust
use anyhow::Result;
use async_trait::async_trait;

use tenable_rs::TenableClient;

use crate::evidence::CsvCollector;

pub struct TenableAssetsCollector {
    client: TenableClient,
}

impl TenableAssetsCollector {
    pub fn new(client: TenableClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for TenableAssetsCollector {
    fn name(&self) -> &str {
        "Tenable Assets"
    }

    fn filename_prefix(&self) -> &str {
        "Tenable_Assets"
    }

    fn headers(&self) -> &'static [&'static str] {
        &[
            "Asset ID",
            "Hostname",
            "FQDNs",
            "IPv4 Addresses",
            "IPv6 Addresses",
            "MAC Addresses",
            "Operating System",
            "Agent Name",
            "Network Name",
            "Tracking Method",
            "Has Agent",
            "Is Licensed",
            "Exposure Score",
            "Sources",
            "Tags",
            "First Seen",
            "Last Seen",
            "Created At",
            "Updated At",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let assets = match self.client.assets().export_all(None, None).await {
            Ok(a) => a,
            Err(tenable_rs::TenableError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };

        let rows = assets
            .into_iter()
            .map(|a| {
                let tags = a
                    .tags
                    .unwrap_or_default()
                    .into_iter()
                    .map(|t| format!("{}={}", t.key, t.value))
                    .collect::<Vec<_>>()
                    .join("; ");
                let sources = a
                    .sources
                    .unwrap_or_default()
                    .into_iter()
                    .map(|s| s.name)
                    .collect::<Vec<_>>()
                    .join("; ");
                vec![
                    a.id,
                    a.hostname.unwrap_or_default().join("; "),
                    a.fqdn.unwrap_or_default().join("; "),
                    a.ipv4.unwrap_or_default().join("; "),
                    a.ipv6.unwrap_or_default().join("; "),
                    a.mac_address.unwrap_or_default().join("; "),
                    a.operating_system.unwrap_or_default().join("; "),
                    a.agent_name.unwrap_or_default().join("; "),
                    a.network_name.unwrap_or_default(),
                    a.tracking_method.unwrap_or_default(),
                    a.has_agent
                        .map(|b| if b { "YES" } else { "NO" })
                        .unwrap_or_default()
                        .to_string(),
                    a.is_licensed
                        .map(|b| if b { "YES" } else { "NO" })
                        .unwrap_or_default()
                        .to_string(),
                    a.exposure_score
                        .map(|s| format!("{s:.1}"))
                        .unwrap_or_default(),
                    sources,
                    tags,
                    a.first_seen.unwrap_or_default(),
                    a.last_seen.unwrap_or_default(),
                    a.created_at.unwrap_or_default(),
                    a.updated_at.unwrap_or_default(),
                ]
            })
            .collect();

        Ok(rows)
    }
}
```

### Step 2: Register module in src/providers/tenable/mod.rs

Add `pub mod assets;` to the module declarations:

```rust
pub mod assets;
pub mod factory;
pub mod pci_asv;
pub mod vulnerabilities;
pub mod was;
```

### Step 3: Verify

```bash
cargo check --features tenable 2>&1 | grep "^error"
```

Expected: no output.

### Step 4: Run tests

```bash
cargo test --features tenable 2>&1 | tail -5
```

Expected: `test result: ok.`

---

## Task 4: Compliance Export Collector

**Files:**
- Create: `src/providers/tenable/compliance.rs`
- Modify: `src/providers/tenable/mod.rs`

`tenable-rs` already has `ComplianceApi::export_all()` and `ComplianceFinding` type. The `ComplianceFinding` fields:
- `asset: ComplianceAsset` (with `id`, `fqdn`, `hostname`, `ipv4`)
- `check_name: Option<String>`
- `check_info: Option<String>`
- `status: CheckStatus` (Passed/Failed/Warning/Unknown)
- `expected_value: Option<String>`
- `actual_value: Option<String>`
- `policy_name: Option<String>`
- `audit_file: Option<String>`
- `check_id: Option<String>`
- `reference: Option<Vec<String>>`
- `first_seen: Option<String>`
- `last_seen: Option<String>`

`CheckStatus` derives `Debug` so `format!("{:?}", status)` gives `"Passed"`, `"Failed"`, etc.

### Step 1: Create src/providers/tenable/compliance.rs

```rust
use anyhow::Result;
use async_trait::async_trait;

use tenable_rs::TenableClient;

use crate::evidence::CsvCollector;

pub struct TenableComplianceCollector {
    client: TenableClient,
}

impl TenableComplianceCollector {
    pub fn new(client: TenableClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CsvCollector for TenableComplianceCollector {
    fn name(&self) -> &str {
        "Tenable Compliance Findings"
    }

    fn filename_prefix(&self) -> &str {
        "Tenable_Compliance_Findings"
    }

    fn headers(&self) -> &'static [&'static str] {
        &[
            // Asset
            "Asset ID",
            "Asset Hostname",
            "Asset FQDN",
            "Asset IPv4",
            // Check
            "Check ID",
            "Check Name",
            "Check Info",
            "Status",
            "Expected Value",
            "Actual Value",
            // Policy
            "Policy Name",
            "Audit File",
            "References",
            // Lifecycle
            "First Seen",
            "Last Seen",
        ]
    }

    async fn collect_rows(
        &self,
        _account_id: &str,
        _region: &str,
        _dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>> {
        let findings = match self.client.compliance().export_all(None).await {
            Ok(f) => f,
            Err(tenable_rs::TenableError::Api { status: 404, .. }) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };

        let rows = findings
            .into_iter()
            .map(|f| {
                vec![
                    f.asset.id,
                    f.asset.hostname.unwrap_or_default(),
                    f.asset.fqdn.unwrap_or_default(),
                    f.asset.ipv4.unwrap_or_default(),
                    f.check_id.unwrap_or_default(),
                    f.check_name.unwrap_or_default(),
                    f.check_info
                        .unwrap_or_default()
                        .replace(['\n', '\r'], " "),
                    format!("{:?}", f.status),
                    f.expected_value.unwrap_or_default(),
                    f.actual_value.unwrap_or_default(),
                    f.policy_name.unwrap_or_default(),
                    f.audit_file.unwrap_or_default(),
                    f.reference.unwrap_or_default().join("; "),
                    f.first_seen.unwrap_or_default(),
                    f.last_seen.unwrap_or_default(),
                ]
            })
            .collect();

        Ok(rows)
    }
}
```

### Step 2: Register module in src/providers/tenable/mod.rs

```rust
pub mod assets;
pub mod compliance;
pub mod factory;
pub mod pci_asv;
pub mod vulnerabilities;
pub mod was;
```

### Step 3: Verify

```bash
cargo check --features tenable 2>&1 | grep "^error"
```

Expected: no output.

### Step 4: Run tests

```bash
cargo test --features tenable 2>&1 | tail -5
```

Expected: `test result: ok.`

### Step 5: Commit tasks 3 and 4 together

```bash
git add src/providers/tenable/assets.rs \
        src/providers/tenable/compliance.rs \
        src/providers/tenable/mod.rs
git commit -m "feat(tenable): add assets and compliance CSV collectors"
```

---

## Task 5: Wire New Collectors into TUI and Factory

**Files:**
- Modify: `src/tui/collector_data.rs`
- Modify: `src/tui/app/mod.rs`
- Modify: `src/providers/tenable/factory.rs`

This wires the two new collectors through the full stack: TUI item list → opt-in defaults → factory dispatch.

### Step 1: Add entries to COLLECTOR_ITEMS in collector_data.rs

The current Tenable block ends at index 129 (`tenable-pci-asv`). Append two entries immediately after `tenable-pci-asv`:

```rust
    (
        "tenable-assets",
        "Asset Inventory         ",
        CloudProvider::Tenable,
    ),
    (
        "tenable-compliance",
        "Compliance Findings      ",
        CloudProvider::Tenable,
    ),
```

The display strings are padded to 25 characters to match the existing entries. Check the existing entries' padding — each entry's display string is 25 chars including trailing spaces.

### Step 2: Add new keys to hardcoded_optins in src/tui/app/mod.rs

Find the `hardcoded_optins` array (around line 138). Add the two new keys:

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
];
```

### Step 3: Update factory.rs to import and dispatch new collectors

Open `src/providers/tenable/factory.rs`. Add imports:

```rust
use super::assets::TenableAssetsCollector;
use super::compliance::TenableComplianceCollector;
use super::pci_asv::TenablePciAsvCollector;
use super::vulnerabilities::TenableVulnerabilitiesCollector;
use super::was::TenableWasCollector;
```

In `csv_collectors()`, add the two new branches after the existing `tenable-pci-asv` branch:

```rust
if self.selected.iter().any(|s| s == "tenable-assets") {
    v.push(Box::new(TenableAssetsCollector::new(self.client.clone())));
}
if self.selected.iter().any(|s| s == "tenable-compliance") {
    v.push(Box::new(TenableComplianceCollector::new(self.client.clone())));
}
```

The complete `csv_collectors` method after the change:

```rust
fn csv_collectors(&self) -> Vec<Box<dyn CsvCollector>> {
    let mut v: Vec<Box<dyn CsvCollector>> = Vec::new();
    if self.selected.iter().any(|s| s == "tenable-vulns") {
        v.push(Box::new(TenableVulnerabilitiesCollector::new(
            self.client.clone(),
            self.selected_scan_ids.clone(),
        )));
    }
    if self.selected.iter().any(|s| s == "tenable-was") {
        v.push(Box::new(TenableWasCollector::new(
            self.client.clone(),
            self.selected_was_scan_ids.clone(),
        )));
    }
    if self.selected.iter().any(|s| s == "tenable-pci-asv") {
        v.push(Box::new(TenablePciAsvCollector::new(self.client.clone())));
    }
    if self.selected.iter().any(|s| s == "tenable-assets") {
        v.push(Box::new(TenableAssetsCollector::new(self.client.clone())));
    }
    if self.selected.iter().any(|s| s == "tenable-compliance") {
        v.push(Box::new(TenableComplianceCollector::new(self.client.clone())));
    }
    v
}
```

### Step 4: Verify

```bash
cargo check --features tenable 2>&1 | grep "^error"
```

Expected: no output.

### Step 5: Run all tests

```bash
cargo test --features tenable 2>&1 | tail -10
```

Expected: `test result: ok.` All tests pass including the TUI collector visibility tests.

### Step 6: Spot-check TUI index tests

The `tenable_provider_hides_aws_collectors` and `aws_provider_hides_tenable_collectors` tests in `src/tui/app/mod.rs` reference `item 127` as `tenable-vulns`. After adding new Tenable entries, verify these tests still reference correct indices:

```bash
cargo test --features tenable tenable_provider -- --nocapture 2>&1
cargo test --features tenable aws_provider_hides -- --nocapture 2>&1
```

If tests fail because indices shifted, update the hardcoded index in the test assertions to the correct value. Use:

```bash
grep -n "tenable-vulns" src/tui/collector_data.rs
```

to find the current line and count items before it to determine the new index.

### Step 7: Commit

```bash
git add src/tui/collector_data.rs \
        src/tui/app/mod.rs \
        src/providers/tenable/factory.rs
git commit -m "feat(tui): register tenable-assets and tenable-compliance collectors"
```

---

## Task 6: Full Build and Final Commit

### Step 1: Full build

```bash
cargo build --features tenable 2>&1 | grep "^error"
```

Expected: no output.

### Step 2: Full test suite

```bash
cargo test --features tenable 2>&1 | tail -10
```

Expected: `test result: ok.`

### Step 3: Commit anything remaining (if uncommitted)

```bash
git status
```

If clean, nothing to do. If there are unstaged files, stage and commit them.

---

## Verification Checklist

| Requirement | Task |
|-------------|------|
| Chunk downloads run 4 at a time (not serially) | Task 1 |
| 429 retries up to 5× with backoff instead of once | Task 2 |
| `TenableAssetsCollector` produces a 19-column CSV | Task 3 |
| `TenableComplianceCollector` produces a 15-column CSV | Task 4 |
| `tenable-assets` and `tenable-compliance` appear in TUI (opt-in, Tenable provider only) | Task 5 |
| All existing tests still pass | Task 6 |
