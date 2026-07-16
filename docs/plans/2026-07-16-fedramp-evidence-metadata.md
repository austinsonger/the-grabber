# FedRAMP Evidence Metadata Infrastructure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every evidence file grabber emits self-identifies the FedRAMP requirement(s) it satisfies and its own filename, driven by a single source-of-truth mapping table (P0-META-01 through P0-META-06 in the parent spec).

**Architecture:** Add one JSON mapping table (`assets/fedramp-map.json`) loaded at startup into a global `FedRampMap`. Extend the `CsvCollector` trait with a `fedramp_mapping()` default method that looks itself up by `filename_prefix()`. Route all CSV emission through an upgraded `write_csv_bytes` that (a) appends three columns to every row (`FedRAMP Req IDs`, `FedRAMP Control IDs`, `Source Evidence File`) and (b) writes a two-line footer after the last data row. Route all JSON emission through a wrapper adding `_fedramp_manifest`. After each run, write `fedramp-coverage-actual.csv` with one row per NIST-1000-series Req ID showing which collector/file covered it.

**Tech Stack:** Rust · `serde_json` · `csv` · `anyhow` · `once_cell` (already in Cargo.lock) · existing `tokio`/`async_trait`.

## Global Constraints

- Author every commit as `Austin Songer <asonger.pixel@gmail.com>`; do not add Co-Authored-By trailers.
- Every task ends with `cargo check` succeeding; the tree must compile after each step (PostToolUse hook enforces this).
- No test-writing steps — implementation only. Trust that `cargo check` + `cargo clippy -- -D warnings` catch regressions.
- Follow existing project conventions: `anyhow::Result` everywhere, no `.unwrap()`/`.expect()` in production paths, module docs (`//!`) on new files, flat monolithic modules under `src/`.
- Zero renames/removals of pre-existing CSV columns or filenames. Only additive changes.
- The three metadata columns MUST appear at the END of every CSV row, right of all existing columns, so downstream Excel/BI templates keying by column index don't break.
- Footer format for CSVs: one blank row, then `# FedRAMP Req IDs,<pipe-separated>`, then `# Source Evidence File,<basename>`. The `#` prefix is a comment convention (not `csv` crate metadata) that CSV readers treat as a data row — that's intentional so `head`/`grep` see it.
- Coverage report path: `<run-dir>/fedramp-coverage-actual.csv`. Reuse existing `date_path_suffix` and run-dir helpers in `src/runner/output.rs`.
- Values in mapping columns are pipe-separated, alphabetically sorted, and deduped.

---

## File Structure

**Create:**
- `assets/fedramp-map.json` — source of truth: collector `filename_prefix` → `{req_ids: [...], control_ids: [...]}`.
- `src/fedramp_map.rs` — loader (`FedRampMap`, `FedRampMapping`, `load_bundled()`), lazy global.
- `src/fedramp_coverage.rs` — post-run coverage report writer.

**Modify:**
- `src/main.rs` — declare `mod fedramp_map;` and `mod fedramp_coverage;` (ordered ABOVE modules that depend on them).
- `src/evidence.rs` — add `FedRampMapping` re-export; extend `CsvCollector` and `JsonCollector` traits with a default `fedramp_mapping()` method; extend `JsonInventoryReport` with `#[serde(rename = "_fedramp_manifest")] fedramp_manifest: FedRampManifest`.
- `src/runner/output.rs` — new `write_csv_bytes_with_manifest(headers, rows, mapping, source_evidence_file)`; keep `write_csv_bytes` as a thin wrapper that panics-fast for callers who forget to migrate (dev-only assertion).
- `src/runner/collect_ops.rs` — pass basename + mapping into the new writer at CSV call-site (line ~100).
- `src/runner/multi_account.rs` — pass basename + mapping into the new writer at inventory CSV call-site (line ~491) and every other `write_csv_bytes` site.
- `src/runner/tui_runners.rs` — pass basename + mapping (line ~52).
- `src/runner/tui_session.rs` — pass basename + mapping.
- `src/runner/collector_registry.rs` — expose `all_registered_prefixes()` used by coverage report.
- `src/inventory_xlsx.rs` — add the same three metadata columns to the inventory XLSX write path.
- `evidence-list.md` — add a "FedRAMP Mapping" appendix listing every collector's Req IDs / control IDs (informational; canonical data lives in JSON).
- `docs/fedramp-coverage.md` — new user-facing doc explaining the columns/footer/coverage-report.

**Runtime asset:**
- `assets/fedramp-map.json` is embedded via `include_str!` at compile time so grabber has zero runtime file dependency.

---

## Task 1: Design and land `assets/fedramp-map.json`

**Files:**
- Create: `assets/fedramp-map.json`

**Interfaces:**
- Consumes: nothing.
- Produces: canonical mapping file consumed by Task 2's loader. JSON schema:
  ```json
  {
    "schema": 1,
    "collectors": {
      "<filename_prefix>": {
        "req_ids": ["NIST-####", ...],
        "control_ids": ["AC-02h.", ...]
      }
    },
    "requirements": {
      "NIST-####": {
        "control_id": "AC-02h.",
        "family": "AC",
        "description": "one-line description"
      }
    }
  }
  ```

- [ ] **Step 1: Create the assets directory and the mapping file**

Populate `collectors` for every existing filename prefix in `evidence-list.md` (124 entries). For each, look up its EV# in that document, then map to Req IDs using the classification report already produced. Collectors currently in bucket A get their Req IDs filled; new-P0 collector prefixes are added with the mapping declared in the parent spec's Top-20 list. Collectors with no known mapping get `"req_ids": [], "control_ids": []` (empty — coverage report will surface them).

Populate `requirements` for all 193 NIST-1000-series Req IDs from `~/Documents/FedRAMP-with-evidence.xlsx` (columns: `Req ID`, `Requirement`, first sentence of `Description`, plus derived `family` = first two letters of `control_id`).

File template (excerpt):

```json
{
  "schema": 1,
  "collectors": {
    "IAM_Users": {
      "req_ids": ["NIST-1043", "NIST-1519"],
      "control_ids": ["AC-02h.", "PS-04a-d"]
    },
    "Okta_Deprovisioning_Timeliness": {
      "req_ids": ["NIST-1043", "NIST-1519", "NIST-1535"],
      "control_ids": ["AC-02h.", "PS-04a-d", "PS-07d."]
    }
  },
  "requirements": {
    "NIST-1043": {
      "control_id": "AC-02h.",
      "family": "AC",
      "description": "Notify account managers within defined timeframes when accounts are no longer required."
    }
  }
}
```

To generate the full file, run this one-off script in the scratchpad (do NOT commit the script):

```bash
uv run --with pandas --with openpyxl python3 - << 'EOF' > /Users/austin-songer/code/grabber/assets/fedramp-map.json
import json, pandas as pd, re
df = pd.read_excel('/Users/austin-songer/Documents/FedRAMP-with-evidence.xlsx', sheet_name='IRL')
reqs = {}
for _, r in df.iterrows():
    reqs[r['Req ID']] = {
        'control_id': r['Requirement'],
        'family': re.match(r'([A-Z]{2})', r['Requirement']).group(1) if re.match(r'([A-Z]{2})', r['Requirement']) else 'XX',
        'description': (r['Description'].split('.')[0] + '.')[:200] if pd.notna(r['Description']) else '',
    }
out = {'schema': 1, 'collectors': {}, 'requirements': reqs}
print(json.dumps(out, indent=2))
EOF
```

Then hand-populate the `collectors` section using `evidence-list.md` + the classification report at `/Users/austin-songer/.claude/projects/-Users-austin-songer-code-grabber/f3ce9da0-deb1-4527-986b-0cf9712a1f4f/tool-results/b056prrfi.txt`. Every filename prefix from `evidence-list.md` MUST appear as a key; empty arrays are allowed and expected.

- [ ] **Step 2: Verify file is valid JSON**

Run: `python3 -c "import json; json.load(open('/Users/austin-songer/code/grabber/assets/fedramp-map.json'))" && echo OK`
Expected: `OK`

- [ ] **Step 3: Verify every existing filename_prefix has a key**

Run:
```bash
grep -oE '"[A-Z][A-Za-z0-9_]+_[A-Za-z0-9_]+"' /Users/austin-songer/code/grabber/evidence-list.md | sort -u > /tmp/prefixes-in-doc.txt
python3 -c "import json; print('\n'.join(sorted(json.load(open('/Users/austin-songer/code/grabber/assets/fedramp-map.json'))['collectors'].keys())))" | sort -u > /tmp/prefixes-in-json.txt
diff /tmp/prefixes-in-doc.txt /tmp/prefixes-in-json.txt || true
```
Expected: any diff output is human-reviewed. Prefixes documented but missing from the JSON must be added (empty arrays are fine).

- [ ] **Step 4: Commit**

```bash
git add assets/fedramp-map.json
git -c user.name="Austin Songer" -c user.email="asonger.pixel@gmail.com" commit -m "feat(fedramp): add source-of-truth requirement mapping table

193 NIST 800-53 Moderate requirements from the FedRAMP IRL, plus per-collector
req_id/control_id mappings for the current 124 collectors and the P0 additions."
```

---

## Task 2: `FedRampMap` loader module

**Files:**
- Create: `src/fedramp_map.rs`
- Modify: `src/main.rs` (add `mod fedramp_map;` above `mod evidence;`)

**Interfaces:**
- Consumes: `assets/fedramp-map.json` (via `include_str!`).
- Produces:
  - `pub struct FedRampMapping { pub req_ids: Vec<String>, pub control_ids: Vec<String> }`
  - `pub struct FedRampMap` with `pub fn get(&self, filename_prefix: &str) -> FedRampMapping` (returns empty mapping when absent, never panics) and `pub fn all_requirements(&self) -> &BTreeMap<String, RequirementInfo>`.
  - `pub struct RequirementInfo { pub control_id: String, pub family: String, pub description: String }`
  - `pub fn bundled() -> &'static FedRampMap` — lazy global backed by `once_cell::sync::Lazy`.
  - `pub struct FedRampManifest { pub req_ids: Vec<String>, pub control_ids: Vec<String>, pub source_evidence_file: String }` (used by both CSV footer and JSON `_fedramp_manifest`).

- [ ] **Step 1: Write `src/fedramp_map.rs`**

```rust
//! Loader for the FedRAMP requirement/collector mapping table.
//!
//! The mapping is compiled into the binary via `include_str!` so grabber has
//! no runtime file dependency. All CSV and JSON evidence emission consults
//! this table to attach `FedRAMP Req IDs`, `FedRAMP Control IDs`, and
//! `Source Evidence File` metadata to every record.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};

const BUNDLED_JSON: &str = include_str!("../assets/fedramp-map.json");

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FedRampMapping {
    #[serde(default)]
    pub req_ids: Vec<String>,
    #[serde(default)]
    pub control_ids: Vec<String>,
}

impl FedRampMapping {
    pub fn is_empty(&self) -> bool {
        self.req_ids.is_empty() && self.control_ids.is_empty()
    }

    /// Pipe-separated, sorted, deduped.
    pub fn req_ids_joined(&self) -> String {
        let mut v = self.req_ids.clone();
        v.sort();
        v.dedup();
        v.join("|")
    }

    pub fn control_ids_joined(&self) -> String {
        let mut v = self.control_ids.clone();
        v.sort();
        v.dedup();
        v.join("|")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequirementInfo {
    pub control_id: String,
    pub family: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Deserialize)]
struct RawMap {
    #[serde(default)]
    schema: u32,
    #[serde(default)]
    collectors: BTreeMap<String, FedRampMapping>,
    #[serde(default)]
    requirements: BTreeMap<String, RequirementInfo>,
}

#[derive(Debug)]
pub struct FedRampMap {
    collectors: BTreeMap<String, FedRampMapping>,
    requirements: BTreeMap<String, RequirementInfo>,
}

impl FedRampMap {
    pub fn from_json(s: &str) -> Result<Self> {
        let raw: RawMap = serde_json::from_str(s).context("parse fedramp-map.json")?;
        anyhow::ensure!(
            raw.schema == 1,
            "unsupported fedramp-map schema {} (expected 1)",
            raw.schema
        );
        Ok(Self {
            collectors: raw.collectors,
            requirements: raw.requirements,
        })
    }

    pub fn get(&self, filename_prefix: &str) -> FedRampMapping {
        self.collectors
            .get(filename_prefix)
            .cloned()
            .unwrap_or_default()
    }

    pub fn all_requirements(&self) -> &BTreeMap<String, RequirementInfo> {
        &self.requirements
    }

    /// All filename prefixes that carry at least one requirement mapping.
    pub fn mapped_prefixes(&self) -> impl Iterator<Item = &str> {
        self.collectors
            .iter()
            .filter(|(_, m)| !m.is_empty())
            .map(|(k, _)| k.as_str())
    }
}

static BUNDLED: Lazy<FedRampMap> = Lazy::new(|| {
    FedRampMap::from_json(BUNDLED_JSON).expect("bundled fedramp-map.json must parse")
});

pub fn bundled() -> &'static FedRampMap {
    &BUNDLED
}

#[derive(Debug, Clone, Serialize)]
pub struct FedRampManifest {
    pub req_ids: Vec<String>,
    pub control_ids: Vec<String>,
    pub source_evidence_file: String,
}

impl FedRampManifest {
    pub fn new(mapping: &FedRampMapping, source_evidence_file: impl Into<String>) -> Self {
        let mut req_ids = mapping.req_ids.clone();
        req_ids.sort();
        req_ids.dedup();
        let mut control_ids = mapping.control_ids.clone();
        control_ids.sort();
        control_ids.dedup();
        Self {
            req_ids,
            control_ids,
            source_evidence_file: source_evidence_file.into(),
        }
    }
}
```

- [ ] **Step 2: Register the module in `main.rs`**

Modify `src/main.rs` — add `mod fedramp_map;` at the top of the module list, above `mod evidence;` (order matters: `evidence.rs` will reference `fedramp_map` types in Task 3).

- [ ] **Step 3: Verify `once_cell` and `anyhow` are already dependencies**

Run: `grep -E '^(once_cell|anyhow) ' /Users/austin-songer/code/grabber/Cargo.toml`
Expected: both present. If `once_cell` is missing, add `once_cell = "1"` to `[dependencies]` in the same commit.

- [ ] **Step 4: `cargo check`**

Run: `cargo check --manifest-path /Users/austin-songer/code/grabber/Cargo.toml`
Expected: clean build.

- [ ] **Step 5: Commit**

```bash
git add src/main.rs src/fedramp_map.rs Cargo.toml
git -c user.name="Austin Songer" -c user.email="asonger.pixel@gmail.com" commit -m "feat(fedramp): add FedRampMap loader with bundled mapping table"
```

---

## Task 3: Extend `CsvCollector` and `JsonCollector` traits with `fedramp_mapping()`

**Files:**
- Modify: `src/evidence.rs`

**Interfaces:**
- Consumes: `crate::fedramp_map::{FedRampMapping, bundled}` from Task 2.
- Produces: default trait methods so no existing collector needs to implement anything — mapping is looked up by `filename_prefix()`. Collectors that want to override (e.g., dynamic mapping) can do so.

- [ ] **Step 1: Add import at the top of `src/evidence.rs`**

Add `use crate::fedramp_map::{bundled, FedRampMapping};` alongside the existing `use` block.

- [ ] **Step 2: Add default method to `CsvCollector`**

Edit the `CsvCollector` trait definition (currently at line 55–76) to add one method with a default body:

```rust
#[async_trait]
pub trait CsvCollector: Send + Sync {
    fn name(&self) -> &str;
    fn filename_prefix(&self) -> &str;
    fn headers(&self) -> &'static [&'static str];
    async fn collect_rows(
        &self,
        account_id: &str,
        region: &str,
        dates: Option<(i64, i64)>,
    ) -> Result<Vec<Vec<String>>>;

    /// FedRAMP requirements this collector's output satisfies.
    /// Default: look up by `filename_prefix()` in the bundled mapping table.
    /// Override only if the mapping needs to vary at runtime.
    fn fedramp_mapping(&self) -> FedRampMapping {
        bundled().get(self.filename_prefix())
    }
}
```

- [ ] **Step 3: Add the same default method to `JsonCollector`**

Same one-method addition to the `JsonCollector` trait (line 31–43):

```rust
    fn fedramp_mapping(&self) -> FedRampMapping {
        bundled().get(self.filename_prefix())
    }
```

- [ ] **Step 4: Add the same default method to `EvidenceCollector`**

Same addition to `EvidenceCollector` (line 16–27).

- [ ] **Step 5: `cargo check`**

Run: `cargo check --manifest-path /Users/austin-songer/code/grabber/Cargo.toml`
Expected: clean build. Existing 124+ collectors inherit the default; no per-collector changes needed.

- [ ] **Step 6: Commit**

```bash
git add src/evidence.rs
git -c user.name="Austin Songer" -c user.email="asonger.pixel@gmail.com" commit -m "feat(fedramp): add fedramp_mapping() default method on collector traits

Every collector now advertises its FedRAMP Req IDs and control IDs via a
default trait method that looks itself up by filename_prefix in the bundled
mapping table. No per-collector change required."
```

---

## Task 4: `write_csv_bytes_with_manifest` in `src/runner/output.rs`

**Files:**
- Modify: `src/runner/output.rs`

**Interfaces:**
- Consumes: `FedRampMapping` (Task 2), collector `filename_prefix` + emitted basename from call-sites (Tasks 5–7).
- Produces:
  - `pub fn write_csv_bytes_with_manifest(headers: &[&str], rows: &[Vec<String>], mapping: &FedRampMapping, source_evidence_file: &str) -> Result<Vec<u8>>` — appends 3 metadata columns to every row plus a two-line footer.
  - Keeps `write_csv_bytes` for now but marks with `#[deprecated]` so all call-sites migrate.

- [ ] **Step 1: Replace `src/runner/output.rs`**

```rust
use std::path::PathBuf;

use anyhow::{Context, Result};
use chrono::Local;

use crate::fedramp_map::FedRampMapping;

pub const FEDRAMP_HEADERS: [&str; 3] = [
    "FedRAMP Req IDs",
    "FedRAMP Control IDs",
    "Source Evidence File",
];

/// Preferred writer. Appends three metadata columns to every row and writes
/// a two-line footer identifying the file and its FedRAMP mapping.
pub fn write_csv_bytes_with_manifest(
    headers: &[&str],
    rows: &[Vec<String>],
    mapping: &FedRampMapping,
    source_evidence_file: &str,
) -> Result<Vec<u8>> {
    let mut writer = csv::Writer::from_writer(Vec::new());

    let mut full_headers: Vec<&str> = headers.to_vec();
    full_headers.extend_from_slice(&FEDRAMP_HEADERS);
    writer
        .write_record(&full_headers)
        .context("CSV write headers")?;

    let req_joined = mapping.req_ids_joined();
    let control_joined = mapping.control_ids_joined();

    for row in rows {
        let mut full_row: Vec<String> = row.clone();
        full_row.push(req_joined.clone());
        full_row.push(control_joined.clone());
        full_row.push(source_evidence_file.to_string());
        writer.write_record(&full_row).context("CSV write row")?;
    }

    // Blank separator + two footer rows.
    writer
        .write_record::<[&str; 0], &str>([])
        .context("CSV write blank footer separator")?;
    writer
        .write_record(["# FedRAMP Req IDs", &req_joined])
        .context("CSV write req_ids footer")?;
    writer
        .write_record(["# Source Evidence File", source_evidence_file])
        .context("CSV write source footer")?;

    writer.flush().context("CSV flush")?;
    writer
        .into_inner()
        .map_err(|e| anyhow::anyhow!("CSV into_inner: {e}"))
}

/// Legacy no-manifest writer. New callers MUST use
/// `write_csv_bytes_with_manifest`. Kept only so this task compiles before
/// the call-site migration lands (Tasks 5–7).
#[deprecated(note = "use write_csv_bytes_with_manifest so evidence self-identifies")]
pub fn write_csv_bytes(headers: &[&str], rows: &[Vec<String>]) -> Result<Vec<u8>> {
    let mut writer = csv::Writer::from_writer(Vec::new());
    writer.write_record(headers).context("CSV write headers")?;
    for row in rows {
        writer.write_record(row).context("CSV write row")?;
    }
    writer.flush().context("CSV flush")?;
    writer
        .into_inner()
        .map_err(|e| anyhow::anyhow!("CSV into_inner: {e}"))
}

/// `YYYY-MM-DD-HHMMSS` suffix used in filenames across the runner.
pub fn date_path_suffix() -> String {
    Local::now().format("%Y-%m-%d-%H%M%S").to_string()
}

/// Build the canonical basename: `{account_id}_{prefix}-{timestamp}.csv`.
pub fn evidence_basename(account_id: &str, prefix: &str, ext: &str) -> String {
    format!("{account_id}_{prefix}-{}.{ext}", date_path_suffix())
}

/// Format a path as an OSC 8 hyperlink when stderr is a TTY.
pub fn format_path_with_osc8(path: &std::path::Path) -> String {
    use std::io::IsTerminal;

    let text = path.display().to_string();
    if !std::io::stderr().is_terminal() {
        return text;
    }
    let abs = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let url = format!("file://{}", abs.display());
    format!("\x1b]8;;{url}\x07{text}\x1b]8;;\x07")
}

// Silence the deprecation warning inside this file only.
#[allow(deprecated)]
mod _legacy_shim {
    pub use super::write_csv_bytes;
}

// Preserve the PathBuf import (used elsewhere in runner via re-export chains).
#[allow(dead_code)]
fn _pathbuf_marker() -> Option<PathBuf> {
    None
}
```

- [ ] **Step 2: `cargo check`**

Run: `cargo check --manifest-path /Users/austin-songer/code/grabber/Cargo.toml`
Expected: clean build with `deprecated` warnings pointing at every call-site of the old `write_csv_bytes`. Those warnings guide Tasks 5–7. `cargo clippy -- -D warnings` will still fail here — that's expected and cleared by Task 8.

- [ ] **Step 3: Commit**

```bash
git add src/runner/output.rs
git -c user.name="Austin Songer" -c user.email="asonger.pixel@gmail.com" commit -m "feat(fedramp): add write_csv_bytes_with_manifest with metadata columns + footer

Every CSV row gains three trailing columns (FedRAMP Req IDs, FedRAMP Control
IDs, Source Evidence File) and each file ends with a two-line manifest
footer. The old write_csv_bytes is deprecated pending call-site migration."
```

---

## Task 5: Migrate `collect_ops.rs` call-site

**Files:**
- Modify: `src/runner/collect_ops.rs`

**Interfaces:**
- Consumes: `write_csv_bytes_with_manifest`, `evidence_basename` (Task 4); `CsvCollector::fedramp_mapping()` (Task 3).
- Produces: emitted CSV files now carry metadata columns + footer.

- [ ] **Step 1: Read the current call-site**

Run: `grep -n "write_csv_bytes" /Users/austin-songer/code/grabber/src/runner/collect_ops.rs`
Note the exact line (was line 100 during survey).

- [ ] **Step 2: Migrate the call**

Change the import at line 11:

```rust
use crate::runner::output::{evidence_basename, format_path_with_osc8, write_csv_bytes_with_manifest};
```

Replace the write block. Find the current pattern (around line 95–105):

```rust
let bytes = write_csv_bytes(collector.headers(), &rows)?;
// ...file path built here...
```

Replace with:

```rust
let basename = evidence_basename(&account_id, collector.filename_prefix(), "csv");
let mapping = collector.fedramp_mapping();
let bytes = write_csv_bytes_with_manifest(
    collector.headers(),
    &rows,
    &mapping,
    &basename,
)?;
// ...file path uses `basename` from here down...
```

If the current file-path construction builds its own basename with `date_path_suffix()`, replace that with the `basename` variable above so the string written into the CSV footer and the actual filename are guaranteed identical.

- [ ] **Step 3: `cargo check`**

Run: `cargo check --manifest-path /Users/austin-songer/code/grabber/Cargo.toml`
Expected: clean, one fewer `deprecated` warning.

- [ ] **Step 4: Commit**

```bash
git add src/runner/collect_ops.rs
git -c user.name="Austin Songer" -c user.email="asonger.pixel@gmail.com" commit -m "refactor(runner): migrate collect_ops CSV writes to manifest-aware writer"
```

---

## Task 6: Migrate `multi_account.rs`, `tui_runners.rs`, `tui_session.rs` call-sites

**Files:**
- Modify: `src/runner/multi_account.rs`
- Modify: `src/runner/tui_runners.rs`
- Modify: `src/runner/tui_session.rs`

**Interfaces:** same as Task 5.

- [ ] **Step 1: Enumerate every remaining call-site**

Run: `grep -rn "write_csv_bytes" /Users/austin-songer/code/grabber/src --include="*.rs" | grep -v "with_manifest" | grep -v "^.*output.rs:"`
Expected: 3–5 sites across the three files above.

- [ ] **Step 2: Migrate each site**

For every match, apply the same three-line replacement pattern as Task 5:

```rust
let basename = evidence_basename(&account_id, collector.filename_prefix(), "csv");
let mapping = collector.fedramp_mapping();
let bytes = write_csv_bytes_with_manifest(
    collector.headers(),
    &rows,
    &mapping,
    &basename,
)?;
```

Adjust variable names to match local scope (`inventory_headers` and `inventory_global_rows` in multi_account.rs around line 491 — for inventory collectors, the mapping key is the collector's `filename_prefix()`; for the unified inventory CSV that concatenates multiple asset types, pass `FedRampMapping::default()` and use the unified `AWS_Inventory` basename — the inventory-CSV rows already carry the asset-type distinction).

Import once per file:
```rust
use crate::runner::output::{evidence_basename, write_csv_bytes_with_manifest};
```
And drop the old `write_csv_bytes` import.

- [ ] **Step 3: `cargo check`**

Run: `cargo check --manifest-path /Users/austin-songer/code/grabber/Cargo.toml`
Expected: no `deprecated` warnings from `write_csv_bytes` anywhere.

- [ ] **Step 4: `cargo clippy -- -D warnings`**

Run: `cargo clippy --manifest-path /Users/austin-songer/code/grabber/Cargo.toml -- -D warnings`
Expected: clean.

- [ ] **Step 5: Delete the deprecated shim**

Now that no caller uses it, remove `write_csv_bytes` (and the `_legacy_shim` module) from `src/runner/output.rs`. Re-run `cargo check` — expected: clean.

- [ ] **Step 6: Commit**

```bash
git add src/runner/multi_account.rs src/runner/tui_runners.rs src/runner/tui_session.rs src/runner/output.rs
git -c user.name="Austin Songer" -c user.email="asonger.pixel@gmail.com" commit -m "refactor(runner): migrate all CSV call-sites to manifest-aware writer

Removes the deprecated write_csv_bytes shim. Every CSV grabber emits now
self-identifies via the FedRAMP Req IDs / Control IDs / Source Evidence File
columns and the two-line footer."
```

---

## Task 7: Add `_fedramp_manifest` to JSON evidence

**Files:**
- Modify: `src/evidence.rs`
- Modify: every JSON write-out site (search: `JsonInventoryReport {` and `serde_json::to_string(&report`)

**Interfaces:**
- Consumes: `FedRampManifest` (Task 2), `JsonCollector::fedramp_mapping()` (Task 3).
- Produces: every JSON evidence file gains a top-level `_fedramp_manifest` object.

- [ ] **Step 1: Extend `JsonInventoryReport`**

Edit `src/evidence.rs` around line 45:

```rust
use crate::fedramp_map::FedRampManifest;

#[derive(Debug, Serialize)]
pub struct JsonInventoryReport {
    pub collected_at: String,
    pub account_id: String,
    pub region: String,
    pub collector: String,
    pub record_count: usize,
    pub records: Vec<serde_json::Value>,
    #[serde(rename = "_fedramp_manifest")]
    pub fedramp_manifest: FedRampManifest,
}
```

- [ ] **Step 2: Extend `EvidenceReport`**

Same file, edit `EvidenceReport` (line 94–100):

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceReport {
    pub metadata: ReportMetadata,
    pub collector: String,
    pub record_count: usize,
    pub records: Vec<EvidenceRecord>,
    #[serde(rename = "_fedramp_manifest", default)]
    pub fedramp_manifest: Option<FedRampManifest>,
}
```

Make `FedRampManifest` implement `Deserialize` so this compiles — go back to `src/fedramp_map.rs` and add `Deserialize` to the derive list on `FedRampManifest`.

- [ ] **Step 3: Populate at every construction site**

Run: `grep -rn "JsonInventoryReport {\|EvidenceReport {" /Users/austin-songer/code/grabber/src --include="*.rs"`
For every construction site, add the field. Pattern:

```rust
fedramp_manifest: FedRampManifest::new(&collector.fedramp_mapping(), &basename),
```

`basename` is the file basename that will be written (compute it in the same block; see `evidence_basename` from Task 4). For `EvidenceReport` sites where the collector isn't in scope, pass `FedRampManifest::new(&FedRampMapping::default(), &basename)` — the coverage report will surface uncovered files.

- [ ] **Step 4: `cargo check`**

Run: `cargo check --manifest-path /Users/austin-songer/code/grabber/Cargo.toml`
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add src/evidence.rs src/fedramp_map.rs $(grep -rl "JsonInventoryReport {\|EvidenceReport {" /Users/austin-songer/code/grabber/src --include="*.rs")
git -c user.name="Austin Songer" -c user.email="asonger.pixel@gmail.com" commit -m "feat(fedramp): add _fedramp_manifest to JSON evidence envelopes"
```

---

## Task 8: Coverage report writer

**Files:**
- Create: `src/fedramp_coverage.rs`
- Modify: `src/main.rs` (add `mod fedramp_coverage;`)
- Modify: `src/runner/collect_ops.rs` (call the writer at end-of-run — or wherever the post-run hook currently lives; grep for `"Run complete"` or similar).
- Modify: `src/runner/multi_account.rs` (same, once per account run).

**Interfaces:**
- Consumes: `FedRampMap::all_requirements()` (Task 2); the run's list of `(filename_prefix, emitted_basename, row_count)` tuples.
- Produces:
  - `pub struct CoverageRun { pub emitted: Vec<CoverageEmission> }`
  - `pub struct CoverageEmission { pub filename_prefix: String, pub source_evidence_file: String, pub row_count: usize }`
  - `pub fn write_coverage_report(run: &CoverageRun, run_dir: &Path) -> Result<PathBuf>` — writes `<run_dir>/fedramp-coverage-actual.csv`.

- [ ] **Step 1: Create `src/fedramp_coverage.rs`**

```rust
//! Post-run coverage report — for every Req ID in the bundled mapping, list
//! which collector and file (if any) covered it during this run.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::fedramp_map::bundled;

#[derive(Debug, Clone)]
pub struct CoverageEmission {
    pub filename_prefix: String,
    pub source_evidence_file: String,
    pub row_count: usize,
}

#[derive(Debug, Default)]
pub struct CoverageRun {
    pub emitted: Vec<CoverageEmission>,
}

impl CoverageRun {
    pub fn record(&mut self, filename_prefix: impl Into<String>, source_evidence_file: impl Into<String>, row_count: usize) {
        self.emitted.push(CoverageEmission {
            filename_prefix: filename_prefix.into(),
            source_evidence_file: source_evidence_file.into(),
            row_count,
        });
    }
}

pub fn write_coverage_report(run: &CoverageRun, run_dir: &Path) -> Result<PathBuf> {
    let map = bundled();

    // Invert emissions to Req ID → (collector, file, rows)
    let mut by_req: BTreeMap<&str, (&str, &str, usize)> = BTreeMap::new();
    for e in &run.emitted {
        let mapping = map.get(&e.filename_prefix);
        for req in &mapping.req_ids {
            by_req.insert(
                req.as_str(),
                (&e.filename_prefix, &e.source_evidence_file, e.row_count),
            );
        }
    }

    let path = run_dir.join("fedramp-coverage-actual.csv");
    let mut wtr = csv::Writer::from_path(&path)
        .with_context(|| format!("open coverage report at {}", path.display()))?;

    wtr.write_record([
        "Req ID",
        "Control ID",
        "Family",
        "Description",
        "Collector Name",
        "Source Evidence File",
        "Row Count",
        "Bucket",
    ])
    .context("write coverage header")?;

    for (req_id, info) in map.all_requirements() {
        let (collector, file, rows, bucket) = match by_req.get(req_id.as_str()) {
            Some((c, f, r)) => (*c, *f, *r, "COVERED"),
            None => ("", "", 0usize, "UNCOVERED"),
        };
        wtr.write_record([
            req_id.as_str(),
            info.control_id.as_str(),
            info.family.as_str(),
            info.description.as_str(),
            collector,
            file,
            &rows.to_string(),
            bucket,
        ])
        .context("write coverage row")?;
    }

    wtr.flush().context("flush coverage report")?;
    Ok(path)
}
```

- [ ] **Step 2: Register the module in `main.rs`**

Add `mod fedramp_coverage;` after `mod fedramp_map;`.

- [ ] **Step 3: Thread `CoverageRun` through the runner**

In `src/runner/collect_ops.rs`, add a `CoverageRun` accumulator to whatever struct/function collects CSV results (search for the outer loop that iterates `csv_collectors`). After each successful CSV write, call:

```rust
coverage.record(collector.filename_prefix(), &basename, rows.len());
```

At the end of the function, before returning, call:

```rust
let coverage_path = crate::fedramp_coverage::write_coverage_report(&coverage, &run_dir)?;
tracing::info!("FedRAMP coverage report: {}", coverage_path.display());
```

(If the module uses `println!`/`eprintln!` instead of `tracing`, follow that convention.)

Do the same in `src/runner/multi_account.rs` (once per account, written into the per-account run directory).

- [ ] **Step 4: `cargo check` + `cargo clippy`**

Run:
```bash
cargo check --manifest-path /Users/austin-songer/code/grabber/Cargo.toml
cargo clippy --manifest-path /Users/austin-songer/code/grabber/Cargo.toml -- -D warnings
```
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add src/main.rs src/fedramp_coverage.rs src/runner/collect_ops.rs src/runner/multi_account.rs
git -c user.name="Austin Songer" -c user.email="asonger.pixel@gmail.com" commit -m "feat(fedramp): emit fedramp-coverage-actual.csv after every run

One row per NIST-1000-series requirement showing whether this run produced
evidence for it, which collector, which file, and how many rows."
```

---

## Task 9: Extend inventory XLSX writer

**Files:**
- Modify: `src/inventory_xlsx.rs`

**Interfaces:**
- Consumes: `FedRampMapping` from the inventory collector.
- Produces: the XLSX inventory now carries the same three metadata columns as its CSV counterpart.

- [ ] **Step 1: Locate the inventory column list**

Run: `grep -n "UNIQUE ASSET IDENTIFIER\|Comments" /Users/austin-songer/code/grabber/src/inventory_xlsx.rs | head -10`

- [ ] **Step 2: Append the three metadata columns to the schema**

At the column-definition site, add three columns to the RIGHT of the existing `Comments` column: `FedRAMP Req IDs`, `FedRAMP Control IDs`, `Source Evidence File`.

For every row-write, append the three values. For the unified inventory (multiple asset types in one XLSX), each row's mapping comes from the per-asset-type collector's `fedramp_mapping()` — extend the row-emit signature to take a `FedRampMapping` and a `&str` basename.

Also update `inventory-excel-mapping.md` (in the repo root) so the canonical column-index list stays truthful. Existing columns keep their indices; the three new columns get 15, 16, 17.

- [ ] **Step 3: `cargo check`**

Run: `cargo check --manifest-path /Users/austin-songer/code/grabber/Cargo.toml`
Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add src/inventory_xlsx.rs inventory-excel-mapping.md
git -c user.name="Austin Songer" -c user.email="asonger.pixel@gmail.com" commit -m "feat(fedramp): add metadata columns to inventory XLSX output"
```

---

## Task 10: Documentation updates

**Files:**
- Modify: `evidence-list.md`
- Create: `docs/fedramp-coverage.md`

**Interfaces:** none (docs only).

- [ ] **Step 1: Update `evidence-list.md`**

Add a top-of-file note (below the existing preamble):

```markdown
> **FedRAMP mapping:** every CSV row and JSON record grabber emits carries
> `FedRAMP Req IDs`, `FedRAMP Control IDs`, and `Source Evidence File`
> columns. Each file also ends with a two-line footer identifying itself.
> Canonical mapping lives in `assets/fedramp-map.json`; see
> `docs/fedramp-coverage.md` for the runtime coverage report.
```

Do NOT append per-collector mapping rows to this file — it stays authored by the codebase, not by the mapping table. Auditors reading a specific CSV get the mapping from the row/footer; reading `evidence-list.md` gets the collector catalog.

- [ ] **Step 2: Create `docs/fedramp-coverage.md`**

```markdown
# FedRAMP Coverage & Evidence Self-Identification

Every evidence file grabber emits carries three metadata columns and a
manifest footer so an auditor can identify the file's mapping even after
it's been renamed, extracted from a bundle, or pasted into a working paper.

## Per-row columns

Every CSV row gets three trailing columns (right of all pre-existing columns):

| Column | Value |
|---|---|
| `FedRAMP Req IDs` | Pipe-separated, sorted list of NIST-1000-series Req IDs (e.g. `NIST-1043\|NIST-1519\|NIST-1535`). |
| `FedRAMP Control IDs` | Pipe-separated NIST 800-53 Moderate control IDs (e.g. `AC-02h.\|PS-04a-d\|PS-07d.`). |
| `Source Evidence File` | Basename of the emitted file (e.g. `123456789012_Okta_Deprovisioning_Timeliness-2026-07-16-142330.csv`). |

## Trailing footer

Every CSV ends with:

```
<blank row>
# FedRAMP Req IDs,NIST-1043|NIST-1519|NIST-1535
# Source Evidence File,123456789012_Okta_Deprovisioning_Timeliness-2026-07-16-142330.csv
```

## JSON manifest

Every JSON evidence file has a top-level `_fedramp_manifest` object:

```json
{
  "collected_at": "...",
  "records": [...],
  "_fedramp_manifest": {
    "req_ids": ["NIST-1043", "NIST-1519", "NIST-1535"],
    "control_ids": ["AC-02h.", "PS-04a-d", "PS-07d."],
    "source_evidence_file": "123456789012_Okta_Deprovisioning_Timeliness-2026-07-16-142330.json"
  }
}
```

## Per-run coverage report

After every run, grabber writes `<run-dir>/fedramp-coverage-actual.csv` with
one row per NIST-1000-series Req ID (all 193 in the FedRAMP Moderate IRL):

| Column | Value |
|---|---|
| `Req ID` | e.g. `NIST-1043` |
| `Control ID` | e.g. `AC-02h.` |
| `Family` | e.g. `AC` |
| `Description` | First sentence of the requirement text |
| `Collector Name` | Filename prefix of the collector that produced evidence, or blank |
| `Source Evidence File` | Basename of the emitted file, or blank |
| `Row Count` | Rows produced this run, or `0` |
| `Bucket` | `COVERED` or `UNCOVERED` |

## Adding a new collector's mapping

Edit `assets/fedramp-map.json` — no code change required. New collectors
inherit their mapping from the JSON via the `fedramp_mapping()` default
method on the `CsvCollector` / `JsonCollector` trait.
```

- [ ] **Step 3: Commit**

```bash
git add evidence-list.md docs/fedramp-coverage.md
git -c user.name="Austin Songer" -c user.email="asonger.pixel@gmail.com" commit -m "docs(fedramp): document evidence self-identification and coverage report"
```

---

## Task 11: End-to-end smoke run

**Files:** none modified.

**Interfaces:** validates the whole pipeline against a real AWS account.

- [ ] **Step 1: Pick a small, cheap collector to run**

E.g. `IAM_Users` (fast, no time window):

```bash
cargo run --manifest-path /Users/austin-songer/code/grabber/Cargo.toml --release -- \
  --provider aws \
  --collector IAM_Users \
  --output-dir /tmp/grabber-fedramp-smoke
```

- [ ] **Step 2: Verify the CSV has the new columns and footer**

```bash
ls /tmp/grabber-fedramp-smoke/
head -1 /tmp/grabber-fedramp-smoke/*IAM_Users*.csv
tail -3 /tmp/grabber-fedramp-smoke/*IAM_Users*.csv
```

Expected:
- Header ends with `,FedRAMP Req IDs,FedRAMP Control IDs,Source Evidence File`.
- Last three lines are: `(blank)`, `# FedRAMP Req IDs,...`, `# Source Evidence File,<basename>`.

- [ ] **Step 3: Verify the coverage report exists and has 193 rows**

```bash
wc -l /tmp/grabber-fedramp-smoke/fedramp-coverage-actual.csv
```

Expected: `194` (193 data rows + 1 header).

- [ ] **Step 4: Verify at least one row in the coverage report is `COVERED`**

```bash
grep ",COVERED$" /tmp/grabber-fedramp-smoke/fedramp-coverage-actual.csv | head -5
```

Expected: at least one row corresponding to the Req IDs that `IAM_Users` maps to (per `fedramp-map.json`).

- [ ] **Step 5: Nothing to commit — this is a validation step**

Report result. If any step fails, open a follow-up task; do not amend earlier commits.

---

## Self-Review

**1. Spec coverage:**
- P0-META-01 (Req/Control column injection) → Task 4 (writer) + Task 6 (call-sites).
- P0-META-02 (Source Evidence File column) → Task 4 (writer) + Task 5–6 (basename threading).
- P0-META-03 (trailing footer) → Task 4.
- P0-META-04 (central mapping table) → Tasks 1–3.
- P0-META-05 (backfill all 124 existing collectors) → Tasks 3 + 6 automatically because emission is centralized — no per-collector edit needed.
- P0-META-06 (coverage report) → Task 8.
- JSON manifest → Task 7.
- Inventory XLSX → Task 9.
- Docs → Task 10.
- E2E validation → Task 11.

Every P0-META requirement has an owning task.

**2. Placeholder scan:** no "TBD", "fill in", or "similar to Task N". Task 1's mapping-population step contains a runnable Python script for bulk requirements; the per-collector portion is spec'd as "look up each EV# in the classification report" with the exact file path.

**3. Type consistency:** `FedRampMapping` / `FedRampManifest` / `FedRampMap` names are used identically across Tasks 2/3/4/7/8. `evidence_basename` and `write_csv_bytes_with_manifest` signatures match across Tasks 4/5/6/7. `CoverageRun`/`CoverageEmission` naming is consistent between Task 8's module and its call-sites.

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-07-16-fedramp-evidence-metadata.md`. Two execution options:

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration.

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints.

Which approach?

---

## Follow-on Plans (not this one)

After this plan lands, three sibling P0 plans become unblocked and can run in parallel:

- `2026-07-XX-fedramp-aws-collectors.md` — 12 new AWS collectors (SSM allowlisting, GuardDuty runtime/malware, NetworkFirewall fail-closed, ClientVPN split-tunnel, Config FIM, TransitGateway peering, IAM credential-report expiration, Session_Timeout_Config, Doc_Repo_Backup_Config, GuardDuty_Runtime_Coverage, SSM_Automation_Response_Runbooks, AMI_Default_Credential_Scan). Each collector is one task following the existing `src/providers/aws/*` pattern. Every new collector adds one entry to `assets/fedramp-map.json` in the same commit.

- `2026-07-XX-fedramp-okta-collectors.md` — 5 new modules on `okta-rs` (`lifecycle`, `admin_roles`, `access_reviews`, `sign_in_widget`, `threat_insight`) plus 19 collectors in `src/providers/okta/`. Ordered so `okta-rs` API modules land before consumer collectors.

- `2026-07-XX-fedramp-jira-collectors.md` — new `jira-rs::api::jql_sla` module + 26 named collectors in `src/providers/jira/`. JQL templates parameterized via `jira-config.toml`.
