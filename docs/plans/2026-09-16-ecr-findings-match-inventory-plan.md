# ECR Findings Match Inventory — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The Inspector2 ECR image findings CSV contains every ACTIVE vulnerability for exactly the image digests listed in the newest inventory CSV, grouped one row per vulnerability with inventory asset IDs one per line, plus a separate check (CLI and TUI) that proves it.

**Architecture:** A crate-level reader (`src/inventory_digests.rs`) returns the inventory's container digests. The existing `InspectorEcrImagesCollector` stops choosing images itself: it queries `ListFindings` per inventory digest (expanding image indexes), annotates each row with the inventory asset ID, and rolls up by (CVE, package) with newline-separated lists. A new `src/ecr_findings_check.rs` compares live Inspector2 vulnerability IDs per asset with the CSV and is exposed as `--check-ecr-findings` and a TUI feature.

**Tech Stack:** Rust, tokio, `aws-sdk-inspector2`, `aws-sdk-ecr`, `csv`, `serde_json`, `ratatui`/`crossterm`, `tempfile` (tests).

**Spec:** `docs/plans/2026-09-16-ecr-findings-match-inventory.md`

## Global Constraints

- Errors: `anyhow::Result` / `Context`; no `unwrap()`/`expect()` in production code (tests may use `expect`).
- Imports grouped std → external crates → `crate::*`, blank line between groups.
- `cargo fmt`, `cargo clippy -- -D warnings` clean for every file you touch (pre-existing warnings elsewhere are out of scope), `cargo test` passes.
- Every task leaves the tree compiling (a hook runs `cargo check` after each write): add a file before declaring it in a parent `mod`/`lib.rs`.
- Commits: author `Austin Songer <asonger.pixel@gmail.com>`, on `main`, no co-author or "Generated with" trailers.
- Only ACTIVE findings. No date filter for ECR image findings.
- Grouping key stays (CVE ID, Package Name); non-CVE findings keep one row per finding ARN.
- Multi-value cells (`Repository Name`, `Image Tags`, `Image Hash`, `Resource ID`, `Asset Identifier`) are newline (`\n`) separated, each sorted and de-duplicated.
- Asset identifiers are copied verbatim from the inventory's `UNIQUE ASSET IDENTIFIER` column.
- CHANGELOG uses placeholder IDs (`123456789012`), never real account IDs.
- Deviation from spec (intentional): the inventory reader lives at `src/inventory_digests.rs` (crate level) instead of under `inspector_ecr/`, because the check module also needs it.

## File map

| File | Responsibility |
|---|---|
| `src/inventory_digests.rs` (new) | Find newest `AWS_Inventory-*.csv`; parse `Container Image` rows into `InventoryImage`; shared newest-file finder. |
| `src/providers/aws/inspector_ecr/transforms.rs` | Add `annotate_inventory_row`, `index_child_digests`; change `rollup_ecr_by_cve` separators; delete `filter_latest_image_per_repo`, `dedup_ecr_image_rows`. |
| `src/providers/aws/inspector_ecr/mod.rs` | Collector: inventory-driven queries, index expansion, header `Inventory File`. Extract per-finding row builder `finding_row`. |
| `src/ecr_findings_check.rs` (new) | Check logic (pure comparison + AWS queries + CSV report). |
| `src/cli.rs`, `src/main.rs`, `src/runner/cli_runners.rs` | `--check-ecr-findings` flag and runner. |
| `src/tui/state.rs`, `src/tui/app/mod.rs`, `src/tui/app/nav.rs`, `src/tui/events.rs`, `src/tui/ui/mod.rs`, `src/tui/ui/ecr_check.rs` (new), `src/tui/ui/frame.rs`, `src/tui/ui/setup.rs`, `src/runner/tui_session.rs` | TUI "ECR Findings Check" feature. |
| `CHANGELOG.md` | Operator-facing entries. |

---

### Task 1: Remove superseded experiments

**Files:**
- Delete: `src/ecr_production_images.rs`, `docs/plans/2026-09-16-ecr-production-image-check.md`
- Modify: `src/lib.rs`, `src/cli.rs`, `src/main.rs`, `src/runner/cli_runners.rs`, `CHANGELOG.md`

**Interfaces:**
- Consumes: nothing.
- Produces: a tree with no `ecr_production_images` / `check_ecr_production` / `check_ecr_inventory` symbols. Keeps the paginated `describe_images` loop in `src/inventory_orchestrator/compute.rs` and its `Fixed` CHANGELOG entry.

- [ ] **Step 1: Delete the production-image check wiring**

In `src/main.rs` remove this block:

```rust
    if cli.check_ecr_production {
        return run_ecr_production_check_cli(&cli).await;
    }

```

and change the import back to:

```rust
use the_grabber::runner::cli_runners::{run_inventory_cli, run_poam_cli, run_standard_cli};
```

In `src/runner/cli_runners.rs` delete the whole `pub async fn run_ecr_production_check_cli(cli: &Cli) -> Result<()> { … }` function and its doc comment.

In `src/cli.rs` delete the block starting at `// ------- ECR production image check -------` through the `pub prod_tag: Option<String>,` field (three fields: `check_ecr_production`, `org_profile`, `prod_tag`).

In `src/lib.rs` delete the line `pub mod ecr_production_images;`.

- [ ] **Step 2: Delete files**

```bash
git rm -q --cached src/ecr_production_images.rs 2>/dev/null; rm -f src/ecr_production_images.rs
git rm -q docs/plans/2026-09-16-ecr-production-image-check.md
```

- [ ] **Step 3: Remove CHANGELOG entry**

In `CHANGELOG.md` under `## [Unreleased]` → `### Added`, delete the entire bullet that begins `- **\`--check-ecr-production\` checks that Inspector2 is scanning the image` (through the line ending `profile.` before the next `- **` bullet). Confirm no mention of `--check-ecr-inventory` or `--check-ecr-production` remains:

Run: `grep -n "check-ecr" CHANGELOG.md`
Expected: no output.

- [ ] **Step 4: Verify**

Run: `cargo build 2>&1 | grep -E "^error|Finished"` → `Finished`
Run: `grep -rn "ecr_production_images\|check_ecr_production\|check_ecr_inventory\|ecr_inventory_check" src` → no output.
Run: `cargo test` → all pass.

- [ ] **Step 5: Commit**

```bash
git add -A src/lib.rs src/cli.rs src/main.rs src/runner/cli_runners.rs CHANGELOG.md src/inventory_orchestrator/compute.rs docs/plans
git commit -m "Remove superseded ECR image checks; keep inventory image pagination"
```

(`src/inventory_orchestrator/compute.rs` carries the already-written pagination fix; `git diff --cached src/inventory_orchestrator/compute.rs` must show only the `describe_images` loop change.)

---

### Task 2: Inventory digest reader

**Files:**
- Create: `src/inventory_digests.rs`
- Modify: `src/lib.rs` (add `pub mod inventory_digests;` after the file exists)

**Interfaces:**
- Produces:
  ```rust
  pub struct InventoryImage { pub asset_id: String, pub account: String, pub region: String,
      pub repository: String, pub repository_arn: String, pub digest: String }
  pub struct Inventory { pub path: PathBuf, pub images: Vec<InventoryImage>, pub rows_without_digest: usize }
  pub fn latest_file(dir: &Path, marker: &str) -> Result<PathBuf>
  pub fn read_inventory(path: &Path) -> Result<Inventory>
  pub fn load_latest(dir: &Path) -> Result<Inventory>   // latest_file(dir, "AWS_Inventory-") + read_inventory
  ```

- [ ] **Step 1: Write the failing tests** (create the file with tests and stub signatures)

```rust
//! Container image digests listed in an inventory CSV (`AWS_Inventory-*.csv`).
//! The inventory decides which ECR image digests the findings output covers.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventoryImage {
    pub asset_id: String,
    pub account: String,
    pub region: String,
    pub repository: String,
    pub repository_arn: String,
    pub digest: String,
}

#[derive(Debug, Clone)]
pub struct Inventory {
    pub path: PathBuf,
    pub images: Vec<InventoryImage>,
    pub rows_without_digest: usize,
}

pub fn latest_file(_dir: &Path, _marker: &str) -> Result<PathBuf> {
    bail!("unimplemented")
}

pub fn read_inventory(_path: &Path) -> Result<Inventory> {
    bail!("unimplemented")
}

pub fn load_latest(dir: &Path) -> Result<Inventory> {
    read_inventory(&latest_file(dir, "AWS_Inventory-")?)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER: &str = "UNIQUE ASSET IDENTIFIER,IPv4 or IPv6 Address,Virtual,Public,DNS Name or URL,MAC Address,Location,Asset Type,Hardware Make/Model,Software/ Database Vendor,Software/ Database Name & Version,Function,VLAN/ Network ID,Comments,FedRAMP Req IDs,FedRAMP Control IDs,Source Evidence File\n";

    fn write(dir: &Path, name: &str, body: &str) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, format!("{HEADER}{body}")).expect("write");
        p
    }

    #[test]
    fn parses_container_rows() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = write(
            dir.path(),
            "AWS_Inventory-2026-09-16-172542.csv",
            "123456789012.dkr.ecr.us-east-1.amazonaws.com/team/app,,Yes,No,,,us-east-1 / ECR Repo: team/app,Container Image,,team/app,team/app | Tags: v1,,,\"RepositoryArn: arn:aws:ecr:us-east-1:123456789012:repository/team/app | ImageDigest: sha256:abc | ImageTags: v1\",,,f.csv\n\
             123456789012.dkr.ecr.us-east-1.amazonaws.com/empty,,Yes,No,,,us-east-1,Container Image,,empty,empty,,,\"RepositoryArn: arn:aws:ecr:us-east-1:123456789012:repository/empty | ImageCount: 0\",,,f.csv\n\
             arn:aws:kms:us-east-1:123456789012:key/1,,Yes,No,,,us-east-1,KMS Key,,x,x,,,Arn: x,,,f.csv\n",
        );
        let inv = read_inventory(&p).expect("read");
        assert_eq!(inv.rows_without_digest, 1);
        assert_eq!(
            inv.images,
            vec![InventoryImage {
                asset_id: "123456789012.dkr.ecr.us-east-1.amazonaws.com/team/app".into(),
                account: "123456789012".into(),
                region: "us-east-1".into(),
                repository: "team/app".into(),
                repository_arn: "arn:aws:ecr:us-east-1:123456789012:repository/team/app".into(),
                digest: "sha256:abc".into(),
            }]
        );
    }

    #[test]
    fn latest_file_picks_newest_recursively() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(dir.path().join("2026/08-AUG")).expect("mkdir");
        std::fs::create_dir_all(dir.path().join("2026/09-SEP")).expect("mkdir");
        write(&dir.path().join("2026/08-AUG"), "AWS_Inventory-2026-08-31-235959.csv", "");
        let newest = write(&dir.path().join("2026/09-SEP"), "AWS_Inventory-2026-09-16-172542.csv", "");
        write(&dir.path().join("2026/09-SEP"), "AWS_Inventory-2026-09-16-090000.csv", "");
        assert_eq!(latest_file(dir.path(), "AWS_Inventory-").expect("found"), newest);
        assert!(latest_file(dir.path(), "Nope-").is_err());
    }
}
```

- [ ] **Step 2: Add the module and run tests to verify they fail**

Add `pub mod inventory_digests;` to `src/lib.rs` (alphabetical position, after `pub mod fedramp_map;`).

Run: `cargo test --lib inventory_digests`
Expected: FAIL (`unimplemented`).

- [ ] **Step 3: Implement**

Replace the two stub functions:

```rust
/// Newest file under `dir` (recursive; hidden dirs and `target` skipped) whose
/// name contains `marker` followed by a fixed-width `YYYY-MM-DD-HHMMSS.csv`.
pub fn latest_file(dir: &Path, marker: &str) -> Result<PathBuf> {
    fn walk(dir: &Path, marker: &str, best: &mut Option<(String, PathBuf)>) -> Result<()> {
        for entry in std::fs::read_dir(dir).with_context(|| format!("cannot read {}", dir.display()))? {
            let path = entry?.path();
            let name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
            if path.is_dir() {
                if !name.starts_with('.') && name != "target" {
                    walk(&path, marker, best)?;
                }
                continue;
            }
            let Some(stem) = name.strip_suffix(".csv") else { continue };
            let Some(pos) = stem.find(marker) else { continue };
            let stamp = &stem[pos + marker.len()..];
            if stamp.len() != 17 || !stamp.chars().all(|c| c.is_ascii_digit() || c == '-') {
                continue;
            }
            if best.as_ref().is_none_or(|(s, _)| stamp > s.as_str()) {
                *best = Some((stamp.to_string(), path));
            }
        }
        Ok(())
    }
    let mut best = None;
    walk(dir, marker, &mut best)?;
    match best {
        Some((_, p)) => Ok(p),
        None => bail!("no '*{marker}YYYY-MM-DD-HHMMSS.csv' under {}", dir.display()),
    }
}

fn comment_field<'a>(comments: &'a str, key: &str) -> Option<&'a str> {
    comments
        .split(" | ")
        .find_map(|p| p.trim().strip_prefix(key).map(str::trim))
        .filter(|v| !v.is_empty())
}

/// `Container Image` rows of an inventory CSV that carry an `ImageDigest`.
pub fn read_inventory(path: &Path) -> Result<Inventory> {
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .from_path(path)
        .with_context(|| format!("cannot open {}", path.display()))?;
    let headers = reader.headers().context("inventory CSV header")?.clone();
    let col = |name: &str| {
        headers
            .iter()
            .position(|h| h.trim() == name)
            .with_context(|| format!("{} missing '{name}' column", path.display()))
    };
    let (id_i, type_i, comments_i) = (col("UNIQUE ASSET IDENTIFIER")?, col("Asset Type")?, col("Comments")?);

    let mut images = Vec::new();
    let mut rows_without_digest = 0;
    for rec in reader.records() {
        let rec = rec.with_context(|| format!("CSV parse error in {}", path.display()))?;
        if rec.get(type_i).map(str::trim) != Some("Container Image") {
            continue;
        }
        let comments = rec.get(comments_i).unwrap_or("");
        let (Some(arn), Some(digest)) = (
            comment_field(comments, "RepositoryArn:"),
            comment_field(comments, "ImageDigest:"),
        ) else {
            rows_without_digest += 1;
            continue;
        };
        // arn:aws:ecr:<region>:<account>:repository/<name>
        let mut parts = arn.splitn(6, ':');
        let (region, account, rest) = (parts.nth(3), parts.next(), parts.next());
        let (Some(region), Some(account), Some(repository)) =
            (region, account, rest.and_then(|r| r.strip_prefix("repository/")))
        else {
            rows_without_digest += 1;
            continue;
        };
        images.push(InventoryImage {
            asset_id: rec.get(id_i).unwrap_or("").trim().to_string(),
            account: account.to_string(),
            region: region.to_string(),
            repository: repository.to_string(),
            repository_arn: arn.to_string(),
            digest: digest.to_string(),
        });
    }
    Ok(Inventory { path: path.to_path_buf(), images, rows_without_digest })
}
```

- [ ] **Step 4: Run tests**

Run: `cargo fmt && cargo test --lib inventory_digests`
Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
git add src/inventory_digests.rs src/lib.rs
git commit -m "Add inventory container digest reader"
```

---

### Task 3: Row annotation, index manifest parsing, newline rollup

**Files:**
- Modify: `src/providers/aws/inspector_ecr/transforms.rs`

**Interfaces:**
- Consumes: nothing.
- Produces:
  ```rust
  pub(super) const IDX_ASSET_ID: usize = 47;
  pub(super) const IDX_INVENTORY_FILE: usize = 48;
  pub(super) fn annotate_inventory_row(row: Vec<String>, asset_id: &str, inventory_file: &str) -> Vec<String>
  pub(super) fn index_child_digests(manifest_json: &str) -> Vec<String>
  pub(super) fn rollup_ecr_by_cve(rows: Vec<Vec<String>>) -> Vec<Vec<String>>   // now newline-joined
  ```
  Base row from the collector has 42 columns (indices 0–41). `annotate_inventory_row` appends 42–48: Affected Image Count `"1"`, Oldest Push Date = row[29], Newest Push Date = row[29], Has Closed Findings `"NO"`, Package Version Varies `"NO"`, Asset Identifier, Inventory File.

- [ ] **Step 1: Write failing tests** — append to the existing `#[cfg(test)] mod tests` in `transforms.rs` (create the module if absent: `#[cfg(test)] mod tests { use super::*; }`):

```rust
    fn base_row(cve: &str, pkg: &str, repo: &str, hash: &str, res_id: &str, score: &str) -> Vec<String> {
        let mut r = vec![String::new(); 42];
        r[0] = format!("arn:finding:{repo}:{cve}");
        r[6] = score.to_string();
        r[8] = cve.to_string();
        r[15] = pkg.to_string();
        r[16] = "1.0".to_string();
        r[23] = repo.to_string();
        r[24] = "v1".to_string();
        r[25] = hash.to_string();
        r[29] = "2026-09-01T00:00:00+00:00".to_string();
        r[30] = "NO".to_string();
        r[31] = "0".to_string();
        r[32] = res_id.to_string();
        r[40] = "2026-08-01T00:00:00+00:00".to_string();
        r
    }

    #[test]
    fn annotate_appends_inventory_columns() {
        let row = annotate_inventory_row(base_row("CVE-1", "openssl", "app", "sha256:a", "arn:a", "7"), "asset-app", "AWS_Inventory-x.csv");
        assert_eq!(row.len(), 49);
        assert_eq!(row[42], "1");
        assert_eq!(row[43], row[29]);
        assert_eq!(row[IDX_ASSET_ID], "asset-app");
        assert_eq!(row[IDX_INVENTORY_FILE], "AWS_Inventory-x.csv");
    }

    #[test]
    fn rollup_groups_same_cve_package_with_newlines_and_keeps_different_cves_apart() {
        let rows = vec![
            annotate_inventory_row(base_row("CVE-1", "openssl", "web", "sha256:w", "arn:w", "5"), "asset-web", "inv.csv"),
            annotate_inventory_row(base_row("CVE-1", "openssl", "api", "sha256:p", "arn:p", "9"), "asset-api", "inv.csv"),
            annotate_inventory_row(base_row("CVE-2", "openssl", "api", "sha256:p", "arn:p", "4"), "asset-api", "inv.csv"),
        ];
        let mut out = rollup_ecr_by_cve(rows);
        out.sort_by(|a, b| a[8].cmp(&b[8]));
        assert_eq!(out.len(), 2);
        assert_eq!(out[0][8], "CVE-1");
        assert_eq!(out[0][IDX_ASSET_ID], "asset-api\nasset-web");
        assert_eq!(out[0][23], "api\nweb");
        assert_eq!(out[0][25], "sha256:p\nsha256:w");
        assert_eq!(out[0][32], "arn:p\narn:w");
        assert_eq!(out[0][42], "2");
        assert_eq!(out[1][8], "CVE-2");
        assert_eq!(out[1][IDX_ASSET_ID], "asset-api");
    }

    #[test]
    fn index_children_skip_attestations() {
        let m = r#"{"manifests":[
            {"digest":"sha256:amd","platform":{"os":"linux","architecture":"amd64"}},
            {"digest":"sha256:att","platform":{"os":"unknown","architecture":"unknown"}}]}"#;
        assert_eq!(index_child_digests(m), ["sha256:amd"]);
        assert!(index_child_digests("not json").is_empty());
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --lib inspector_ecr`
Expected: compile error — `annotate_inventory_row`, `IDX_ASSET_ID`, `index_child_digests` not found.

- [ ] **Step 3: Implement**

At the top of `transforms.rs` (after `secs_to_rfc3339`) add:

```rust
pub(super) const IDX_ASSET_ID: usize = 47;
pub(super) const IDX_INVENTORY_FILE: usize = 48;

/// Appends the per-image annotation columns (42–48) to a 42-column finding row.
pub(super) fn annotate_inventory_row(mut row: Vec<String>, asset_id: &str, inventory_file: &str) -> Vec<String> {
    let pushed = row.get(29).cloned().unwrap_or_default();
    row.push("1".to_string()); // 42 Affected Image Count
    row.push(pushed.clone()); // 43 Oldest Push Date
    row.push(pushed); // 44 Newest Push Date
    row.push("NO".to_string()); // 45 Has Closed Findings (ACTIVE only)
    row.push("NO".to_string()); // 46 Package Version Varies
    row.push(asset_id.to_string()); // 47 Asset Identifier
    row.push(inventory_file.to_string()); // 48 Inventory File
    row
}

/// Per-platform digests inside an image index manifest; attestation manifests
/// (`os: unknown`) are skipped.
pub(super) fn index_child_digests(manifest_json: &str) -> Vec<String> {
    #[derive(serde::Deserialize)]
    struct Index {
        #[serde(default)]
        manifests: Vec<Child>,
    }
    #[derive(serde::Deserialize)]
    struct Child {
        digest: String,
        platform: Option<Platform>,
    }
    #[derive(serde::Deserialize)]
    struct Platform {
        #[serde(default)]
        os: String,
    }
    serde_json::from_str::<Index>(manifest_json)
        .map(|i| {
            i.manifests
                .into_iter()
                .filter(|c| c.platform.as_ref().is_none_or(|p| p.os != "unknown"))
                .map(|c| c.digest)
                .collect()
        })
        .unwrap_or_default()
}
```

In `rollup_ecr_by_cve`:
1. Update the header comment to say multi-value cells are newline-separated and to list `47 Asset Identifier`.
2. Replace every `s.split("; ")` inside the function with `s.split('\n')` (fields 23, 24, 32, 47).
3. Replace the `image_hash` block with:
   ```rust
        let mut hashes: Vec<String> = group_rows
            .iter()
            .flat_map(|r| r.get(25).map(|s| s.split('\n').map(str::to_string).collect::<Vec<_>>()).unwrap_or_default())
            .filter(|s| !s.is_empty())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        hashes.sort();
   ```
4. In the `set!` block use `"\n"` instead of `"; "` for 23, 24, 32, 47 and `set!(25, hashes.join("\n"));`.

Delete the functions `filter_latest_image_per_repo` and `dedup_ecr_image_rows` (and their comments) from `transforms.rs`.

- [ ] **Step 4: Fix the collector import so the tree compiles**

In `src/providers/aws/inspector_ecr/mod.rs` change the `use transforms::{…}` line to:

```rust
use transforms::{annotate_inventory_row, index_child_digests, rollup_ecr_by_cve, secs_to_rfc3339};
```

and temporarily replace the post-processing at the end of `collect_rows` (the `let before = rows.len(); … Ok(rows)` block) with:

```rust
        let rows: Vec<Vec<String>> = rows
            .into_iter()
            .map(|r| annotate_inventory_row(r, "", ""))
            .collect();
        let _ = index_child_digests;
        Ok(rollup_ecr_by_cve(rows))
```

(Task 5 replaces this body entirely.)

- [ ] **Step 5: Run tests**

Run: `cargo fmt && cargo test --lib inspector_ecr && cargo build 2>&1 | grep -E "^error|Finished"`
Expected: 3 new tests pass; `Finished`.

- [ ] **Step 6: Commit**

```bash
git add src/providers/aws/inspector_ecr/transforms.rs src/providers/aws/inspector_ecr/mod.rs
git commit -m "ECR findings transforms: inventory annotation, newline rollup, index manifest parsing"
```

---

### Task 4: Extract the per-finding row builder

**Files:**
- Modify: `src/providers/aws/inspector_ecr/mod.rs`

**Interfaces:**
- Produces: `fn finding_row(f: &aws_sdk_inspector2::types::Finding) -> Option<Vec<String>>` — returns the 42 base columns for an ECR container image finding, `None` if the resource type is not `AWS_ECR_CONTAINER_IMAGE`. Also `const ECR_IMAGE_BASE_COLUMNS: usize = 42;`.

- [ ] **Step 1: Move code**

Cut the body of `for f in resp.findings() { … }` in `collect_rows` (from `let resource_type_str = f` through `rows.push(vec![ … ]);`) into a new free function below the `impl`:

```rust
const ECR_IMAGE_BASE_COLUMNS: usize = 42;

/// The 42 base columns (see `headers()`, indices 0–41) for one ECR image finding.
fn finding_row(f: &aws_sdk_inspector2::types::Finding) -> Option<Vec<String>> {
    let resource_type_str = f.resources().first().map(|r| r.r#type().as_str()).unwrap_or("");
    if resource_type_str != "AWS_ECR_CONTAINER_IMAGE" {
        return None;
    }
    // … the existing extraction code, unchanged …
    Some(vec![
        // … the existing 42 values, unchanged …
    ])
}
```

Delete the `if f.status().as_str() == "CLOSED" { continue; }` check (queries are ACTIVE-only from Task 5). Replace `continue` for the resource-type check with `return None` as shown. In `collect_rows` the loop body becomes:

```rust
                for f in resp.findings() {
                    if let Some(row) = finding_row(f) {
                        rows.push(row);
                        severity_count += 1;
                    }
                }
```

Add at the end of `finding_row` before `Some(…)`: `debug_assert_eq!(row.len(), ECR_IMAGE_BASE_COLUMNS);` by first binding `let row = vec![…];` then `debug_assert_eq!(…); Some(row)`.

- [ ] **Step 2: Verify behaviour unchanged**

Run: `cargo fmt && cargo build 2>&1 | grep -E "^error|Finished" && cargo test --lib inspector_ecr`
Expected: `Finished`; tests pass.

- [ ] **Step 3: Commit**

```bash
git add src/providers/aws/inspector_ecr/mod.rs
git commit -m "Extract ECR image finding row builder"
```

---

### Task 5: Inventory-driven collector

**Files:**
- Modify: `src/providers/aws/inspector_ecr/mod.rs`

**Interfaces:**
- Consumes: `crate::inventory_digests::{load_latest, InventoryImage}`, `annotate_inventory_row`, `index_child_digests`, `rollup_ecr_by_cve`, `finding_row`.
- Produces: `pub(crate) async fn active_findings_for_digest(client: &Inspector2Client, repository: &str, digest: &str) -> Result<Vec<aws_sdk_inspector2::types::Finding>>` and `pub(crate) async fn platform_digests(ecr: &aws_sdk_ecr::Client, repository: &str, digest: &str) -> Result<Vec<String>>` — reused by the check (Task 6). Header list gains `"Inventory File", // 48`. Make `inspector_ecr` module items reachable: in `src/providers/aws/mod.rs` the module must be `pub mod inspector_ecr;` (change from `mod` if needed).

AWS orchestration here has no unit test (live credentials required); pure pieces were tested in Tasks 2–3. Verification is the live run in Task 8.

- [ ] **Step 1: Collector struct and header**

```rust
pub struct InspectorEcrImagesCollector {
    client: Inspector2Client,
    ecr: aws_sdk_ecr::Client,
}

impl InspectorEcrImagesCollector {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            client: Inspector2Client::new(config),
            ecr: aws_sdk_ecr::Client::new(config),
        }
    }
}
```

In `headers()` append after `"Asset Identifier",       // 47`: `"Inventory File",         // 48`.

- [ ] **Step 2: Helpers**

Add below `finding_row`:

```rust
const INDEX_MEDIA_TYPES: [&str; 2] = [
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
];

/// The digest itself, or its per-platform digests when it is an image index.
pub(crate) async fn platform_digests(ecr: &aws_sdk_ecr::Client, repository: &str, digest: &str) -> Result<Vec<String>> {
    let resp = ecr
        .batch_get_image()
        .repository_name(repository)
        .image_ids(aws_sdk_ecr::types::ImageIdentifier::builder().image_digest(digest).build())
        .set_accepted_media_types(Some(
            INDEX_MEDIA_TYPES
                .iter()
                .map(|s| s.to_string())
                .chain([
                    "application/vnd.oci.image.manifest.v1+json".to_string(),
                    "application/vnd.docker.distribution.manifest.v2+json".to_string(),
                ])
                .collect(),
        ))
        .send()
        .await
        .with_context(|| format!("ecr:BatchGetImage {repository}@{digest}"))?;
    let Some(image) = resp.images().first() else {
        anyhow::bail!("ecr:BatchGetImage {repository}@{digest}: image not found");
    };
    let is_index = image
        .image_manifest_media_type()
        .is_some_and(|m| INDEX_MEDIA_TYPES.contains(&m));
    let children = if is_index {
        index_child_digests(image.image_manifest().unwrap_or(""))
    } else {
        vec![]
    };
    Ok(if children.is_empty() { vec![digest.to_string()] } else { children })
}

/// Every ACTIVE Inspector2 finding on one ECR image digest.
pub(crate) async fn active_findings_for_digest(
    client: &Inspector2Client,
    repository: &str,
    digest: &str,
) -> Result<Vec<aws_sdk_inspector2::types::Finding>> {
    let eq = |v: &str| {
        StringFilter::builder()
            .comparison(StringComparison::Equals)
            .value(v)
            .build()
            .context("Inspector2 string filter")
    };
    let criteria = FilterCriteria::builder()
        .resource_type(eq("AWS_ECR_CONTAINER_IMAGE")?)
        .ecr_image_repository_name(eq(repository)?)
        .ecr_image_hash(eq(digest)?)
        .finding_status(eq("ACTIVE")?)
        .build();
    let mut out = Vec::new();
    let mut token: Option<String> = None;
    loop {
        let resp = client
            .list_findings()
            .max_results(100)
            .filter_criteria(criteria.clone())
            .set_next_token(token.clone())
            .send()
            .await
            .with_context(|| format!("inspector2:ListFindings {repository}@{digest}"))?;
        out.extend(resp.findings().iter().cloned());
        token = resp.next_token().map(str::to_string);
        if token.is_none() {
            break;
        }
    }
    Ok(out)
}
```

Add `use anyhow::Context;` to the imports (`use anyhow::{Context, Result};`). Remove now-unused imports (`DateFilter`, `InspectorDateTime`, `SortCriteria`, `SortField`, `SortOrder`) — the compiler lists them.

- [ ] **Step 3: Replace `collect_rows`**

Replace the whole body after the `get_configuration` probe (keep the probe) with:

```rust
        let inventory = match crate::inventory_digests::load_latest(std::path::Path::new("inventory")) {
            Ok(inv) => inv,
            Err(e) => anyhow::bail!(
                "Inspector2 ECR Images needs an inventory: run inventory first ({e:#})"
            ),
        };
        let inventory_file = inventory
            .path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        if let Ok(modified) = std::fs::metadata(&inventory.path).and_then(|m| m.modified()) {
            let age = std::time::SystemTime::now().duration_since(modified).unwrap_or_default();
            if age > std::time::Duration::from_secs(24 * 3600) {
                eprintln!(
                    "  WARN: inventory {} is {} hours old",
                    inventory.path.display(),
                    age.as_secs() / 3600
                );
            }
        }
        eprintln!(
            "  Inspector2 ECR Images: inventory {} ({} images, {} container rows without a digest)",
            inventory.path.display(),
            inventory.images.len(),
            inventory.rows_without_digest
        );

        let mut rows = Vec::new();
        for image in inventory.images.iter().filter(|i| i.region == region) {
            let digests = match platform_digests(&self.ecr, &image.repository, &image.digest).await {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("  WARN: {} ({}): {e:#}; querying the inventory digest only", image.asset_id, image.digest);
                    vec![image.digest.clone()]
                }
            };
            for digest in digests {
                match active_findings_for_digest(&self.client, &image.repository, &digest).await {
                    Ok(findings) => rows.extend(
                        findings
                            .iter()
                            .filter_map(finding_row)
                            .map(|r| annotate_inventory_row(r, &image.asset_id, &inventory_file)),
                    ),
                    Err(e) => eprintln!("  WARN: {} ({digest}): {e:#}", image.asset_id),
                }
            }
        }

        let before = rows.len();
        let rows = rollup_ecr_by_cve(rows);
        eprintln!(
            "  Inspector2 ECR Images: {before} ACTIVE findings on inventory digests → {} rows (one per CVE + package)",
            rows.len()
        );
        Ok(rows)
```

Rename the parameters `_account_id`/`_region`/`dates` to `_account_id: &str, region: &str, _dates: Option<(i64, i64)>` and delete the severity loop, the `MAX_ROWS_PER_SEVERITY`/`SEVERITY_LEVELS` constants and the date-filter comment block.

- [ ] **Step 4: Build, lint, test**

Run: `cargo fmt && cargo clippy -- -D warnings 2>&1 | grep -E "^\s+--> src/providers/aws/inspector_ecr" -B6; cargo test --lib`
Expected: no clippy findings in `inspector_ecr`; all tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/providers/aws/inspector_ecr/mod.rs src/providers/aws/mod.rs
git commit -m "Collect ECR image findings for exactly the inventory's digests"
```

---

### Task 6: `--check-ecr-findings`

**Files:**
- Create: `src/ecr_findings_check.rs`
- Modify: `src/lib.rs`, `src/cli.rs`, `src/main.rs`, `src/runner/cli_runners.rs`

**Interfaces:**
- Consumes: `crate::inventory_digests::{latest_file, load_latest, InventoryImage}`, `crate::providers::aws::inspector_ecr::{active_findings_for_digest, platform_digests}`.
- Produces:
  ```rust
  pub enum CheckResult { Ok, MissingInCsv, ExtraInCsv, NoScanData }   // as_str(): OK, MISSING_IN_CSV, EXTRA_IN_CSV, NO_SCAN_DATA
  pub struct AssetCheck { pub asset_id: String, pub digests: Vec<String>, pub scan_status: String, pub scan_reason: String,
      pub live: BTreeSet<String>, pub csv: BTreeSet<String>, pub result: CheckResult }
  pub struct Report { pub inventory_path: PathBuf, pub findings_path: PathBuf, pub assets: Vec<AssetCheck>, pub report_path: PathBuf }
  impl Report { pub fn failures(&self) -> usize; pub fn summary_lines(&self) -> Vec<String> }
  pub fn classify(live: &BTreeSet<String>, csv: &BTreeSet<String>, coverage: Option<(&str, &str)>) -> CheckResult
  pub fn csv_ids_by_asset(path: &Path) -> Result<HashMap<String, BTreeSet<String>>>
  pub async fn run(config: &aws_config::SdkConfig, region: &str, inventory_dir: &Path, evidence_dir: &Path) -> Result<Report>
  ```

- [ ] **Step 1: Write failing tests** — create the file with the public types, `todo`-free stubs returning `Default`/errors, and:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn set(ids: &[&str]) -> BTreeSet<String> {
        ids.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn classification() {
        assert_eq!(classify(&set(&["CVE-1"]), &set(&["CVE-1"]), Some(("ACTIVE", "SUCCESSFUL"))), CheckResult::Ok);
        assert_eq!(classify(&set(&[]), &set(&[]), Some(("ACTIVE", "SUCCESSFUL"))), CheckResult::Ok);
        assert_eq!(classify(&set(&["CVE-1", "CVE-2"]), &set(&["CVE-1"]), Some(("ACTIVE", "SUCCESSFUL"))), CheckResult::MissingInCsv);
        assert_eq!(classify(&set(&["CVE-1"]), &set(&["CVE-1", "CVE-9"]), Some(("ACTIVE", "SUCCESSFUL"))), CheckResult::ExtraInCsv);
        assert_eq!(classify(&set(&[]), &set(&[]), None), CheckResult::NoScanData);
        assert_eq!(classify(&set(&[]), &set(&[]), Some(("INACTIVE", "SCAN_ELIGIBILITY_EXPIRED"))), CheckResult::NoScanData);
    }

    #[test]
    fn csv_ids_split_asset_identifier_lines() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = dir.path().join("f.csv");
        let mut w = csv::Writer::from_path(&p).expect("writer");
        w.write_record(["Finding ARN", "Title", "CVE ID", "Asset Identifier"]).expect("hdr");
        w.write_record(["arn:1", "t", "CVE-1", "asset-a\nasset-b"]).expect("row");
        w.write_record(["arn:2", "Some non-CVE title", "", "asset-b"]).expect("row");
        w.flush().expect("flush");
        let m = csv_ids_by_asset(&p).expect("read");
        assert_eq!(m["asset-a"], set(&["CVE-1"]));
        assert_eq!(m["asset-b"], set(&["CVE-1", "Some non-CVE title"]));
    }
}
```

Add `pub mod ecr_findings_check;` to `src/lib.rs`.

Run: `cargo test --lib ecr_findings_check` → FAIL.

- [ ] **Step 2: Implement pure parts**

```rust
//! `--check-ecr-findings`: for every ECR image in the newest inventory, the set
//! of ACTIVE Inspector2 vulnerability IDs must equal the IDs in the newest ECR
//! findings CSV whose `Asset Identifier` lists that asset.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use aws_sdk_inspector2::types::{CoverageFilterCriteria, CoverageStringComparison, CoverageStringFilter};

use crate::inventory_digests::{latest_file, load_latest};
use crate::providers::aws::inspector_ecr::{active_findings_for_digest, platform_digests};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CheckResult {
    Ok,
    MissingInCsv,
    ExtraInCsv,
    NoScanData,
}

impl CheckResult {
    pub fn as_str(self) -> &'static str {
        match self {
            CheckResult::Ok => "OK",
            CheckResult::MissingInCsv => "MISSING_IN_CSV",
            CheckResult::ExtraInCsv => "EXTRA_IN_CSV",
            CheckResult::NoScanData => "NO_SCAN_DATA",
        }
    }
}

#[derive(Debug, Clone)]
pub struct AssetCheck {
    pub asset_id: String,
    pub digests: Vec<String>,
    pub scan_status: String,
    pub scan_reason: String,
    pub live: BTreeSet<String>,
    pub csv: BTreeSet<String>,
    pub result: CheckResult,
}

#[derive(Debug)]
pub struct Report {
    pub inventory_path: PathBuf,
    pub findings_path: PathBuf,
    pub assets: Vec<AssetCheck>,
    pub report_path: PathBuf,
}

/// Coverage is (status code, reason) for the scanned digest; `None` = not covered.
pub fn classify(live: &BTreeSet<String>, csv: &BTreeSet<String>, coverage: Option<(&str, &str)>) -> CheckResult {
    match coverage {
        Some(("ACTIVE", _)) => {}
        _ => return CheckResult::NoScanData,
    }
    if !live.is_subset(csv) {
        CheckResult::MissingInCsv
    } else if !csv.is_subset(live) {
        CheckResult::ExtraInCsv
    } else {
        CheckResult::Ok
    }
}

/// Vulnerability ID used on both sides: CVE ID, or the title for non-CVE findings.
fn vuln_id(cve: &str, title: &str) -> String {
    if cve.trim().is_empty() { title.trim().to_string() } else { cve.trim().to_string() }
}

pub fn csv_ids_by_asset(path: &Path) -> Result<HashMap<String, BTreeSet<String>>> {
    let mut r = csv::ReaderBuilder::new()
        .flexible(true)
        .from_path(path)
        .with_context(|| format!("cannot open {}", path.display()))?;
    let h = r.headers()?.clone();
    let col = |n: &str| h.iter().position(|x| x == n).with_context(|| format!("{} missing '{n}'", path.display()));
    let (cve_i, title_i, asset_i) = (col("CVE ID")?, col("Title")?, col("Asset Identifier")?);
    let mut out: HashMap<String, BTreeSet<String>> = HashMap::new();
    for rec in r.records() {
        let rec = rec?;
        let id = vuln_id(rec.get(cve_i).unwrap_or(""), rec.get(title_i).unwrap_or(""));
        for asset in rec.get(asset_i).unwrap_or("").split('\n').map(str::trim).filter(|a| !a.is_empty()) {
            out.entry(asset.to_string()).or_default().insert(id.clone());
        }
    }
    Ok(out)
}

impl Report {
    pub fn failures(&self) -> usize {
        self.assets.iter().filter(|a| a.result != CheckResult::Ok).count()
    }

    pub fn summary_lines(&self) -> Vec<String> {
        let mut counts: BTreeMap<CheckResult, usize> = BTreeMap::new();
        for a in &self.assets {
            *counts.entry(a.result).or_default() += 1;
        }
        let mut lines = vec![
            format!("Inventory: {}", self.inventory_path.display()),
            format!("Findings:  {}", self.findings_path.display()),
            format!("Assets checked: {}   Failures: {}", self.assets.len(), self.failures()),
        ];
        lines.extend(counts.into_iter().map(|(r, n)| format!("  {}: {n}", r.as_str())));
        lines.push(format!("Report: {}", self.report_path.display()));
        lines
    }
}
```

Run: `cargo fmt && cargo test --lib ecr_findings_check` → 2 passed.

- [ ] **Step 3: Implement `run`**

```rust
async fn coverage_for(
    insp: &aws_sdk_inspector2::Client,
    resource_id: &str,
) -> Result<Option<(String, String)>> {
    let criteria = CoverageFilterCriteria::builder()
        .resource_id(
            CoverageStringFilter::builder()
                .comparison(CoverageStringComparison::Equals)
                .value(resource_id)
                .build()
                .context("coverage filter")?,
        )
        .build();
    let resp = insp
        .list_coverage()
        .filter_criteria(criteria)
        .send()
        .await
        .with_context(|| format!("inspector2:ListCoverage {resource_id}"))?;
    Ok(resp.covered_resources().first().and_then(|c| {
        c.scan_status()
            .map(|s| (s.status_code().as_str().to_string(), s.reason().as_str().to_string()))
    }))
}

pub async fn run(
    config: &aws_config::SdkConfig,
    region: &str,
    inventory_dir: &Path,
    evidence_dir: &Path,
) -> Result<Report> {
    let inventory = load_latest(inventory_dir)?;
    let findings_path = latest_file(evidence_dir, "_Inspector2_ECR_Image_Findings-")?;
    let csv_ids = csv_ids_by_asset(&findings_path)?;
    let insp = aws_sdk_inspector2::Client::new(config);
    let ecr = aws_sdk_ecr::Client::new(config);

    let mut assets = Vec::new();
    for image in inventory.images.iter().filter(|i| i.region == region) {
        let digests = platform_digests(&ecr, &image.repository, &image.digest)
            .await
            .unwrap_or_else(|_| vec![image.digest.clone()]);
        let mut live = BTreeSet::new();
        let mut worst: Option<(String, String)> = None;
        let mut all_active = true;
        for d in &digests {
            let cov = coverage_for(&insp, &format!("{}/{d}", image.repository_arn)).await?;
            match &cov {
                Some((s, _)) if s == "ACTIVE" => {}
                _ => {
                    all_active = false;
                    worst = cov.clone().or(Some(("NOT_COVERED".into(), String::new())));
                }
            }
            for f in active_findings_for_digest(&insp, &image.repository, d).await? {
                let cve = f.package_vulnerability_details().map(|v| v.vulnerability_id()).unwrap_or("");
                live.insert(vuln_id(cve, f.title().unwrap_or("")));
            }
        }
        let (status, reason) = if all_active {
            ("ACTIVE".to_string(), String::new())
        } else {
            worst.unwrap_or_default()
        };
        let csv = csv_ids.get(&image.asset_id).cloned().unwrap_or_default();
        let coverage = if status == "NOT_COVERED" { None } else { Some((status.as_str(), reason.as_str())) };
        let result = classify(&live, &csv, coverage);
        assets.push(AssetCheck {
            asset_id: image.asset_id.clone(),
            digests,
            scan_status: status,
            scan_reason: reason,
            live,
            csv,
            result,
        });
    }

    let report_path = findings_path
        .parent()
        .unwrap_or(Path::new("."))
        .join(format!("ECR-Findings-Check-{}.csv", chrono::Local::now().format("%Y-%m-%d-%H%M%S")));
    let mut w = csv::Writer::from_path(&report_path)
        .with_context(|| format!("cannot write {}", report_path.display()))?;
    w.write_record([
        "Asset Identifier", "Digests", "Inspector Scan Status", "Inspector Scan Reason",
        "Inspector ACTIVE Count", "CSV Count", "Missing In CSV", "Extra In CSV", "Result",
    ])?;
    for a in &assets {
        let missing: Vec<&str> = a.live.difference(&a.csv).map(String::as_str).collect();
        let extra: Vec<&str> = a.csv.difference(&a.live).map(String::as_str).collect();
        w.write_record([
            a.asset_id.clone(),
            a.digests.join("\n"),
            a.scan_status.clone(),
            a.scan_reason.clone(),
            a.live.len().to_string(),
            a.csv.len().to_string(),
            missing.join("\n"),
            extra.join("\n"),
            a.result.as_str().to_string(),
        ])?;
    }
    w.flush()?;
    Ok(Report { inventory_path: inventory.path, findings_path, assets, report_path })
}
```

In `src/providers/aws/mod.rs` ensure `pub mod inspector_ecr;`. In `inspector_ecr/mod.rs` the two helpers are `pub(crate)` (Task 5).

- [ ] **Step 4: CLI flag, runner, dispatch**

`src/cli.rs`, after the `verify_manifest` field:

```rust
    /// Check that the newest ECR image findings CSV (under --output, default .)
    /// lists every ACTIVE Inspector2 vulnerability for every ECR image digest in
    /// the newest inventory CSV (under ./inventory). Uses --profile/--region for
    /// live Inspector2 queries. Writes ECR-Findings-Check-<ts>.csv next to the
    /// findings CSV; exits non-zero on any failure.
    #[arg(long, default_value_t = false)]
    pub check_ecr_findings: bool,
```

`src/runner/cli_runners.rs`, before `pub async fn run_poam_cli`:

```rust
/// `--check-ecr-findings`: prints the summary; exits 1 when any asset fails.
pub async fn run_ecr_findings_check_cli(cli: &Cli) -> Result<()> {
    let (_, config, _) =
        crate::aws_loader::load_cli_probe_and_work_configs_opts(&cli.region, cli.profile.as_deref(), false).await;
    let evidence_dir = cli.output.clone().unwrap_or_else(|| PathBuf::from("."));
    let report = crate::ecr_findings_check::run(
        &config,
        &cli.region,
        std::path::Path::new("inventory"),
        &evidence_dir,
    )
    .await?;
    for line in report.summary_lines() {
        println!("{line}");
    }
    if report.failures() > 0 {
        std::process::exit(1);
    }
    Ok(())
}
```

`src/main.rs`: import `run_ecr_findings_check_cli` alongside the other runners and add before `if cli.inventory {`:

```rust
    if cli.check_ecr_findings {
        return run_ecr_findings_check_cli(&cli).await;
    }
```

- [ ] **Step 5: Verify**

Run: `cargo fmt && cargo clippy -- -D warnings 2>&1 | grep -E "^\s+--> src/(ecr_findings_check|runner/cli_runners|cli|main)" -B6; cargo test --lib && cargo build 2>&1 | grep -E "^error|Finished"`
Expected: no findings in these files; tests pass; `Finished`.
Run: `./target/debug/grabber --help | grep check-ecr-findings` → the flag is listed.

- [ ] **Step 6: Commit**

```bash
git add src/ecr_findings_check.rs src/lib.rs src/cli.rs src/main.rs src/runner/cli_runners.rs src/providers/aws/mod.rs
git commit -m "Add --check-ecr-findings to verify findings cover every inventory image digest"
```

---

### Task 7: TUI "ECR Findings Check"

**Files:**
- Create: `src/tui/ui/ecr_check.rs`
- Modify: `src/tui/state.rs`, `src/tui/app/mod.rs`, `src/tui/app/nav.rs`, `src/tui/events.rs`, `src/tui/ui/mod.rs`, `src/tui/ui/frame.rs`, `src/tui/ui/setup.rs`, `src/runner/tui_session.rs`

**Interfaces:**
- Consumes: `crate::ecr_findings_check::run`, `Report::summary_lines`, `Report::failures`.
- Produces: `Feature::EcrFindingsCheck`; screens `EcrCheckAccount`, `EcrCheckRunning`, `EcrCheckResults`; App fields `ecr_check_account_list: Vec<usize>`, `ecr_check_account_cursor: usize`, `ecr_check_selected_account_idx: Option<usize>`, `ecr_check_lines: Vec<String>`, `ecr_check_failed: bool`.

Flow: FeatureSelection → EcrCheckAccount (pick one AWS account; Enter) → EcrCheckRunning (async driver in `tui_session.rs` runs the check with that account's profile/region, evidence dir = account `output_dir`, else app output dir) → EcrCheckResults (summary; Enter = new session, Esc = back to feature selection). Never part of Inventory.

- [ ] **Step 1: `state.rs`**

Add to `enum Feature` after `StigRemediation,`:

```rust
    /// Verify the ECR image findings CSV covers every inventory image digest.
    EcrFindingsCheck,
```

Add to `enum Screen` at the end:

```rust
    /// ECR findings check: pick the AWS account whose Inspector2 data to query.
    EcrCheckAccount,
    /// ECR findings check: running (async work; no key handling).
    EcrCheckRunning,
    /// ECR findings check: summary and report path.
    EcrCheckResults,
```

Run `cargo check 2>&1 | grep -E "^error" -A4` — note every "non-exhaustive patterns" location; Steps 2–6 cover them.

- [ ] **Step 2: `app/mod.rs` fields**

In `pub struct App` after the `stig_*` fields:

```rust
    /// ECR findings check (Feature::EcrFindingsCheck).
    pub ecr_check_account_list: Vec<usize>,
    pub ecr_check_account_cursor: usize,
    pub ecr_check_selected_account_idx: Option<usize>,
    pub ecr_check_lines: Vec<String>,
    pub ecr_check_failed: bool,
```

In `App::new` initialiser after `stig_account_cursor: 0,`:

```rust
            ecr_check_account_list: Vec::new(),
            ecr_check_account_cursor: 0,
            ecr_check_selected_account_idx: None,
            ecr_check_lines: Vec::new(),
            ecr_check_failed: false,
```

- [ ] **Step 3: `app/nav.rs`**

`next_screen`, inside `Screen::FeatureSelection => match self.selected_feature {`:

```rust
                Feature::EcrFindingsCheck => Screen::EcrCheckAccount,
```

and add arms:

```rust
            Screen::EcrCheckAccount => {
                self.ecr_check_selected_account_idx = self
                    .ecr_check_account_list
                    .get(self.ecr_check_account_cursor)
                    .copied();
                Screen::EcrCheckRunning
            }
```

In every other `match self.selected_feature` inside `next_screen`/`prev_screen` that the compiler flags, add `Feature::EcrFindingsCheck => Screen::FeatureSelection,`.

`prev_screen` arms:

```rust
            Screen::EcrCheckAccount | Screen::EcrCheckResults => Screen::FeatureSelection,
```

`validate_current`, inside `Screen::FeatureSelection => {` next to the StigRemediation block:

```rust
                if self.selected_feature == Feature::EcrFindingsCheck {
                    self.ecr_check_account_list = self
                        .accounts
                        .iter()
                        .enumerate()
                        .filter(|(_, a)| a.provider == CloudProvider::Aws)
                        .map(|(i, _)| i)
                        .collect();
                    self.ecr_check_account_cursor = 0;
                    if self.ecr_check_account_list.is_empty() {
                        self.error_msg = Some("No AWS accounts found in ~/.aws/config".into());
                        return false;
                    }
                }
```

`reset`, next to the `stig_*` resets:

```rust
        self.ecr_check_account_list.clear();
        self.ecr_check_account_cursor = 0;
        self.ecr_check_selected_account_idx = None;
        self.ecr_check_lines.clear();
        self.ecr_check_failed = false;
```

- [ ] **Step 4: `events.rs`**

Add `EcrCheckRun,` to `enum Action`; in `event_loop` add `Action::EcrCheckRun => return Ok(()),` next to `Action::StigScan`.

Feature cycling in `handle_feature_selection`:

```rust
        KeyCode::Up | KeyCode::Left => {
            app.selected_feature = match app.selected_feature {
                Feature::Collectors => Feature::EcrFindingsCheck,
                Feature::Inventory => Feature::Collectors,
                Feature::Poam => Feature::Inventory,
                Feature::StigRemediation => Feature::Poam,
                Feature::EcrFindingsCheck => Feature::StigRemediation,
            };
        }
        KeyCode::Down | KeyCode::Right => {
            app.selected_feature = match app.selected_feature {
                Feature::Collectors => Feature::Inventory,
                Feature::Inventory => Feature::Poam,
                Feature::Poam => Feature::StigRemediation,
                Feature::StigRemediation => Feature::EcrFindingsCheck,
                Feature::EcrFindingsCheck => Feature::Collectors,
            };
        }
```

Screen dispatch (next to `Screen::StigRemediationAccount => return handle_stig_remediation_account(app, key),`):

```rust
        Screen::EcrCheckAccount => return handle_ecr_check_account(app, key),
        Screen::EcrCheckRunning => {}
        Screen::EcrCheckResults => return handle_ecr_check_results(app, key),
```

Handlers:

```rust
fn handle_ecr_check_account(app: &mut App, key: KeyCode) -> Action {
    let len = app.ecr_check_account_list.len();
    match key {
        KeyCode::Up => {
            app.ecr_check_account_cursor = app.ecr_check_account_cursor.saturating_sub(1);
            Action::Continue
        }
        KeyCode::Down => {
            if app.ecr_check_account_cursor + 1 < len {
                app.ecr_check_account_cursor += 1;
            }
            Action::Continue
        }
        KeyCode::Enter => {
            app.next_screen();
            Action::EcrCheckRun
        }
        KeyCode::Esc => {
            app.prev_screen();
            Action::Continue
        }
        _ => Action::Continue,
    }
}

fn handle_ecr_check_results(app: &mut App, key: KeyCode) -> Action {
    match key {
        KeyCode::Enter => Action::NewCollection,
        KeyCode::Esc => {
            app.prev_screen();
            Action::Continue
        }
        KeyCode::Char('q') => Action::Quit,
        _ => Action::Continue,
    }
}
```

(If the dispatch `match` for these screens does not `return` an `Action` for sibling screens, follow the exact form used by the `StigRemediationAccount` arm in the same match.)

- [ ] **Step 5: UI — `ui/ecr_check.rs`, `ui/mod.rs`, `ui/setup.rs`**

Create `src/tui/ui/ecr_check.rs`:

```rust
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Paragraph};
use ratatui::Frame;

use super::widgets::{content_inset, draw_list_with_detail};
use super::{App, BORDER_SUBTLE, GREEN, RED, TEXT_BRIGHT, TEXT_DIM, TEXT_NORMAL};

pub(super) fn draw_ecr_check_account(f: &mut Frame, area: Rect, app: &App) {
    let chunks = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Fill(1),
    ])
    .split(content_inset(area));
    f.render_widget(
        Paragraph::new(Span::styled(
            "Select the AWS account whose Inspector2 findings to check against the inventory",
            Style::default().fg(TEXT_BRIGHT).add_modifier(Modifier::BOLD),
        ))
        .alignment(Alignment::Center),
        chunks[0],
    );
    f.render_widget(
        Paragraph::new(Span::styled(
            "Uses the newest inventory/**/AWS_Inventory-*.csv and the newest *_Inspector2_ECR_Image_Findings-*.csv",
            Style::default().fg(TEXT_DIM),
        ))
        .alignment(Alignment::Center),
        chunks[1],
    );
    let items: Vec<(String, String)> = app
        .ecr_check_account_list
        .iter()
        .filter_map(|&i| app.accounts.get(i))
        .map(|a| (a.name.clone(), a.profile.clone().unwrap_or_default()))
        .collect();
    draw_list_with_detail(f, chunks[3], "AWS Accounts", &items, app.ecr_check_account_cursor);
}

pub(super) fn draw_ecr_check_running(f: &mut Frame, area: Rect, _app: &App) {
    let v = Layout::vertical([Constraint::Fill(1), Constraint::Length(1), Constraint::Fill(1)]).split(area);
    f.render_widget(
        Paragraph::new(Span::styled(
            "Checking ECR findings against the inventory (live Inspector2 queries)…",
            Style::default().fg(TEXT_NORMAL),
        ))
        .alignment(Alignment::Center),
        v[1],
    );
}

pub(super) fn draw_ecr_check_results(f: &mut Frame, area: Rect, app: &App) {
    let color = if app.ecr_check_failed { RED } else { GREEN };
    let title = if app.ecr_check_failed {
        " ECR Findings Check: FAILURES "
    } else {
        " ECR Findings Check: OK "
    };
    let lines: Vec<Line> = app
        .ecr_check_lines
        .iter()
        .map(|l| Line::from(Span::styled(l.clone(), Style::default().fg(TEXT_NORMAL))))
        .collect();
    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(color))
        .title(Span::styled(title, Style::default().fg(color)));
    let _ = BORDER_SUBTLE;
    f.render_widget(Paragraph::new(lines).block(block), content_inset(area));
}
```

(Check `draw_list_with_detail` and the colour constants are exported from `super`/`super::widgets` exactly as `stig_remediation.rs` imports them; copy its `use` lines if they differ, and drop `BORDER_SUBTLE` if unused.)

`ui/mod.rs`: add `mod ecr_check;` with the other UI modules; in `draw()`'s screen match:

```rust
        Screen::EcrCheckAccount => ecr_check::draw_ecr_check_account(f, content, app),
        Screen::EcrCheckRunning => ecr_check::draw_ecr_check_running(f, content, app),
        Screen::EcrCheckResults => ecr_check::draw_ecr_check_results(f, content, app),
```

add `| Screen::EcrCheckRunning | Screen::EcrCheckResults` to the `show_steps` exclusion list, and in the `steps` match: `Feature::EcrFindingsCheck => STEPS_ECR_CHECK,` (import it like `STEPS_STIG_REMEDIATION`).

`ui/setup.rs` `draw_feature_selection` options array, add last:

```rust
        (
            Feature::EcrFindingsCheck,
            "ECR Findings Check",
            "Verify the ECR image findings CSV lists every ACTIVE vulnerability for every inventory image digest",
        ),
```

- [ ] **Step 6: `ui/frame.rs`**

Next to `STEPS_STIG_REMEDIATION`:

```rust
pub(super) const STEPS_ECR_CHECK: &[&str] = &["Account", "Check", "Results"];
```

`screen_to_step`:

```rust
        Feature::EcrFindingsCheck => match screen {
            Screen::EcrCheckAccount => Some(0),
            Screen::EcrCheckRunning => Some(1),
            Screen::EcrCheckResults => Some(2),
            _ => None,
        },
```

`get_hints`:

```rust
        Screen::EcrCheckAccount => vec![("↑↓", "Navigate"), ("⏎", "Run check"), ("Esc", "Back")],
        Screen::EcrCheckRunning => vec![],
        Screen::EcrCheckResults => vec![("⏎", "New session"), ("Esc", "Back"), ("q", "Quit")],
```

- [ ] **Step 7: Async driver — `runner/tui_session.rs`**

Next to the `StigRemediationScanning` block (outside any `#[cfg(feature = "okta")]`):

```rust
        if app.screen == crate::tui::Screen::EcrCheckRunning {
            let mut terminal = setup_terminal()?;
            terminal.draw(|f| crate::tui::ui::draw(f, &app))?;

            let account = app.ecr_check_selected_account_idx.and_then(|i| app.accounts.get(i)).cloned();
            match account {
                None => {
                    app.ecr_check_failed = true;
                    app.ecr_check_lines = vec!["No AWS account selected".to_string()];
                }
                Some(acct) => {
                    let region = acct.region.clone().unwrap_or_else(|| app.selected_region());
                    let (_, config, _) = crate::aws_loader::load_cli_probe_and_work_configs_opts(
                        &region,
                        acct.profile.as_deref(),
                        false,
                    )
                    .await;
                    let evidence_dir = std::path::PathBuf::from(
                        acct.output_dir.clone().unwrap_or_else(|| app.output_dir.value.clone()),
                    );
                    match crate::ecr_findings_check::run(
                        &config,
                        &region,
                        std::path::Path::new("inventory"),
                        &evidence_dir,
                    )
                    .await
                    {
                        Ok(report) => {
                            app.ecr_check_failed = report.failures() > 0;
                            app.ecr_check_lines = report.summary_lines();
                        }
                        Err(e) => {
                            app.ecr_check_failed = true;
                            app.ecr_check_lines = vec![format!("Check failed: {e:#}")];
                        }
                    }
                }
            }
            app.screen = crate::tui::Screen::EcrCheckResults;
            restore_terminal(&mut terminal)?;
            continue;
        }
```

(`Account` must be `Clone`; if it isn't, clone the three needed fields — `profile`, `region`, `output_dir` — into locals instead of cloning the account.)

- [ ] **Step 8: Verify**

Run: `cargo fmt && cargo clippy -- -D warnings 2>&1 | grep -E "^\s+--> src/(tui|runner/tui_session)" -B6; cargo test --lib && cargo build 2>&1 | grep -E "^error|Finished"`
Expected: no new findings in TUI files; tests pass; `Finished`.
Run the TUI manually: `./target/debug/grabber` → Feature screen shows "ECR Findings Check"; ↑/↓ cycles through five features; Enter lists AWS accounts; Esc returns.

- [ ] **Step 9: Commit**

```bash
git add src/tui src/runner/tui_session.rs
git commit -m "TUI: add ECR Findings Check feature"
```

---

### Task 8: CHANGELOG, live verification, spec status

**Files:**
- Modify: `CHANGELOG.md`, `docs/plans/2026-09-16-ecr-findings-match-inventory.md` (status line)

- [ ] **Step 1: CHANGELOG**

Under `## [Unreleased]`, add to `### Added`:

```markdown
- **`--check-ecr-findings` and a TUI "ECR Findings Check" verify that ECR image
  findings match the inventory.** For every ECR image in the newest
  `AWS_Inventory-*.csv`, the check compares the ACTIVE vulnerabilities Inspector2
  reports for that exact image digest (per platform for multi-architecture
  images) with the rows in the newest `*_Inspector2_ECR_Image_Findings-*.csv`
  that list the image's asset identifier. Each asset is `OK`, `MISSING_IN_CSV`,
  `EXTRA_IN_CSV` or `NO_SCAN_DATA` (not scanned, or Inspector2 stopped scanning
  it — the reason is shown). Results are written to
  `ECR-Findings-Check-<timestamp>.csv` next to the findings CSV; the command
  exits with status 1 unless every asset is `OK`. The TUI check is its own
  feature and never runs as part of Inventory.
```

Add a `### Changed` section (create it between `### Added` and `### Fixed` if absent):

```markdown
- **ECR image findings now cover exactly the image digests in the inventory,
  with every ACTIVE vulnerability.** The `Inspector2_ECR_Image_Findings` CSV is
  built from the newest `AWS_Inventory-*.csv`: for each inventoried ECR image it
  lists all ACTIVE Inspector2 findings for that digest, regardless of the run's
  date range. Findings are still one row per vulnerability (CVE and package);
  `Asset Identifier` now holds the inventory's `UNIQUE ASSET IDENTIFIER` for
  every affected image, one per line, as the FedRAMP POA&M template requires,
  and a new `Inventory File` column names the inventory used. `Repository
  Name`, `Image Tags`, `Image Hash` and `Resource ID` list one value per line.
  Collection now fails with "run inventory first" when no inventory exists.

  Previously the CSV picked, per repository, the newest pushed image that had
  findings — often a different digest than the inventory listed — so findings
  were attributed to images not in the inventory, and ACTIVE vulnerabilities
  first seen before the date range were left out. POA&M item counts built from
  earlier CSVs may differ.
```

- [ ] **Step 2: Live verification (read-only, federal)**

```bash
cargo build --release
./target/release/grabber                     # TUI: Inventory → Federal_Ops account → run
./target/release/grabber                     # TUI: Collectors → AWS → Federal_Security → Inspector2 ECR Images → run
./target/release/grabber --check-ecr-findings --profile fed:SecurityAdmin-132576345808 --region us-east-1 \
  --output ./evidence-output/federal/security
```

Expected: findings CSV rows each have a non-empty `Asset Identifier` that exists in the inventory; the check reports `OK` for every scanned asset and `NO_SCAN_DATA` with a reason for unscanned/expired ones; no `MISSING_IN_CSV`/`EXTRA_IN_CSV`. If any appear, stop and investigate before committing.

Then run the TUI "ECR Findings Check" with `Federal_Security` and confirm the same summary.

- [ ] **Step 3: Mark spec implemented**

In `docs/plans/2026-09-16-ecr-findings-match-inventory.md` change the first status line to `Status: implemented.`

- [ ] **Step 4: Commit**

```bash
git add CHANGELOG.md docs/plans/2026-09-16-ecr-findings-match-inventory.md docs/plans/2026-09-16-ecr-findings-match-inventory-plan.md
git commit -m "CHANGELOG: ECR findings match inventory and --check-ecr-findings"
```
