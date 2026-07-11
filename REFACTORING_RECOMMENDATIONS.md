# Grabber — Refactoring Recommendations

> **Branch:** `refractor` | **Date:** 2026-05-14 | **Scope:** Full codebase audit
>
> Five areas evaluated in parallel: file size & modularization, error handling, import
> conventions, AWS SDK / async patterns, and Clippy / code quality.

---

## Executive Summary

| Area | Severity | Finding |
|------|----------|---------|
| AWS Paginators | 🔴 Critical | Zero files use `.into_paginator()`; 52 files use manual `next_token` loops |
| File Size | 🔴 Critical | 26 files exceed the 200-line guideline; largest is 716 lines (one function) |
| Error Handling | 🟠 High | `zip_bundle.rs` silently swallows write errors; ~22 `.unwrap()` calls in prod code |
| Code Quality | 🟠 High | 62 Clippy warnings; `CollectorRegistry` is dead infrastructure; deprecated SDK calls |
| Import Conventions | 🟡 Medium | 2 files split import groups incorrectly; otherwise broadly compliant |

---

## 1. File Size & Modularization

### Files Exceeding the 200-Line Guideline

26 source files exceed the project limit. The 10 most critical:

| File | Lines | Primary Issue |
|------|-------|---------------|
| `src/runner/tui_session.rs` | 716 | Entire file is one 694-line `async fn` |
| `src/tui/events.rs` | 651 | All screen handlers in one flat file |
| `src/runner/multi_account.rs` | 634 | Types, collection loop, and post-processing mixed together |
| `src/providers/aws/factory.rs` | 588 | `csv_collectors()` is 383 lines alone |
| `src/tui/collector_data.rs` | 549 | Two large static arrays with no separation |
| `src/inventory_xlsx.rs` | 495 | ZIP helpers, XML builders, and template logic co-located |
| `src/tui/app/mod.rs` | 493 | Struct definition, constructor, and tests all in `mod.rs` |
| `src/providers/aws/inspector_ecr/mod.rs` | 483 | Row-building logic embedded in `collect_rows` |
| `src/providers/aws/inspector.rs` | 477 | Dedup logic, headers, and row builder in one file |
| `src/tui/ui/options.rs` | 456 | Six near-identical toggle widgets inlined |

### Recommended Extractions

**`src/runner/tui_session.rs` (716 → ~100 lines)**
- Extract `src/runner/session/account_prep.rs` — lines 76–521: AWS account-building loop (`build_aws_account_runs`, per-account credential/region/collector setup)
- Extract `src/runner/session/tenable_prep.rs` — lines 523–628: Tenable account preparation
- Keep only the orchestration shell in `tui_session.rs`

**`src/tui/events.rs` (651 → ~80 lines)**
- Extract `src/tui/events/setup_screens.rs` — simple sequential handlers (Welcome → PoamMonth)
- Extract `src/tui/events/collector_screens.rs` — `handle_select_collectors`, `handle_inventory`
- Extract `src/tui/events/options_screens.rs` — options, confirm, results, provider selection
- Keep only `event_loop` + `handle_key` dispatch in `mod.rs`

**`src/runner/multi_account.rs` (634 → ~100 lines)**
- Extract `src/runner/multi_account/types.rs` — `AccountCollectors` struct and `GLOBAL_COLLECTOR_KEYS`
- Extract `src/runner/multi_account/collector_loop.rs` — the `tokio::spawn` inner collection loop
- Keep orchestration and TUI event loop in `mod.rs`

**`src/providers/aws/factory.rs` (588 → ~150 lines)**
- Extract `src/providers/aws/factory/csv.rs` — split `csv_collectors` into domain helpers:
  `build_iam_collectors()`, `build_network_collectors()`, `build_security_collectors()`,
  `build_storage_collectors()` — each returning `Vec<Box<dyn CsvCollector>>`
- Keep struct definition, `new`, `json_collectors`, `evidence_collectors` in `mod.rs`

**`src/tui/collector_data.rs` (549 → 5 lines)**
- Extract `src/tui/collector_data/items.rs` — `COLLECTOR_ITEMS` static
- Extract `src/tui/collector_data/regions.rs` — `AWS_REGIONS` static
- `mod.rs` re-exports both

**`src/inventory_xlsx.rs` (495 → ~130 lines)**
- Extract `src/inventory_xlsx/zip_helpers.rs` — ZIP/workbook XML navigation
- Extract `src/inventory_xlsx/xml.rs` — row/cell XML builders and injection
- Extract `src/inventory_xlsx/template.rs` — column mapping/resolution
- Keep `write_inventory_xlsx` entry point and tests in `mod.rs`

**`src/tui/app/mod.rs` (493 → ~180 lines)**
- Extract `src/tui/app/defaults.rs` — `compute_default_collector_selection` helper
- Extract `src/tui/app/tests.rs` — `#[cfg(test)]` block (lines 289–493)

**`src/providers/aws/inspector.rs` (477 → ~150 lines)**
Convert to `src/providers/aws/inspector/mod.rs` and extract:
- `src/providers/aws/inspector/dedup.rs` — `dedup_findings_rows`
- `src/providers/aws/inspector/row_builder.rs` — `build_finding_row(f: &Finding) -> Vec<String>`

**`src/providers/aws/inspector_ecr/mod.rs` (483 → ~200 lines)**
- Extract `src/providers/aws/inspector_ecr/row_builder.rs` — per-finding field extraction (~200 lines)
- `transforms.rs` already exists for post-processing; keep the paginated loop skeleton in `mod.rs`

**`src/tui/ui/options.rs` (456 → ~100 lines)**
- Extract `src/tui/ui/options/toggles.rs` — generic `draw_toggle(...)` widget helper
- Extract `src/tui/ui/options/region_list.rs` — `draw_region_list(f, area, app)`
- Keep `draw_options` layout orchestration in `mod.rs`

---

## 2. Error Handling

### Summary

| Pattern | Production occurrences |
|---------|----------------------|
| `.unwrap()` | ~22 |
| `.expect(...)` | ~26 (most in tests) |
| `panic!` | 0 |
| Silent `let _ =` discards | ~30+ |

`thiserror` is not used anywhere — the codebase uses `anyhow` exclusively. For an application binary this is appropriate and consistent.

### Critical: Silent Error Swallowing

**`src/zip_bundle.rs:18`** — 🔴 **Highest priority**
```rust
// CURRENT — write failure is silently discarded
let _ = zip.write_all(&data);

// FIX — propagate write errors
zip.write_all(&data).context("failed to write zip entry")?;
```
A silent write failure here produces a corrupt/incomplete output archive with no diagnostic.

**`src/runner/tui_session.rs:197`** — `let _ = std::fs::create_dir_all(&dir)`
If the output directory cannot be created, all subsequent file writes in the session will also fail. Surface this error before entering the TUI.

**`src/app_config.rs:191–192`** — `fs::read_to_string(path).ok()? / toml::from_str(..).ok()?`
A malformed config file is silently treated as a missing file. Log a warning or surface the parse error.

### Top 10 `.unwrap()` Calls to Replace

| Priority | Location | Risk | Fix |
|----------|----------|------|-----|
| 1 | `src/providers/aws/rds.rs:90` | 🔴 High — panics if snapshot has no creation timestamp | `.ok_or_else(|| anyhow!("snapshot missing created_at"))?` |
| 2 | `src/providers/aws/rds.rs:166` | 🔴 High — same, second call site | Same fix |
| 3 | `src/providers/aws/inspector_ecr/transforms.rs:354` | 🟠 Medium-high — panics if group is empty after grouping | `.ok_or_else(|| anyhow!("empty group in ECR transform"))?` |
| 4 | `src/tui/state.rs:146` | 🟠 Medium — TUI crash if cursor at position 0 | Guard with `if cursor > 0` or use `if let Some(c) = ...` |
| 5 | `src/tui/state.rs:154` | 🟠 Medium — same pattern, second call | Same fix |
| 6 | `src/tui/state.rs:161` | 🟠 Medium — panics if cursor at end of string | `if let Some(c) = ...` guard |
| 7 | `src/providers/aws/cloudtrail_s3.rs:104` | 🟡 Low-medium — `sem.acquire().await.unwrap()` | `.await.context("semaphore closed")?` |
| 8 | `src/providers/aws/inspector_ecr/transforms.rs:89` | 🟡 Low — guarded by `len() == 1` but fragile | Replace with `unwrap_or_default()` or `if let Some` |
| 9 | `src/runner/cli_runners.rs:214` | 🟡 Low — `.expect("start_date is Some — guarded by caller")` | Use `.context(...)` and propagate as `?` |
| 10 | `src/runner/tui_session.rs:81,86` | 🟡 Low — hardcoded time literals | Validate once at startup with `?` |

---

## 3. Import Conventions

The declared convention (three groups: `std` → `external` → `internal`, separated by blank lines) is broadly followed. Two files violate it:

### Violations

**`src/tui/ui/frame.rs`**
`super::theme` is imported in two separate `use` blocks with a `crate::tui::state` import between them. The internal group is fragmented. Merge all `super::theme` items into a single `use super::theme::{...}` block.

**`src/providers/aws/factory.rs`**
`crate::*` internal imports are split into two non-contiguous blocks (lines 1–2 and 4+) with a blank line between them, making them appear as separate groups. Consolidate into one contiguous internal block.

### Code Style Issues Found During Import Review

**Magic numbers in `src/tui/events.rs` (lines 537–586)**
`app.options_field` is compared against bare integer literals `1` through `6`. Each number maps to a specific UI field (date format, signing, chain-of-custody, etc.) with no named constant declaration. Introduce an `OptionsField` enum or named `usize` constants:
```rust
// Instead of: app.options_field == 3
const FIELD_CHAIN_OF_CUSTODY: usize = 3;
// or: OptionsField::ChainOfCustody
```

**Magic number in `src/main.rs` (line 30)**
`16 * 1024 * 1024` for thread stack size. Extract as `const THREAD_STACK_SIZE: usize = 16 * 1024 * 1024;`.

**Duplicate `use super::theme` in `src/tui/ui/frame.rs`**
New theme constants (`BG_ELEVATED`, `CYAN_DIM`) were added in a second block instead of merged into the first. Merge.

---

## 4. AWS SDK & Async Patterns

### 🔴 Critical: Zero Paginator Usage (52 Files Affected)

**No file in the codebase uses `.into_paginator()`**. The manual `next_token` loop pattern is copy-pasted across 52 AWS provider files:

```rust
// CURRENT — repeated 52 times
let mut next_token: Option<String> = None;
loop {
    let mut req = self.client.list_findings().max_results(100);
    if let Some(ref t) = next_token {
        req = req.next_token(t);
    }
    let resp = req.send().await?;
    // process resp ...
    next_token = resp.next_token().map(|s| s.to_string());
    if next_token.is_none() { break; }
}

// RECOMMENDED — for operations without mid-stream truncation needs
let mut paginator = self.client
    .list_findings()
    .into_paginator()
    .send();
while let Some(resp) = paginator.next().await {
    let resp = resp.context("list_findings")?;
    // process resp ...
}
```

**Caveat:** `src/providers/aws/inspector.rs` has a legitimate reason to stay manual — it implements a `MAX_ROWS` cap with a custom sort that requires mid-stream truncation, which the paginator API does not support. All other files should migrate.

Representative files to prioritize for migration:
- `src/providers/aws/ec2_inventory.rs` (3 separate manual loops)
- `src/providers/aws/macie.rs`
- `src/providers/aws/public_resources.rs`
- `src/providers/aws/route53_config.rs`
- `src/providers/aws/network_gateways.rs`
- `src/providers/aws/dynamodb.rs` (uses `last_evaluated_table_name`)
- `src/providers/aws/waf.rs` (uses `next_marker`)

### Blocking I/O Inside `tokio::spawn`

`std::fs` calls exist inside `tokio::spawn` closures, blocking the async executor thread:

| Location | Issue | Fix |
|----------|-------|-----|
| `src/runner/multi_account.rs:279` | `std::fs::create_dir_all(rdir)` inside spawn | `tokio::fs::create_dir_all(rdir).await` |
| `src/runner/tui_runners.rs:269` | `run_poam(...)` (likely file I/O) called inside spawn with no `.await` | `tokio::task::spawn_blocking(|| run_poam(...)).await??` |
| `src/audit_log.rs` | Sync `fs::write`, `OpenOptions::new()` called from async context | Use `tokio::fs` equivalents or `spawn_blocking` |

### `tokio::spawn` Error Handling Gaps

Two fire-and-forget spawns drop their `JoinHandle`, silently swallowing panics:

| Location | Problem |
|----------|---------|
| `src/runner/tui_runners.rs:258` | Handle dropped — a panic inside `run_poam` will hang the TUI waiting for `Progress::Finished` |
| `src/runner/multi_account.rs:108` | Handle dropped — same risk |

The `inventory_orchestrator` correctly uses `JoinSet` with `join_next().await` — that pattern should be adopted here:
```rust
// Instead of dropping the handle:
let handle = tokio::spawn(async move { /* ... */ });
// Await it where appropriate, or propagate panics:
handle.await.context("background task panicked")??;
```

---

## 5. Code Quality & Clippy

**Total warnings: 62** (30 are auto-fixable with `cargo clippy --fix`).
**Public API surface:** 259 `pub fn` / `pub async fn`.

### Clippy Warnings by Category

| Count | Warning | Lint | Auto-fixable? |
|-------|---------|------|--------------|
| 9 | Redundant closure `\|x\| f(x)` → `f` | `redundant_closure` | ✅ Yes |
| 6 | `.clone()` on `Copy` type (`DateTime`) | `clone_on_copy` | ✅ Yes |
| 3 | `&Box<dyn T>` → use `&dyn T` | `borrowed_box` | ✅ Yes |
| 3 | `&PathBuf` param → use `&Path` | `ptr_arg` | ✅ Yes |
| 3 | Functions with 8–10 arguments (limit 7) | `too_many_arguments` | ❌ Manual |
| 3 | Complex tuple types — use type aliases | `type_complexity` | ❌ Manual |
| 3 | `row.get(0)` → `row.first()` | `get_first` | ✅ Yes |
| 3 | `Iterator::last()` on `DoubleEndedIterator` → `.next_back()` | `iter_last` | ✅ Yes |
| 3 | Dead imports (`PURPLE`, `TEAL`, `CYAN_DIM`, `CloudProvider`) | `unused_imports` | ✅ Yes |
| ~8 | Dead code (fields, functions, structs) | `dead_code` | ❌ Manual |
| 1 | `s.len() % 2 != 0` → `.is_multiple_of(2)` | `manual_is_multiple_of` | ✅ Yes |
| 1 | Deprecated `data_sources()` AWS SDK call | `deprecated` | ❌ Manual |
| 1 | `.and_then(\|x\| Some(y))` → `.map()` | `bind_instead_of_map` | ✅ Yes |
| 1 | Manual prefix stripping → `.strip_prefix()` | `manual_strip` | ✅ Yes |
| 1 | Manual `PartialOrd` that can be derived | `non_canonical_partial_ord_impl` | ✅ Yes |

### Functions That Are Too Long

| File | Function | Lines | Action |
|------|----------|-------|--------|
| `src/runner/tui_session.rs` | `run_tui_session()` | 694 | Split into `setup_session`, `run_provider_loop`, `run_account_batch`, `finalize_session` |
| `src/providers/aws/factory.rs` | `csv_collectors()` | ~383 | Split into domain builder helpers (see Section 1) |

The inline tuple type at `tui_session.rs:108` — `Vec<(String, String, String, Option<PathBuf>, Vec<String>)>` — should be replaced with a named struct (`AccountRunSpec`), which would also resolve the `type_complexity` Clippy warning.

### Dead Infrastructure

**`src/runner/collector_registry.rs`** — `CollectorRegistry` has 5 `pub fn` methods and a `Default` impl but is **never constructed anywhere in the codebase**. Either wire it into the runner or delete it.

**`src/inventory_core.rs:tag_value`** — exported as `pub` but never imported by any other module. Change to `pub(crate)` or remove if truly unused.

### Deprecated AWS SDK Calls

**`src/providers/aws/guardduty_config.rs:77`** — calls `data_sources()`, which is deprecated. Migrate to the AWS GuardDuty Features API. (The related `security_svc_config.rs` already suppresses the warning with `#[allow(deprecated)]` in four places; that suppression should be removed after the migration.)

### Missing Idiomatic Trait Implementations

| Type | File | Missing | Benefit |
|------|------|---------|---------|
| `OutcomeStatus` | `src/audit_log.rs` | `Display` | Cleaner log output without `{:?}` |
| `AccountRunSpec` (proposed) | `src/runner/tui_session.rs` | Struct itself | Eliminates the 5-tuple and `type_complexity` warning |
| `OptionsField` (proposed) | `src/tui/events.rs` | Enum | Replaces magic integer literals 1–6 |

### Suppressed Warnings Audit

| File | Suppression | Verdict |
|------|-------------|---------|
| `src/runner/multi_account.rs:60` | `#[allow(dead_code)]` | Remove — the field should be used or deleted |
| `src/providers/aws/cloudtrail_s3.rs:350` | `#[allow(dead_code)]` | Remove — `days_in_range()` is dead; delete the function |
| `src/providers/aws/security_svc_config.rs:87,90,97,105` | `#[allow(deprecated)]` ×4 | Remove after migrating to the Features API |

---

## Prioritized Action Plan

### Sprint 1 — Immediate (days 1–3)

1. **Fix `zip_bundle.rs:18`** — replace `let _ = zip.write_all(...)` with `?` propagation. One-line fix with high impact.
2. **Run `cargo clippy --fix`** — eliminates 30 warnings automatically (redundant closures, clone-on-copy, `&Box`, `&PathBuf`, `get_first`, `iter_last`, dead imports, `bind_instead_of_map`, `manual_strip`, `manual_is_multiple_of`).
3. **Fix `rds.rs:90` and `rds.rs:166`** — replace `created_at.unwrap()` with `?` propagation to prevent panics on malformed snapshot responses.
4. **Fix `tui/state.rs` cursor unwraps (lines 146, 154, 161)** — guard with `if let Some` to prevent TUI crashes.

### Sprint 2 — Short-term (week 1–2)

5. **Migrate `tokio::spawn` blocking I/O** — `multi_account.rs:279`, `tui_runners.rs:269`, `audit_log.rs` sync FS calls.
6. **Handle dropped `JoinHandle`s** — `tui_runners.rs:258` and `multi_account.rs:108`.
7. **Fix import fragmentation** — `tui/ui/frame.rs` and `providers/aws/factory.rs`.
8. **Replace magic numbers** — introduce `OptionsField` enum or named constants in `tui/events.rs`.
9. **Migrate deprecated GuardDuty `data_sources()` call** and remove the four `#[allow(deprecated)]` suppressions.
10. **Delete or wire in `CollectorRegistry`** — it is dead infrastructure.

### Sprint 3 — Modularization (weeks 2–4)

11. **Extract `tui_session.rs` → `session/account_prep.rs` + `session/tenable_prep.rs`** — highest priority split; the 694-line function is the single biggest maintainability liability.
12. **Extract `tui/events.rs` → `events/{setup_screens,collector_screens,options_screens}.rs`**.
13. **Extract `multi_account.rs` → `multi_account/{types,collector_loop}.rs`**.
14. **Extract `factory.rs` csv_collectors into domain builder helpers**.
15. **Split `tui/collector_data.rs` → `collector_data/{items,regions}.rs`** — mechanical, low-risk.

### Sprint 4 — Paginator Migration (ongoing)

16. **Migrate all 52 AWS provider files from manual `next_token` loops to `.into_paginator()`**, starting with the highest-volume files (`ec2_inventory.rs`, `macie.rs`, `public_resources.rs`). Exclude `inspector.rs` (legitimate mid-stream truncation requirement).

---

## Quick Reference: Auto-fixable Items

Run this to resolve 30 warnings with no manual work:

```bash
cargo clippy --fix --allow-dirty
```

Then run `cargo test` to verify nothing regressed.
