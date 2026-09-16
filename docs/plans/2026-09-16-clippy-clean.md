# Clippy Clean (`-D warnings`) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `cargo clippy -- -D warnings` passes with zero errors (currently 29).

**Architecture:** Mechanical lint fixes only. Dead code is deleted, style lints take clippy's suggested rewrite, long signatures get a crate-level `too_many_arguments` allow, complex tuple types get `type` aliases, and the two deprecated GuardDuty `data_sources()` reads get a scoped `#[allow(deprecated)]`. No behavior changes.

**Tech Stack:** Rust stable (clippy 1.94), cargo.

**Spec:** the clippy output pasted in the request (29 errors, `the-grabber` lib).

## Global Constraints

- No observable behavior change: output files, CSV columns and CLI flags stay identical. So **no CHANGELOG entry** (CLAUDE.md: skip for changes with no outward effect).
- No `unwrap()`/`expect()` added in production code.
- Work on `main`; commit as Austin Songer, no co-author trailers.
- `src/runner/tui_session.rs`, `src/aws_loader.rs`, and `CHANGELOG.md` have **uncommitted user work**. Ask the user to commit or stash it before Task 3. Never `git add` those files wholesale without that confirmation.
- A PostToolUse hook runs `cargo check` after each write, so every edit must leave the tree compiling.
- Verification per task: `cargo clippy -- -D warnings 2>&1 | grep -c '^error'` count drops as listed, and `cargo test` stays green.

---

### Task 1: Remove dead code and unused bindings (compiler lints, 7 errors)

**Files:**
- Modify: `src/poam/oscal/mod.rs:16-19`
- Modify: `src/poam/oscal/reconcile.rs:271,274` (test module)
- Modify: `src/poam/oscal/model.rs:139-145`
- Modify: `src/tui/ui/collectors.rs:2`
- Modify: `src/audit_log.rs:401`
- Modify: `src/providers/aws/organizations.rs:45`
- Modify: `src/providers/aws/iam_inventory/mod.rs:36-47`
- Modify: `src/providers/tenable/vulnerabilities.rs:8-17`

**Interfaces:**
- Consumes: nothing.
- Produces: `oscal` re-exports shrink to `Metadata, Observation, PlanOfActionAndMilestones, PoamItem, Risk`. `TenableVulnerabilitiesCollector::new(client, _scan_ids)` keeps its signature, so `src/providers/tenable/factory.rs` is untouched.

- [ ] **Step 1: Trim the OSCAL re-export**

`src/poam/oscal/mod.rs`:
```rust
pub(super) use model::{Metadata, Observation, PlanOfActionAndMilestones, PoamItem, Risk};
```

- [ ] **Step 2: Point the reconcile test at `model` directly**

The test at `src/poam/oscal/reconcile.rs:271` and `:274` used the removed re-export. Replace:
```rust
            related_risks: vec![crate::poam::oscal::model::RelatedRisk {
```
```rust
            related_observations: vec![crate::poam::oscal::model::RelatedObservation {
```
If the test module imports `Prop` (or any other removed name) through `crate::poam::oscal::`, repoint it the same way to `crate::poam::oscal::model::`.

- [ ] **Step 3: Delete `RiskLogEntry`**

Delete the whole struct in `src/poam/oscal/model.rs` (the `#[derive(...)]` line plus `pub(in crate::poam) struct RiskLogEntry { ... }`). Nothing constructs it.

- [ ] **Step 4: Drop unused `Color` import**

`src/tui/ui/collectors.rs:2`:
```rust
use ratatui::style::{Modifier, Style};
```

- [ ] **Step 5: Fix `sanitized_cli_args`**

`src/audit_log.rs:401`. `.peekable()` is never peeked, so remove both:
```rust
    let args = std::env::args();
```

- [ ] **Step 6: Fix `next_token` dead init**

`src/providers/aws/organizations.rs:45`. Both arms of the following `match` either `return` or assign, so declare without a value:
```rust
        let mut next_token: Option<String>;
```

- [ ] **Step 7: Delete `trust_policy_principals`**

Delete the doc comment and function at `src/providers/aws/iam_inventory/mod.rs:36-47`. `url_decode` stays; `policy.rs` and `role.rs` still call it.

- [ ] **Step 8: Drop unused Tenable `scan_ids` field**

`src/providers/tenable/vulnerabilities.rs`. The export API can't filter by integer scan IDs (see the comment at line 81), so the field is never read:
```rust
pub struct TenableVulnerabilitiesCollector {
    client: TenableClient,
}

impl TenableVulnerabilitiesCollector {
    /// `_scan_ids` is accepted for factory symmetry but unused: the export
    /// API identifies scans by UUID, not the integer IDs selected in the TUI.
    pub fn new(client: TenableClient, _scan_ids: Vec<i64>) -> Self {
        Self { client }
    }
}
```

- [ ] **Step 9: Verify**

Run: `cargo clippy -- -D warnings 2>&1 | grep -E 'unused|never (used|read|constructed)|does not need to be mutable'`
Expected: no output.
Run: `cargo test poam::`
Expected: PASS.

- [ ] **Step 10: Commit**

```bash
git add src/poam/oscal/mod.rs src/poam/oscal/reconcile.rs src/poam/oscal/model.rs src/tui/ui/collectors.rs src/audit_log.rs src/providers/aws/organizations.rs src/providers/aws/iam_inventory/mod.rs src/providers/tenable/vulnerabilities.rs
git commit -m "chore: remove dead code and unused bindings flagged by clippy"
```

---

### Task 2: Take clippy's style rewrites (10 errors)

**Files:**
- Modify: `src/app_config.rs:79-80`
- Modify: `src/inventory_xlsx.rs:19-21,172-173`
- Modify: `src/providers/okta/automated_provisioning_events.rs:100`
- Modify: `src/runner/tui_runners.rs:1,17,20,110,113,208,212`

**Interfaces:**
- Consumes: nothing.
- Produces: `run_tui_csv_collector(collector: &dyn CsvCollector, …, out_dir: &Path, …)`, `run_tui_inv_collector(collector: &dyn JsonCollector, …, out_dir: &Path, …)`, `run_tui_json_collector(collector: &dyn EvidenceCollector, …, out_dir: &Path, …)`. Callers in `src/runner/multi_account.rs` pass `&Box<dyn _>` and `&PathBuf`, which deref-coerce, so callers don't change.

- [ ] **Step 1: Doc list indentation**

`src/app_config.rs:80`, three spaces to align under `a.`:
```rust
///    b. Add any listed in `enable_extra` (useful for per-account
///       overrides that add org-level collectors).
```
becomes
```rust
///    b. Add any listed in `enable_extra` (useful for per-account
///    overrides that add org-level collectors).
```
If clippy still complains, use exactly the indentation its `help: try using` line shows.

`src/inventory_xlsx.rs:20-21`:
```rust
//! - Row 3+     : data rows written by this module, mapped into the template's
//!   actual columns by matching row-2 header labels against
//!   [`crate::inventory_core::INVENTORY_CSV_HEADERS`]
```

- [ ] **Step 2: `strip_prefix`**

`src/inventory_xlsx.rs:172-176`:
```rust
                    return Some(match target.strip_prefix('/') {
                        Some(stripped) => stripped.to_string(),
                        None => format!("xl/{target}"),
                    });
```

- [ ] **Step 3: Redundant `into_iter`**

`src/providers/okta/automated_provisioning_events.rs:100`:
```rust
            .chain(membership_events)
```

- [ ] **Step 4: `&Box<dyn _>` → `&dyn _`, `&PathBuf` → `&Path`**

`src/runner/tui_runners.rs`:
- line 1: `use std::path::Path;` (keep `PathBuf` only if still referenced; the compiler will say)
- line 17: `collector: &dyn CsvCollector,`
- line 110: `collector: &dyn JsonCollector,`
- line 208: `collector: &dyn EvidenceCollector,`
- lines 20, 113, 212: `out_dir: &Path,`

Bodies only call `out_dir.join(..)`, which `Path` supports.

- [ ] **Step 5: Verify**

Run: `cargo clippy -- -D warnings 2>&1 | grep -E 'overindented|manual|into_iter|Box<T>|&PathBuf'`
Expected: no output.

- [ ] **Step 6: Commit**

```bash
git add src/app_config.rs src/inventory_xlsx.rs src/providers/okta/automated_provisioning_events.rs src/runner/tui_runners.rs
git commit -m "chore: apply clippy style suggestions"
```

---

### Task 3: Signature complexity lints (10 errors)

**Precondition:** user's WIP in `src/runner/tui_session.rs` is committed or stashed (see Global Constraints).

**Files:**
- Modify: `Cargo.toml` (add `[lints.clippy]`)
- Modify: `src/runner/multi_account.rs:1-20,76-82,206-209`
- Modify: `src/runner/tui_session.rs:358`

**Interfaces:**
- Consumes: nothing.
- Produces: `pub type RegionalCollectors = (String, PathBuf, Vec<Box<dyn CsvCollector>>, Vec<Box<dyn JsonCollector>>, Vec<Box<dyn EvidenceCollector>>);` in `multi_account.rs`. Tuple shape is unchanged, so `tui_session.rs:573-814` construction/destructuring is untouched.

Decision: `too_many_arguments` (6 hits) is allowed crate-wide rather than refactored into param structs. These are internal runner functions with one or two callers each; a struct per function is churn with no payoff. Revisit if a signature grows further.

- [ ] **Step 1: Allow `too_many_arguments` crate-wide**

Append to `Cargo.toml` (root package, not the workspace crates):
```toml
[lints.clippy]
too_many_arguments = "allow"
```

- [ ] **Step 2: Alias the regional collector tuple**

`src/runner/multi_account.rs`, after the imports:
```rust
/// (region_name, out_dir, csv_collectors, inv_collectors, json_collectors)
pub type RegionalCollectors = (
    String,
    PathBuf,
    Vec<Box<dyn CsvCollector>>,
    Vec<Box<dyn JsonCollector>>,
    Vec<Box<dyn EvidenceCollector>>,
);
```
Field at line 76:
```rust
    pub regional_collectors: Vec<RegionalCollectors>,
```

- [ ] **Step 3: Simplify the JoinSet type**

`src/runner/multi_account.rs:206`. `Result` is already `anyhow::Result`:
```rust
                let mut join_set: tokio::task::JoinSet<(String, Result<Vec<Vec<String>>>)> =
                    tokio::task::JoinSet::new();
```
If clippy still flags it, add above the `impl`/fn: `type RegionRows = (String, Result<Vec<Vec<String>>>);` and use `JoinSet<RegionRows>`.

- [ ] **Step 4: Alias the account-run tuple**

`src/runner/tui_session.rs`, near the top after imports:
```rust
/// (profile, region, account_id, output_path, collector_keys)
type AccountRun = (String, String, String, Option<PathBuf>, Vec<String>);
```
Line 358:
```rust
            let mut account_runs: Vec<AccountRun> = Vec::new();
```

- [ ] **Step 5: Verify**

Run: `cargo clippy -- -D warnings 2>&1 | grep -E 'too many arguments|very complex type'`
Expected: no output.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml src/runner/multi_account.rs src/runner/tui_session.rs
git commit -m "chore: alias complex runner types and allow too_many_arguments"
```

---

### Task 4: Deprecated GuardDuty `data_sources()` (2 errors)

**Files:**
- Modify: `src/inventory_orchestrator/security_services.rs:374`
- Modify: `src/providers/aws/guardduty_config.rs:77`

**Interfaces:**
- Consumes/Produces: nothing new.

Decision: allow, don't migrate. Detectors created before GuardDuty's `features` API still report protection status through `dataSources`, and the inventory row already emits `features` alongside it. Dropping `data_sources` would blank the S3/EKS/malware columns in `GuardDuty_Config` evidence for those detectors, which is an evidence change needing its own plan and CHANGELOG entry.

- [ ] **Step 1: Scope the allow to the statement**

`src/inventory_orchestrator/security_services.rs:374`:
```rust
            // Legacy dataSources block is still populated for older detectors;
            // `features` is emitted alongside it.
            #[allow(deprecated)]
            let data_sources = summarize_data_sources(detector.data_sources());
```

`src/providers/aws/guardduty_config.rs:77`:
```rust
            // Legacy dataSources block; still the only protection status source
            // for detectors predating the `features` API.
            #[allow(deprecated)]
            let ds = resp.data_sources();
```

- [ ] **Step 2: Full verification**

Run: `cargo clippy -- -D warnings`
Expected: `Finished` with no errors.
Run: `cargo fmt --check && cargo test`
Expected: clean format, all tests PASS.

- [ ] **Step 3: Commit**

```bash
git add src/inventory_orchestrator/security_services.rs src/providers/aws/guardduty_config.rs
git commit -m "chore: allow deprecated GuardDuty data_sources reads"
```
