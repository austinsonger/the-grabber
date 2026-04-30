# Parallel Collector Execution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace sequential per-account collector loops with concurrent `JoinSet`-based execution, limited by a configurable semaphore (default 8), for both single-region and multi-region modes.

**Architecture:** Within the existing `tokio::spawn` background task in `run_tui_multi_account`, spawn per-collector sub-tasks using `tokio::task::JoinSet` gated by a `tokio::sync::Semaphore`. The three runner helpers (`run_tui_csv_collector`, `run_tui_inv_collector`, `run_tui_json_collector`) are refactored to return `(Vec<String>, Vec<CollectorOutcome>)` so results can be collected after concurrent joins. Each collector writes to a unique filename so no file-level locking is needed.

**Tech Stack:** Rust, Tokio (`JoinSet`, `Semaphore`, `OwnedSemaphorePermit`), `std::sync::Arc`

---

## File Map

| File | Change |
|------|--------|
| `src/app_config.rs` | Add `collector_concurrency: Option<usize>` to `Defaults` |
| `src/tui/mod.rs` | Add `collector_concurrency: usize` to `App`; read from config in `App::new()` |
| `src/main.rs` | (1) Add `Arc`/`Semaphore` imports; (2) refactor three runner helpers to return values; (3) add `concurrency: usize` param to `run_tui_multi_account`; (4) replace sequential inner loops with `JoinSet`+`Semaphore`; (5) pass concurrency from `App` to the function call |

---

## Task 1: Add `collector_concurrency` to `AppConfig`

**Files:**
- Modify: `src/app_config.rs:25-53`

- [ ] **Step 1: Add field to `Defaults`**

In `src/app_config.rs`, add one field to `Defaults` after `sign`:

```rust
/// Maximum number of collectors to run concurrently within a single account/region.
/// Defaults to 8 when not set.
pub collector_concurrency: Option<usize>,
```

The full `Defaults` struct becomes:

```rust
#[derive(Debug, Default, Deserialize)]
pub struct Defaults {
    pub profile_contains: Option<String>,
    pub region: Option<String>,
    pub output_dir: Option<String>,
    pub start_date_offset_days: Option<u32>,
    pub include_raw: Option<bool>,
    pub zip: Option<bool>,
    pub sign: Option<bool>,
    pub collector_concurrency: Option<usize>,
    #[serde(default)]
    pub collectors: CollectorConfig,
}
```

- [ ] **Step 2: Build to confirm no compile errors**

```bash
cd /Users/austin-songer/code/grabber && cargo check 2>&1 | tail -5
```

Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add src/app_config.rs
git commit -m "feat(config): add collector_concurrency field to Defaults"
```

---

## Task 2: Thread concurrency through `App` and into collection

**Files:**
- Modify: `src/tui/mod.rs` (App struct and App::new)
- Modify: `src/main.rs` (call site of `run_tui_multi_account`)

- [ ] **Step 1: Add field to `App` struct**

In `src/tui/mod.rs`, add to `App` struct after `skip_chain_of_custody`:

```rust
/// Maximum concurrent collectors within one account/region pass.
pub collector_concurrency: usize,
```

- [ ] **Step 2: Initialize in `App::new()`**

In `src/tui/mod.rs`, inside `App::new()` after `let sign = ...` line (~line 845):

```rust
let collector_concurrency = config
    .defaults
    .collector_concurrency
    .unwrap_or(8)
    .max(1);
```

Then in the `Self { ... }` literal, add after `sign`:

```rust
collector_concurrency,
```

- [ ] **Step 3: Pass to `run_tui_multi_account` call**

In `src/main.rs`, find the `run_tui_multi_account(` call (~line 924). Add `app.collector_concurrency` as a new argument:

```rust
let collector_concurrency = app.collector_concurrency;
// ...
let restart = run_tui_multi_account(
    &mut terminal,
    &mut app,
    &params,
    prepared,
    tx,
    do_zip,
    do_sign,
    skip_inventory_csv,
    skip_run_manifest,
    skip_chain_of_custody,
    collector_concurrency,
)
.await?;
```

- [ ] **Step 4: Add `concurrency: usize` parameter to `run_tui_multi_account`**

In `src/main.rs`, update the function signature at line ~2459:

```rust
async fn run_tui_multi_account(
    terminal: &mut ratatui::Terminal<ratatui::backend::CrosstermBackend<std::io::Stdout>>,
    app: &mut App,
    params: &CollectParams,
    prepared: Vec<AccountCollectors>,
    tx: mpsc::UnboundedSender<Progress>,
    do_zip: bool,
    do_sign: bool,
    skip_inventory_csv: bool,
    skip_run_manifest: bool,
    skip_chain_of_custody: bool,
    concurrency: usize,
) -> Result<bool> {
```

- [ ] **Step 5: Thread `concurrency` into the background `tokio::spawn` closure**

Inside `run_tui_multi_account`, `concurrency` must be captured by the `tokio::spawn(async move { ... })` closure. Since it's `usize` (Copy), it's automatically captured. No extra clone needed.

- [ ] **Step 6: Build to confirm no compile errors**

```bash
cd /Users/austin-songer/code/grabber && cargo check 2>&1 | tail -10
```

Expected: no errors (or only unused-variable warnings for `concurrency`).

- [ ] **Step 7: Commit**

```bash
git add src/tui/mod.rs src/main.rs
git commit -m "feat(tui): thread collector_concurrency through App into collection task"
```

---

## Task 3: Refactor runner helpers to return results

The three `run_tui_*_collector` helpers currently take `&mut written` and `&mut outcomes`. These must be changed to return values so they can be called inside `tokio::spawn` closures (which require owned data).

**Files:**
- Modify: `src/main.rs:2162-2392` (the three helper functions)

- [ ] **Step 1: Refactor `run_tui_csv_collector` to return `(Vec<String>, Vec<audit_log::CollectorOutcome>)`**

Replace the existing function (lines ~2162-2231) with:

```rust
async fn run_tui_csv_collector(
    collector: &Box<dyn CsvCollector>,
    account_id: &str,
    region: &str,
    out_dir: &PathBuf,
    timestamp: &str,
    tx: &mpsc::UnboundedSender<Progress>,
    timeout: std::time::Duration,
    dates: Option<(i64, i64)>,
) -> (Vec<String>, Vec<audit_log::CollectorOutcome>) {
    let mut written: Vec<String> = Vec::new();
    let mut outcomes: Vec<audit_log::CollectorOutcome> = Vec::new();
    let name = collector.name().to_string();
    let _ = tx.send(Progress::Started {
        collector: name.clone(),
    });
    match tokio::time::timeout(timeout, collector.collect_rows(account_id, region, dates)).await {
        Ok(Ok(rows)) => {
            let count = rows.len();
            let _ = tx.send(Progress::Done {
                collector: name.clone(),
                count,
            });
            if count == 0 {
                outcomes.push(audit_log::CollectorOutcome::empty(&name));
                return (written, outcomes);
            }
            let filename = format!(
                "{}_{}-{}.csv",
                account_id,
                collector.filename_prefix(),
                timestamp
            );
            let path = out_dir.join(&filename);
            if let Ok(bytes) = write_csv_bytes(collector.headers(), &rows) {
                if std::fs::write(&path, bytes).is_ok() {
                    outcomes.push(audit_log::CollectorOutcome::success(&name, count, &path));
                    written.push(path.display().to_string());
                } else {
                    outcomes.push(audit_log::CollectorOutcome::error(
                        &name,
                        "write failed".to_string(),
                    ));
                }
            } else {
                outcomes.push(audit_log::CollectorOutcome::error(
                    &name,
                    "CSV serialisation failed".to_string(),
                ));
            }
        }
        Ok(Err(e)) => {
            let msg = format!("{:#}", e);
            eprintln!("  ERROR [csv] {}: {}", name, msg);
            let _ = tx.send(Progress::Error {
                collector: name.clone(),
                message: msg.clone(),
            });
            outcomes.push(audit_log::CollectorOutcome::error(&name, msg));
        }
        Err(_) => {
            eprintln!("  ERROR [csv] {}: timed out after 3 minutes", name);
            let _ = tx.send(Progress::Error {
                collector: name.clone(),
                message: "timed out after 3 minutes".to_string(),
            });
            outcomes.push(audit_log::CollectorOutcome::timeout(&name));
        }
    }
    (written, outcomes)
}
```

- [ ] **Step 2: Refactor `run_tui_inv_collector` to return `(Vec<String>, Vec<audit_log::CollectorOutcome>)`**

Replace the existing function (lines ~2233-2309) with:

```rust
async fn run_tui_inv_collector(
    collector: &Box<dyn JsonCollector>,
    account_id: &str,
    region: &str,
    out_dir: &PathBuf,
    timestamp: &str,
    tx: &mpsc::UnboundedSender<Progress>,
    timeout: std::time::Duration,
) -> (Vec<String>, Vec<audit_log::CollectorOutcome>) {
    let mut written: Vec<String> = Vec::new();
    let mut outcomes: Vec<audit_log::CollectorOutcome> = Vec::new();
    let name = collector.name().to_string();
    let _ = tx.send(Progress::Started {
        collector: name.clone(),
    });
    match tokio::time::timeout(timeout, collector.collect_records(account_id, region)).await {
        Ok(Ok(records)) => {
            let count = records.len();
            let _ = tx.send(Progress::Done {
                collector: name.clone(),
                count,
            });
            if count == 0 {
                outcomes.push(audit_log::CollectorOutcome::empty(&name));
                return (written, outcomes);
            }
            let report = JsonInventoryReport {
                collected_at: Utc::now().to_rfc3339(),
                account_id: account_id.to_string(),
                region: region.to_string(),
                collector: name.clone(),
                record_count: count,
                records,
            };
            let filename = format!(
                "{}_{}-{}.json",
                account_id,
                collector.filename_prefix(),
                timestamp
            );
            let path = out_dir.join(&filename);
            if let Ok(json) = serde_json::to_string_pretty(&report) {
                if std::fs::write(&path, json).is_ok() {
                    outcomes.push(audit_log::CollectorOutcome::success(&name, count, &path));
                    written.push(path.display().to_string());
                } else {
                    outcomes.push(audit_log::CollectorOutcome::error(
                        &name,
                        "write failed".to_string(),
                    ));
                }
            } else {
                outcomes.push(audit_log::CollectorOutcome::error(
                    &name,
                    "JSON serialisation failed".to_string(),
                ));
            }
        }
        Ok(Err(e)) => {
            let msg = format!("{:#}", e);
            eprintln!("  ERROR [inv] {}: {}", name, msg);
            let _ = tx.send(Progress::Error {
                collector: name.clone(),
                message: msg.clone(),
            });
            outcomes.push(audit_log::CollectorOutcome::error(&name, msg));
        }
        Err(_) => {
            eprintln!("  ERROR [inv] {}: timed out after 3 minutes", name);
            let _ = tx.send(Progress::Error {
                collector: name.clone(),
                message: "timed out after 3 minutes".to_string(),
            });
            outcomes.push(audit_log::CollectorOutcome::timeout(&name));
        }
    }
    (written, outcomes)
}
```

- [ ] **Step 3: Refactor `run_tui_json_collector` to return `(Vec<String>, Vec<audit_log::CollectorOutcome>)`**

Replace the existing function (lines ~2311-2392) with:

```rust
async fn run_tui_json_collector(
    collector: &Box<dyn EvidenceCollector>,
    params: &CollectParams,
    region: &str,
    account_id: &str,
    out_dir: &PathBuf,
    timestamp: &str,
    tx: &mpsc::UnboundedSender<Progress>,
    timeout: std::time::Duration,
) -> (Vec<String>, Vec<audit_log::CollectorOutcome>) {
    let mut written: Vec<String> = Vec::new();
    let mut outcomes: Vec<audit_log::CollectorOutcome> = Vec::new();
    let name = collector.name().to_string();
    let _ = tx.send(Progress::Started {
        collector: name.clone(),
    });
    match tokio::time::timeout(timeout, collector.collect(params)).await {
        Ok(Ok(records)) => {
            let count = records.len();
            let _ = tx.send(Progress::Done {
                collector: name.clone(),
                count,
            });
            if count == 0 {
                outcomes.push(audit_log::CollectorOutcome::empty(&name));
                return (written, outcomes);
            }
            let report = EvidenceReport {
                metadata: ReportMetadata {
                    collected_at: Utc::now().to_rfc3339(),
                    region: region.to_string(),
                    start_date: params.start_time.format("%Y-%m-%d").to_string(),
                    end_date: params.end_time.format("%Y-%m-%d").to_string(),
                    filter: params.filter.clone(),
                },
                collector: name.clone(),
                record_count: count,
                records,
            };
            let filename = format!(
                "{}_{}-{}.json",
                account_id,
                collector.filename_prefix(),
                timestamp
            );
            let path = out_dir.join(&filename);
            if let Ok(json) = serde_json::to_string_pretty(&report) {
                if std::fs::write(&path, json).is_ok() {
                    outcomes.push(audit_log::CollectorOutcome::success(&name, count, &path));
                    written.push(path.display().to_string());
                } else {
                    outcomes.push(audit_log::CollectorOutcome::error(
                        &name,
                        "write failed".to_string(),
                    ));
                }
            } else {
                outcomes.push(audit_log::CollectorOutcome::error(
                    &name,
                    "JSON serialisation failed".to_string(),
                ));
            }
        }
        Ok(Err(e)) => {
            let msg = format!("{:#}", e);
            eprintln!("  ERROR [json] {}: {}", name, msg);
            let _ = tx.send(Progress::Error {
                collector: name.clone(),
                message: msg.clone(),
            });
            outcomes.push(audit_log::CollectorOutcome::error(&name, msg));
        }
        Err(_) => {
            eprintln!("  ERROR [json] {}: timed out after 3 minutes", name);
            let _ = tx.send(Progress::Error {
                collector: name.clone(),
                message: "timed out after 3 minutes".to_string(),
            });
            outcomes.push(audit_log::CollectorOutcome::timeout(&name));
        }
    }
    (written, outcomes)
}
```

- [ ] **Step 4: Fix all call sites of the three helpers**

All six sequential calls in `run_tui_multi_account` use the old `&mut written, &mut outcomes` signature. Replace each with the new return-value pattern. For example, the `rcsv` loop (lines ~2655-2668) becomes:

```rust
for collector in rcsv {
    let (w, o) = run_tui_csv_collector(
        collector,
        &acct.account_id,
        region_name,
        rdir,
        &timestamp,
        &tx,
        collector_timeout,
        dates,
    )
    .await;
    all_written_files.extend(w);
    acct_outcomes.extend(o);
}
```

Apply the same pattern to the `rinv` loop (using `run_tui_inv_collector`), the `rjson` loop (using `run_tui_json_collector`), and the three single-region loops.

- [ ] **Step 5: Build to confirm no compile errors**

```bash
cd /Users/austin-songer/code/grabber && cargo check 2>&1 | tail -10
```

Expected: no errors.

- [ ] **Step 6: Smoke test with a real AWS profile to verify no regressions**

```bash
cd /Users/austin-songer/code/grabber && cargo build --release 2>&1 | tail -5
```

Run the TUI briefly and confirm it still starts, the Running screen shows, and output files are written.

- [ ] **Step 7: Commit**

```bash
git add src/main.rs
git commit -m "refactor(runner): return (written, outcomes) from runner helpers instead of &mut params"
```

---

## Task 4: Add `Arc`/`Semaphore` imports to `main.rs`

**Files:**
- Modify: `src/main.rs:93-102` (import block)

- [ ] **Step 1: Add imports**

After the existing `use tokio::sync::mpsc;` line (~line 102), add:

```rust
use std::sync::Arc;
use tokio::sync::Semaphore;
```

- [ ] **Step 2: Build**

```bash
cd /Users/austin-songer/code/grabber && cargo check 2>&1 | tail -5
```

Expected: no errors (warnings about unused imports are fine at this stage).

- [ ] **Step 3: Commit**

```bash
git add src/main.rs
git commit -m "chore(main): import Arc and Semaphore for parallel collector execution"
```

---

## Task 5: Parallelize single-region collector loops

**Files:**
- Modify: `src/main.rs` — the single-region path inside `run_tui_multi_account` (lines ~2700-2782)

The single-region path currently runs three sequential loops: `json_collectors`, `json_inv_collectors`, `csv_collectors`. Replace all three with a single `JoinSet` that launches all collectors together, gated by the shared semaphore.

- [ ] **Step 1: Replace the three sequential single-region loops**

Find the `else if acct.discovered_regions.is_empty() && !has_inventory_multi_region {` block (line ~2700). The non-inventory branch (lines ~2766-2782) and the `json`/`json_inv` branches above it are replaced with:

```rust
} else if acct.discovered_regions.is_empty() && !has_inventory_multi_region {
    // ── Single-region path: run all collectors concurrently ──
    let sem = Arc::new(Semaphore::new(concurrency));
    let mut join_set: tokio::task::JoinSet<(Vec<String>, Vec<audit_log::CollectorOutcome>)> =
        tokio::task::JoinSet::new();

    // JSON time-windowed collectors
    for collector in acct.json_collectors.into_iter() {
        let sem = Arc::clone(&sem);
        let params = params_clone.clone();
        let region = acct.region.clone();
        let account_id = acct.account_id.clone();
        let out_dir = out_dir.clone();
        let timestamp = timestamp.clone();
        let tx = tx.clone();
        join_set.spawn(async move {
            let _permit = sem.acquire_owned().await.expect("semaphore closed");
            run_tui_json_collector(
                &collector,
                &params,
                &region,
                &account_id,
                &out_dir,
                &timestamp,
                &tx,
                collector_timeout,
            )
            .await
        });
    }

    // JSON inventory collectors
    for collector in acct.json_inv_collectors.into_iter() {
        let sem = Arc::clone(&sem);
        let account_id = acct.account_id.clone();
        let region = acct.region.clone();
        let out_dir = out_dir.clone();
        let timestamp = timestamp.clone();
        let tx = tx.clone();
        join_set.spawn(async move {
            let _permit = sem.acquire_owned().await.expect("semaphore closed");
            run_tui_inv_collector(
                &collector,
                &account_id,
                &region,
                &out_dir,
                &timestamp,
                &tx,
                collector_timeout,
            )
            .await
        });
    }

    if is_inventory_mode {
        // Inventory CSV: rows go to global buffer, not a file
        for collector in acct.csv_collectors.into_iter() {
            let sem = Arc::clone(&sem);
            let account_id = acct.account_id.clone();
            let region = acct.region.clone();
            let tx = tx.clone();
            // Use a separate JoinSet for inventory rows so we can collect them
            let mut inv_join: tokio::task::JoinSet<(usize, Result<Vec<Vec<String>>, anyhow::Error>)> =
                tokio::task::JoinSet::new();
            let sem2 = Arc::clone(&sem);
            let name = collector.name().to_string();
            inv_join.spawn(async move {
                let _permit = sem2.acquire_owned().await.expect("semaphore closed");
                let _ = tx.send(Progress::Started { collector: name.clone() });
                let result = tokio::time::timeout(
                    collector_timeout,
                    collector.collect_rows(&account_id, &region, dates),
                )
                .await
                .map_err(|_| anyhow::anyhow!("timed out"))
                .and_then(|r| r);
                match &result {
                    Ok(rows) => {
                        let _ = tx.send(Progress::Done { collector: name, count: rows.len() });
                    }
                    Err(e) => {
                        let _ = tx.send(Progress::Error { collector: name, message: format!("{e:#}") });
                    }
                }
                (0usize, result)
            });
            while let Some(res) = inv_join.join_next().await {
                if let Ok((_, Ok(rows))) = res {
                    inventory_global_rows.extend(rows);
                }
            }
        }
    } else {
        // Evidence CSV collectors
        for collector in acct.csv_collectors.into_iter() {
            let sem = Arc::clone(&sem);
            let account_id = acct.account_id.clone();
            let region = acct.region.clone();
            let out_dir = out_dir.clone();
            let timestamp = timestamp.clone();
            let tx = tx.clone();
            join_set.spawn(async move {
                let _permit = sem.acquire_owned().await.expect("semaphore closed");
                run_tui_csv_collector(
                    &collector,
                    &account_id,
                    &region,
                    &out_dir,
                    &timestamp,
                    &tx,
                    collector_timeout,
                    dates,
                )
                .await
            });
        }
    }

    // Collect all results
    while let Some(res) = join_set.join_next().await {
        match res {
            Ok((w, o)) => {
                all_written_files.extend(w);
                acct_outcomes.extend(o);
            }
            Err(e) => {
                eprintln!("  ERROR: collector task panicked: {e}");
            }
        }
    }
}
```

> **Note on inventory single-region path:** The inventory path above uses a nested `inv_join` per collector. An alternative is to pre-split inventory from non-inventory and run them in separate join sets. The above inline approach avoids that restructuring and is simpler for a single-region fallback that rarely has many collectors.

- [ ] **Step 2: Build**

```bash
cd /Users/austin-songer/code/grabber && cargo check 2>&1 | tail -20
```

Expected: no errors. The borrow checker will enforce that moved collectors are not used after the `into_iter()`.

- [ ] **Step 3: Commit**

```bash
git add src/main.rs
git commit -m "feat(runner): parallelize single-region collector execution with JoinSet+Semaphore"
```

---

## Task 6: Parallelize multi-region inner collector loops

**Files:**
- Modify: `src/main.rs` — the multi-region path inside `run_tui_multi_account` (lines ~2645-2699)

The multi-region path iterates over regions sequentially. Within each region, collectors run sequentially. Parallelize the collector execution within each region.

- [ ] **Step 1: Replace the three sequential inner loops in the multi-region path**

Find `for (region_name, rdir, rcsv, rinv, rjson) in &acct.regional_collectors {` (line ~2650). Currently this uses `&acct.regional_collectors`. To move collectors into spawns, change to consume via `.into_iter()`.

First, update `AccountCollectors.regional_collectors` to use `Vec<(...)>` (it already is), and change the loop from a borrow to a consume. Also, we must remove `discovered_regions` check from the `else if` guard since we now consume `regional_collectors`:

```rust
if !acct.discovered_regions.is_empty() && !has_inventory_multi_region {
    eprintln!(
        "  all-regions: {} regions pre-built",
        acct.discovered_regions.len()
    );
    for (region_name, rdir, rcsv, rinv, rjson) in acct.regional_collectors.into_iter() {
        let _ = tx.send(Progress::RegionStarted {
            region: region_name.clone(),
        });
        let _ = std::fs::create_dir_all(&rdir);

        // Run all collectors for this region concurrently
        let sem = Arc::new(Semaphore::new(concurrency));
        let mut join_set: tokio::task::JoinSet<(Vec<String>, Vec<audit_log::CollectorOutcome>)> =
            tokio::task::JoinSet::new();

        for collector in rcsv.into_iter() {
            let sem = Arc::clone(&sem);
            let account_id = acct.account_id.clone();
            let rname = region_name.clone();
            let rdir = rdir.clone();
            let timestamp = timestamp.clone();
            let tx = tx.clone();
            join_set.spawn(async move {
                let _permit = sem.acquire_owned().await.expect("semaphore closed");
                run_tui_csv_collector(
                    &collector,
                    &account_id,
                    &rname,
                    &rdir,
                    &timestamp,
                    &tx,
                    collector_timeout,
                    dates,
                )
                .await
            });
        }

        for collector in rinv.into_iter() {
            let sem = Arc::clone(&sem);
            let account_id = acct.account_id.clone();
            let rname = region_name.clone();
            let rdir = rdir.clone();
            let timestamp = timestamp.clone();
            let tx = tx.clone();
            join_set.spawn(async move {
                let _permit = sem.acquire_owned().await.expect("semaphore closed");
                run_tui_inv_collector(
                    &collector,
                    &account_id,
                    &rname,
                    &rdir,
                    &timestamp,
                    &tx,
                    collector_timeout,
                )
                .await
            });
        }

        for collector in rjson.into_iter() {
            let sem = Arc::clone(&sem);
            let params = params_clone.clone();
            let rname = region_name.clone();
            let account_id = acct.account_id.clone();
            let rdir = rdir.clone();
            let timestamp = timestamp.clone();
            let tx = tx.clone();
            join_set.spawn(async move {
                let _permit = sem.acquire_owned().await.expect("semaphore closed");
                run_tui_json_collector(
                    &collector,
                    &params,
                    &rname,
                    &account_id,
                    &rdir,
                    &timestamp,
                    &tx,
                    collector_timeout,
                )
                .await
            });
        }

        while let Some(res) = join_set.join_next().await {
            match res {
                Ok((w, o)) => {
                    all_written_files.extend(w);
                    acct_outcomes.extend(o);
                }
                Err(e) => {
                    eprintln!("  ERROR: collector task panicked: {e}");
                }
            }
        }
    }
}
```

> **Regions still run sequentially** — `RegionStarted` progress events and per-region output directory creation happen one region at a time. This is intentional; parallelizing across regions can be done in a separate pass if needed.

- [ ] **Step 2: Build**

```bash
cd /Users/austin-songer/code/grabber && cargo check 2>&1 | tail -20
```

Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add src/main.rs
git commit -m "feat(runner): parallelize per-region collector execution in multi-region mode"
```

---

## Task 7: Verify `CollectParams` implements `Clone`

The parallel spawns clone `params_clone` per task. `CollectParams` must implement `Clone`.

**Files:**
- Verify/modify: `src/evidence.rs`

- [ ] **Step 1: Check if `CollectParams` derives `Clone`**

```bash
grep -n "CollectParams\|derive.*Clone" /Users/austin-songer/code/grabber/src/evidence.rs | head -10
```

Expected: `#[derive(..., Clone, ...)]` on `CollectParams`. If missing:

- [ ] **Step 2: Add `Clone` to `CollectParams` if missing**

In `src/evidence.rs`, find the `CollectParams` struct definition and add `Clone`:

```rust
#[derive(Debug, Clone)]
pub struct CollectParams {
    pub start_time: chrono::DateTime<chrono::Utc>,
    pub end_time: chrono::DateTime<chrono::Utc>,
    pub filter: Option<String>,
    pub include_raw: bool,
}
```

- [ ] **Step 3: Build**

```bash
cd /Users/austin-songer/code/grabber && cargo check 2>&1 | tail -5
```

- [ ] **Step 4: Commit if changed**

```bash
git add src/evidence.rs
git commit -m "fix(evidence): derive Clone for CollectParams (required for parallel spawns)"
```

---

## Task 8: End-to-end validation

- [ ] **Step 1: Full build in release mode**

```bash
cd /Users/austin-songer/code/grabber && cargo build --release 2>&1 | tail -10
```

Expected: clean build.

- [ ] **Step 2: Run existing tests**

```bash
cd /Users/austin-songer/code/grabber && cargo test 2>&1 | tail -20
```

Expected: all tests pass.

- [ ] **Step 3: Manual smoke test — TUI single-region**

Launch the TUI with a real AWS profile, pick a small set of collectors (e.g. 5-10), run, and verify:
- Running screen shows multiple collectors transitioning from Waiting → Running simultaneously (previously only one was Running at a time)
- Output files are written correctly with no corruption
- Run manifest records correct outcomes

- [ ] **Step 4: Manual smoke test — TUI multi-region**

In SetOptions, select 2-3 explicit regions. Run, and verify:
- Within each region, multiple collectors transition concurrently
- Output files appear in correct region subdirectories

- [ ] **Step 5: Verify concurrency config override**

Add to `config.toml`:
```toml
[defaults]
collector_concurrency = 3
```

Re-run and confirm at most 3 collectors appear in Running state simultaneously in the TUI.

- [ ] **Step 6: Final commit**

```bash
git add -A
git commit -m "feat: parallel collector execution with configurable concurrency limit (default 8)"
```

---

## Self-Review Checklist

**Spec coverage:**
- ✅ Single-region: collectors run concurrently — Task 5
- ✅ Multi-region: within each region, collectors run concurrently — Task 6
- ✅ Configurable concurrency limit (default 8) — Tasks 1-2
- ✅ Error handling per collector unchanged — Tasks 3-4 (same error paths, now return instead of mutate)
- ✅ Progress reporting preserved — `tx.send(Progress::Started/Done/Error)` unchanged per collector
- ✅ Thread-safe file writes — each collector writes to a unique filename (no shared mutable state)
- ✅ Timeout mechanisms respected — `collector_timeout` passed through identically
- ✅ Audit log outcomes collected — `acct_outcomes.extend(o)` after join
- ✅ Memory: `Semaphore` caps active goroutines, so peak memory is bounded by `concurrency` concurrent collectors

**Placeholder scan:** None found — all code blocks are complete.

**Type consistency:**
- `run_tui_csv_collector` takes `&Box<dyn CsvCollector>` in Tasks 3 and 5 ✅
- `run_tui_inv_collector` takes `&Box<dyn JsonCollector>` in Tasks 3 and 6 ✅
- `run_tui_json_collector` takes `&Box<dyn EvidenceCollector>` in Tasks 3 and 5-6 ✅
- Return type `(Vec<String>, Vec<audit_log::CollectorOutcome>)` consistent across Tasks 3-6 ✅
- `concurrency: usize` threaded from Task 1 → Task 2 → Tasks 5-6 ✅
