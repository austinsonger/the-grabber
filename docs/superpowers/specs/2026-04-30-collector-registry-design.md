# Collector Registry Design

**Date:** 2026-04-30  
**Status:** Approved

## Problem

`main.rs` is 3,906 lines. The three `build_*` functions (`build_csv_collectors`, `build_json_inv_collectors`, `build_json_collectors`) contain ~400 lines of `if has("key") { v.push(...) }` blocks covering ~115 collectors. A separate `GLOBAL_COLLECTOR_KEYS` constant (~28 entries) tracks which collectors run globally vs. per-region. Adding a new collector requires touching `main.rs` in three places: the `mod` declaration, a `use` import, and an `if has(...)` block in the appropriate build function.

## Goal

Adding a new collector = one new `.rs` file + one `mod` line in `main.rs`. The build functions need zero changes.

## Out of Scope

- `CloudTrailS3Collector` — requires runtime CLI args (`bucket`, `prefix`, `account_ids`, `regions`); stays in `build_s3_collector_from_cli`
- `InventoryCollector` — requires a `inventory_types` parameter; built separately
- All three collector trait definitions in `evidence.rs` — unchanged
- All `mod` declarations in `main.rs` — Rust requires them; unavoidable

## Approach: `inventory` crate distributed registration

Add `inventory = "0.3"` to `Cargo.toml`. Each collector registers itself at link time via `inventory::submit!`. The build functions iterate the registry at runtime.

## New Types — `src/registry.rs`

```rust
use aws_config::SdkConfig;
use crate::evidence::{CsvCollector, EvidenceCollector, JsonCollector};

#[derive(Copy, Clone)]
pub enum CollectorFactory {
    Csv(fn(&SdkConfig) -> Box<dyn CsvCollector>),
    JsonInv(fn(&SdkConfig) -> Box<dyn JsonCollector>),
    Evidence(fn(&SdkConfig) -> Box<dyn EvidenceCollector>),
}

pub struct CollectorEntry {
    pub key: &'static str,
    pub is_global: bool,
    pub factory: CollectorFactory,
}

inventory::collect!(CollectorEntry);
```

`CollectorFactory` derives `Copy` + `Clone` because `fn` pointers are `Copy`. This is required: `inventory::iter` yields `&'static CollectorEntry` references, so `e.factory` must be copyable to use in a `match` without moving out of the reference.

`is_global: true` replaces the `GLOBAL_COLLECTOR_KEYS` constant. The two callsites that previously used `GLOBAL_COLLECTOR_KEYS.contains(k)` become an `inventory::iter` lookup.

## Registration Pattern

Each collector `.rs` file adds one `inventory::submit!` block per collector type it defines:

```rust
// bottom of src/apigateway.rs
inventory::submit! {
    crate::registry::CollectorEntry {
        key: "api-gateway",
        is_global: false,
        factory: crate::registry::CollectorFactory::Csv(
            |cfg| Box::new(ApiGatewayCollector::new(cfg))
        ),
    }
}
```

Files that define multiple collectors (e.g. `account_config.rs` defines `AccountContactsCollector`, `IamAccountSummaryCollector`, `SamlProviderCollector`) get one `inventory::submit!` block per type.

## Updated Build Functions

```rust
fn build_csv_collectors(names: &[&str], config: &SdkConfig) -> Vec<Box<dyn CsvCollector>> {
    inventory::iter::<CollectorEntry>()
        .filter(|e| names.contains(&e.key))
        .filter_map(|e| match e.factory {
            CollectorFactory::Csv(f) => Some(f(config)),
            _ => None,
        })
        .collect()
}

fn build_json_inv_collectors(names: &[&str], config: &SdkConfig) -> Vec<Box<dyn JsonCollector>> {
    inventory::iter::<CollectorEntry>()
        .filter(|e| names.contains(&e.key))
        .filter_map(|e| match e.factory {
            CollectorFactory::JsonInv(f) => Some(f(config)),
            _ => None,
        })
        .collect()
}

fn build_json_collectors(names: &[&str], config: &SdkConfig) -> Vec<Box<dyn EvidenceCollector>> {
    inventory::iter::<CollectorEntry>()
        .filter(|e| names.contains(&e.key))
        .filter_map(|e| match e.factory {
            CollectorFactory::Evidence(f) => Some(f(config)),
            _ => None,
        })
        .collect()
}
```

## GLOBAL_COLLECTOR_KEYS Replacement

The two callsites in `main.rs` that filter collector keys by global/regional:

```rust
// was: .filter(|k| GLOBAL_COLLECTOR_KEYS.contains(k))
.filter(|k| {
    inventory::iter::<CollectorEntry>()
        .find(|e| &e.key == k)
        .map_or(false, |e| e.is_global)
})
```

After migration, `const GLOBAL_COLLECTOR_KEYS` is deleted entirely.

## Migration Steps

Execute in one pass to avoid a broken intermediate state:

1. Add `inventory = "0.3"` to `Cargo.toml`
2. Create `src/registry.rs` with `CollectorEntry`, `CollectorFactory`, `inventory::collect!`
3. Add `mod registry;` to `main.rs`
4. Add `inventory::submit!` blocks to all 80+ collector `.rs` files
5. Replace the three `build_*` functions with the iterator versions above
6. Replace both `GLOBAL_COLLECTOR_KEYS` callsites with `inventory::iter` lookups
7. Delete `const GLOBAL_COLLECTOR_KEYS`
8. Delete the ~115 `use crate::xyz::XyzCollector` imports from `main.rs`

## Verification

After migration, confirm every previously-registered key has a corresponding `inventory::submit!`:

```bash
# count of submit! blocks across all collector files (excluding registry.rs)
grep -r 'inventory::submit!' src/ --include='*.rs' | grep -v registry.rs | wc -l
```

This count must match the total number of `if has(...)` lines that existed across the three old build functions.

## Risks

| Risk | Mitigation |
|------|-----------|
| Key registered under wrong `CollectorFactory` variant — compiles but silently drops output | Verification grep; manual smoke test of affected collector after migration |
| Registration order is non-deterministic | Build functions don't depend on order; no impact |
| `inventory` linker-section mechanism on non-standard targets | `inventory 0.3` is widely used and tested on all major Rust targets including macOS, Linux, and musl |

## Expected Impact on `main.rs`

| Before | After |
|--------|-------|
| ~115 `use crate::xyz::XyzCollector` imports | 0 (moved to each collector file) |
| ~400 lines in three `build_*` functions | ~21 lines (3 × 7-line functions) |
| 28-entry `GLOBAL_COLLECTOR_KEYS` constant | Deleted |
| **~545 lines removed** | |
