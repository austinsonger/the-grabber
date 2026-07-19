# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

The Grabber (binary name `grabber`) is a Rust CLI/TUI that collects compliance evidence and asset inventory from AWS, Okta, Jira, and Tenable, writing CSV/JSON evidence, FedRAMP-aligned inventory (XLSX), and OSCAL POA&M documents. It has three entry modes from one binary: an interactive `ratatui` wizard (default, no args), a flag-driven non-interactive CLI (`--start-date`/`--lookback`), and dedicated `--inventory`/`--poam` workflows.

## Build & test commands

```bash
cargo check                       # fast compile check
cargo build --release             # release binary → target/release/grabber
cargo run -- [args]               # run with no args for the TUI
cargo clippy -- -D warnings       # must be clean before committing
cargo fmt                         # required formatting

cargo test                        # workspace tests (root crate + crates/*)
cargo test <test_name>            # single test
cargo test <module_name>::        # all tests in a module
cargo test <test_name> -- --nocapture
```

Default features are `tenable`, `okta`, `jira` (all compiled in by default). `azure` and `gcp` are optional and must be built explicitly:

```bash
cargo build --features azure,gcp
cargo build --no-default-features --features tenable   # narrow the build down
```

The workspace also contains three standalone API-client crates consumed as path dependencies: `crates/tenable-rs`, `crates/okta-rs`, `crates/jira-rs`. `okta-rs` has its own `tests/` directory — run those with `cargo test -p okta-rs`.

## Architecture

### Provider trait system (`src/providers/`)

Every data source is a **provider** (`CloudProvider::{Aws,Azure,Gcp,Tenable,Okta,Jira}`) implementing `ProviderFactory` (`src/providers/mod.rs`). A factory exposes three collector kinds, each with its own trait in `src/evidence.rs`:

- `CsvCollector` — point-in-time snapshots (IAM, EC2, S3 state, etc.), written as CSV.
- `JsonCollector` — structured/nested snapshots (policy docs, configs), written as JSON.
- `EvidenceCollector` — time-windowed data (CloudTrail events, findings), takes a date range.

Each provider lives under `src/providers/<provider>/`, one file per collector/service, wired together in that provider's `factory.rs`. Non-AWS providers (`azure`, `gcp`, `tenable`, `okta`, `jira`) are gated behind Cargo features and `#[cfg(feature = "...")]` in `src/providers/mod.rs`.

**Adding a collector**: create `src/providers/<provider>/<name>.rs` implementing the relevant trait, declare it in `<provider>/mod.rs`, and register its selector key in `<provider>/factory.rs`. `main.rs` never needs to change for this.

Every collector's `fedramp_mapping()` defaults to a lookup by `filename_prefix()` in the bundled table (`src/fedramp_map.rs`, sourced from `assets/fedramp-map.json`) — this is what drives `src/fedramp_coverage.rs` and the FedRAMP control annotations embedded in output files.

### Orchestration (`src/runner/`)

- `collector_registry.rs` — maps selector keys to `ProviderFactory`-produced collectors and resolves account-level `enable`/`disable`/`enable_extra` config overrides.
- `collect_ops.rs` — runs collectors concurrently with per-collector timeouts (3 min) and classifies outcomes (`failure_classifier.rs` distinguishes hard errors from benign "skipped" states like missing permissions or disabled services).
- `multi_account.rs` / `multi_region_cli.rs` — iterate accounts from `config.toml` and, for AWS, round-robin regions.
- `output.rs` — filename conventions (`{AccountName}_{Collector}-{timestamp}.{csv,json}`), the append-only chain-of-custody log, and the `RUN-MANIFEST-*.json` writer.
- `cli_runners.rs` vs `tui_runners.rs` — the same collection pipeline driven from the flag-based CLI path and the TUI path respectively; `tui_session.rs` is the TUI entry point from `main.rs`.

### TUI wizard (`src/tui/`)

`ratatui` + `crossterm`, driven by a single `Screen` enum (`src/tui/state.rs`) and an `App` struct (`src/tui/app/mod.rs`, split across `mod.rs`/`methods.rs`/`nav.rs`). The wizard is a linear state machine — adding or reordering a step touches **all** of the following, or the screen will render but never be reachable/navigable:

1. **`src/tui/state.rs`** — add the `Screen` variant (and any new state fields it needs, e.g. `TextInput`/`HashSet` selection state, on `App` in `app/mod.rs`).
2. **`src/tui/app/nav.rs`** — wire `next_screen()`/`prev_screen()` transitions to and from the new screen (transitions branch on `Feature` and `CloudProvider`, so a new provider-specific step usually needs a match arm per relevant provider too).
3. **`src/tui/events.rs`** — add a `handle_<screen>(app, key)` function and dispatch to it from the screen match in `event_loop`.
4. **`src/tui/ui/mod.rs`** — dispatch `Screen::NewScreen => some_module::draw_new_screen(f, content, app)` in `draw()`, plus the actual render function in a `src/tui/ui/*.rs` module (existing ones: `setup.rs`, `account_screens.rs`, `collectors.rs`, `scan_selection.rs`, `jira_project_selection.rs`, `poam_screens.rs`, `options.rs`, `confirm.rs`, `running.rs`, `results.rs`).
5. **`src/tui/ui/frame.rs`** — update the step indicator (`STEPS_*` arrays, `screen_to_step`) and footer hints (`get_hints`) so the new screen shows correct progress/keybindings.
6. If the screen is provider-specific (like `TenableEndpoint`, `ScanSelection`, `JiraProjectSelection`), also check `src/tui/menus/<provider>.rs` (per-provider collector category/menu data) and whether `has_accounts()`-style branching in `nav.rs`/`ui/mod.rs` needs a new case.

When a plan touches the TUI, treat these six as one atomic unit of work — a plan that only adds a `Screen` variant or only adds a render function is incomplete.

`src/tui/menus/` holds per-provider collector menu structures (categories + selector/display pairs) kept deliberately separate per provider so AWS's ~144-collector category tree doesn't bleed into Okta/Jira/Tenable's much smaller menus. `src/tui/collector_data.rs` holds shared static data (e.g. `AWS_REGIONS`).

### POA&M (`src/poam/`)

Reconciles evidence findings (ECR/Inspector CSVs, Tenable vulnerability/compliance CSVs) into either the legacy `FedRAMP-POAM.xlsx` workbook (`workbook.rs`) or an OSCAL POA&M JSON document (`oscal/`, validated against `assets/oscal_poam_schema.v1.1.2.json`). `reconcile.rs` / `oscal/reconcile.rs` dedup findings by freshness (prefer the newest observation) — this is the pattern to follow if you add another finding source. Custom (manually-added) POA&M items go through `oscal/custom_item.rs` and are addressable/removable by UUID via the CLI (`--poam-add-item`, `--poam-remove-item`).

### Config & app entry (`src/app_config.rs`, `src/cli.rs`, `src/main.rs`)

`config.toml` (see `config.example.toml`) drives the account picker: `[[account]]` blocks plus global `[defaults]` and per-account `[account.collectors]` overrides, resolved with the `enable` (exclusive) → `disable`/`enable_extra` (additive) precedence described in `README.md`. Sibling `*-config.toml` files (`tenable-config.toml`, `okta-config.toml`, `jira-config.toml`) configure those providers independently and are loaded by their own provider modules.

`main.rs` dispatches on `Cli` flags (clap) into one of four paths: verify-only (`--verify-manifest`), inventory CLI, POA&M CLI, or TUI/standard-CLI (chosen by whether `--start-date`/`--lookback` is present). Keep `main.rs` a thin dispatcher — real logic belongs in `src/runner/` or the feature-specific module.

### Output artifacts

Evidence runs can optionally emit (all opt-in via CLI flags or config): `RUN-MANIFEST-<run_id>.json` (per-collector outcome/count/size), `CHAIN-OF-CUSTODY-<run_id>.json` + append-only `CHAIN-OF-CUSTODY.jsonl` (`src/audit_log.rs`), a bundled `Evidence-<timestamp>.zip` (`src/zip_bundle.rs`), and an HMAC-SHA256 `SIGNING-MANIFEST-*.json` + key (`src/signing.rs`, also independently verifiable via `--verify-manifest`).

## Code conventions (from AGENTS.md)

- Errors: `anyhow::Result` / `anyhow::Context` everywhere; never `unwrap()`/`expect()` in production code; use `anyhow::bail!` for early exits.
- Async: `tokio`; wrap CPU-bound/blocking work (zip compression, heavy parsing) in `tokio::task::spawn_blocking`.
- AWS SDK: use the official `aws-sdk-*`/`aws-config` crates directly, inject `&aws_config::SdkConfig` rather than constructing clients inside collectors, and always paginate via `.into_paginator().items().send()`.
- Imports grouped std → external crates → `crate::*`, blank line between groups.
- Structs mirroring AWS resources/config derive `Debug, Clone, Serialize, Deserialize`.

## Planning docs

Feature plans live in `docs/plans/`, named `YYYY-MM-DD-<slug>.md`. These capture intent only — do not start implementing from one without explicit confirmation.
