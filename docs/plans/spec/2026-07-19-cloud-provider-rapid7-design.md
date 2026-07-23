# Cloud Provider: Rapid7 — Design

**Status:** Approved by user 2026-07-19, ready for implementation planning.

## Goal

Add Rapid7 as a new `CloudProvider` in the-grabber, spanning all three Rapid7 products the org uses:

1. **InsightVM — cloud (Insight Platform / "Command Platform")**
2. **InsightVM — on-prem Security Console (Nexpose REST API v3)**
3. **InsightCloudSec** (cloud security posture management / misconfiguration findings)

For each product: collect vulnerability/finding data (mapped into OSCAL POA&M, matching the existing Tenable pipeline) and asset/resource inventory (raw evidence only, not POA&M-mapped — matching Tenable's `assets.rs`/`pci_asv.rs`/`was.rs`).

## Non-goals

- No new CLI flags. POA&M mapping activates automatically when `--poam-format oscal|both` is used and Rapid7 CSVs are present, exactly like Tenable today.
- No changes to the XLSX/workbook POA&M path (`src/poam/reconcile.rs`/`workbook.rs`) — Rapid7 only feeds the OSCAL path, same as Tenable.
- No live-account integration testing in this repo (no committed credentials); all tests use inline fixtures / `wiremock`.

## Terminology

Single `CloudProvider::Rapid7` enum variant, even though it spans three products — mirrors how Tenable is one `CloudProvider` variant despite not being an infrastructure cloud. "Cloud Provider" in this codebase means "a system a collector belongs to," not literally IaaS.

## Architecture

- New SDK crate `crates/rapid7-rs`, added to the workspace, gated by a new Cargo feature `rapid7 = ["dep:rapid7-rs"]` added to `default = [...]` in the root `Cargo.toml`, alongside `tenable`/`okta`/`jira`.
- Inside `rapid7-rs`, three independent client modules — the three products have unrelated auth models and wire formats, so one shared client would be a false abstraction:
  - `platform` — InsightVM cloud, Bulk Export GraphQL API
  - `console` — InsightVM on-prem Security Console, REST v3 + Basic Auth
  - `cloudsec` — InsightCloudSec, REST v2/v3 + `Api-Key` header
- `src/providers/rapid7/` — six `CsvCollector` implementations (see table below), plus `factory.rs` implementing `ProviderFactory` (`Rapid7ProviderFactory`), following `src/providers/tenable/factory.rs` structurally.
- `src/providers/mod.rs` — add `Rapid7` variant to the `CloudProvider` enum, register the `pub mod rapid7` behind `#[cfg(feature = "rapid7")]`.
- No `EvidenceSource` changes needed: that enum is only constructed by `EvidenceCollector` impls (time-windowed evidence, e.g. AWS CloudTrail/Backup/RDS). Tenable's collectors — and Rapid7's, following the same shape — implement `CsvCollector` instead, which never touches `EvidenceSource`; each collector's `filename_prefix()` is a plain `&str` (verified: the existing `EvidenceSource::Tenable*` variants are unused dead code, confirmed via grep).

## Credentials & config

One `Account` entry (`provider = "rapid7"`) may carry any subset of three independent credential groups. Only collectors whose credential group is fully populated get built by the factory — this lets an org configure just InsightVM, just InsightCloudSec, or any combination, on one account entry.

New fields on `Account` (`src/app_config.rs`), each with an env-var-wins-over-TOML resolver method matching the existing `tenable_*_resolved()` pattern:

```rust
// InsightVM Platform (cloud, Bulk Export API)
pub rapid7_platform_api_key: Option<String>,   // env: RAPID7_PLATFORM_API_KEY
pub rapid7_platform_region: Option<String>,    // env: RAPID7_PLATFORM_REGION, default "us"
                                                // valid: us, us2, us3, eu, ca, au, ap

// Security Console (on-prem, REST v3, Basic Auth)
pub rapid7_console_url: Option<String>,        // env: RAPID7_CONSOLE_URL, e.g. "https://console.internal:3780"
pub rapid7_console_username: Option<String>,   // env: RAPID7_CONSOLE_USERNAME
pub rapid7_console_password: Option<String>,   // env: RAPID7_CONSOLE_PASSWORD
pub rapid7_console_insecure_tls: Option<bool>, // env: RAPID7_CONSOLE_INSECURE_TLS, default false
                                                // when true, log a loud warning and build the
                                                // reqwest client with .danger_accept_invalid_certs(true)

// InsightCloudSec (Api-Key header)
pub rapid7_cloudsec_url: Option<String>,       // env: RAPID7_CLOUDSEC_URL, default "https://cloudsec.insight.rapid7.com"
pub rapid7_cloudsec_api_key: Option<String>,   // env: RAPID7_CLOUDSEC_API_KEY
```

`rapid7-config.example.toml` added at repo root (mirrors `tenable-config.example.toml`); `load_config()` gains a `rapid7-config.toml` merge block, mirroring the Tenable/Okta/Jira blocks in `src/app_config.rs`.

## Collectors & data flow

| File (`src/providers/rapid7/`) | Product | Retrieval | `filename_prefix()` | POA&M-mapped? |
|---|---|---|---|---|
| `insightvm_vulnerabilities.rs` | InsightVM cloud | Bulk Export: `createVulnerabilityExport` GraphQL mutation at `/export/graphql` → poll `export(id)` until `status: SUCCEEDED` → download Parquet (`asset_vulnerability` export type, URLs expire in 15 min) → parse rows via `parquet`/`arrow` crates | `Rapid7_InsightVM_Vulnerability_Findings` | Yes |
| `insightvm_assets.rs` | InsightVM cloud | Same Bulk Export mechanism, `asset` export type | `Rapid7_InsightVM_Assets` | No |
| `console_vulnerabilities.rs` | Security Console | `GET /api/3/assets/{id}/vulnerabilities` (per-asset findings) joined with `GET /api/3/vulnerabilities/{id}` (full CVE/CVSS/severity definitions), paged via `page`/`size` query params (max size 500), envelope `{resources, page, links}` | `Rapid7_Console_Vulnerability_Findings` | Yes |
| `console_assets.rs` | Security Console | `GET /api/3/assets`, same paging envelope | `Rapid7_Console_Assets` | No |
| `cloudsec_findings.rs` | InsightCloudSec | `GET /v2/public/insights/list` ("Insights" = check definitions; findings = matches), cursor-paginated | `Rapid7_InsightCloudSec_Findings` | Yes |
| `cloudsec_resources.rs` | InsightCloudSec | `POST /v3/public/resource/etl-query`, cursor-paginated | `Rapid7_InsightCloudSec_Resources` | No |

Each collector returns `Vec<Vec<String>>` rows matching its declared `headers()`, per the existing `CsvCollector` trait (`src/evidence.rs`). `Rapid7ProviderFactory::csv_collectors()` matches selected collector keys AND checks the relevant credential group is populated before instantiating each collector — an account with only InsightCloudSec creds configured only ever offers the two `cloudsec_*` collectors, regardless of which keys are nominally selected.

**Filename convention:** `{account_id}_{prefix}-{timestamp}.csv`, matching `evidence_basename()` in `src/runner/output.rs` — this is what the POA&M-side CSV marker matching relies on (see below).

**Error isolation:** collectors return `anyhow::Result<Vec<Vec<String>>>`; a failed collector (e.g. a Bulk Export that times out or reports `FAILED`) surfaces as an error for that collector only and does not abort the run, matching the runner's existing per-collector error capture.

**Rate limiting:** InsightVM Platform / Bulk Export responses include `RateLimit-Limit`/`RateLimit-Remaining`/`RateLimit-Reset` headers (Command Platform-wide behavior); the `platform` client retries 429s honoring `RateLimit-Reset`, mirroring `TenableClient`'s existing 429/`Retry-After` exponential-backoff pattern (`crates/tenable-rs/src/client.rs`). Security Console and InsightCloudSec have no documented numeric rate limits; the plan still adds conservative retry-on-429/503 with backoff as a defensive default.

## POA&M mapping (the three vulnerability/finding collectors only)

`src/poam/rapid7_csv_reader.rs` — three row structs (`Rapid7InsightVmVulnRow`, `Rapid7ConsoleVulnRow`, `Rapid7CloudSecFindingRow`) + `select_latest_rapid7_*_csv`/`read_rapid7_*_csv` functions, reusing the existing `select_latest_csv_by_marker(dir, marker)` helper (`src/poam/csv_reader.rs`) with markers `"_Rapid7_InsightVM_Vulnerability_Findings-"`, `"_Rapid7_Console_Vulnerability_Findings-"`, `"_Rapid7_InsightCloudSec_Findings-"`.

`src/poam/oscal/rapid7_build.rs` — three builders, matching the exact signature shape already established by `build_tenable_vuln_triple`:

```rust
pub(in crate::poam) fn build_rapid7_insightvm_vuln_triple(row: &Rapid7InsightVmVulnRow, now: &str) -> (Observation, Risk, PoamItem)
pub(in crate::poam) fn build_rapid7_console_vuln_triple(row: &Rapid7ConsoleVulnRow, now: &str) -> (Observation, Risk, PoamItem)
pub(in crate::poam) fn build_rapid7_cloudsec_finding_triple(row: &Rapid7CloudSecFindingRow, now: &str) -> (Observation, Risk, PoamItem)
```

Each sets `PoamItem` props: `weakness-source-identifier` = row's stable key, `finding-source` = `"Rapid7 InsightVM"` / `"Rapid7 Security Console"` / `"Rapid7 InsightCloudSec"`, `finding-type` = `"vulnerability"` (InsightVM/Console) or `"compliance-check"` (CloudSec, matching Tenable compliance's use of that label). Each product maps its own remediation-status vocabulary to `RiskStatus::Open`/`Closed` via a dedicated `map_rapid7_*_status` function, mirroring `map_tenable_vuln_state`/`map_tenable_compliance_status`.

Dedup-by-freshness helpers added to `src/poam/mod.rs` for all three row types, following the exact `dedupe_tenable_vulns_by_stable_key` shape (HashMap keyed by stable key, `is_newer_by_field` comparing each product's freshest timestamp field). Wired into `run_poam_with_paths` alongside the existing Inspector2 + Tenable calls — all sources remain optional/tolerant-of-absence, and a missing Rapid7 CSV is not an error.

Reconciliation (`oscal::reconcile_document`) requires no changes — it already keys on the `weakness-source-identifier` prop generically, regardless of source.

## TUI wiring

- `src/tui/menus/mod.rs` — add a Rapid7 entry to `PROVIDER_MENUS`, with menu items for the six collector keys (`rapid7-insightvm-vulns`, `rapid7-insightvm-assets`, `rapid7-console-vulns`, `rapid7-console-assets`, `rapid7-cloudsec-findings`, `rapid7-cloudsec-resources`), grouped/labeled by product in the menu display.
- `src/runner/tui_session.rs` — account-preparation block that builds up to three separate clients (`platform::Client`, `console::Client`, `cloudsec::Client`) depending on which credential group is populated on the selected account, following the existing Tenable account-prep block (lines 660-719) as the structural template.
- `src/tui/app/` default collector keys — no Rapid7 keys in the default set (matching how Tenable/Okta collector keys aren't force-selected by default either); the user opts in via the menu.

## Testing

No committed fixture files — inline CSV/JSON/Parquet-bytes literals in `#[cfg(test)]` modules colocated with each reader/mapper, following the exact pattern in `src/poam/tenable_csv_reader.rs` and `src/poam/oscal/tenable_build.rs`.

`rapid7-rs` client tests use `wiremock = "0.6"` (already a dev-dependency in `tenable-rs`/`okta-rs` — same crate, same pattern) to mock:
- `platform`: the GraphQL export-create + poll + Parquet-download sequence (including a `FAILED`-status and a timeout case)
- `console`: paginated `/api/3/assets` and `/api/3/vulnerabilities/{id}` responses, plus a 401 (bad Basic Auth) case
- `cloudsec`: paginated `/v2/public/insights/list` and `/v3/public/resource/etl-query` responses

End-to-end POA&M tests mirror `run_poam_with_oscal_format_includes_tenable_findings_when_present` (`src/poam/mod.rs`): write synthetic Inspector2 + Rapid7 CSVs into a `tempfile::tempdir()`, run `run_poam_with_paths`, assert the OSCAL document contains items with the expected `finding-source` values and no duplicate/missing findings after a second reconcile pass.

## Documentation

- `README.md` — new `## Rapid7` section (feature flag note, config TOML example for all three credential groups, env var list, collectors table), following the existing `## Tenable` section as template.
- `evidence-list.md` — six new `EV###` rows for the Rapid7 collectors.
- `cli-examples.md` — a `## Rapid7` section with example commands, following the existing `## Tenable` section.
- `docs/plans/multi-provider-refactor.md` — add a Rapid7 row to the provider comparison table.

## Open assumptions requiring a verification task early in the implementation plan

Research against Rapid7's official docs (2026-07) left two points unconfirmed and flagged for a live/interactive-docs check before the corresponding client code is finalized — the plan should include an explicit early task for each:

1. **InsightCloudSec auth header name.** Official Rapid7 docs say `Api-Key`; one third-party integration guide says `X-Api-Key`. Plan defaults to `Api-Key` (first-party source) but flags a verification task.
2. **Security Console v3 exact vulnerability/asset JSON field names.** The OpenAPI spec (`console-swagger.json`, official, on GitHub under `rapid7/vm-console-client-python`) is confirmed to exist and is authoritative, but was too large to fully extract during design research. Implementation should fetch and parse this spec directly rather than guess field names.

The InsightVM Bulk Export API and the Security Console's base URL/auth/pagination envelope are confirmed with high confidence from official sources and need no such verification step.
