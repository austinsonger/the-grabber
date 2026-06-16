# `refractor` vs `main` — functional differences

Snapshot of what the `refractor` branch does that `main` does not (and vice versa). 95 commits ahead of `main`; 271 files touched (+36,470 / −17,700).

## Headline

`main` is an AWS-only evidence collector with a flat `src/` layout. `refractor` rewrites it as a **multi-provider** collector — AWS plus Tenable, Okta, and Jira — with a `providers/` module tree and three sibling Rust crates under `crates/`. The TUI gains a provider-selection step and provider-specific sub-flows (Tenable scan picker, Jira project picker).

## New providers

### Tenable (`--features tenable`, on by default)

- New workspace crate [crates/tenable-rs](crates/tenable-rs/) — HTTP client (SigV4-style retry on 429, exponential backoff up to 5×, parallel export-chunk downloads), with API modules for `assets`, `audit_log`, `compliance`, `scans`, `users`, `vulns`, and WAS (Web App Scanning).
- Collectors: vulnerabilities, assets, compliance, audit log, users + scanner permissions, WAS findings, PCI ASV.
- Endpoint switch: commercial (`cloud.tenable.com`) vs FedRAMP (`fedcloud.tenable.com`).
- TUI gains a `Screen::ScanSelection` step that lists VM + WAS scans, filterable by Recent / Past 12 months / All time. Selected VM scan IDs and WAS UUIDs flow into the collectors as scope filters.

### Okta (`--features okta`, on by default)

- New workspace crate [crates/okta-rs](crates/okta-rs/) — SSWS-auth HTTP client with Link-header pagination and 429 retry.
- Collectors emit CSV only (originally json/evidence collectors; converted in `9843c6d`): `okta-users`, `okta-groups`, `okta-group-members`, `okta-apps`, `okta-policies`, `okta-factors`, `okta-system-log` (time-windowed by global date range).
- Config via `okta-config.toml` or `OKTA_DOMAIN` / `OKTA_API_TOKEN` env.

### Jira (`--features jira`, on by default)

- New workspace crate [crates/jira-rs](crates/jira-rs/) — Basic-auth (email + token) client with 429 retry.
- Collectors: `jira-projects`, `jira-issues`.
- TUI gains `Screen::JiraProjectSelection` — when Issues is selected, a project picker (multi-select) appears after the collector screen; the chosen project keys are folded into the JQL alongside the global timeframe.
- Config via `jira-config.toml` or `JIRA_DOMAIN` / `JIRA_EMAIL` / `JIRA_API_TOKEN` env.

## Other providers in progress

### Azure (`--features azure`, scaffolded)

- Current status: framework-only. `src/providers/azure/` exists with `mod.rs` + `factory.rs`, but no Azure collectors are shipping yet.
- What is already wired: provider enum + dispatch path (`CloudProvider::Azure`), feature gating, and account/region plumbing in `AzureProviderFactory`.
- Planned direction: `DefaultAzureCredential`-based auth and service collectors for Activity Log, Defender, Entra ID, Key Vault, Storage, VMs, Policy, NSG, RBAC, SQL, AKS, ACR, App Service, and Monitor Alerts.
- Tracking docs: `docs/plans/azure-services-implementation.md` and `docs/plans/multi-provider-refactor.md`.

### GCP (`--features gcp`, scaffolded)

- Current status: framework-only. `src/providers/gcp/` exists with `mod.rs` + `factory.rs`, but no GCP collectors are shipping yet.
- What is already wired: provider enum + dispatch path (`CloudProvider::Gcp`), feature gating, and project/region plumbing in `GcpProviderFactory`.
- Planned direction: ADC (`google-cloud-auth`) auth and a shared HTTP client, then phased collectors for IAM, Compute, GCS, Cloud Audit Logs, KMS, SCC, Cloud SQL, GKE, Secret Manager, VPC, Cloud DNS, Pub/Sub, and Cloud Monitoring.
- Tracking docs: `docs/plans/gcp-collector-implementation.md` and `docs/plans/multi-provider-refactor.md`.

Today, `main` remains AWS-only and `refractor` has production-ready non-AWS support for Tenable, Okta, and Jira, with Azure/GCP still in implementation.

## AWS additions

New CSV collectors registered on `refractor`:

- ACM Private CA (`acm-pca`)
- Client VPN (`client-vpn`)
- Network Firewall
- Route 53 DNSSEC
- Shield / DDoS
- Service Quotas
- License Manager
- SSM software inventory
- SSM Session Manager logs
- CloudTrail Change Events, CloudTrail S3 Data Events
- Inspector V2 SBOM export

Removed: `ecr-scan` (ECR image scan findings) — taken out in `675d321`.

New SDK crates pulled in: `aws-sdk-acmpca`, `aws-sdk-shield`, `aws-sdk-licensemanager`, `aws-sdk-servicequotas`, `aws-sdk-networkfirewall`.

## TUI rewrite

| Area | `main` | `refractor` |
|------|--------|-------------|
| Layout | Flat `src/tui/ui.rs`, monolithic event loop | Split into `tui/ui/{frame, theme, widgets, account_screens, poam_screens, collectors, scan_selection, jira_project_selection, …}` and `tui/app/{mod, nav, methods}` |
| Provider step | none (AWS implied) | `Screen::ProviderSelection` tile grid; cursor + filtering downstream by provider |
| Account screen | AWS profiles only | Filters by selected provider; auto-selects for Tenable/Okta/Jira |
| Tenable-specific | n/a | `TenableEndpoint` + `ScanSelection` screens; AllTime filter; unified VM + WAS list |
| Jira-specific | n/a | `JiraProjectSelection` screen; pre-fetched project list; multi-select |
| Result panels | Errors only | Adds a *Skipped* panel for benign failures (`59519d3`) |
| Endpoint label | Region-only header | `endpoint_label` field for non-region-scoped providers |
| Search | Search/filter design only | Implemented across the collector list with category jumps |

## Output & integrity changes

- `--write-run-manifest` and `--write-chain-of-custody` are now **opt-in flags** (off by default). On `main` these artifacts were always written.
- Signing manifest, HMAC-SHA256 verification, and `--verify-manifest` flow are unchanged.
- Output directory layout adds per-provider subdirs (`evidence-output/Jira/`, `evidence-output/Okta/`, …).

## Configuration

- `Cargo.toml` becomes a workspace root for the three new crates.
- New feature flags: `tenable`, `okta`, `jira` (all on by default), plus stub features `azure` and `gcp` with optional dependencies wired for future implementation.
- New TOML files: `tenable-config.toml`, `okta-config.toml`, `jira-config.toml` (each example committed; the real file gitignored).
- Env-var fallbacks for all three providers (env wins over TOML).

## Code organization

- Everything under `src/` that used to be flat (`access_analyzer.rs`, `acm.rs`, `cloudtrail*.rs`, `ec2_config.rs`, `ecr.rs`, `iam_inventory.rs`, `inventory_orchestrator.rs`, `poam.rs`, `ssm_patch_detail.rs`, …) moved into `src/providers/aws/`.
- A `ProviderFactory` trait now sits between the runner and provider-specific collectors (`09e0ac9`); each provider has its own `factory.rs`.
- `CloudProvider` enum (`Aws | Tenable | Okta | Jira | Azure | Gcp`) drives provider-aware filtering and dispatch throughout the TUI.

## Docs & planning

- New planning docs under `docs/plans/` and `docs/superpowers/plans/` for Okta, Jira, Tenable performance work, Inspector SBOM export, agentic POA&M sync, and Azure/GCP roadmaps.
- Deleted in this branch: outdated specs for collector registry, SSO precheck, TUI search/filter, parallel collector execution, back-nav, plus the old `wireframe-spec.md` and `poam-tui-option.md`.

## What did **not** change functionally

- The POA&M reconciliation flow (regions/year/month picker + reconciler) carries over with the same UX, just relocated into `tui/ui/poam_screens.rs`.
- The legacy AWS-profile / region picker path still works when no `[[account]]` entries are configured.
- Signing, zipping, and the verify-manifest CLI behavior are unchanged.
- Inventory mode (multi-account AWS asset inventory) is preserved; collectors are re-homed but their outputs are equivalent.
