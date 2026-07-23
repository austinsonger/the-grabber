# ServiceNow Cloud Provider — Design Spec

**Status:** Approved by user 2026-07-19. Ready for implementation planning.

## Goal

Add ServiceNow as a first-class evidence-collection provider in The Grabber, on par with the existing Jira and Okta integrations: a new `CloudProvider::ServiceNow` variant, a `crates/servicenow-rs` API client, a `src/providers/servicenow` module implementing `ProviderFactory`, full TUI/CLI wiring, and both a foundational set of core-ITSM collectors and the full FedRAMP evidence-collector set (mirroring Jira's 26 ticket-evidence collectors).

## Why

ServiceNow is the enterprise alternative to Jira for change management, incident response, and HR/access-approval ticketing — the exact same FedRAMP control surface Jira's 26-collector set already proves (AC-17, AC-20, AC-22, AU-02, AU-06, CA-03, CM-03/06/07/10, CP-02/04/07/10, IR-04/06, MA-04, PS-03/04/05/07/08, SC-07, SI-02/03). Customers running ServiceNow instead of (or alongside) Jira need the same evidence coverage from their actual system of record.

## Reference Patterns to Mirror

- Provider contract: `src/providers/mod.rs` (`CloudProvider` enum, `ProviderFactory` trait)
- API client with token-based auth + retry: `crates/jira-rs/src/client.rs`
- Generic time-windowed ticket query executor: `crates/jira-rs/src/api/jql_sla.rs` (`JqlSlaApi::search` → `SlaIssue` with `duration_hours`, `extra` field bag)
- Base collector (typed, no SLA math): `src/providers/jira/issues.rs`, `src/providers/jira/projects.rs`
- FedRAMP ticket-evidence collector (SLA math): `src/providers/jira/offboarding_sla.rs`
- Provider factory: `src/providers/jira/factory.rs`
- Config merge + env-var resolvers: `src/app_config.rs` (Jira fields + `jira-config.toml` merge block)
- Full "add a new top-level provider" precedent: `docs/plans/2026-06-10-add-okta.md`
- Full "add FedRAMP ticket-evidence collectors to an existing provider" precedent: `docs/plans/2026-07-16-fedramp-jira-collectors.md`
- FedRAMP control mapping table: `assets/fedramp-map.json` (`Jira_*` entries)

## Architecture

### Crate: `crates/servicenow-rs`

Async Rust client for the ServiceNow Table API (`/api/now/table/{table}`).

**Auth:** OAuth 2.0 client-credentials grant. `POST {instance}/oauth_token.do` with form body `grant_type=client_credentials&client_id=...&client_secret=...` returns `{access_token, expires_in, token_type}`. `ServiceNowClient` holds the token behind a `tokio::sync::Mutex<TokenState>` and calls `ensure_token()` before every request, refreshing when within 60s of `expires_at`. This is the one structural difference from Jira's static Basic-auth header — every other request-plumbing detail (429 retry with backoff, pagination) mirrors `JiraClient` exactly.

**Pagination:** `sysparm_limit` / `sysparm_offset` query params (ServiceNow does not use Link headers or Jira's `nextPageToken` — it's classic offset pagination). Loop until a page returns fewer than `sysparm_limit` records.

**Generic query executor — `TableApi::query_sla`:**

```rust
pub struct SlaRecord {
    pub number: String,
    pub short_description: String,
    pub state: String,
    pub opened_at: String,
    pub resolved_at: Option<String>,
    pub duration_hours: Option<f64>,
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl<'c> TableApi<'c> {
    pub async fn query_sla(
        &self,
        table: &str,
        sysparm_query: &str,
        extra_fields: &[&str],
    ) -> Result<Vec<SlaRecord>, ServiceNowError>;
}
```

Mirrors `JqlSlaApi::search` field-for-field: base fields `number, short_description, state, opened_at, resolved_at` (ServiceNow tables extending `task` all have these — `incident`, `change_request`, `problem`, `sc_req_item`), `duration_hours` computed the same way (`resolved_at - opened_at` in hours, `None` if not yet resolved), `extra_fields` projected into a free-form `extra` map the same way. This single executor powers all 26 FedRAMP collectors, parameterized by `(table, sysparm_query, extra_fields)` — same as `jql_sla` powering all 26 Jira collectors.

**Typed foundational APIs** (no SLA math, just list-and-parse): `IncidentsApi`, `ChangeRequestsApi`, `ProblemsApi`, `CatalogRequestsApi`, `CmdbCiApi`, `UsersApi`, `GroupsApi` — each a thin `list_all()` over its table with typed response structs, same shape as `jira-rs`'s `ProjectsApi`/`IssuesApi`.

### Provider wiring

- `CloudProvider::ServiceNow` variant in `src/providers/mod.rs`.
- `src/providers/servicenow/factory.rs` implementing `ProviderFactory`, `account_id()` = instance name, `region()` = "".
- `servicenow-config.toml` (gitignored), merged into `AppConfig.account` at startup like `jira-config.toml`/`okta-config.toml`.
- Env var overrides: `SERVICENOW_INSTANCE_URL`, `SERVICENOW_CLIENT_ID`, `SERVICENOW_CLIENT_SECRET` (env wins over TOML, same resolver pattern as `jira_domain_resolved()`).
- Cargo feature `servicenow` (optional dep, added to `default = [...]` features list like `tenable`/`okta`/`jira`).

### Config shape

```toml
[[account]]
name                     = "ServiceNow"
provider                 = "servicenow"
description              = "ServiceNow production instance"
output_dir               = "./evidence-output/servicenow"
servicenow_instance_url  = "https://acme.service-now.com"
servicenow_client_id     = ""
servicenow_client_secret = ""

# ── FedRAMP category overrides ──────────────────────────────────────────
# Table-query collectors read these categories from config so customers can
# override per tenant. Any keys not set fall back to the defaults shown
# below in the collector code — same pattern as jira-config.toml's
# [project_keys] block.
[servicenow_categories]
security       = "Security"        # sc_req_item category — generic security-review items
change         = "Standard"        # change_request category
hr             = "HR"              # sc_req_item category
hr_offboarding = "HR Offboarding"  # sc_req_item category
hr_transfer    = "HR Transfer"     # sc_req_item category
marketing      = "Content Review"  # sc_req_item category
incident       = "Security Incident" # incident category
```

## Foundational Collectors (7)

Core ITSM tables present in every ServiceNow instance — no dependency on paid add-ons (Security Incident Response, HR Service Delivery, Vulnerability Response). All read-only `list_all()` collectors, no SLA math.

| Key | Type | Table | Columns |
|---|---|---|---|
| `servicenow-incidents` | CSV | `incident` | Number, Short Description, State, Priority, Opened By, Assigned To, Opened At, Resolved At |
| `servicenow-change-requests` | CSV | `change_request` | Number, Short Description, State, Type, Requested By, Assigned To, Opened At, Closed At |
| `servicenow-problems` | CSV | `problem` | Number, Short Description, State, Opened By, Assigned To, Opened At, Resolved At |
| `servicenow-catalog-requests` | CSV | `sc_req_item` | Number, Short Description, State, Requested For, Assigned To, Opened At, Closed At |
| `servicenow-cmdb-ci` | JSON | `cmdb_ci` | full CI records (nested class/attributes, JSON like Jira's `policies.rs`) |
| `servicenow-users` | CSV | `sys_user` | User Name, Email, Active, Department, Manager, Last Login |
| `servicenow-groups` | CSV | `sys_user_group` | Name, Description, Active, Manager |

## FedRAMP Evidence Collectors (26)

Same 26 FedRAMP requirement/control IDs as Jira's set (control coverage is provider-agnostic), re-targeted at ServiceNow tables. Jira's "project + issuetype + labels" JQL filter becomes a ServiceNow `sysparm_query` filtering by `category` (and `state`/`active` where relevant), using the `[servicenow_categories]` config overrides above.

**Table assignment strategy:**
- **IR-\* family** (incident-response workflows) → `incident` table, `category={incident}`
- **CM-\*/SI-02 family** (change-management workflows) → `change_request` table, `category={change}`
- **Everything else** (generic approval/review workflows — access requests, HR notifications, compliance reviews) → `sc_req_item` table, `category=` the relevant `[servicenow_categories]` key. This is the closest ServiceNow analog to Jira's generic "issue with an approver + requested_by + opened_at/closed_at."

**Documented simplification:** ServiceNow's true approval trail lives in `sysapproval_approver` (a separate table, N+1 join per record) and Jira's "first status transition" changelog-diving has no clean ServiceNow equivalent without a second query per record. Rather than build that join, "Approver"/"Reviewer"-style columns read from `assigned_to` (or a configurable custom field, documented per-collector) as a proxy — the same complexity budget Jira spent (most Jira collectors also just read one field off the issue). `duration_hours` still comes from `opened_at`→`resolved_at`/`closed_at`, matching Jira's `created`→`resolved` math exactly. `sysapproval_approver` joins, `task_sla`-based real SLA tracking, and app-specific tables (`sn_si_incident`, `hr_case`) are explicitly out of scope for this plan (see below).

**Full collector table** (filename prefix, table, category key, req/control IDs — identical to the matching `Jira_*` entry in `assets/fedramp-map.json`):

| Collector | `filename_prefix` | Table | Category key | `req_ids` | `control_ids` |
|---|---|---|---|---|---|
| Offboarding SLA | `ServiceNow_Offboarding_SLA` | `sc_req_item` | hr_offboarding | NIST-1043, NIST-1519, NIST-1535 | AC-02h., PS-04a./b./d., PS-07d. |
| Remote Access Approvals | `ServiceNow_Remote_Access_Approvals` | `sc_req_item` | security | NIST-1086 | AC-17b. |
| External System Approvals | `ServiceNow_External_System_Approvals` | `sc_req_item` | security | NIST-1103 | AC-20(01)(a), AC-20(01)(b) |
| Public Content Review | `ServiceNow_Public_Content_Review` | `sc_req_item` | marketing | NIST-1108, NIST-1110, NIST-1111 | AC-22a., AC-22c., AC-22d. |
| Logging Coordination | `ServiceNow_Logging_Coordination` | `sc_req_item` | security | NIST-1133 | AU-02b. |
| Audit Posture Change | `ServiceNow_Audit_Posture_Change` | `sc_req_item` | security | NIST-1144 | AU-06c. |
| ISA Annual Review | `ServiceNow_ISA_Annual_Review` | `sc_req_item` | security | NIST-1181, NIST-1182 | CA-03b., CA-03c. |
| Change Retention | `ServiceNow_Change_Retention` | `change_request` | change | NIST-1215 | CM-03e. |
| Baseline Exceptions | `ServiceNow_Baseline_Exceptions` | `sc_req_item` | security | NIST-1236 | CM-06c. |
| Allowlist Review | `ServiceNow_Allowlist_Review` | `sc_req_item` | security | NIST-1247 | CM-07(05)(c) |
| SW License Review | `ServiceNow_SW_License_Review` | `change_request` | change | NIST-1254 | CM-10a. |
| CP Update Trigger | `ServiceNow_CP_Update_Trigger` | `change_request` | change | NIST-1014 | CP-02e.[01] |
| CP Test POA&M | `ServiceNow_CP_Test_POAM` | `change_request` | change | NIST-1273 | CP-04c. |
| DR Test Results | `ServiceNow_DR_Test_Results` | `change_request` | change | NIST-1282, NIST-1301 | CP-07b.[02], CP-10 |
| IR CP Coordination | `ServiceNow_IR_CP_Coordination` | `incident` | incident | NIST-1367 | IR-04b. |
| IR Lessons Learned Closure | `ServiceNow_IR_Lessons_Learned_Closure` | `incident` | incident | NIST-1369 | IR-04c.[02] |
| IR Severity vs Rigor | `ServiceNow_IR_Severity_vs_Rigor` | `incident` | incident | NIST-1370 | IR-04d. |
| IR External Reporting SLA | `ServiceNow_IR_External_Reporting_SLA` | `incident` | incident | NIST-1385 | IR-06a., IR-06b. |
| Remote Maintenance Approvals | `ServiceNow_Remote_Maintenance_Approvals` | `sc_req_item` | security | NIST-1411 | MA-04a. |
| Special Protection Approvals | `ServiceNow_Special_Protection_Approvals` | `sc_req_item` | hr | NIST-1517 | PS-03(03)(a), PS-03(03)(b) |
| Data Reassignment | `ServiceNow_Data_Reassignment` | `sc_req_item` | hr_offboarding | NIST-1521 | PS-04e. |
| Transfer Notifications | `ServiceNow_Transfer_Notifications` | `sc_req_item` | hr_transfer | NIST-1527 | PS-05d. |
| Sanctions ISSO Notify | `ServiceNow_Sanctions_ISSO_Notify` | `sc_req_item` | hr | NIST-1538 | PS-08b. |
| Firewall Exception Duration | `ServiceNow_Firewall_Exception_Duration` | `sc_req_item` | security | NIST-1633 | SC-07(04)(d) |
| Patch Test Records | `ServiceNow_Patch_Test_Records` | `change_request` | change | NIST-1688 | SI-02b. |
| Malware False Positive | `ServiceNow_Malware_False_Positive` | `sc_req_item` | security | NIST-1702 | SI-03d. |

All 26 get entries in `assets/fedramp-map.json` with the `req_ids`/`control_ids` shown above (copied verbatim from the matching `Jira_*` entry).

## TUI Wiring

- `CloudProvider::ServiceNow` routes `ProviderSelection -> SelectCollectors -> SetOptions -> Confirm`, skipping the account-picker and any endpoint-selection screen (instance URL comes from `servicenow-config.toml`) — same routing shape as `CloudProvider::Okta` (see Task 19 of the Okta plan), not Tenable's `TenableEndpoint`/`ScanSelection` path.
- `src/tui/collector_data.rs`: register all 33 `servicenow-*` keys (7 foundational + 26 FedRAMP) under a new "ServiceNow" category.
- `src/tui/app/mod.rs`: default `servicenow-*` collector keys; `validate_current` guard requiring at least one `CloudProvider::ServiceNow` account when the provider is selected (mirrors the Okta guard).
- `src/runner/tui_session.rs`: an OAuth-aware account-preparation block — same shape as the Jira/Okta blocks (missing-config → `prep_log` message + continue; build client; build factory; push `AccountCollectors`), except client construction is `async` (it mints an OAuth token) where Jira's/Okta's are sync.

## Documentation

- README: new `## ServiceNow` H2 section (config block, OAuth app-registration steps, collectors table for all 33 keys, required ServiceNow role — minimum `sn_incident_read`/`itil` or equivalent read scope).
- `cli-examples.md`: a ServiceNow collect-all example.
- `evidence-list.md`: new "Ticketing — ServiceNow" section, one row per collector, updated summary counts.

## Out of Scope

- ServiceNow Security Incident Response (`sn_si_incident`) and HR Service Delivery (`hr_case`) app-specific tables — these require paid ServiceNow modules not every customer has licensed; the plan uses only core ITSM tables (`incident`, `change_request`, `problem`, `sc_req_item`) that ship with every instance.
- `sysapproval_approver`-based true approver-of-record (documented simplification above: use `assigned_to`/configurable custom field instead).
- `task_sla` table-based native SLA tracking (documented simplification above: use `opened_at`→`resolved_at` duration math instead, matching Jira's approach).
- Any POA&M/vulnerability-findings integration via ServiceNow Vulnerability Response — that responsibility belongs to Tenable in this codebase; ServiceNow here is ticket/ITSM evidence only.
- Write operations (creating/updating ServiceNow records) — read-only evidence collection only, matching every other provider in this codebase.

## Conventions

- No test-writing steps in the implementation plan — each task is implement + `cargo check` + commit. No wiremock/unit/integration test scaffolding (standing preference for this repo; tests can be added later if needed).
- No "harness-reset decoy" commits after real commits — that pattern was retracted 2026-07-17 and must not reappear despite its presence in the `2026-07-16-fedramp-jira-collectors.md` precedent plan.
- Commits authored as Austin Songer, no co-author trailers.
- Work proceeds task-by-task with `cargo check` kept green after every file write (order child module files before the parent `mod.rs` declares them, matching the Okta plan's stub-first pattern).
