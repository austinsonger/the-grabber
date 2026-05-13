# PRD: Agentic Inventory & POAM Harness with Google Drive Sync

**Status:** Draft
**Author:** Austin Songer
**Date:** 2026-05-13
**Project:** The Grabber (`grabber`)

---

## Problem Statement

The Grabber collects AWS asset inventory and reconciles Inspector2 ECR findings into a FedRAMP POA&M workbook — but the entire pipeline is manually driven, covers only one vulnerability source, and terminates as local files. A compliance engineer must run AWS Inspector2 (container image scanning) and Tenable (web application and database scanning) separately, interpret the output from each, manually combine the findings into the POAM, move the resulting XLSX into a shared drive, and keep it in sync across audit cycles. Because these two scanners cover entirely different infrastructure domains, every audit cycle requires two separate collection runs and a manual merge step before the POAM reflects the full picture. This creates friction, introduces human error in POAM entries, and means the authoritative POAM document lives on someone's laptop rather than in a shared, auditable location. As audit scope, account coverage, and scan volume grow, this approach does not scale.

---

## Goals

1. **Reduce time-to-updated-POAM** from a manual multi-step process (run grabber → run Tenable export → merge → edit XLSX → upload to Drive) to a single command or automated schedule.
2. **Combine findings from AWS Inspector2 and Tenable into one POAM**, with clear source labeling per scanning domain (Inspector2 for container images, Tenable for web apps and databases), so the full vulnerability posture is visible in one place without manual merging.
3. **Make the POAM in Google Drive the authoritative source of truth**, eliminating local XLSX files as the terminal artifact.
4. **Enable AI-assisted POAM enrichment** — remediation prioritization, vendor dependency assessment, and scheduled completion dates that go beyond the current regex/rule-based logic, applied consistently across both scanning sources.
5. **Make grabber's inventory, POAM, and Tenable capabilities accessible as MCP tools**, so they can be composed with other tools (Google Drive, Claude Code, future integrations) without forking the core codebase.
6. **Zero regression on existing workflows** — CLI mode, TUI mode, and local XLSX output continue to work exactly as they do today.

---

## Non-Goals

1. **Not replacing GuardDuty or general AWS security findings in the POAM.** The agentic scope is specifically the Inspector2 ECR image findings pipeline, the AWS asset inventory, and Tenable vulnerability and compliance scans. Other collector categories are out of scope for this effort.
2. **Not a full Google Drive file management solution.** The MCP server will read and write specific spreadsheet ranges in a known POAM document. It will not provide general Drive search, file creation, or folder management beyond what the POAM workflow requires.
3. **Not building a new agent runtime.** The orchestration layer is Claude (via MCP) — we are not building a custom LLM inference loop or agent framework. The grabber exposes tools; Claude uses them.
4. **Not migrating the evidence CSV pipeline to Google Drive.** Raw Inspector2 CSV files, Tenable export files, and inventory CSVs continue to write to the local filesystem. Only the reconciled POAM output syncs to Drive.
5. **Not adding real-time or event-driven triggering.** V1 is invoked explicitly (CLI flag or Claude prompt). Scheduled runs and webhook-based triggers are a future consideration.
6. **Not building full Tenable.sc (on-premises) support in V1.** The initial Tenable integration targets Tenable.io (`cloud.tenable.com`). Tenable.sc support, which requires a configurable base URL and different auth, is a Phase 2 item.

---

## User Stories

### Compliance Engineer (primary persona)

- As a compliance engineer, I want to run a single command that collects AWS inventory, pulls Tenable vulnerability findings, reconciles both into the POAM, and updates the Google Sheet, so that I don't have to manually manage multiple exports and merge them by hand.

- As a compliance engineer, I want the POAM in Google Sheets to show only the diff from the last run (new open items added, resolved items moved to the Closed tab) regardless of whether findings came from Inspector2 or Tenable, so that I can review what changed without re-reading the entire document.

- As a compliance engineer, I want each POAM row to clearly identify its source (e.g. "AWS Inspector2 - ECR" for container image findings vs "Tenable.io - Web App" or "Tenable.io - Database" for Tenable findings), so that I can trace any finding back to its scanner and infrastructure domain during an audit.

- As a compliance engineer, I want AI-generated remediation plan text that incorporates CVSS vector, EPSS score, Tenable VPR score, package context, and fix availability, so that POAM entries are more useful to the engineering teams responsible for remediation.

- As a compliance engineer, I want the scheduled completion date logic to be explainable and auditable, so that I can defend the date derivation to an auditor without digging into source code.

- As a compliance engineer, I want to ask Claude "what changed in the POAM this month?" and get a plain-English summary broken down by source, so that I can prepare status updates without manually diffing spreadsheets.

### Security Operations (secondary persona)

- As a security operations engineer, I want to run `grabber inventory` and have the asset list automatically reflected in a Google Sheet, so that the inventory used for FedRAMP evidence is always current and accessible to the full team.

- As a security operations engineer, I want Tenable asset records to be included in the inventory sheet alongside AWS assets, so the full scope of scanned infrastructure is visible in one place.

- As a security operations engineer, I want to query the current POAM state via a Claude prompt (e.g. "how many CRITICAL Tenable findings have been open more than 30 days?"), so that I can answer audit questions quickly without opening a spreadsheet.

- As a security operations engineer, I want to see Tenable compliance check failures (FAILED status) surfaced in the POAM or a separate compliance tab, so that configuration-level weaknesses are tracked alongside vulnerability findings.

### Auditor / Reviewer (read-only persona)

- As an auditor, I want every POAM row to have a clear last-updated timestamp, source scanner label, and reference to the originating scan or CSV file, so that I can trace every finding back to its evidence source.

- As an auditor, I want to see that Tenable findings use a stable identifier (asset ID + plugin ID + port/protocol) as the Weakness Source Identifier, so that findings are consistently tracked across scan cycles without duplication.

---

## Requirements

### Must-Have — P0

**1. Grabber MCP server binary**
The project builds a second binary (`grabber-mcp`) that exposes grabber's inventory, POAM, and Tenable capabilities as MCP tools over JSON-RPC stdio.

*Acceptance criteria:*
- [ ] `grabber-mcp` starts with `--mcp` flag and reads JSON-RPC 2.0 messages from stdin, writes responses to stdout
- [ ] `tools/list` returns all tools with correct JSON Schema input definitions
- [ ] `tools/call` for each tool returns a valid JSON result or a structured error
- [ ] Server exits cleanly on stdin EOF

**2. `run_inventory` MCP tool**
Wraps `InventoryCollector` and returns asset rows as JSON instead of writing to CSV.

*Acceptance criteria:*
- [ ] Accepts `account_id`, `region`, and optional `asset_types` array
- [ ] Returns JSON array of rows using the canonical 14-column inventory schema
- [ ] If `asset_types` is omitted, collects all types (EC2, S3, RDS, Lambda, KMS, ALB, ElastiCache, Container)
- [ ] AWS authentication uses the same profile/credential chain as the existing CLI
- [ ] Errors from individual asset type collectors are returned as warnings, not fatal errors (matches existing behavior in `inventory_orchestrator.rs`)

**3. `run_poam_reconcile` MCP tool**
Wraps the existing `run_poam` flow (Inspector2 ECR findings) and returns the reconcile result as structured JSON.

*Acceptance criteria:*
- [ ] Accepts `year`, `month`, and optional `evidence_base` path
- [ ] Returns `{ "added_open": [...], "moved_closed": [...], "kept_open_count": N, "warnings": [...] }` — full row data for open/closed sets, not just counts
- [ ] Does NOT write to the local XLSX as a side effect when called via MCP (write is a separate tool call)
- [ ] Reconcile logic is byte-for-byte identical to existing `reconcile_workbook` — no behavioral changes
- [ ] Returns a structured error if no Inspector2 ECR CSV is found at the evidence path

**4. `get_current_poam` MCP tool**
Reads the current POAM state from the configured source (local XLSX initially; Google Sheet once Piece 2 is wired).

*Acceptance criteria:*
- [ ] Returns `{ "open_rows": [...], "closed_rows": [...], "headers": { "open": [...], "closed": [...] } }`
- [ ] Source (local XLSX vs Google Sheet) is configured via environment variable, not a tool parameter
- [ ] Returns structured error if source file/sheet is not accessible

**5. `run_tenable_vulns` MCP tool**
Exports vulnerability findings from Tenable.io via the `tenable-rs` crate and returns them as POAM-ready rows.

*Acceptance criteria:*
- [ ] Authenticates via `TENABLE_ACCESS_KEY` and `TENABLE_SECRET_KEY` environment variables
- [ ] Accepts optional `filters` (JSON object matching Tenable export filter schema), `state` (default: `["open","reopened"]`), and `severity_min` (default: `"medium"`)
- [ ] Returns `{ "findings": [...], "total": N }` where each finding includes: stable_key (`{asset_id}:{plugin_id}:{port}:{protocol}`), severity, cvss3_base_score, vpr_score, cve list, plugin name/description, solution text, asset hostname/IP, first_found, last_found, state, source scanner label `"Tenable.io"`
- [ ] Findings with `state: "fixed"` are returned separately under `"resolved"` for POAM close-out
- [ ] Returns structured error if Tenable credentials are missing or API returns 4xx/5xx

**6. `run_tenable_assets` MCP tool**
Exports the Tenable asset inventory and returns rows in the canonical 14-column inventory schema.

*Acceptance criteria:*
- [ ] Returns assets from `tenable-rs` `AssetRecord` type mapped to the same 14-column schema used by `run_inventory`
- [ ] Maps `AssetRecord.ipv4` → IPv4/IPv6 column, `fqdn` → DNS/URL column, `operating_system` → SW Name/Ver column, `exposure_score` → Comments column
- [ ] Assets with `is_deleted: true` are excluded
- [ ] Returns `{ "rows": [...], "total": N }`

**7. `run_tenable_compliance` MCP tool**
Exports Tenable compliance check results (FAILED checks) for surfacing in the POAM or a separate compliance tab.

*Acceptance criteria:*
- [ ] Returns only `FAILED` and `WARNING` status checks by default (configurable via `status_filter` parameter)
- [ ] Each record includes: asset identifier, check name, policy name, actual vs expected value, audit file reference, first/last seen dates
- [ ] Returns `{ "findings": [...], "total": N }`

**8. `merge_poam_findings` MCP tool**
Combines Inspector2 container image findings and Tenable web app/database findings into a single unified set of POAM rows. These two scanners cover entirely distinct infrastructure domains and will not produce duplicate findings in normal use.

*Acceptance criteria:*
- [ ] Accepts `inspector2_rows` (output of `run_poam_reconcile`) and `tenable_findings` (output of `run_tenable_vulns`)
- [ ] Concatenates both sets as independent rows — no deduplication logic applied
- [ ] Each row retains its `Weakness Detector Source` value (`"AWS Inspector2 - ECR"` or `"Tenable.io"`) from its originating tool
- [ ] Returns `{ "open_rows": [...], "closed_rows": [...], "inspector2_count": N, "tenable_count": N }`
- [ ] Either input may be empty (e.g. if only one source was run this cycle) without error

**9. Google Sheets MCP server binary**
A separate binary (`grabber-sheets-mcp`) that exposes Google Sheets read/write tools for the POAM spreadsheet.

*Acceptance criteria:*
- [ ] Authenticates via Google service account JSON key (path configured via `GOOGLE_SERVICE_ACCOUNT_KEY` env var)
- [ ] Does not require user OAuth flow — service account only
- [ ] `tools/list` returns all Sheets tools with correct schemas
- [ ] All API errors are returned as structured tool errors, not panics

**10. `read_poam_sheet` tool (Sheets MCP)**
Reads the Open Items and Closed Items tabs from the configured Google Sheet.

*Acceptance criteria:*
- [ ] Returns `{ "open_rows": [...], "closed_rows": [...], "open_headers": [...], "closed_headers": [...] }`
- [ ] Sheet ID is configured via `POAM_SPREADSHEET_ID` env var
- [ ] Tab names are configurable via env vars (default: "Open POA&M Items", "Closed POA&M Items")
- [ ] Returns empty arrays (not error) if a tab has no data rows beyond the header

**11. `write_poam_open_items` and `write_poam_closed_items` tools (Sheets MCP)**
Replace the content of a sheet tab with a provided set of rows.

*Acceptance criteria:*
- [ ] Accepts `rows` array (each row is an array of strings, matching the POAM column schema)
- [ ] Preserves the header row — never overwrites column A1
- [ ] Clears existing data rows before writing new ones (full replacement, not append)
- [ ] Returns `{ "rows_written": N }` on success
- [ ] Returns structured error if the spreadsheet is not accessible or the sheet is protected

**12. `append_inventory_rows` tool (Sheets MCP)**
Appends asset inventory rows to an Inventory tab, skipping rows whose unique ID already exists.

*Acceptance criteria:*
- [ ] Accepts `rows` array and optional `sheet_name` (default: "Asset Inventory")
- [ ] Deduplicates by the value in column A (Unique Asset Identifier) — existing IDs are skipped
- [ ] Returns `{ "appended": N, "skipped_duplicates": N }`

**13. MCP server wiring documented**
The project includes a `.claude/settings.json` snippet and a setup guide showing how to wire both MCP servers into Claude Code.

*Acceptance criteria:*
- [ ] `settings.json` snippet is correct JSON and references both binaries
- [ ] Required environment variables are documented (AWS_PROFILE, TENABLE_ACCESS_KEY, TENABLE_SECRET_KEY, GOOGLE_SERVICE_ACCOUNT_KEY, POAM_SPREADSHEET_ID)
- [ ] A usage example shows the full end-to-end flow: run AWS inventory + Tenable assets → reconcile Inspector2 POAM + Tenable vulns → merge → sync to Drive

---

### Nice-to-Have — P1

**14. `summarize_poam_changes` MCP tool**
After a reconcile+merge, returns a plain-English summary broken down by source: new findings by severity per scanner, findings closed per scanner, findings approaching their scheduled completion date, cross-source CVE duplicates found.

**15. AI-enriched remediation plans**
When building new open POAM rows, use the Claude API to generate a more detailed remediation plan. For Tenable findings, incorporate `plugin.solution`, `plugin.synopsis`, VPR score, and `has_patch`. For Inspector2 findings, incorporate CVSS vector, EPSS score, package context, and fix availability. The enrichment is additive — existing fields are not replaced.

**16. Tenable VPR-based prioritization**
When merging findings, use the Tenable VPR (Vulnerability Priority Rating) score to flag findings that should be escalated above their raw CVSS severity. VPR > 7.0 on a finding rated "Medium" CVSS should be surfaced with a note in the Comments field.

**17. Inventory delta reporting**
`run_inventory` and `run_tenable_assets` optionally accept a `previous_run` JSON blob and return `{ "added": [...], "removed": [...], "unchanged_count": N }`. Makes the Drive sync surgical rather than a full rewrite each cycle.

**18. Dry-run mode for Sheets writes**
`write_poam_open_items` accepts a `dry_run: true` parameter that validates the rows and returns what would be written without modifying the sheet.

**19. Tenable compliance tab in Google Sheet**
`grabber-sheets-mcp` gains a `write_compliance_findings` tool that writes Tenable compliance check failures to a dedicated "Compliance Findings" tab in the POAM spreadsheet, separate from the vulnerability-based Open/Closed tabs.

---

### Future Considerations — P2

**20. Scheduled / automated runs**
A cron-style trigger (GitHub Actions, launchd, or AWS EventBridge) that runs the full pipeline on a recurring schedule and posts a Slack summary with finding counts by source.

**21. Multi-account POAM aggregation**
Run inventory and POAM reconcile across multiple AWS accounts, aggregate with Tenable findings, and write to a single Google Sheet with an account-ID/site-name column.

**22. Tenable.sc (on-premises) support**
The `TenableProviderFactory` already has a `site_name` field. Add configurable base URL and Tenable.sc session-token auth to support on-premises deployments alongside Tenable.io.

**23. POAM → Jira/Linear ticket creation**
When a new CRITICAL/HIGH finding is added to the POAM from either source, automatically create a ticket in the team's issue tracker with the remediation plan as the description and the source scanner as a label.

**24. Audit export**
Generate a timestamped, read-only snapshot of the POAM (PDF or locked sheet) suitable for submission to a 3PAO or auditor, with chain-of-custody metadata from the existing `audit_log.rs` system.

**25. Cross-source CVE deduplication (other deployment configurations)**
In this project's deployment, Inspector2 scans container images and Tenable scans web apps and databases — these domains do not overlap. However, other teams using this tool may run both scanners against the same hosts. A future option in `merge_poam_findings` could deduplicate by CVE ID for those configurations, keeping the Inspector2 row as primary and appending the Tenable asset reference. Off by default.

**26. Azure/GCP POAM integration**
Extend the POAM pipeline to handle findings from Azure Defender and GCP Security Command Center alongside Inspector2 and Tenable.

---

## Success Metrics

### Leading Indicators (measure within 2 weeks of ship)

| Metric | Target | Measurement |
|---|---|---|
| POAM sync end-to-end latency | < 90 seconds from command invocation to Google Sheet updated (AWS + Tenable) | Timed runs against production account |
| Tool call success rate | > 99% of MCP tool calls return a valid result (not a server error) | Stderr/log output across 20+ test runs |
| Inspector2 reconcile parity | 100% of findings produced by MCP tool match findings produced by existing `--poam` CLI for the same inputs | Automated comparison test |
| Tenable stable key uniqueness | Zero duplicate stable keys (`{asset_id}:{plugin_id}:{port}:{protocol}`) within a single Tenable export | Assertion in Tenable tool test |
| Zero local XLSX writes in MCP mode | MCP tool calls never write to `evidence-output/poam/` as a side effect | File system assertion in CI |

### Lagging Indicators (measure at 30 and 90 days)

| Metric | Target | Measurement |
|---|---|---|
| POAM update frequency | Increases from roughly monthly to at least bi-weekly | Git/Drive revision history |
| Manual XLSX edits after sync | Drops to < 5% of POAM update events | Google Sheets revision history |
| Time-to-POAM-update | Reduces from estimated 45–60 min manual process to < 5 min | Before/after time tracking |
| Source coverage completeness | Both Inspector2 (container) and Tenable (web app/database) findings present in every POAM sync run | Row count by `Weakness Detector Source` value |
| Auditor feedback on POAM quality | No findings related to missing remediation plan detail, stale entries, or missing source attribution in next audit cycle | Audit report |

---

## Open Questions

| # | Question | Owner | Blocking? |
|---|---|---|---|
| 1 | Does the Google Sheet POAM need to remain in the exact FedRAMP template format (column names, tab names), or can we adjust column order? The current reconcile logic normalizes headers by name, so minor changes are tolerable — but this should be confirmed before the Sheets write implementation. | Austin + Compliance | **Yes** — affects `write_poam_open_items` schema |
| 2 | Service account vs. user OAuth for Google auth? Service account is simpler server-to-server but requires sharing the Sheet with the service account email. Is that acceptable given the sensitivity of POAM data? | Austin | **Yes** — affects auth implementation |
| 3 | What is the `POAM_SPREADSHEET_ID`? The specific Google Sheet to target needs to be identified before end-to-end testing. | Austin | Yes, for testing only |
| 4 | Should the Sheets MCP server be a separate binary in this repo, or a separate repo/package entirely? The `--features` flag pattern already used for Azure/GCP could apply here and keep the Google auth dependency optional. | Engineering | No — can decide at implementation start |
| 5 | What Tenable severity threshold should feed the POAM? The current Inspector2 pipeline includes all findings with a Finding ARN. For Tenable, the default is Medium and above, but Critical-only vs. High+ vs. Medium+ changes POAM volume significantly depending on web app and database scan results. | Austin | **Yes** — affects `run_tenable_vulns` default filter |
| 6 | Does the Tenable account have active scan policies configured for web app and database targets? The `tenable-rs` crate uses the Tenable.io export API, which exports across all scan history. If no scans have run recently, the export will be empty. | Austin | Yes, for end-to-end testing |
| 8 | For AI-enriched remediation plans (P1): which Claude model and approximate token cost per POAM run? With combined Inspector2 + Tenable findings potentially reaching 100–200 new items per cycle at ~500 tokens/finding, this is 50–100K tokens/run — still modest but should be confirmed against actual finding volume. | Austin | No |

---

## Timeline Considerations

No hard deadlines identified. This is an internal tooling improvement, not customer-facing.

**Suggested phasing:**

- **Phase 1 — Grabber MCP server (AWS only):** Build the `grabber-mcp` binary with `run_inventory`, `run_poam_reconcile`, and `get_current_poam` tools. Entirely self-contained — no Google or Tenable dependency. Can be wired into Claude Code immediately.

- **Phase 2 — Tenable MCP tools:** Add `run_tenable_vulns`, `run_tenable_assets`, `run_tenable_compliance`, and `merge_poam_findings` to `grabber-mcp`. Requires Tenable credentials and a live Tenable.io account for end-to-end testing (open question 7).

- **Phase 3 — Google Sheets MCP server:** Build `grabber-sheets-mcp` with read/write tools. Requires resolving open questions 1–3 first.

- **Phase 4 — End-to-end wiring + docs:** Wire both servers into `.claude/settings.json`, test the full Claude-orchestrated flow with both sources, write setup guide.

- **Phase 5 — P1 enhancements:** Enriched remediation plans, VPR prioritization, inventory delta reporting, dry-run mode — after Phase 4 is validated.

**Dependencies:**
- Tenable API credentials (blocks Phase 2 end-to-end testing)
- Google service account credentials and Sheet ID (blocks Phase 3 end-to-end testing)
- Confirmation of POAM column schema compatibility with current Google Sheet template (blocks Phase 3 implementation)
- Tenable severity threshold decision (blocks Phase 2 `run_tenable_vulns` default filter)

---

## Appendix: Architecture Summary

```
┌──────────────────────────────────────────────────────────┐
│                    Claude (MCP client)                    │
│  "Reconcile POAM for May from Inspector2 + Tenable        │
│   and sync to Drive"                                      │
└────────────┬──────────────────────────┬───────────────────┘
             │ MCP                      │ MCP
             ▼                          ▼
┌─────────────────────────┐   ┌──────────────────────────┐
│      grabber-mcp        │   │   grabber-sheets-mcp     │
│                         │   │                          │
│ run_inventory           │   │ read_poam_sheet          │
│ run_poam_reconcile      │   │ write_poam_open_items    │
│ get_current_poam        │   │ write_poam_closed_items  │
│ run_tenable_vulns       │   │ append_inventory_rows    │
│ run_tenable_assets      │   │ write_compliance_findings│
│ run_tenable_compliance  │   └──────────┬───────────────┘
│ merge_poam_findings     │              │
└────────┬────────────────┘              ▼
         │                   ┌──────────────────────────┐
         ▼                   │   Google Sheets API v4   │
┌────────────────────┐       │   (service account auth) │
│  AWS (SDK calls)   │       └──────────────────────────┘
│  inventory_core    │
│  poam/reconcile    │
└────────────────────┘
┌────────────────────┐
│  Tenable.io API    │
│  tenable-rs crate  │
│  vulns / assets /  │
│  compliance export │
└────────────────────┘
```

All three MCP server binaries are additive. The existing `grabber` CLI/TUI is completely unchanged.
