# PRD: Agentic Inventory & POAM Harness with Google Drive Sync

**Status:** Draft
**Author:** Austin Songer
**Date:** 2026-05-13
**Project:** The Grabber (`grabber`)

---

## Problem Statement

The Grabber collects AWS asset inventory and reconciles Inspector2 ECR findings into a FedRAMP POA&M workbook — but the entire pipeline is manually driven and terminates as local files. A compliance engineer must decide which collectors to run, interpret the output, manually move the resulting XLSX into a shared drive, and keep it in sync across audit cycles. This creates friction, introduces human error in POAM entries, and means the authoritative POAM document lives on someone's laptop rather than in a shared, auditable location. As audit scope and account coverage grow, this approach does not scale.

---

## Goals

1. **Reduce time-to-updated-POAM** from a manual multi-step process (run grabber → review output → edit XLSX → upload to Drive) to a single command or automated schedule.
2. **Make the POAM in Google Drive the authoritative source of truth**, eliminating local XLSX files as the terminal artifact.
3. **Enable AI-assisted POAM enrichment** — remediation prioritization, vendor dependency assessment, and scheduled completion dates that go beyond the current regex/rule-based logic.
4. **Make grabber's inventory and POAM capabilities accessible as MCP tools**, so they can be composed with other tools (Google Drive, Claude Code, future integrations) without forking the core codebase.
5. **Zero regression on existing workflows** — CLI mode, TUI mode, and local XLSX output continue to work exactly as they do today.

---

## Non-Goals

1. **Not replacing GuardDuty or general security findings in the POAM.** The agentic scope is specifically the Inspector2 ECR image findings pipeline and the AWS asset inventory. Other collector categories are out of scope for this effort.
2. **Not a full Google Drive file management solution.** The MCP server will read and write specific spreadsheet ranges in a known POAM document. It will not provide general Drive search, file creation, or folder management beyond what the POAM workflow requires.
3. **Not building a new agent runtime.** The orchestration layer is Claude (via MCP) — we are not building a custom LLM inference loop or agent framework. The grabber exposes tools; Claude uses them.
4. **Not migrating the evidence CSV pipeline to Google Drive.** Raw Inspector2 CSV files and inventory CSVs continue to write to the local filesystem. Only the reconciled POAM output syncs to Drive.
5. **Not adding real-time or event-driven triggering.** V1 is invoked explicitly (CLI flag or Claude prompt). Scheduled runs and webhook-based triggers are a future consideration.

---

## User Stories

### Compliance Engineer (primary persona)

- As a compliance engineer, I want to run a single command that collects inventory, reconciles POAM findings, and updates the Google Sheet, so that I don't have to manually manage the XLSX and re-upload it after every collection cycle.

- As a compliance engineer, I want the POAM in Google Sheets to show only the diff from the last run (new open items added, resolved items moved to the Closed tab), so that I can review what changed without re-reading the entire document.

- As a compliance engineer, I want AI-generated remediation plan text that incorporates package version, CVSS context, and fix availability, so that POAM entries are more useful to the engineering teams responsible for remediation.

- As a compliance engineer, I want the scheduled completion date logic to be explainable and auditable, so that I can defend the date derivation to an auditor without digging into source code.

- As a compliance engineer, I want to ask Claude "what changed in the POAM this month?" and get a plain-English summary, so that I can prepare status updates without manually diffing spreadsheets.

### Security Operations (secondary persona)

- As a security operations engineer, I want to run `grabber inventory` and have the asset list automatically reflected in a Google Sheet, so that the inventory used for FedRAMP evidence is always current and accessible to the full team.

- As a security operations engineer, I want to query the current POAM state via a Claude prompt (e.g. "how many CRITICAL findings have been open more than 30 days?"), so that I can answer audit questions quickly without opening a spreadsheet.

### Auditor / Reviewer (read-only persona)

- As an auditor, I want the POAM Google Sheet to have a clear last-updated timestamp and source reference (which CSV file produced each row), so that I can trace every finding back to its evidence source.

---

## Requirements

### Must-Have — P0

**1. Grabber MCP server binary**
The project builds a second binary (`grabber-mcp`) that exposes grabber's inventory and POAM capabilities as MCP tools over JSON-RPC stdio.

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
Wraps the existing `run_poam` flow and returns the reconcile result as structured JSON.

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

**5. Google Sheets MCP server binary**
A separate binary (`grabber-sheets-mcp`) that exposes Google Sheets read/write tools for the POAM spreadsheet.

*Acceptance criteria:*
- [ ] Authenticates via Google service account JSON key (path configured via `GOOGLE_SERVICE_ACCOUNT_KEY` env var)
- [ ] Does not require user OAuth flow — service account only
- [ ] `tools/list` returns all Sheets tools with correct schemas
- [ ] All API errors are returned as structured tool errors, not panics

**6. `read_poam_sheet` tool (Sheets MCP)**
Reads the Open Items and Closed Items tabs from the configured Google Sheet.

*Acceptance criteria:*
- [ ] Returns `{ "open_rows": [...], "closed_rows": [...], "open_headers": [...], "closed_headers": [...] }`
- [ ] Sheet ID is configured via `POAM_SPREADSHEET_ID` env var
- [ ] Tab names are configurable via env vars (default: "Open POA&M Items", "Closed POA&M Items")
- [ ] Returns empty arrays (not error) if a tab has no data rows beyond the header

**7. `write_poam_open_items` and `write_poam_closed_items` tools (Sheets MCP)**
Replace the content of a sheet tab with a provided set of rows.

*Acceptance criteria:*
- [ ] Accepts `rows` array (each row is an array of strings, matching the POAM column schema)
- [ ] Preserves the header row — never overwrites column A1
- [ ] Clears existing data rows before writing new ones (full replacement, not append)
- [ ] Returns `{ "rows_written": N }` on success
- [ ] Returns structured error if the spreadsheet is not accessible or the sheet is protected

**8. `append_inventory_rows` tool (Sheets MCP)**
Appends asset inventory rows to an Inventory tab, skipping rows whose unique ID already exists.

*Acceptance criteria:*
- [ ] Accepts `rows` array and optional `sheet_name` (default: "Asset Inventory")
- [ ] Deduplicates by the value in column A (Unique Asset Identifier) — existing IDs are skipped
- [ ] Returns `{ "appended": N, "skipped_duplicates": N }`

**9. MCP server wiring documented**
The project includes a `.claude/settings.json` snippet and a setup guide showing how to wire both MCP servers into Claude Code.

*Acceptance criteria:*
- [ ] `settings.json` snippet is correct JSON and references both binaries
- [ ] Required environment variables are documented (AWS_PROFILE, GOOGLE_SERVICE_ACCOUNT_KEY, POAM_SPREADSHEET_ID)
- [ ] A usage example shows the end-to-end flow: run inventory → reconcile POAM → sync to Drive

---

### Nice-to-Have — P1

**10. `summarize_poam_changes` MCP tool**
After a reconcile, returns a plain-English summary of what changed: new findings by severity, findings closed, findings approaching their scheduled completion date, vendor-dependency cases.

**11. AI-enriched remediation plans**
When building new open POAM rows, call the Claude API to generate a more detailed remediation plan that incorporates CVSS vector, EPSS score, package context, and fix availability — beyond the current `compose_remediation_plan` string concatenation.

*Constraint:* This is a tool-call side effect, not a change to the core reconcile logic. The enrichment is additive to the existing fields.

**12. Inventory delta reporting**
`run_inventory` optionally accepts a `previous_run` JSON blob and returns `{ "added": [...], "removed": [...], "unchanged_count": N }` in addition to the full row set. Makes the Drive sync more surgical.

**13. Dry-run mode for Sheets writes**
`write_poam_open_items` accepts a `dry_run: true` parameter that validates the rows and returns what would be written without modifying the sheet.

---

### Future Considerations — P2

**14. Scheduled / automated runs**
A cron-style trigger (GitHub Actions, launchd, or AWS EventBridge) that runs the full pipeline on a recurring schedule and posts a Slack summary.

**15. Multi-account POAM aggregation**
Run inventory and POAM reconcile across multiple AWS accounts and aggregate into a single Google Sheet with an account-ID column.

**16. POAM → Jira/Linear ticket creation**
When a new CRITICAL/HIGH finding is added to the POAM, automatically create a ticket in the team's issue tracker with the remediation plan as the description.

**17. Audit export**
Generate a timestamped, read-only snapshot of the POAM (PDF or locked sheet) suitable for submission to a 3PAO or auditor, with chain-of-custody metadata from the existing `audit_log.rs` system.

**18. Azure/GCP POAM integration**
Extend the POAM pipeline to handle findings from Azure Defender and GCP Security Command Center, not just AWS Inspector2 ECR.

---

## Success Metrics

### Leading Indicators (measure within 2 weeks of ship)

| Metric | Target | Measurement |
|---|---|---|
| POAM sync end-to-end latency | < 90 seconds from command invocation to Google Sheet updated | Timed runs against production account |
| Tool call success rate | > 99% of MCP tool calls return a valid result (not a server error) | Stderr/log output across 20+ test runs |
| Reconcile parity | 100% of findings produced by MCP tool match findings produced by existing `--poam` CLI for the same inputs | Automated comparison test |
| Zero local XLSX writes in MCP mode | MCP tool calls never write to `evidence-output/poam/` as a side effect | File system assertion in CI |

### Lagging Indicators (measure at 30 and 90 days)

| Metric | Target | Measurement |
|---|---|---|
| POAM update frequency | Increases from roughly monthly to at least bi-weekly | Git/Drive revision history |
| Manual XLSX edits after sync | Drops to < 5% of POAM update events | Google Sheets revision history |
| Time-to-POAM-update | Reduces from estimated 45–60 min manual process to < 5 min | Before/after time tracking |
| Auditor feedback on POAM quality | No findings related to missing remediation plan detail or stale entries in next audit cycle | Audit report |

---

## Open Questions

| # | Question | Owner | Blocking? |
|---|---|---|---|
| 1 | Does the Google Sheet POAM need to remain in the exact FedRAMP template format (column names, tab names), or can we adjust column order? The current reconcile logic normalizes headers by name, so minor changes are tolerable — but this should be confirmed before the Sheets write implementation. | Austin + Compliance | **Yes** — affects `write_poam_open_items` schema |
| 2 | Service account vs. user OAuth for Google auth? Service account is simpler server-to-server, but requires sharing the Sheet with the service account email. Is that acceptable given the sensitivity of POAM data? | Austin | **Yes** — affects auth implementation |
| 3 | What is the `POAM_SPREADSHEET_ID`? The specific Google Sheet to target needs to be identified before end-to-end testing. | Austin | Yes, for testing only |
| 4 | Should the Sheets MCP server be a separate binary in this repo, or a separate repo/package entirely? Keeping it here simplifies releases but couples the Google auth dependency to the core grabber build. The `--features` flag pattern already used for Azure/GCP could apply here. | Engineering | No — can decide at implementation start |
| 5 | For AI-enriched remediation plans (P1), which Claude model and what approximate token cost per POAM run? At ~50 new findings per month at ~500 tokens/finding, this is roughly 25K tokens/run — negligible, but should be confirmed against actual finding volume. | Austin | No |

---

## Timeline Considerations

No hard deadlines identified. This is an internal tooling improvement, not customer-facing.

**Suggested phasing:**

- **Phase 1 — Grabber MCP server:** Build the `grabber-mcp` binary with `run_inventory`, `run_poam_reconcile`, and `get_current_poam` tools. Entirely self-contained — no Google dependency. Can be wired into Claude Code immediately for interactive use even before Phase 2.

- **Phase 2 — Google Sheets MCP server:** Build `grabber-sheets-mcp` with read/write tools. Requires resolving open questions 1–3 first.

- **Phase 3 — End-to-end wiring + docs:** Wire both servers into `.claude/settings.json`, test the full Claude-orchestrated flow, write setup guide.

- **Phase 4 — P1 enhancements:** Enriched remediation plans, inventory delta reporting, dry-run mode — after Phase 3 is validated.

**Dependencies:**
- Google service account credentials and Sheet ID (blocks Phase 2 end-to-end testing)
- Confirmation of POAM column schema compatibility with current Google Sheet template (blocks Phase 2 implementation)

---

## Appendix: Architecture Summary

```
┌──────────────────────────────────────────────────┐
│                  Claude (MCP client)              │
│   "Reconcile POAM for May and sync to Drive"      │
└────────────┬─────────────────────┬───────────────┘
             │ MCP                 │ MCP
             ▼                     ▼
┌────────────────────┐   ┌─────────────────────────┐
│   grabber-mcp      │   │  grabber-sheets-mcp      │
│                    │   │                          │
│ run_inventory      │   │ read_poam_sheet          │
│ run_poam_reconcile │   │ write_poam_open_items    │
│ get_current_poam   │   │ write_poam_closed_items  │
└────────┬───────────┘   │ append_inventory_rows    │
         │               └──────────┬───────────────┘
         ▼                          ▼
┌────────────────────┐   ┌─────────────────────────┐
│  AWS (SDK calls)   │   │  Google Sheets API v4    │
│  inventory_core    │   │  (service account auth)  │
│  poam/reconcile    │   │                          │
└────────────────────┘   └─────────────────────────┘
```

Both MCP servers are additive binaries. The existing `grabber` CLI/TUI is completely unchanged.
