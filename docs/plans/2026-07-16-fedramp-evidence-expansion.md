# PRD: FedRAMP Moderate Evidence Expansion

**Status:** Draft
**Author:** Austin Songer
**Date:** 2026-07-16
**Source input:** `~/Documents/FedRAMP-with-evidence.xlsx` (IRL sheet, 193 rows)

---

## Problem Statement

Grabber automates **39 of 193** (20%) FedRAMP NIST 800-53 Moderate evidence
requirements. The other 154 items are still gathered by hand — engineers open
Okta reports, run JQL in Jira, screenshot policy pages, and email HR for
offboarding timestamps every audit cycle. Each ATO/ConMon window costs the
security team several full weeks of clerical work, and each hand-collected
artifact is a fresh chance for an auditor to catch a stale, mislabeled, or
missing file.

83% of the 193 items *are* automatable given the current codebase, existing
API clients, and a handful of new integrations. We're leaving that leverage
on the table.

## Goals

1. **Raise automated coverage from 20% → 78%** of the 193 NIST 800-53 Moderate
   requirements within two release cycles.
2. **Cut audit-window evidence-collection time by 60%** (measured as engineer
   hours spent on FedRAMP evidence pulls per ConMon cycle).
3. **Ship the top 20 highest-value new collectors first** — the items the
   research pass identified as high-frequency, high-audit-scrutiny, and
   low-implementation-cost.
4. **Expand three provider surfaces** without breaking the flat-module
   architecture: `okta-rs` (5 new modules), `jira-rs` (generic JQL executor),
   and AWS collectors (12 new modules).
5. **Land two new integration crates** — LMS and HRIS — that alone unlock 34
   requirements and every timeliness-SLA join key.

## Non-Goals

1. **We will not replace the human artifacts** (signed docs, board approvals,
   contract clauses, physical badge records). 33 of 193 items stay manual;
   grabber will document the gap, not fake evidence.
2. **We will not build a full GRC platform.** No control-mapping UI, no POA&M
   authoring, no SSP editor. Grabber emits evidence; the GRC tool of record
   consumes it.
3. **We will not add EDR, DLP, SIEM, wireless-controller, or physical-access
   integrations in this cycle.** They unlock ≤7 requirements each; deferred to
   a later PRD once the top-tier work ships.
4. **We will not touch the existing 124 AWS collectors' output schemas.** New
   collectors follow the same `<AccountId>_<Prefix>-<TS>.csv` convention; no
   breaking changes.
5. **We will not build a scheduler or "continuous compliance" daemon.** Grabber
   stays a CLI/TUI run-on-demand tool; scheduling lives in the caller (cron,
   GitHub Actions, ConMon runbook).

## User Stories

### Compliance engineer (primary user)

- As a compliance engineer preparing a FedRAMP ConMon package, I want to run
  one grabber invocation and receive CSVs covering ≥78% of the required
  evidence, so that I no longer chase artifacts across five SaaS UIs.
- As a compliance engineer, I want offboarding-timeliness evidence that joins
  Okta deactivation timestamps to Jira offboarding-ticket resolution times, so
  that I can prove the 24-hour PS-04 SLA in a single CSV instead of splicing
  two exports by hand.
- As a compliance engineer, I want a bucket-G report listing every requirement
  grabber *cannot* auto-collect, so that I know exactly what manual work
  remains and can plan for it.

### Security engineer (secondary user)

- As a security engineer, I want SC-07 boundary-protection evidence
  (split-tunnel, fail-closed, NetworkFirewall config) as first-class CSVs, so
  that I can validate the actual network posture instead of trusting the SSP
  narrative.
- As a security engineer, I want Okta ThreatInsight and AWS GuardDuty
  malware-scan history in the same run, so that AC-02(12) and SI-03c. are
  provable from one output bundle.

### Audit-package assembler (tertiary user)

- As an audit-package assembler, I want every new collector's output to carry
  the same 14-column bundle-manifest metadata as today's collectors (account
  ID, run timestamp, region, collector name), so that the ZIP bundle and
  signing flow keep working unchanged.
- As an audit-package assembler, I want each evidence file to self-identify
  the FedRAMP requirement(s) it satisfies *and* its own filename, so that when
  a file is emailed, extracted, or renamed downstream, an auditor can still
  tell exactly which control it maps to and confirm the file's original
  identity.

## Requirements

### Must-Have (P0) — this release cycle

**Evidence self-identification (applies to every collector, existing and new)**

- P0-META-01 **Requirement mapping columns.** Every CSV emitted by grabber
  MUST include two new columns on every row:
  - `FedRAMP Req IDs` — pipe-separated list of NIST Req IDs the collector
    satisfies (e.g., `NIST-1043|NIST-1519|NIST-1535`).
  - `FedRAMP Control IDs` — pipe-separated list of NIST 800-53 control IDs
    (e.g., `AC-02h.|PS-04a-d|PS-07d.`).
  For JSON evidence (EV1–EV4), the same fields are added to every top-level
  record. Values are the collector's *declared* mapping — not per-row inferred
  — so every row from a given collector carries identical mapping strings.
- P0-META-02 **Filename echo.** Every CSV/JSON emitted by grabber MUST include
  a `Source Evidence File` column/field on every row, populated with the
  emitted file's basename (e.g.,
  `123456789012_Okta_Deprovisioning_Timeliness-2026-07-16-142330.csv`). This
  guarantees a file that gets renamed, extracted from a bundle, or pasted
  into a working paper still identifies itself.
- P0-META-03 **Trailing manifest footer.** Every CSV file MUST end with two
  extra rows after the last data row (or after a single blank separator row):
  a row `# FedRAMP Req IDs,<pipe-separated>` and a row
  `# Source Evidence File,<basename>`. Every JSON file MUST end with a
  top-level object key `_fedramp_manifest` containing
  `{ "req_ids": [...], "control_ids": [...], "source_evidence_file": "..." }`.
  Rationale: users who read raw files (grep, `less`, `head`) get the mapping
  even without loading all rows.
- P0-META-04 **Central mapping table.** A single source-of-truth file
  `assets/fedramp-map.json` MUST list, per collector, its Req IDs and control
  IDs. The runner loads this at startup and every collector reads its mapping
  from the table — collectors do NOT hardcode strings. Adding or removing a
  mapping is a one-file edit.
- P0-META-05 **Backfill existing collectors.** All 124 existing collectors
  get their P0-META-01/02/03 columns and footer applied in this release.
  This is a schema change; call it out in the CHANGELOG and bump grabber's
  minor version.
- P0-META-06 **Coverage report emission.** After every run, grabber writes
  `<run-dir>/fedramp-coverage-actual.csv` with one row per Req ID (all 193),
  columns: `Req ID, Control ID, Category, Collector Name, Source Evidence
  File, Row Count, Bucket (A/B/C/D/E/F/G)`. Requirements with no collector
  yet are emitted with empty `Collector Name` / `Source Evidence File` and
  `Bucket = G` (or the bucket the classifier assigned). This satisfies the
  audit-package assembler user story end-to-end.

**AWS — 12 new collectors** (one Rust module each under `src/`, registered in
`src/main.rs` and `src/runner/collector_registry.rs`).

**AWS — 12 new collectors** (one Rust module each under `src/`, registered in
`src/main.rs` and `src/runner/collector_registry.rs`).

- P0-AWS-01 `IAM_Credential_Report_Expiration` — parses
  `iam:GetCredentialReport` for password/access-key expiration windows.
  Satisfies AC-02(02).
- P0-AWS-02 `TransitGateway_VPCPeering_Config` — `ec2:DescribeTransitGateways`
  + peering + attachments. CA-09b.
- P0-AWS-03 `Session_Timeout_Config` — ELB idle timeouts + ClientVPN + SSM
  Session Manager preferences. CA-09c.
- P0-AWS-04 `SSM_Application_Allowlist` — SSM Distributor + State Manager
  associations + compliance items. CM-07(02), CM-07(05)(b).
- P0-AWS-05 `Doc_Repo_Backup_Config` — S3 versioning + replication for
  documentation buckets; joined to backup vault recovery points. CP-09c.
- P0-AWS-06 `ClientVPN_SplitTunnel_Config` — `ec2:DescribeClientVpnEndpoints`.
  SC-07(07).
- P0-AWS-07 `GuardDuty_Runtime_Coverage` — `guardduty:GetCoverageStatistics`
  by resource type. SC-07(12).
- P0-AWS-08 `NetworkFirewall_FailClosed_Config` —
  `network-firewall:DescribeFirewall` stream-exception policy. SC-07(18).
- P0-AWS-09 `GuardDuty_Malware_Scan_History` —
  `guardduty:DescribeMalwareScans` with real timestamps.
  SI-03c.01[01].
- P0-AWS-10 `SSM_Automation_Response_Runbooks` — Automation documents +
  EventBridge rule targets. SI-06d.
- P0-AWS-11 `Config_FIM_Rules` — `config:DescribeConfigRules` filtered to
  integrity rules. SI-07b.
- P0-AWS-12 `AMI_Default_Credential_Scan` — SSM State Manager CIS association
  compliance + Inspector2 `default_credentials` findings. IA-05e.

**Okta — 5 new API modules + 19 new collectors** under `crates/okta-rs/src/api/`.

- P0-OKTA-01 New module `lifecycle` — `/api/v1/mappings`, `/api/v1/idps`,
  System Log filters for `user.lifecycle.*`.
- P0-OKTA-02 New module `admin_roles` — admin role assignments and role
  history.
- P0-OKTA-03 New module `access_reviews` — `/governance/api/v1/campaigns`
  (Identity Governance).
- P0-OKTA-04 New module `sign_in_widget` — `/api/v1/brands/{id}/pages/sign-in/customized`
  and `/api/v1/policies?type=OKTA_SIGN_ON`.
- P0-OKTA-05 New module `threat_insight` — System Log filter on
  `security.threat.detected`.
- P0-OKTA-06 through P0-OKTA-19 — 19 collectors in
  `src/providers/okta/` calling the new modules. Covers AC-02h., AC-02k.,
  AC-02l., AC-02(01), AC-02(12), AC-02(13), AC-06(07), AC-08a-b., AC-11a-b.,
  AC-22a., CM-05(05)(b), IA-02(05), IA-05b., IA-05i., PS-04a-d, PS-05b-c.,
  PS-07d.

**Jira — 1 generic JQL executor + 26 named collectors** under `crates/jira-rs/`
and `src/providers/jira/`.

- P0-JIRA-01 New module `jql_sla` in `crates/jira-rs/src/api/` — takes a JQL,
  returns issues with SLA-timing fields extracted from changelog (created,
  first-transition, resolved, per-status duration, approver identity from
  history).
- P0-JIRA-02 through P0-JIRA-27 — 26 collectors in `src/providers/jira/`
  wrapping named JQL queries per the mapping table (AC-17b., AC-20(01),
  AC-22c./d., AU-02b., AU-06c., CA-03c., CA-09d., CM-03e., CM-06c.,
  CM-07(05)(c), CP-02e., CP-04c., CP-07b., CP-10, IR-04b-d., IR-06a-b.,
  PS-03(03), PS-04e., PS-05, PS-08b., SC-07(04)(d)/(e), SI-02b., SI-03d.).
  Query templates live in `config.toml` so customers can override JQL/project
  keys per tenant.

**Acceptance criteria — P0**

- [ ] `cargo run --release -- --provider okta --provider jira --provider aws`
      produces CSVs for every P0 collector above with non-empty output when
      the source system has data.
- [ ] `evidence-list.md` updated with EV125–EV181 entries covering every new
      collector, including columns.
- [ ] A new `docs/fedramp-coverage.md` table maps each of the 193 Req IDs to a
      collector name or the reason it's manual (bucket G).
- [ ] `assets/fedramp-map.json` exists and is loaded by the runner; every
      registered collector has a non-empty mapping entry.
- [ ] Every emitted CSV includes the columns `FedRAMP Req IDs`,
      `FedRAMP Control IDs`, and `Source Evidence File` on every row.
- [ ] Every emitted CSV ends with the `# FedRAMP Req IDs` and
      `# Source Evidence File` trailing rows (after a blank separator).
- [ ] Every emitted JSON file contains a top-level `_fedramp_manifest`
      object with `req_ids`, `control_ids`, and `source_evidence_file`.
- [ ] `<run-dir>/fedramp-coverage-actual.csv` is generated after every run
      and contains a row for all 193 Req IDs.
- [ ] Backfill: all 124 pre-existing collectors also carry the new columns
      and footer; snapshot tests updated in the same commit series.
- [ ] `cargo test` passes; `cargo clippy -- -D warnings` clean.
- [ ] Zero regressions in the existing 124 collectors' *core* columns and
      filenames (only the three metadata columns and the footer rows are
      added; nothing renamed or removed).
- [ ] Inventory-CSV 14-column canonical schema is extended to 16 columns
      (`FedRAMP Req IDs`, `FedRAMP Control IDs`) plus the trailing manifest;
      `Source Evidence File` reuses the existing `Comments`/`UNIQUE ASSET
      IDENTIFIER` column pattern — pick one and document in
      `inventory-excel-mapping.md`.
- [ ] TUI Feature-Selection screen groups new collectors under existing
      categories (no new top-level menus).

### Nice-to-Have (P1) — fast follow

- P1-LMS-01 New crate `crates/lms-rs` with pluggable driver (`knowbe4`,
  `cornerstone`, `talentlms`, `rippling_learning`). Ships one driver in v1;
  others load lazily. Unlocks 24 AT/CP/IR/PS training-completion
  requirements.
- P1-HRIS-01 New crate `crates/hris-rs` (`bamboohr`, `rippling`, `workday`).
  Ships one driver in v1. Provides hire/term/transfer timestamps used as the
  join key for every PS-04/PS-05 timeliness SLA.
- P1-JIRA-28 `Jira_Ticket_SLA` — post-P0 refinement to auto-detect SLA fields
  from Jira's SLA custom-field schema instead of relying on changelog
  scraping.
- P1-COV-01 **[promoted to P0-META-06]** — the coverage-report emission is now
  a P0 requirement. In P1, add `--coverage-format html` and
  `--coverage-format xlsx` renderers on top of the P0 CSV so the compliance
  team can drop the report straight into an audit package.

### Future Considerations (P2) — design-in, do not build

- P2-MDM-01 New crate `crates/mdm-rs` (`jamf`, `intune`, `kandji`). Unlocks 7
  AC-11(01)/AC-18(03)/AC-19 items.
- P2-EDR-01 New crate `crates/edr-rs` (`crowdstrike`, `sentinelone`). Unlocks
  4 SI-03c./MA-03(02) items.
- P2-VRM-01 New crate `crates/vrm-rs` (`vanta`, `drata`, `onetrust`,
  `servicenow_grc`). Unlocks 8 PS-07/RA-03/SR-05/SR-06 items.
- P2-GITHUB-01 GitHub SAST + branch-protection collector inside a new
  `crates/git-rs`. Unlocks SA-11(01) and CM-05(01)(a).
- P2-PHYS-01 Physical-access integration (`envoy`, `kisi`, `genea`,
  `verkada`). Unlocks 6 PE-03 items.
- P2-DOCS-01 Confluence + SharePoint Graph collector for CP-02 distribution
  and PS-06 acknowledgment tracking. Unlocks 5 items.
- P2-CONT-01 `--continuous` mode with a persistent state store so second and
  subsequent runs can emit change-only deltas. Architectural design should
  not preclude this — keep collector functions idempotent and side-effect
  free.

## Success Metrics

### Leading indicators (measured within 30 days of ship)

- **Coverage ratio**: `automated / 193` reported by the new
  `--coverage-report`. Target: **≥ 78%** (150/193) after P0+P1 land; **≥ 20%
  → ≥ 45%** after P0 alone (39 → ~87 covered items).
- **Collector runtime**: full P0 run against a real ConMon-scale account
  completes in **< 30 minutes** on the reference workload (measured against
  the current 12-minute baseline for the 124 existing collectors).
- **CSV emptiness rate**: proportion of P0 collectors returning zero rows on
  the reference tenant. Target: **< 15%** (collector implementations should
  degrade gracefully but not silently no-op).

### Lagging indicators (measured over 1 audit cycle, ~90 days)

- **Engineer hours per ConMon evidence cycle**: baseline ~120 hrs. Target:
  **≤ 50 hrs** after P0+P1.
- **Auditor findings tied to "evidence not provided" or "evidence stale"**:
  baseline ~8/cycle. Target: **≤ 2/cycle**.
- **Reruns per collector per cycle**: baseline ~2.4 (engineer notices missing
  data, re-runs). Target: **≤ 1.2**.

Measurement method: instrument the runner to write
`<run-dir>/collector-timing.csv` (already partially there for AWS) and expand
it to cover every provider. Hours-saved data pulled from the compliance
team's existing time-tracking Jira project.

## Open Questions

- **[stakeholder]** Which LMS is the company standard? Driver order in
  `crates/lms-rs` depends on the answer. If unknown, ship the KnowBe4 driver
  first (largest FedRAMP-security-training market share).
- **[stakeholder]** Which HRIS is authoritative for hire/term/transfer? Same
  question for `crates/hris-rs`.
- **[engineering]** Does Okta Identity Governance license exist in the current
  tenant? Access-review campaign endpoints require it. If not, AC-06(07) and
  CM-05(05)(b) fall back to bucket D (Jira certification tickets).
- **[engineering]** Are Jira project keys stable across tenants? If not, JQL
  template variables must be parameterized per-tenant in `jira-config.toml`.
  The current `jira-config.example.toml` supports one `project_key` — extend
  to a `{project_key_by_purpose}` map (e.g.,
  `access_requests = "SEC"`, `change_requests = "CHG"`,
  `offboarding = "HR-OFF"`).
- **[engineering]** How do we handle Okta System Log's 90-day retention window
  for offboarding-timeliness queries older than 90 days? Options: (a) accept
  90-day evidence horizon, (b) require customers to export to a SIEM, (c)
  ship a companion daily-snapshot mode. Recommend (a) for v1.
- **[data]** `assets/fedramp-map.json` is now a P0 deliverable (see
  P0-META-04). Open sub-question: do we version the schema
  (`{ "schema": 1, "collectors": {...} }`) from day one to allow future
  bucket/category additions without breakage? Recommend **yes**.
- **[data]** Column-name choice for the mapping fields. Proposed:
  `FedRAMP Req IDs` and `FedRAMP Control IDs`. Alternative more consistent
  with existing snake-ish CSV headers: `fedramp_req_ids`,
  `fedramp_control_ids`. Existing collectors use Title Case; recommend
  matching that (`FedRAMP Req IDs`, `FedRAMP Control IDs`,
  `Source Evidence File`).
- **[engineering]** Some collectors satisfy overlapping requirements (e.g.,
  `Okta_Deprovisioning_Timeliness` covers AC-02h., PS-04, PS-07d.). Should
  the pipe-separated list be sorted alphabetically or ordered by primary →
  secondary control? Recommend alphabetical for deterministic diffs.
- **[legal]** Some Okta System Log fields contain user PII (IP, geo, UA). Are
  we OK writing those to unencrypted CSVs, or does the ZIP-bundle signing
  flow need to force at-rest encryption for the Okta bundle?

## Timeline Considerations

- **Hard external dependency:** Next ConMon window closes on the annual
  FedRAMP schedule. P0 needs to be in-tree at least 30 days before that
  window so the compliance team can dry-run against it.
- **Provider dependencies:**
  - `okta-rs` module additions can proceed today; no external blockers.
  - `jira-rs` JQL executor can proceed today; no external blockers.
  - LMS crate blocked on vendor decision (see open questions).
  - HRIS crate blocked on vendor decision (see open questions).
  - AWS collectors blocked on nothing; `aws-sdk-*` for
    `network-firewall`, `guardduty` (coverage/malware), and `ec2` (client-vpn)
    are already pulled in.
- **Phasing:**
  - **Phase 1 (P0)** — 12 AWS + 5 Okta modules + 19 Okta collectors + Jira JQL
    executor + 26 Jira collectors. Feature-complete in one release cycle.
  - **Phase 2 (P1)** — LMS + HRIS crates after vendor selection. One release
    cycle; ships one driver per crate.
  - **Phase 3 (P2)** — MDM, EDR, VRM, GitHub, Physical, Docs, and continuous
    mode. Separate PRD per crate, prioritized by unlock count.
- **Suggested phasing if Phase 1 is too large:** split P0 by provider.
  Ship `okta-rs` expansion first (highest per-item audit value: 19 items
  including PS-04 offboarding SLA, the #1 auditor question), then AWS, then
  Jira. Each provider slice is independently valuable.

## Appendix A — Coverage math

| Bucket | Count | % of 193 |
|---|---:|---:|
| A: Already covered | 39 | 20% |
| B: New AWS collector (P0) | 12 | 6% |
| C: New Okta collector (P0) | 19 | 10% |
| D: New Jira collector (P0) | 26 | 13% |
| E: New Tenable collector | 0 | 0% |
| F: New external integration | 64 | 33% |
| G: Not automatable | 33 | 17% |
| **P0 target coverage (A+B+C+D)** | **96** | **50%** |
| **P0+P1 target (add LMS+HRIS = 34 F items)** | **130** | **67%** |
| **P0+P1+P2 target (all F integrations)** | **160** | **83%** |

The 78% goal in this PRD assumes P0 + P1 + top P2 items (MDM + EDR + VRM +
GitHub = 21 additional items → 151/193 = 78%).

## Appendix B — Top 20 collector build order (source of truth for P0 sequencing)

1. `Okta_Deprovisioning_Timeliness` (AC-02h., PS-04, PS-07d.)
2. `Jira_Offboarding_SLA` joined with (1) — end-to-end 24hr/8hr proof
3. `Okta_Access_Certification_Campaigns` (AC-06(07), CM-05(05)(b), PS-05c.)
4. `IAM_Credential_Report_Expiration` (AC-02(02))
5. `Okta_ThreatInsight_Detections` (AC-02(12))
6. `Okta_Group_Membership_Change_Log` (AC-02, PS-05, IA-05i., CM-05(05))
7. `Okta_SignIn_Widget_Config` + `Okta_Session_Policy` (AC-08, AC-11)
8. `Jira_DR_Test_Results` (CP-04c., CP-07b., CP-10)
9. `GuardDuty_Malware_Scan_History` (SI-03c.)
10. `SSM_Application_Allowlist` (CM-07(02), (05))
11. `AWS_Config_FIM_Rules` (SI-07)
12. `Jira_Firewall_Exception_Duration` (SC-07(04)(d)/(e))
13. `ClientVPN_SplitTunnel_Config` (SC-07(07))
14. `NetworkFirewall_FailClosed_Config` (SC-07(18))
15. `GuardDuty_Runtime_Coverage` (SC-07(12))
16. `SSM_Automation_Response_Runbooks` (SI-06d)
17. `Jira_Patch_Test_Records` (SI-02b.)
18. `Jira_IR_External_Reporting_SLA` (IR-06)
19. `Jira_Change_Retention` + `Doc_Repo_Backup_Config` (CM-03e., CP-09c.)
20. `TransitGateway_VPCPeering_Config` (CA-09b.)
