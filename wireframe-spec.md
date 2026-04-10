# Webapp Wireframe Spec — The Grabber

**Fidelity:** Annotated Mid-Fi
**Conventions:** Gray/black/white only (no color). `X` boxes for images. Wavy lines (`~~~`) for body text blocks. Real labels on navigation and buttons.

---

## Table of Contents

1. [Dashboard (Home)](#1-dashboard-home)
2. [Wizard Shell](#2-new-collection-wizard--shell)
3. [Step 1 — Account Selection](#3-wizard-step-1--account-selection)
4. [Step 2 — Date Range](#4-wizard-step-2--date-range)
5. [Step 3 — Collector Selection](#5-wizard-step-3--collector-selection)
6. [Step 4 — Options](#6-wizard-step-4--options)
7. [Step 5 — Confirm](#7-wizard-step-5--confirmation)
8. [Running Screen](#8-running-screen--live-progress)
9. [Results Screen](#9-results-screen)
10. [Responsive Breakpoints](#responsive-breakpoints)
11. [Component Inventory](#component-inventory)
12. [Accessibility Notes](#accessibility-notes)

---

## 1. Dashboard (Home)

```
┌─────────────────────────────────────────────────────────────────┐
│ [GRABBER LOGO]          [Accounts ▾]  [History]  [Settings]     │  ← NAV: sticky top, 64px
│─────────────────────────────────────────────────────────────────│
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  H1: Collect AWS Compliance Evidence                     │   │  ← HERO: full-width banner
│  │  H3: Select accounts, choose collectors, run collection  │   │
│  │                        [▶ New Collection]                │   │  ← CTA: primary button
│  └──────────────────────────────────────────────────────────┘   │
│                                                                 │
│  H2: Recent Runs                                [View all →]    │
│  ┌────────────────┐ ┌────────────────┐ ┌────────────────┐       │  ← CARDS: 3-col grid
│  │ Production     │ │ Operations     │ │ Security       │       │
│  │ 2026-04-01     │ │ 2026-03-28     │ │ 2026-03-15     │       │
│  │ 87 collectors  │ │ 42 collectors  │ │ 31 collectors  │       │
│  │ 12,450 records │ │ 6,211 records  │ │ 4,890 records  │       │
│  │ [✓ Completed]  │ │ [✓ Completed]  │ │ [✗ 2 Errors]   │       │
│  │ [Download ▾]   │ │ [Download ▾]   │ │ [View Details] │       │
│  └────────────────┘ └────────────────┘ └────────────────┘       │
│                                                                 │
│  H2: Configured Accounts                        [+ Add Account] │
│  ┌────────────────────────────────────────────────────────────┐ │  ← TABLE: full-width
│  │  Name         │ Account ID    │ Region      │ Status       │ │
│  │  Production   │ 1234-5678-90  │ us-east-1   │ ● Connected  │ │
│  │  Operations   │ 2345-6789-01  │ us-east-2   │ ● Connected  │ │
│  │  Security     │ 3456-7890-12  │ us-west-2   │ ○ Unverified │ │
│  └────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

**Annotations:**

| Element | Behavior |
|---------|----------|
| `[▶ New Collection]` | Navigates to Wizard Step 1 |
| Recent Run card (any click) | Opens Results detail for that run |
| `[Download ▾]` | Dropdown: "Download All (ZIP)", "CSV Only", "JSON Only" |
| `● Connected` / `○ Unverified` | Green dot = STS GetCallerIdentity passed; gray = not yet tested; clicking re-runs canary check |
| `[+ Add Account]` | Opens Account Config slide-over drawer (not a new page) |

**States:**

- **Empty (no runs yet):** Hero CTA remains; "Recent Runs" section shows centered illustration + "No runs yet. Start your first collection."
- **Empty (no accounts):** Accounts table replaced by "No accounts configured. [Add your first account →]" with inline setup guidance.
- **Run in progress (from another tab/session):** Banner at top of page: "A collection is currently running — [View Progress →]"

**Responsive (≤768px):**
- Recent run cards stack to 1-col
- Accounts table collapses to accordion rows (tap row to expand details)
- Nav links collapse to hamburger menu

---

## 2. New Collection Wizard — Shell

*This shell persists across Steps 1–5. Step content renders in the middle area.*

```
┌─────────────────────────────────────────────────────────────────┐
│ [← Back]  New Collection                         [✕ Cancel]     │  ← Header bar
│─────────────────────────────────────────────────────────────────│
│                                                                 │
│   ①  Account  ────  ②  Dates  ────  ③  Collectors  ────       │  ← STEP INDICATOR
│                      ④  Options  ────  ⑤  Confirm              │    (2-row on smaller screens)
│                                                                 │
│─────────────────────────────────────────────────────────────────│
│                                                                 │
│                                                                 │
│                   [ STEP CONTENT AREA ]                         │
│                                                                 │
│                                                                 │
│─────────────────────────────────────────────────────────────────│
│  [← Previous]                              [Continue →]         │  ← FOOTER NAV
└─────────────────────────────────────────────────────────────────┘
```

**Step Indicator States:**

```
  ✓ Account  ────  ✓ Dates  ────  ● Collectors  ────  ○ Options  ────  ○ Confirm
  (done)           (done)          (active, filled)     (pending)        (pending)
```

**Annotations:**

| Element | Behavior |
|---------|----------|
| Step indicator — completed step | Checkmark; clicking navigates back to that step |
| Step indicator — future step | Grayed out; not clickable |
| `[← Back]` header | Same action as `[← Previous]` footer |
| `[✕ Cancel]` | Confirmation dialog: "Discard this collection?" → [Discard] [Keep editing] |
| `[Continue →]` | Disabled until current step passes validation; shows tooltip on hover explaining why |
| Wizard URL | State encoded in URL params (`?step=3&account=prod`) so browser Back/Forward works |

---

## 3. Wizard Step 1 — Account Selection

```
│  H2: Select Account                                             │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  ○  Production                              us-east-1    │   │
│  │     123456789012  ·  ProdAdmin profile      ● Connected  │   │
│  ├──────────────────────────────────────────────────────────┤   │
│  │  ○  Operations                              us-east-2    │   │
│  │     234567890123  ·  OpsAdmin profile       ● Connected  │   │
│  ├──────────────────────────────────────────────────────────┤   │
│  │  ○  Security                                us-west-2    │   │
│  │     345678901234  ·  SecAdmin profile       ○ Unverified │   │
│  ├──────────────────────────────────────────────────────────┤   │
│  │  ○  Manual / Custom                                      │   │
│  │     Enter profile and region manually                    │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                 │
│  [+ Add another account]                                        │
```

**"Manual / Custom" expanded:**

```
│  ● Manual / Custom                                               │
│     ┌────────────────────────────────────┐                       │
│     │  Profile name:  [________________] │                       │
│     │  Region:        [us-east-1      ▾] │  ← searchable dropdown
│     │  Multi-region:  [○ Off  ● On]      │                       │
│     └────────────────────────────────────┘                       │
```

**Annotations:**

| Element | Behavior |
|---------|----------|
| Account rows | Single-select radio group; first account pre-selected if config loaded |
| `● Connected` badge | Clicking runs STS GetCallerIdentity inline; spinner while checking |
| `○ Unverified` badge | Yellow tint; tooltip: "Click to test credentials" |
| "Manual / Custom" | Expands inline fields; profile name = free text matching `~/.aws/config` |
| Region dropdown | Searchable; lists all 20 standard AWS regions |
| Multi-region toggle (Manual) | Enables tag input for specific regions; or "auto-discover all" checkbox |
| `[+ Add another account]` | Opens Account Config slide-over drawer |

**Error state:** Selected account has expired credentials → yellow warning banner above footer: "Credentials may be expired. Re-authenticate before continuing."

---

## 4. Wizard Step 2 — Date Range

```
│  H2: Collection Window                                           │
│                                                                  │
│  ┌────────────────────────┐    ┌────────────────────────┐        │
│  │  H3: Start Date        │    │  H3: End Date          │        │
│  │  ┌──────────────────┐  │    │  ┌──────────────────┐  │        │
│  │  │  2026-01-01  [📅]│  │    │  │  2026-04-01  [📅]│  │        │
│  │  └──────────────────┘  │    │  └──────────────────┘  │        │
│  └────────────────────────┘    └────────────────────────┘        │
│                                                                  │
│  Quick ranges:  [Last 30 days]  [Last 90 days]  [Last 6 months]  │  ← pill buttons
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐    │  ← INFO BOX
│  │  ℹ  Date range applies to: CloudTrail events, Backup     │    │
│  │     jobs, RDS backup events, and S3 data events.         │    │
│  │                                                          │    │
│  │     Snapshot collectors (IAM, EC2, S3 config, KMS…)      │    │
│  │     always capture current state regardless of range.    │    │
│  └──────────────────────────────────────────────────────────┘    │
```

**Calendar popover (on [📅] click):**

```
│  ┌──────────────────────────┐                                    │
│  │  < January 2026  >       │                                    │
│  │  Su Mo Tu We Th Fr Sa    │                                    │
│  │                  1  2  3 │                                    │
│  │   4  5  6  7  8  9 10    │                                    │
│  │  11 12 13 14 15 16 17    │                                    │
│  │  [1] ... [31]            │                                    │
│  └──────────────────────────┘                                    │
```

**Annotations:**

| Element | Behavior |
|---------|----------|
| Date text inputs | Format: YYYY-MM-DD; validates on blur |
| `[📅]` icon | Opens inline calendar popover; selecting a date closes popover and fills field |
| Quick range pills | Populates both fields; highlights active pill; deactivates on manual edit |
| Info box | Static; educates users about which collectors use date range vs. snapshot |

**Error states:**
- Invalid format → red border + "Use YYYY-MM-DD format" below field
- Start > End → red border on end field + "End date must be after start date"
- S3 range > 7 months (when `s3` collector selected) → amber warning: "S3 collector has a 7-month history limit. Reduce range or deselect the S3 collector."

---

## 5. Wizard Step 3 — Collector Selection

```
│  H2: Select Collectors                    [87 of 152 selected]  │
│                                                                 │
│  ┌─────────────────────────────────────┐  [Select All]          │
│  │  🔍  Search collectors…             │  [Deselect All]        │
│  └─────────────────────────────────────┘                        │
│                                                                 │
│  Category:  [All] [IAM] [EC2 & Net] [S3] [Security] [RDS] [+6]  │  ← FILTER CHIPS
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  ▾ IAM  (12 selected / 12 total)           [toggle all ☑]│   │  ← GROUP HEADER
│  │  ├─────────────────────────────────────────────────────  │   │
│  │  │  [☑] iam-users        Current IAM users inventory     │   │
│  │  │  [☑] iam-roles        IAM roles and trust policies    │   │
│  │  │  [☑] iam-policies     Managed & inline policies       │   │
│  │  │  [☑] iam-access-keys  Access key metadata             │   │
│  │  │  [☑] iam-certs        Uploaded server certificates    │   │
│  │  │      ···  7 more  [Show all]                          │   │
│  ├──────────────────────────────────────────────────────────┤   │
│  │  ▾ EC2 & Networking  (8 selected / 23 total) [toggle ☐]  │   │
│  │  │  [☑] ec2-instances    Running/stopped EC2 inventory   │   │
│  │  │  [☑] security-groups  Security group rules            │   │
│  │  │  [☐] ec2-detailed     Extended EC2 attributes         │   │
│  │  │      ···  20 more  [Show all]                         │   │
│  ├──────────────────────────────────────────────────────────┤   │
│  │  ▾ Security Services  (5 selected / 9 total) [toggle ☐]  │   │
│  │  │  [☑] guardduty        GuardDuty findings              │   │
│  │  │  [☑] securityhub      Security Hub findings           │   │
│  │  │  [☐] inspector        Inspector vulnerability scans   │   │
│  │  │      ⚠ Off by default — enable only if Inspector is   │   │  ← DEFAULT-OFF BADGE
│  │  │        active in this account                         │   │
│  │  │  [☐] macie            Macie sensitive data findings   │   │
│  │  │      ⚠ Off by default                                 │   │
│  └──────────────────────────────────────────────────────────┘   │
```

**Search active state:**

```
│  🔍 cloudtrail                              [✕]                  │
│                                                                  │
│  Showing results for "cloudtrail"   (6 matches across 2 groups)  │
│                                                                  │
│  ▾ CloudTrail & Audit  (4 selected / 6 matches)                  │
│     [☑] cloudtrail-config    ← "cloudtrail" highlighted          │
│     [☑] cloudtrail-events    ← "cloudtrail" highlighted          │
│     [☐] ct-selectors         ...                                 │
```

**Annotations:**

| Element | Behavior |
|---------|----------|
| Group header | Click anywhere on header row to expand/collapse |
| `[toggle all ☑/☐]` | Checks/unchecks entire group; icon reflects current group state |
| Collector checkbox | Space or click to toggle |
| "7 more [Show all]" | Expands group to show all collectors (default: 5 per group) |
| Search box | Filters across all groups in real time; matched text highlighted in yellow |
| `[✕]` in search | Clears search, restores full list |
| Category filter chips | Clicking a chip filters to that category only; "All" resets |
| `⚠` badge | Amber; tooltip: full explanation of why disabled by default |
| Collector row — hover | Right-aligned tag appears: `CSV` or `JSON` output type |
| Count badge (H2) | Updates live as selections change |

**Empty search state:**

```
│  No collectors match "xyzabc"                                    │
│  [Clear search]                                                  │
```

**Validation:** `[Continue →]` disabled with tooltip "Select at least one collector" until ≥1 checked.

**Responsive (≤768px):** Filter chips scroll horizontally; group headers sticky on scroll.

---

## 6. Wizard Step 4 — Options

```
│  H2: Collection Options                                          │
│                                                                  │
│  ─── Output ──────────────────────────────────────────────────   │
│                                                                  │
│  H3: Output Directory                                            │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │  ./evidence-output/production                      [🔒]  │    │  ← read-only field
│  └──────────────────────────────────────────────────────────┘    │
│  ℹ Configured per account.  [Edit account settings →]            │
│                                                                  │
│  H3: Include Raw AWS Response                                    │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │  ○ Disabled   ●  Enabled                                 │    │  ← segmented toggle
│  └──────────────────────────────────────────────────────────┘    │
│  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ │  ← description text
│  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~                             │
│                                                                  │
│  ─── Regions ────────────────────────────────────────────────    │
│                                                                  │
│  H3: Region Mode                                                 │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │  ●  Single region:    [us-east-1               ▾]        │    │
│  │  ○  All enabled regions  (auto-discover via EC2)         │    │
│  │  ○  Specific regions:   [+ Add region tag]               │    │
│  └──────────────────────────────────────────────────────────┘    │
│                                                                  │
│  ─── S3 CloudTrail Source  (shown only if 's3' collector on) ──  │  ← CONDITIONAL SECTION
│                                                                  │
│  H3: S3 Bucket (CloudTrail logs)                                 │
│  ┌───────────────────────────────────────────────────────────┐   │
│  │  Bucket name:          [_________________________]        │   │
│  │  Key prefix:           [_________________________]        │   │
│  │  Cross-account profile:[_________________________]        │   │
│  │  Additional accounts:  [_________________________]        │   │
│  │  Additional regions:   [_________________________]        │   │
│  └───────────────────────────────────────────────────────────┘   │
```

**"Specific regions" expanded:**

```
│  ○  Specific regions:                                           │
│     [us-east-1 ×]  [eu-west-1 ×]  [ap-southeast-1 ×]            │  ← tag input
│     [+ Add region ▾]                                             │
```

**Annotations:**

| Element | Behavior |
|---------|----------|
| Output directory | Read-only (lock icon). `[Edit account settings →]` opens settings slide-over |
| Include Raw toggle | Defaults to Disabled; session-persisted; "Enabled" shows size warning tooltip |
| Region — Single | Dropdown pre-filled from account config; searchable |
| Region — All | Shows info tooltip: "Auto-discovers via EC2 DescribeRegions. May significantly increase runtime." |
| Region — Specific | Tag input; typing triggers region name/code autocomplete |
| S3 section | Conditionally visible: appears only when `s3` collector is checked in Step 3 |
| S3 bucket | Required if section visible; validated on Continue |

---

## 7. Wizard Step 5 — Confirmation

```
│  H2: Review & Confirm                                          │
│                                                                │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  ACCOUNT       Production (123456789012)         [✏ Edit]│  │
│  │  PROFILE       ProdAdmin-123456789012                    │  │
│  │  REGION        us-east-1                         [✏ Edit]│  │
│  │  DATE RANGE    2026-01-01  →  2026-04-01         [✏ Edit]│  │
│  │  COLLECTORS    87 selected                       [✏ Edit]│  │
│  │                  [Show full list ▾]                      │  │
│  │  OUTPUT DIR    ./evidence-output/production              │  │
│  │  INCLUDE RAW   Disabled                          [✏ Edit]│  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  ⚠  Estimated runtime: 8–15 minutes                      │  │  ← ESTIMATE BOX
│  │     Based on 87 collectors · single region               │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                │
│  [← Edit]                      [▶▶ Start Collection]           │
```

**"Show full list ▾" expanded:**

```
│  COLLECTORS    87 selected  [Hide list ▲]                       │
│                                                                 │
│  IAM (12)           iam-users, iam-roles, iam-policies…         │
│  EC2 & Net (8)      ec2-instances, security-groups…             │
│  Security (5)       guardduty, securityhub…                     │
│  S3 (10)            s3-config, s3-logging…                      │
│  ···                                                            │
```

**Annotations:**

| Element | Behavior |
|---------|----------|
| `[✏ Edit]` buttons | Jump directly to the relevant wizard step |
| "Show full list ▾" | Inline accordion; grouped by category |
| Estimate box | Heuristic: `collectors × avg_time_per_collector`; shown as a range |
| `[▶▶ Start Collection]` | POSTs to backend; immediately navigates to Running screen |
| Keyboard | `Enter` = Start Collection |

---

## 8. Running Screen — Live Progress

```
┌─────────────────────────────────────────────────────────────────┐
│ [GRABBER LOGO]          [Accounts ▾]  [History]  [Settings]     │
│─────────────────────────────────────────────────────────────────│
│                                                                 │
│  H1: Collecting Evidence — Production                           │
│                                                                 │
│  ██████████████████████░░░░░░░░░░░░░░░░  52 / 87 collectors     │  ← PROGRESS BAR (cyan fill)
│                                                                 │
│  ┌───────────────────────────────────┐  ┌────────────────────┐  │
│  │  H3: Collectors                   │  │  H3: Stats         │  │
│  │                                   │  │  Elapsed    04:32  │  │
│  │  ⠸  cloudtrail-events  running…   │  │  Complete   52/87  │  │
│  │  ·  ec2-instances      waiting    │  │  Records    24,110 │  │
│  │  ·  security-groups    waiting    │  │  Errors     0      │  │
│  │  ✓  iam-users          382 rec    │  └────────────────────┘  │
│  │  ✓  iam-roles          128 rec    │                          │
│  │  ✓  iam-policies        67 rec    │  ┌────────────────────┐  │
│  │  ✗  rds-snapshots      timeout    │  │ H3: Activity Log   │  │
│  │  ✓  guardduty           45 rec    │  │ 04:31  guardduty   │  │
│  │  ✓  securityhub         12 rec    │  │        done 45 rec │  │
│  │  ·  kms                waiting    │  │ 04:28  iam-roles   │  │
│  │                                   │  │        done 128rec │  │
│  │  [ ▾ 77 more collectors ]         │  │ 04:25  cloudtrail  │  │
│  │                                   │  │        started     │  │
│  │                                   │  │ 04:20  iam-users   │  │
│  │                                   │  │        done 382rec │  │
│  └───────────────────────────────────┘  └────────────────────┘  │
│                                                                 │
│  ⚠ Running — do not close this tab.         [✕ Cancel]          │
└─────────────────────────────────────────────────────────────────┘
```

**Collector status icons:**

| Icon | Meaning |
|------|---------|
| `⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏` (animated) | Running |
| `✓` | Completed — record count shown |
| `·` | Waiting in queue |
| `✗` | Failed or timed out |

**Collector list sort order:** Running → Waiting → Completed (most recent first within each group)

**Annotations:**

| Element | Behavior |
|---------|----------|
| Progress bar | Animated fill; transitions gray → filled on progress; turns green on 100% |
| Collector list | Updates via SSE/WebSocket stream; `✗` rows show error message on hover |
| `[ ▾ 77 more ]` | Expands to scrollable list of all collectors |
| Stats card | Elapsed timer: ticks every second; Records: increments as collectors finish |
| Activity log | Newest events top; max 20 visible; scroll for older |
| `[✕ Cancel]` | Confirmation dialog: "Cancel will stop all in-progress collectors. Partial results already saved will remain." |
| Browser tab | `beforeunload` event: browser prompts "Leave site? Changes may not be saved." |

**Completion transition:** Progress bar fills green → status text "Collection complete!" → auto-navigates to Results after 1.5 s.

**Full failure state:** Red banner: "Collection failed — no records written. Check credentials and AWS connectivity."

---

## 9. Results Screen

```
┌─────────────────────────────────────────────────────────────────┐
│ [GRABBER LOGO]          [Accounts ▾]  [History]  [Settings]     │
│─────────────────────────────────────────────────────────────────│
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  ✓  Collection Complete — Production                     │   │  ← SUCCESS BANNER
│  │     87 collectors  ·  31,450 records  ·  04:47 elapsed   │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                 │
│  [⬇ Download All (ZIP)]   [⬇ CSV Only]   [⬇ JSON Only]        │  ← DOWNLOAD BAR
│                                                                 │
│  H2: Output Files                                               │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  🔍 Filter files…                          [Sort: Name ▾]  │  │  ← FILTER/SORT BAR
│  ├───────────────────────────────────────────────────────────┤  │
│  │  📄 Production_CloudTrail-2026-04-01.json   8,210 rec  ⬇  │  │
│  │  📄 Production_IAM_Roles-2026-04-01.json      128 rec  ⬇  │  │
│  │  📄 Production_IAM_Users-2026-04-01.csv       382 rec  ⬇  │  │
│  │  📄 Production_SecurityGroups-2026-04-01.csv   44 rec  ⬇  │  │
│  │  📄 Production_GuardDuty-2026-04-01.csv        45 rec  ⬇  │  │
│  │       ···  82 more files  [Show all]                      │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
│  H2: Errors (1)                                  [▾ expand]     │  ← ERRORS: hidden if 0
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  ✗  rds-snapshots  —  Timed out after 3 minutes            │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                 │
│  [← Run Another Collection]        [View Full History →]        │
└─────────────────────────────────────────────────────────────────┘
```

**Annotations:**

| Element | Behavior |
|---------|----------|
| Success banner | Green border; aggregate stats pulled from collection run metadata |
| `[Download All (ZIP)]` | Streams ZIP of all output files + `evidence-collection.log` |
| `[CSV Only]` / `[JSON Only]` | Filtered ZIP of only that format |
| Filter text box | Real-time file name search across list |
| Sort dropdown | Options: Name (A–Z), Name (Z–A), Size, Record count, Type (CSV/JSON) |
| File row `⬇` | Downloads individual file |
| File row (any click) | Opens file content preview panel (CSV: sortable table view; JSON: collapsible tree) |
| "Show all" link | Expands to full file list |
| Errors section | Hidden entirely if error count = 0; collapsed accordion if count ≥ 1 |
| Error row hover | Expands to show full error message string |
| `[← Run Another Collection]` | New wizard pre-filled with same account/dates/collectors (all editable) |

---

## Responsive Breakpoints

| Screen | ≥1280px Desktop | 768–1279px Tablet | ≤767px Mobile |
|--------|-----------------|-------------------|---------------|
| **Dashboard** | 3-col run cards; full account table | 2-col cards; table scrolls horizontally | 1-col cards; accordion table rows |
| **Wizard shell** | Content + right summary sidebar | Single-panel; sidebar becomes bottom drawer | Single-panel; step indicator 2-row |
| **Collector picker** | 2-col groups side-by-side | 1-col groups full width | 1-col; category filter chips scroll |
| **Running screen** | List left + Stats/Log right (50/50) | Stacked: list above stats | Stats card collapsed; expand on tap |
| **Results** | File list + metadata sidebar | Full-width list | Download bar sticky bottom |

---

## Component Inventory

| Component | Screen(s) | States |
|-----------|-----------|--------|
| Top nav bar | All | Default, scrolled (compact 48px), mobile (hamburger) |
| Run history card | Dashboard | Default, hover, running (in-progress badge), error |
| Account table row | Dashboard | Default, connected, unverified, error |
| Step indicator | Wizard shell | Active, completed (checkmark), pending (grayed) |
| Account radio card | Step 1 | Default, selected, credential-error, checking (spinner) |
| Date text input | Step 2 | Empty, focused, valid, invalid |
| Quick range pill | Step 2 | Default, active |
| Collector group header | Step 3 | Collapsed, expanded, all-checked, partial, none |
| Collector checkbox row | Step 3 | Unchecked, checked, default-off (amber badge) |
| Category filter chip | Step 3 | Default, active |
| Output toggle (Raw) | Step 4 | Disabled, enabled |
| Region selector | Step 4 | Single, all-regions, specific (tag input) |
| Confirmation summary row | Step 5 | Default, hover (shows ✏ Edit) |
| Progress bar | Running | Idle (empty), running (animated), complete (green), failed (red) |
| Collector status row | Running | Waiting (·), running (spinner), done (✓ + count), failed (✗ + error) |
| Stats card | Running | Live-updating (elapsed, counts) |
| Activity log feed | Running | Scrollable; new items animate in from top |
| Download button bar | Results | Default, downloading (spinner on button) |
| File list row | Results | Default, hover (shows ⬇ action) |
| File preview panel | Results | Closed, CSV table view, JSON tree view |
| Error accordion row | Results | Collapsed, expanded |

---

## Accessibility Notes

- All form inputs paired with `<label>` (explicit `for`/`id` association)
- Step indicator: `role="list"` with `aria-current="step"` on active item
- Collector checkboxes: `role="checkbox"` + `aria-checked`; group headers: `role="group"` + `aria-label`
- Progress bar: `role="progressbar"` + `aria-valuenow` / `aria-valuemax` / `aria-valuetext` ("52 of 87 collectors complete")
- Running screen stats: `aria-live="polite"` region; activity log: `aria-live="off"` (user can scroll; don't interrupt)
- Color is **never** the sole state indicator — every semantic color has an accompanying icon and/or text label
- Keyboard nav: `Tab` all interactive elements; `Enter`/`Space` buttons and checkboxes; `Escape` closes modals/drawers
- Download links: `aria-label` includes file name and record count for screen readers
- Error messages: associated with inputs via `aria-describedby`; also announced via `role="alert"` when validation fires
