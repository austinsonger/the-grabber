# PRD: Provider-Scoped TUI Collector Menus

**Status:** Draft
**Author:** Austin Songer
**Date:** 2026-07-16
**Related code:** `src/tui/collector_data.rs`, `src/tui/state.rs::COLLECTOR_CATEGORIES`, `src/tui/ui/collectors.rs`, `src/tui/app/methods.rs`

---

## Problem Statement

The TUI collector-selection screen uses one flat `COLLECTOR_ITEMS` array of 193 items partitioned by a single `COLLECTOR_CATEGORIES` list. The item-level provider filter (`search_matches_item` hides items whose provider ≠ selected provider) works, but the **category structure is AWS-shaped**: 13 of 15 categories (Compute, Storage, Encryption & Secrets, Audit Trail, Network, Security Detection, …) are AWS concepts. When a user picks Okta or Jira, they get one giant flat category holding 24 or 28 unrelated collectors — no meaningful sub-grouping.

Users report seeing "AWS-related options under other providers." The most charitable read is that even though non-matching AWS items are hidden, the AWS-named category headings still leak into the mental model of the non-AWS flow. The blunter read: when there are 28 Jira collectors dumped into a single "Issue Tracker (Jira)" list with no sub-structure, users can't find what they need and the tool feels like AWS with bolt-ons.

## Goals

1. **Each provider has its own menu path** — when the user picks Okta, the categories shown are Okta-native concepts (Lifecycle, Access Governance, Authentication, Threat Detection, etc.), not AWS categories filtered to zero items.
2. **No provider ever sees another provider's items or category names.** Structural isolation, not just row-level filtering.
3. **Each provider's collectors are grouped into ≤ 6 meaningful sub-categories** so a user can scan a category list and jump directly to what they need without paging through 24-28 flat items.
4. **Adding a new collector requires adding it to one provider's menu only** — no cross-provider index math, no risk of it appearing under the wrong provider.
5. **Zero regression on existing selection state, search, keyboard navigation, or the AWS flow** — this is a display and data-structure change, not a behavior change.

## Non-Goals

1. **No changes to `factory.rs` provider dispatch, selector keys, or filename prefixes.** Selector strings like `iam-users`, `okta-deprovisioning`, `jira-offboarding-sla` are the CLI contract; TUI grouping is orthogonal.
2. **No changes to the collector implementations themselves.** Only the menu data changes.
3. **No changes to the ProviderSelection screen** — the earlier step where the user picks AWS / Okta / Jira / Tenable stays as-is.
4. **No multi-provider selection in one collector run** — the current model of "pick one provider, then pick its collectors" holds.
5. **No dynamic categories.** Sub-categories are still hardcoded per provider; we're not building a category-configuration UI.

## User Stories

### Compliance engineer running an Okta-only pull

- As a compliance engineer, when I pick Okta on the provider screen, I want the next screen's category list to show only Okta-native categories (e.g., Lifecycle & Provisioning, Access Governance, Authentication, Threat Detection), so I can find `Okta_Access_Certification_Campaigns` in two keystrokes instead of scrolling a 24-item flat list.
- As a compliance engineer, I do NOT want to see "Compute" or "Storage" or "Security Scanning" categories in the Okta menu even as empty rows — those categories are AWS concepts and their presence signals the tool wasn't built for me.

### Compliance engineer running a Jira-only pull

- As a compliance engineer, when I pick Jira, I want categories like "SLA Tracking", "Incident Response", "Change Management", "HR Workflows", "Security Exceptions" so 28 collectors feel navigable.
- As a compliance engineer, I want `Jira_Offboarding_SLA` under "SLA Tracking" (or "HR Workflows"), not lumped in with `Jira_Baseline_Exceptions` under "Ticketing".

### AWS user (unchanged flow)

- As an AWS user, when I pick AWS, my current flow — 136 items across 13 categories (Compute, Network, etc.) — MUST work identically. No categories renamed, no items removed, no new keystrokes.

### Contributor adding a new collector

- As a contributor adding a new Okta collector, I want to add it in one place (a single Rust source of truth for the Okta menu) without touching AWS or Jira menu data, without recomputing global category boundary indices, and without any risk of it appearing in another provider's menu.

## Requirements

### Must-Have (P0)

**P0-1: Per-provider menu data structures.** Replace the single flat `COLLECTOR_ITEMS` + `COLLECTOR_CATEGORIES` with a per-provider map. Concretely, define:

```rust
pub struct ProviderMenu {
    pub provider: CloudProvider,
    pub categories: &'static [ProviderCategory],
}

pub struct ProviderCategory {
    pub name: &'static str,
    pub items: &'static [(&'static str, &'static str)],  // (selector, display)
}

pub const PROVIDER_MENUS: &[ProviderMenu] = &[
    ProviderMenu {
        provider: CloudProvider::Aws,
        categories: AWS_CATEGORIES,
    },
    ProviderMenu {
        provider: CloudProvider::Okta,
        categories: OKTA_CATEGORIES,
    },
    // etc.
];
```

Each provider's `_CATEGORIES` constant lives in its own file: `src/tui/menus/aws.rs`, `src/tui/menus/okta.rs`, `src/tui/menus/jira.rs`, `src/tui/menus/tenable.rs`.

- Acceptance: `grep "iam-users" src/tui/menus/` matches only in `aws.rs`. `grep "okta-users" src/tui/menus/` matches only in `okta.rs`. No file references items from another provider.

**P0-2: AWS categories preserved verbatim.** The 13 AWS category names (App & Network Services, Audit Trail, Compute, …, Storage) and the mapping of items to those categories stays exactly as today. The AWS flow's visible screen MUST be byte-identical to the pre-refactor state.

- Acceptance: launch TUI, pick AWS, screenshot the category list and item list. Compare to pre-refactor screenshot. Zero visible difference.

**P0-3: Okta gets 4-6 sub-categories.** Group the 24 Okta collectors into named sub-categories. Proposed grouping (finalized during implementation):

| Category | Collectors (selector keys) |
|---|---|
| Directory & Membership | `okta-users`, `okta-groups`, `okta-group-members`, `okta-apps`, `okta-shared-groups`, `okta-publisher-groups` |
| Authentication & Sessions | `okta-policies`, `okta-signin-widget`, `okta-session-policy`, `okta-password-policy`, `okta-factors`, `okta-shared-account-broker` |
| Lifecycle & Provisioning | `okta-deprovisioning`, `okta-auto-provisioning`, `okta-hris-config`, `okta-offboarding-sla`, `okta-contractor-deprov`, `okta-transfer-diff` |
| Access Governance | `okta-access-reviews`, `okta-prod-recert`, `okta-group-changes`, `okta-risk-suspend` |
| Threat Detection & Logs | `okta-threat-insight`, `okta-system-log` |

- Acceptance: pick Okta in TUI, verify 5 categories visible in left pane. Each category holds only its listed selectors. Total = 24 collectors across 5 categories.

**P0-4: Jira gets 5-6 sub-categories.** Proposed grouping:

| Category | Collectors |
|---|---|
| Core | `jira-projects`, `jira-issues` |
| SLA Tracking | `jira-offboarding-sla`, `jira-ir-external`, `jira-sanctions-isso`, `jira-transfer-notify` |
| Access & Approvals | `jira-remote-access-approvals`, `jira-external-system-approvals`, `jira-remote-maint`, `jira-special-protection` |
| Change Management | `jira-change-retention`, `jira-cp-update`, `jira-cp-test-poam`, `jira-baseline-exceptions`, `jira-allowlist-review`, `jira-patch-test`, `jira-sw-license` |
| Incident Response | `jira-ir-cp`, `jira-ir-lessons`, `jira-ir-severity`, `jira-dr-test`, `jira-malware-fp` |
| Compliance & Review | `jira-public-content`, `jira-logging-coordination`, `jira-audit-posture`, `jira-isa-annual`, `jira-fw-exception`, `jira-data-reassignment` |

- Acceptance: pick Jira in TUI, verify 6 categories visible, 28 total collectors distributed.

**P0-5: Tenable stays one category.** Tenable has only 5 collectors — one "Vulnerability Scanning" category is fine. Do NOT split.

**P0-6: Rewrite the TUI rendering to consult `PROVIDER_MENUS` instead of the flat arrays.** Concretely:
- `App::new` builds `app.collector_items` from `PROVIDER_MENUS.iter().find(|m| m.provider == selected).categories`, flattening to the same `(selector, display, provider)` shape the rest of the code already uses.
- `App::category_bounds`, `visible_categories`, `visible_items_in_category` all work against the currently-loaded provider's data, not the global flat arrays.
- `COLLECTOR_CATEGORIES` (top-level constant) is deleted. All references migrate to the per-provider structure.

- Acceptance: `cargo check` clean. `grep -rn "COLLECTOR_CATEGORIES\|COLLECTOR_ITEMS" src/` returns zero hits (or only in the new per-provider files).

**P0-7: Selection state survives provider re-selection cleanly.** If a user selects some Okta collectors, backs out to ProviderSelection, picks Jira, then re-picks Okta, their Okta selections come back. Storing selections in a `HashMap<CloudProvider, HashSet<String>>` keyed by selector (not by global index) is the safest way; index-based storage breaks the moment the flat array changes.

- Acceptance: manual test — select 3 Okta collectors, switch to Jira, select 2 Jira, switch back to Okta → 3 originally-selected Okta collectors still show as selected.

**P0-8: Search still works within the current provider's menu.** Typing `sla` while Okta is picked matches `okta-offboarding-sla` (in the Lifecycle sub-category). Typing `sla` while Jira is picked matches `jira-offboarding-sla`, `jira-ir-external`, `jira-sanctions-isso`, `jira-transfer-notify`.

- Acceptance: search filter treats items and categories the same way as today — hide categories with zero matches, show items whose selector or display contains the term.

### Nice-to-Have (P1)

**P1-1: Category ordering optimized per provider.** For AWS, categories are ordered by rough evidence-collection cadence (identity first, storage last). For Okta, order by workflow (Directory → Auth → Lifecycle → Governance → Threat). For Jira, order by criticality (SLA → Incident → Change → Compliance).

**P1-2: Category descriptions in the header.** When a category is highlighted, show a one-line description under the category title (e.g., "Access Governance: certification campaigns, recertifications, group change audit"). Increases discoverability.

**P1-3: Category badges showing FedRAMP-mapped-vs-total counts.** e.g., "Access Governance 4/4 mapped" — signals which collectors carry FedRAMP mapping vs which are inventory-only.

### Future Considerations (P2)

**P2-1: User-defined menu overrides via config.** Advanced users may want to hide the AWS "Compute" category if their org uses only serverless. A `[tui.menu_overrides]` config block could support this. Design in — don't build.

**P2-2: Multi-provider parallel selection.** Some users want to select AWS + Okta + Jira collectors in one run. This is a bigger architectural change (multi-provider factory dispatch). Design constraint for P0-P1: don't lock ourselves out of it. The `HashMap<CloudProvider, HashSet<String>>` selection storage from P0-7 already supports it.

**P2-3: Category-level bulk select/deselect.** `Shift+Space` to toggle all items in the focused category.

## Success Metrics

### Leading indicators (measured within 2 weeks of ship)

- **Category-list length by provider**: AWS = 13, Okta = 5, Jira = 6, Tenable = 1. Verified in the TUI screenshots.
- **Time-to-select-3-collectors**: measure with the maintainer running the TUI cold-start against each provider. Target: **≤ 8 seconds** for AWS (baseline), **≤ 8 seconds** for Okta and Jira (currently much longer because of flat 24/28-item lists).
- **Zero cross-provider items visible**: `grep`-driven check + eyeball verification per provider.
- **`cargo test --package the-grabber -- tui` passes** with new per-provider test cases covering P0-3, P0-4, P0-7.

### Lagging indicators (measured over 1 audit cycle, ~90 days)

- **Support/self-report incidents of "can't find the collector I need"**: baseline unknown; target zero.
- **New-collector-added-to-wrong-provider bugs**: baseline this session (Plan 3/4 subagents putting collectors into `factory.rs` before wiring TUI is essentially the same bug class). Target zero across the next 10 collectors added.

## Open Questions

- **[stakeholder]** Are the proposed Okta and Jira category splits correct? The mappings above are best-guess by control-family affinity — a compliance engineer familiar with the daily workflow may want different grouping. Blocking for P0-3 and P0-4.
- **[engineering]** Do any of the TUI tests in `src/tui/app/mod.rs` assume the flat `COLLECTOR_ITEMS` shape? A quick `grep "COLLECTOR_ITEMS\|COLLECTOR_CATEGORIES" src/tui/app/` will surface them; they need to be rewritten against the per-provider structure. Non-blocking.
- **[engineering]** Should `provider_badge` in `ui/collectors.rs` be removed since every item in the right pane will now belong to the current provider (so a badge is redundant)? Recommend **yes, remove** in P0 — it's dead weight after this refactor.
- **[design]** Category numbering (`1.App & Network Services 4/6`) currently uses global category index + 1. Per-provider numbering will reset per provider — is that OK? Recommend **yes**; users don't retain global numbers across provider switches.
- **[engineering]** What happens if a user selects a collector, then edits the source code to remove that collector, and re-runs? Today the stored selection is a global index (breaks silently). New selector-keyed storage from P0-7 fixes this — just confirm the migration path handles this cleanly (probably: drop unknown selectors on load).

## Timeline Considerations

- **No external dependency.** This is a pure UI/data-structure refactor.
- **Blocking on:** decision on the Okta and Jira category names/groupings (see open questions).
- **Suggested phasing:**
  - **Phase 1 (P0)**: split menu data into per-provider files, wire the rendering to consult per-provider structure, migrate selection state to selector-keyed. One release.
  - **Phase 2 (P1)**: category descriptions + FedRAMP-mapped badges. One release after.
  - **Phase 3 (P2)**: config-driven overrides + multi-provider mode. Separate PRD.
- **Non-blocking parallel work:** compliance engineer can review the Okta/Jira category proposals while engineering starts the refactor.

## Appendix A — Current-vs-proposed structure diff

**Today (single tree):**
```
COLLECTOR_ITEMS (193 items, flat)
COLLECTOR_CATEGORIES (15 entries)
  App & Network Services (0..6)           ← AWS
  Audit Trail (6..23)                     ← AWS
  Compute (23..39)                        ← AWS
  Containers (39..42)                     ← AWS
  Database & Backup (42..50)              ← AWS
  Encryption & Secrets (50..57)           ← AWS
  Identity & Access (57..70)              ← AWS
  Monitoring & Events (70..80)            ← AWS
  Network (80..103)                       ← AWS
  Organization & Account (103..107)       ← AWS
  Security Detection (107..123)           ← AWS
  Storage (123..136)                      ← AWS
  Security Scanning (136..141)            ← Tenable
  Identity Provider (Okta) (141..165)     ← 24 Okta items, flat
  Issue Tracker (Jira) (165..193)         ← 28 Jira items, flat
```

**Proposed (per-provider):**
```
PROVIDER_MENUS
  Aws → AWS_CATEGORIES (13 categories, ~136 items)   ← unchanged from today
  Okta → OKTA_CATEGORIES (5 categories, 24 items)
    Directory & Membership (6)
    Authentication & Sessions (6)
    Lifecycle & Provisioning (6)
    Access Governance (4)
    Threat Detection & Logs (2)
  Jira → JIRA_CATEGORIES (6 categories, 28 items)
    Core (2)
    SLA Tracking (4)
    Access & Approvals (4)
    Change Management (7)
    Incident Response (5)
    Compliance & Review (6)
  Tenable → TENABLE_CATEGORIES (1 category, 5 items)
    Vulnerability Scanning (5)
```

## Appendix B — File-touch map for engineering

**Create:**
- `src/tui/menus/mod.rs` — `PROVIDER_MENUS` array + `ProviderMenu`/`ProviderCategory` structs
- `src/tui/menus/aws.rs` — `pub const AWS_CATEGORIES`
- `src/tui/menus/okta.rs` — `pub const OKTA_CATEGORIES`
- `src/tui/menus/jira.rs` — `pub const JIRA_CATEGORIES`
- `src/tui/menus/tenable.rs` — `pub const TENABLE_CATEGORIES`

**Delete:**
- `src/tui/collector_data.rs::COLLECTOR_ITEMS` — the flat array (keep the file for `AWS_REGIONS`)
- `src/tui/state.rs::COLLECTOR_CATEGORIES` — the global category list

**Modify:**
- `src/tui/state.rs` — change `App.collector_items` field to be rebuilt per-provider on ProviderSelection→SelectCollectors transition; add `App.provider_selections: HashMap<CloudProvider, HashSet<String>>` for selector-keyed persistence
- `src/tui/app/methods.rs` — `visible_categories`, `visible_items_in_category`, `category_bounds`, `selected_in_category` all work off the current provider's data
- `src/tui/ui/collectors.rs` — drop the AWS-only assumptions; drop `provider_badge` from item rendering (all items in view are the current provider)
- `src/tui/events.rs` — ProviderSelection handler rebuilds `app.collector_items` from `PROVIDER_MENUS`
- `src/tui/app/mod.rs` — update tests to use per-provider fixtures
