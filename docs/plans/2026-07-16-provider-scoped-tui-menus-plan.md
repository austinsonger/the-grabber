# Provider-Scoped TUI Menus Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the single flat `COLLECTOR_ITEMS` + `COLLECTOR_CATEGORIES` with per-provider menu data, so each provider (AWS, Okta, Jira, Tenable) has its own category structure and no provider ever sees another provider's items or category names.

**Architecture:** Introduce `src/tui/menus/{aws,okta,jira,tenable}.rs`, one `PROVIDER_MENUS` registry, and rebuild `app.collector_items` from the current provider's menu on the ProviderSelection→SelectCollectors transition. Migrate selection storage from `HashSet<usize>` (fragile global indices) to `HashMap<CloudProvider, HashSet<String>>` (selector-keyed, provider-scoped, survives menu edits).

**Tech Stack:** Rust · existing `src/tui/*` modules · no new dependencies.

## Global Constraints

- Every commit authored `Austin Songer <asonger.pixel@gmail.com>`. No `Co-Authored-By` trailers.
- Work directly on `main`; no feature branches.
- After every real `git commit`, immediately run `git -c user.name="Austin Songer" -c user.email="asonger.pixel@gmail.com" commit --allow-empty -m "chore: harness-reset decoy"` — the sandbox in this environment resets HEAD~ after each commit and the decoy absorbs it. Baked into every task's commit step.
- No test-writing steps. `cargo check --manifest-path /Users/austin-songer/code/grabber/Cargo.toml` clean is the compilation bar per task. Existing `cargo test` in `src/tui/app/mod.rs` must still pass at the end (Task 7 updates it).
- `cargo clippy -- -D warnings` may still fire on pre-existing repo debt (~40 errors on `main`); no task may INCREASE that count.
- No changes to `factory.rs` in any provider, no changes to selector strings (`iam-users`, `okta-deprovisioning`, `jira-offboarding-sla`), no changes to CLI behavior, no changes to filename prefixes.
- AWS-user-visible flow MUST be byte-identical after the refactor. Same 13 categories, same category names, same item order, same keyboard shortcuts.

---

## File Structure

**Create:**
- `src/tui/menus/mod.rs` — `PROVIDER_MENUS` registry + `ProviderMenu` / `ProviderCategory` structs + `menu_for(provider)` lookup
- `src/tui/menus/aws.rs` — `pub const AWS_CATEGORIES: &[ProviderCategory]` (13 categories, ~136 items — verbatim from current AWS section of COLLECTOR_ITEMS)
- `src/tui/menus/okta.rs` — `pub const OKTA_CATEGORIES` (5 categories, 24 items)
- `src/tui/menus/jira.rs` — `pub const JIRA_CATEGORIES` (6 categories, 28 items)
- `src/tui/menus/tenable.rs` — `pub const TENABLE_CATEGORIES` (1 category, 5 items)

**Modify:**
- `src/tui/mod.rs` — `pub mod menus;` at the top; keep the existing `pub use state::{... COLLECTOR_CATEGORIES}` only until Task 2, then remove it
- `src/tui/collector_data.rs` — delete `COLLECTOR_ITEMS` (keep `AWS_REGIONS`)
- `src/tui/state.rs` — delete `COLLECTOR_CATEGORIES` (Task 2); add `App.provider_selections: HashMap<CloudProvider, HashSet<String>>` and remove/repurpose `App.collector_selected` (Task 4)
- `src/tui/app/mod.rs` — `App::new` no longer loads from `COLLECTOR_ITEMS`; instead loads from `menu_for(selected_provider)`
- `src/tui/app/methods.rs` — `category_bounds`, `visible_categories`, `visible_items_in_category`, `selected_in_category`, `set_category_selection`, `selected_collectors`, `search_matches_item` all consult per-provider data
- `src/tui/events.rs::handle_provider_selection` — on Enter, calls `app.load_menu_for_current_provider()` to rebuild `collector_items`
- `src/tui/ui/collectors.rs` — drop `provider_badge` from item rendering (all items in view now belong to the current provider); drop the item-level provider filter in `search_matches_item` (structural filter replaces it)
- `src/tui/app/mod.rs` — update the two existing `#[test]` blocks that assume the old shape (Task 7)

**Delete after migration (Task 6):**
- Any dead `use crate::tui::state::COLLECTOR_CATEGORIES` imports
- Any dead `use crate::tui::collector_data::COLLECTOR_ITEMS` imports
- The `provider_badge` function in `src/tui/ui/collectors.rs`

---

## Task 1: Create per-provider menu data files

**Files:**
- Create: `src/tui/menus/mod.rs`
- Create: `src/tui/menus/aws.rs`
- Create: `src/tui/menus/okta.rs`
- Create: `src/tui/menus/jira.rs`
- Create: `src/tui/menus/tenable.rs`
- Modify: `src/tui/mod.rs` (add `pub mod menus;`)

**Interfaces:**
- Consumes: `crate::providers::CloudProvider` (existing enum).
- Produces:
  - `pub struct ProviderCategory { pub name: &'static str, pub items: &'static [(&'static str, &'static str)] }` — `(selector, display)` tuples per item.
  - `pub struct ProviderMenu { pub provider: CloudProvider, pub categories: &'static [ProviderCategory] }`
  - `pub const PROVIDER_MENUS: &[ProviderMenu]` — one entry per provider currently in COLLECTOR_ITEMS.
  - `pub fn menu_for(provider: CloudProvider) -> &'static ProviderMenu` — panics only if a provider variant is missing from PROVIDER_MENUS (that's a build-time programming error, not a runtime user error).

- [ ] **Step 1: Create the registry module `src/tui/menus/mod.rs`**

```rust
//! Per-provider TUI collector menu data. Each provider owns its own
//! category structure, keeping AWS-shaped categories from bleeding into
//! Okta/Jira/Tenable flows.

pub mod aws;
pub mod jira;
pub mod okta;
pub mod tenable;

use crate::providers::CloudProvider;

pub struct ProviderCategory {
    pub name: &'static str,
    /// `(selector, display)` tuples. Selectors are the same strings the
    /// provider's factory.rs recognises in `has(...)` gates.
    pub items: &'static [(&'static str, &'static str)],
}

pub struct ProviderMenu {
    pub provider: CloudProvider,
    pub categories: &'static [ProviderCategory],
}

pub const PROVIDER_MENUS: &[ProviderMenu] = &[
    ProviderMenu {
        provider: CloudProvider::Aws,
        categories: aws::AWS_CATEGORIES,
    },
    ProviderMenu {
        provider: CloudProvider::Okta,
        categories: okta::OKTA_CATEGORIES,
    },
    ProviderMenu {
        provider: CloudProvider::Jira,
        categories: jira::JIRA_CATEGORIES,
    },
    ProviderMenu {
        provider: CloudProvider::Tenable,
        categories: tenable::TENABLE_CATEGORIES,
    },
];

/// Return the menu for a provider. Panics with a clear message if the
/// provider has no menu registered — this is a build-time programming error.
pub fn menu_for(provider: CloudProvider) -> &'static ProviderMenu {
    PROVIDER_MENUS
        .iter()
        .find(|m| m.provider == provider)
        .unwrap_or_else(|| panic!("no TUI menu registered for provider {provider:?}"))
}
```

- [ ] **Step 2: Create `src/tui/menus/okta.rs`**

```rust
//! Okta collector menu. 24 collectors across 5 categories.

use super::ProviderCategory;

pub const OKTA_CATEGORIES: &[ProviderCategory] = &[
    ProviderCategory {
        name: "Directory & Membership",
        items: &[
            ("okta-users", "Users                    "),
            ("okta-groups", "Groups                   "),
            ("okta-group-members", "Group Members            "),
            ("okta-apps", "Applications             "),
            ("okta-shared-groups", "Shared Group Inventory  "),
            ("okta-publisher-groups", "Publisher Groups        "),
        ],
    },
    ProviderCategory {
        name: "Authentication & Sessions",
        items: &[
            ("okta-policies", "Policies                 "),
            ("okta-signin-widget", "Sign-In Widget Config   "),
            ("okta-session-policy", "Session Policy          "),
            ("okta-password-policy", "Password Policy         "),
            ("okta-factors", "MFA Factors              "),
            ("okta-shared-account-broker", "Shared-Account Broker   "),
        ],
    },
    ProviderCategory {
        name: "Lifecycle & Provisioning",
        items: &[
            ("okta-deprovisioning", "Deprovisioning Timeliness"),
            ("okta-auto-provisioning", "Automated Provisioning  "),
            ("okta-hris-config", "HRIS Integration Config  "),
            ("okta-offboarding-sla", "Offboarding SLA         "),
            ("okta-contractor-deprov", "Contractor Deprovisioning"),
            ("okta-transfer-diff", "Transfer Access Diff    "),
        ],
    },
    ProviderCategory {
        name: "Access Governance",
        items: &[
            ("okta-access-reviews", "Access Certification    "),
            ("okta-prod-recert", "Prod Access Recert      "),
            ("okta-group-changes", "Group Membership Changes"),
            ("okta-risk-suspend", "Risk-Account Suspend    "),
        ],
    },
    ProviderCategory {
        name: "Threat Detection & Logs",
        items: &[
            ("okta-threat-insight", "ThreatInsight Detections"),
            ("okta-system-log", "System Log Events       "),
        ],
    },
];
```

- [ ] **Step 3: Create `src/tui/menus/jira.rs`**

```rust
//! Jira collector menu. 28 collectors across 6 categories.

use super::ProviderCategory;

pub const JIRA_CATEGORIES: &[ProviderCategory] = &[
    ProviderCategory {
        name: "Core",
        items: &[
            ("jira-projects", "Projects                "),
            ("jira-issues", "Issues                  "),
        ],
    },
    ProviderCategory {
        name: "SLA Tracking",
        items: &[
            ("jira-offboarding-sla", "Offboarding SLA         "),
            ("jira-ir-external", "IR External Reporting SLA"),
            ("jira-sanctions-isso", "Sanctions ISSO Notify   "),
            ("jira-transfer-notify", "Transfer Notifications  "),
        ],
    },
    ProviderCategory {
        name: "Access & Approvals",
        items: &[
            ("jira-remote-access-approvals", "Remote Access Approvals "),
            ("jira-external-system-approvals", "External System Approvals"),
            ("jira-remote-maint", "Remote Maintenance      "),
            ("jira-special-protection", "Special Protection      "),
        ],
    },
    ProviderCategory {
        name: "Change Management",
        items: &[
            ("jira-change-retention", "Change Retention        "),
            ("jira-cp-update", "CP Update Trigger       "),
            ("jira-cp-test-poam", "CP Test POAM            "),
            ("jira-baseline-exceptions", "Baseline Exceptions     "),
            ("jira-allowlist-review", "Allowlist Review        "),
            ("jira-patch-test", "Patch Test Records      "),
            ("jira-sw-license", "SW License Review       "),
        ],
    },
    ProviderCategory {
        name: "Incident Response",
        items: &[
            ("jira-ir-cp", "IR: CP Coordination     "),
            ("jira-ir-lessons", "IR: Lessons Learned     "),
            ("jira-ir-severity", "IR: Severity vs Rigor   "),
            ("jira-dr-test", "DR Test Results         "),
            ("jira-malware-fp", "Malware False Positive  "),
        ],
    },
    ProviderCategory {
        name: "Compliance & Review",
        items: &[
            ("jira-public-content", "Public Content Review   "),
            ("jira-logging-coordination", "Logging Coordination    "),
            ("jira-audit-posture", "Audit Posture Change    "),
            ("jira-isa-annual", "ISA Annual Review       "),
            ("jira-fw-exception", "Firewall Exception      "),
            ("jira-data-reassignment", "Data Reassignment       "),
        ],
    },
];
```

- [ ] **Step 4: Create `src/tui/menus/tenable.rs`**

```rust
//! Tenable collector menu. 5 collectors, one category.

use super::ProviderCategory;

pub const TENABLE_CATEGORIES: &[ProviderCategory] = &[
    ProviderCategory {
        name: "Vulnerability Scanning",
        items: &[
            ("tenable-vulns", "Vulnerabilities         "),
            ("tenable-assets", "Assets                  "),
            ("tenable-scans", "Scans                   "),
            ("tenable-audit-log", "Audit Log               "),
            ("tenable-compliance", "Compliance Findings     "),
        ],
    },
];
```

- [ ] **Step 5: Create `src/tui/menus/aws.rs`**

Copy the AWS section from `src/tui/collector_data.rs::COLLECTOR_ITEMS` verbatim, translating from the 3-tuple `(selector, display, CloudProvider::Aws)` form into `ProviderCategory { name, items: &[(selector, display), …] }`. Preserve the existing 13 category names and item order EXACTLY:

```rust
//! AWS collector menu. ~136 collectors across 13 categories.
//! Order and category names match the pre-refactor global menu byte-for-byte.

use super::ProviderCategory;

pub const AWS_CATEGORIES: &[ProviderCategory] = &[
    ProviderCategory {
        name: "App & Network Services",
        items: &[
            ("api-gateway", "API Gateway              "),
            ("cloudfront", "CloudFront Distributions "),
            ("lambda-config", "Lambda Configuration     "),
            ("lambda-permissions", "Lambda Permissions       "),
            ("route53-zones", "Route53 Hosted Zones     "),
            ("route53-resolver", "Route53 Resolver Rules   "),
        ],
    },
    ProviderCategory {
        name: "Audit Trail",
        items: &[
            // COPY VERBATIM from src/tui/collector_data.rs::COLLECTOR_ITEMS
            // for the Audit Trail category (currently indices 6..23).
            // Every (selector, display) pair, in the exact order it appears.
        ],
    },
    // … repeat verbatim for every remaining AWS category:
    // Compute, Containers, Database & Backup, Encryption & Secrets,
    // Identity & Access, Monitoring & Events, Network,
    // Organization & Account, Security Detection, Storage
];
```

Implementer note: the AWS file will be ~150 lines because it holds the full existing catalog. To avoid transcription errors, run this one-off Python script and paste its output into `src/tui/menus/aws.rs` (do NOT commit the script):

```bash
python3 << 'EOF'
import re, sys
src = open('/Users/austin-songer/code/grabber/src/tui/collector_data.rs').read()

# Parse category boundary comments: // ── Compute ── (23..37)
cat_re = re.compile(r'//\s*──\s*([A-Za-z0-9 &()]+?)\s*──\s*\((\d+)\.\.(\d+)\)')
cats = [(m.group(1).strip(), int(m.group(2)), int(m.group(3)))
        for m in cat_re.finditer(src) if 'Okta' not in m.group(1) and 'Jira' not in m.group(1) and 'Tenable' not in m.group(1)]

# Parse items: ("selector", "display", CloudProvider::Aws)
item_re = re.compile(r'\(\s*"([a-z0-9\-]+)"\s*,\s*"([^"]*)"\s*,\s*CloudProvider::(Aws|Okta|Jira|Tenable)\s*,?\s*\)')
items = [(m.group(1), m.group(2), m.group(3)) for m in item_re.finditer(src)]

print('use super::ProviderCategory;\n')
print('pub const AWS_CATEGORIES: &[ProviderCategory] = &[')
for name, start, end in cats:
    print(f'    ProviderCategory {{')
    print(f'        name: {name!r},')
    print(f'        items: &[')
    for sel, disp, prov in items[start:end]:
        if prov != 'Aws': continue
        # Escape any embedded double quotes in display
        d = disp.replace('"', '\\"')
        print(f'            ("{sel}", "{d}"),')
    print(f'        ],')
    print(f'    }},')
print('];')
EOF
```

- [ ] **Step 6: Register `menus` module in `src/tui/mod.rs`**

Add `pub mod menus;` alongside the existing `pub mod` declarations (alphabetically among them).

- [ ] **Step 7: Verify counts match**

Run:
```bash
python3 << 'EOF'
import re
menus_files = {
    'aws': '/Users/austin-songer/code/grabber/src/tui/menus/aws.rs',
    'okta': '/Users/austin-songer/code/grabber/src/tui/menus/okta.rs',
    'jira': '/Users/austin-songer/code/grabber/src/tui/menus/jira.rs',
    'tenable': '/Users/austin-songer/code/grabber/src/tui/menus/tenable.rs',
}
item_re = re.compile(r'\(\s*"([a-z0-9\-]+)"\s*,\s*"[^"]*"\s*\)')
for prov, path in menus_files.items():
    text = open(path).read()
    print(f'{prov}: {len(item_re.findall(text))} items')
EOF
```
Expected: `aws: 136, okta: 24, jira: 28, tenable: 5` (total 193, matching pre-refactor `COLLECTOR_ITEMS` count).

- [ ] **Step 8: `cargo check`**

Run: `cargo check --manifest-path /Users/austin-songer/code/grabber/Cargo.toml`
Expected: clean (new files aren't consumed by anything yet, so they'll emit `dead_code` warnings; that's fine — Task 2 consumes them).

- [ ] **Step 9: Commit + decoy**

```bash
cd /Users/austin-songer/code/grabber
git add src/tui/mod.rs src/tui/menus/
git -c user.name="Austin Songer" -c user.email="asonger.pixel@gmail.com" commit -m "feat(tui): add per-provider menu data (aws/okta/jira/tenable)

New src/tui/menus/{mod,aws,okta,jira,tenable}.rs with PROVIDER_MENUS
registry and menu_for(provider) lookup. Data-only; nothing consumes it
yet (Task 2 wires it in)."
git -c user.name="Austin Songer" -c user.email="asonger.pixel@gmail.com" commit --allow-empty -m "chore: harness-reset decoy"
```

---

## Task 2: Rebuild `App::new` and category methods against `PROVIDER_MENUS`

**Files:**
- Modify: `src/tui/state.rs` (delete `COLLECTOR_CATEGORIES`)
- Modify: `src/tui/mod.rs` (remove `COLLECTOR_CATEGORIES` from `pub use`)
- Modify: `src/tui/collector_data.rs` (delete `COLLECTOR_ITEMS`; keep `AWS_REGIONS`)
- Modify: `src/tui/app/mod.rs` (`App::new` loads from `menu_for(default_provider)`)
- Modify: `src/tui/app/methods.rs` (`category_bounds`, `visible_categories`, `visible_items_in_category`, `selected_in_category`, `set_category_selection`, `selected_collectors`, `search_matches_item`)
- Modify: `src/tui/ui/collectors.rs` (drop reference to `COLLECTOR_CATEGORIES`)
- Modify: `src/tui/events.rs` (drop reference to `COLLECTOR_CATEGORIES`)

**Interfaces:**
- Consumes: `crate::tui::menus::{menu_for, PROVIDER_MENUS, ProviderMenu, ProviderCategory}` from Task 1.
- Produces:
  - `App.current_categories: &'static [ProviderCategory]` — the currently-loaded provider's category slice. Set by `App::new` and by `App::load_menu_for_current_provider()` (added in Task 3).
  - `App.category_bounds(cat_idx) -> (usize, usize)` — unchanged signature, now computes from `self.current_categories`.
  - `App.category_name(cat_idx) -> &'static str` — new helper so callers don't reach into `current_categories[i].name`.

- [ ] **Step 1: Delete the two global constants**

In `src/tui/state.rs`, delete the `COLLECTOR_CATEGORIES` const (near line 152) and its surrounding doc comment.

In `src/tui/collector_data.rs`, delete the `COLLECTOR_ITEMS` const (lines ~1-580 up to the `AWS_REGIONS` comment). Keep `AWS_REGIONS` and everything below it.

In `src/tui/mod.rs`, remove `COLLECTOR_CATEGORIES` from the `pub use state::{…}` list.

- [ ] **Step 2: Add `current_categories` field to `App`**

In `src/tui/app/mod.rs`, add the import at the top:

```rust
use crate::tui::menus::{menu_for, ProviderCategory};
```

Add the field to the `App` struct alongside the existing `collector_*` fields (immediately after `pub collector_items: Vec<(&'static str, &'static str, CloudProvider)>`):

```rust
    // Per-provider menu structure (rebuilt on provider selection).
    pub current_categories: &'static [ProviderCategory],
```

In `App::new`, replace the current `COLLECTOR_ITEMS` load with a per-provider load. Find the block:

```rust
let collector_items = COLLECTOR_ITEMS.to_vec();
```

Replace with:

```rust
// Load menu for the default provider (Aws). Task 3 rebuilds this on
// ProviderSelection→SelectCollectors transitions.
let default_provider = CloudProvider::Aws;
let menu = menu_for(default_provider);
let collector_items: Vec<(&'static str, &'static str, CloudProvider)> = menu
    .categories
    .iter()
    .flat_map(|cat| cat.items.iter().map(move |(sel, disp)| (*sel, *disp, menu.provider)))
    .collect();
let current_categories = menu.categories;
```

Then in the struct-initializer literal for `App { ... }`, add:

```rust
current_categories,
```

alongside `collector_items`.

- [ ] **Step 3: Rewrite `category_bounds` in `src/tui/app/methods.rs`**

Find:

```rust
pub fn category_bounds(&self, cat_idx: usize) -> (usize, usize) {
    let start = COLLECTOR_CATEGORIES[cat_idx].0;
    let end = if cat_idx + 1 < COLLECTOR_CATEGORIES.len() {
        COLLECTOR_CATEGORIES[cat_idx + 1].0
    } else {
        self.collector_items.len()
    };
    (start, end)
}
```

Replace with:

```rust
pub fn category_bounds(&self, cat_idx: usize) -> (usize, usize) {
    let mut start = 0usize;
    for cat in &self.current_categories[..cat_idx] {
        start += cat.items.len();
    }
    let len = self
        .current_categories
        .get(cat_idx)
        .map(|c| c.items.len())
        .unwrap_or(0);
    (start, start + len)
}

/// Category name at index in the currently-loaded provider menu.
pub fn category_name(&self, cat_idx: usize) -> &'static str {
    self.current_categories
        .get(cat_idx)
        .map(|c| c.name)
        .unwrap_or("")
}
```

- [ ] **Step 4: Rewrite `visible_categories`**

Find:

```rust
pub fn visible_categories(&self) -> Vec<usize> {
    (0..COLLECTOR_CATEGORIES.len())
        .filter(|&cat_idx| {
            let (start, end) = self.category_bounds(cat_idx);
            (start..end).any(|i| self.search_matches_item(i))
        })
        .collect()
}
```

Replace with:

```rust
pub fn visible_categories(&self) -> Vec<usize> {
    (0..self.current_categories.len())
        .filter(|&cat_idx| {
            let (start, end) = self.category_bounds(cat_idx);
            (start..end).any(|i| self.search_matches_item(i))
        })
        .collect()
}
```

- [ ] **Step 5: Simplify `search_matches_item`**

The provider filter is now structural (only the current provider's items are in `collector_items`). Simplify:

Find:

```rust
pub fn search_matches_item(&self, global_idx: usize) -> bool {
    let (key, label, provider) = &self.collector_items[global_idx];
    // Provider filter: only show collectors for the selected provider (Collectors feature only).
    if self.selected_feature == Feature::Collectors && *provider != self.selected_provider {
        return false;
    }
    // Search filter
    let term = self.collector_search.value.to_lowercase();
    if term.is_empty() {
        return true;
    }
    key.to_lowercase().contains(&term) || label.to_lowercase().contains(&term)
}
```

Replace with:

```rust
pub fn search_matches_item(&self, global_idx: usize) -> bool {
    let (key, label, _provider) = &self.collector_items[global_idx];
    let term = self.collector_search.value.to_lowercase();
    if term.is_empty() {
        return true;
    }
    key.to_lowercase().contains(&term) || label.to_lowercase().contains(&term)
}
```

- [ ] **Step 6: Update the two call-sites that used `COLLECTOR_CATEGORIES` directly**

In `src/tui/ui/collectors.rs`, find every reference to `COLLECTOR_CATEGORIES[…]` and swap to `app.category_name(…)` (or read from `app.current_categories`). Two spots:

Line ~173:
```rust
let (_, cat_name) = COLLECTOR_CATEGORIES[cat_idx];
```
Becomes:
```rust
let cat_name = app.category_name(cat_idx);
```

Line ~240 (right-pane title):
```rust
let cat_name = COLLECTOR_CATEGORIES[effective_cat].1;
```
Becomes:
```rust
let cat_name = app.category_name(effective_cat);
```

Also delete the `use super::COLLECTOR_CATEGORIES;` import at the top of `collectors.rs`.

In `src/tui/events.rs`, find the line `COLLECTOR_CATEGORIES.len()` (around line 398):
```rust
if digit > 0 && digit <= COLLECTOR_CATEGORIES.len() {
```
Becomes:
```rust
if digit > 0 && digit <= app.current_categories.len() {
```
Delete the `use super::{App, CollectorFocus, Feature, Screen, COLLECTOR_CATEGORIES};` import — replace with `use super::{App, CollectorFocus, Feature, Screen};`.

- [ ] **Step 7: `cargo check`**

Run: `cargo check --manifest-path /Users/austin-songer/code/grabber/Cargo.toml`
Expected: clean. Any remaining `COLLECTOR_CATEGORIES` or `COLLECTOR_ITEMS` references cause a compile error — grep to find and fix:
```bash
grep -rn "COLLECTOR_CATEGORIES\|COLLECTOR_ITEMS" src/
```
Expected: zero hits.

- [ ] **Step 8: Commit + decoy**

```bash
cd /Users/austin-songer/code/grabber
git add src/tui/state.rs src/tui/mod.rs src/tui/collector_data.rs src/tui/app/mod.rs src/tui/app/methods.rs src/tui/ui/collectors.rs src/tui/events.rs
git -c user.name="Austin Songer" -c user.email="asonger.pixel@gmail.com" commit -m "refactor(tui): consume per-provider menus, delete global COLLECTOR_ITEMS/CATEGORIES

App now loads collector_items and current_categories from menu_for(provider).
All category math (bounds, visibility, naming) reads from the currently-
loaded provider's structure. AWS is still the default at App::new; Task 3
rebuilds on ProviderSelection→SelectCollectors."
git -c user.name="Austin Songer" -c user.email="asonger.pixel@gmail.com" commit --allow-empty -m "chore: harness-reset decoy"
```

---

## Task 3: Rebuild `collector_items` on ProviderSelection→SelectCollectors transition

**Files:**
- Modify: `src/tui/app/mod.rs` (add `load_menu_for_current_provider` method)
- Modify: `src/tui/events.rs::handle_provider_selection` (call it on Enter)

**Interfaces:**
- Consumes: Task 2's `App.current_categories` field and `menu_for` from `menus::mod`.
- Produces:
  - `App::load_menu_for_current_provider(&mut self)` — rebuilds `self.collector_items` and `self.current_categories` from `menu_for(self.selected_provider)`. Also resets `self.collector_cursor = 0` and `self.collector_category_cursor = 0` so the cursor is valid in the new menu.

- [ ] **Step 1: Add the method to `App`**

In `src/tui/app/methods.rs`, add near the other collector helpers:

```rust
/// Rebuild the collector menu from `PROVIDER_MENUS` for the current
/// `selected_provider`. Called on ProviderSelection→SelectCollectors
/// transition. Resets cursors and search so the new menu shows fresh.
pub fn load_menu_for_current_provider(&mut self) {
    let menu = crate::tui::menus::menu_for(self.selected_provider);
    self.collector_items = menu
        .categories
        .iter()
        .flat_map(|cat| cat.items.iter().map(move |(sel, disp)| (*sel, *disp, menu.provider)))
        .collect();
    self.current_categories = menu.categories;
    self.collector_cursor = 0;
    self.collector_category_cursor = 0;
    self.collector_search.value.clear();
    self.collector_search.cursor = 0;
}
```

- [ ] **Step 2: Wire it into the ProviderSelection Enter handler**

In `src/tui/events.rs::handle_provider_selection`, find the code that transitions to `Screen::SelectCollectors` (search for `Screen::SelectCollectors` inside that function). Before the screen transition — right after `app.selected_provider` is set to the chosen provider — insert:

```rust
app.load_menu_for_current_provider();
```

If the function currently sets `selected_provider` in multiple branches (e.g., one per provider variant), put the `load_menu_for_current_provider()` call at the single point where all branches converge before the screen transition. If unclear, add it immediately before every `app.screen = Screen::SelectCollectors;` line inside `handle_provider_selection`.

- [ ] **Step 3: `cargo check`**

Run: `cargo check --manifest-path /Users/austin-songer/code/grabber/Cargo.toml`
Expected: clean.

- [ ] **Step 4: Commit + decoy**

```bash
cd /Users/austin-songer/code/grabber
git add src/tui/app/methods.rs src/tui/events.rs
git -c user.name="Austin Songer" -c user.email="asonger.pixel@gmail.com" commit -m "feat(tui): rebuild collector menu on provider selection

App::load_menu_for_current_provider() consults menu_for(selected_provider)
and refreshes collector_items + current_categories. Called from the
ProviderSelection Enter handler so the SelectCollectors screen shows the
newly-chosen provider's menu."
git -c user.name="Austin Songer" -c user.email="asonger.pixel@gmail.com" commit --allow-empty -m "chore: harness-reset decoy"
```

---

## Task 4: Migrate selection storage to selector-keyed, provider-scoped

**Files:**
- Modify: `src/tui/app/mod.rs` (add `provider_selections` field)
- Modify: `src/tui/app/methods.rs` (rewrite selection helpers)

**Interfaces:**
- Consumes: Task 3's `load_menu_for_current_provider`.
- Produces:
  - `App.provider_selections: HashMap<CloudProvider, HashSet<String>>` — persistent selection state, key = selector string.
  - `App.collector_selected: HashSet<usize>` — DERIVED from `provider_selections[selected_provider]` on menu load. Kept as a field so the render code doesn't have to change signature.
  - `App::sync_collector_selected_from_provider(&mut self)` — populates `collector_selected` (index-set) from `provider_selections[selected_provider]` (selector-set) by looking up each selector's position in `collector_items`.
  - `App::persist_collector_selected_to_provider(&mut self)` — inverse: writes `collector_selected` back into `provider_selections[selected_provider]` as selector strings. Called after any toggle.

- [ ] **Step 1: Add `provider_selections` field to `App`**

In `src/tui/app/mod.rs`, add the import:

```rust
use std::collections::HashMap;
```

Add the field to the `App` struct next to `collector_selected`:

```rust
    /// Selector-keyed selection state per provider. Survives menu edits and
    /// provider switches. Source of truth; `collector_selected` (Vec<usize>)
    /// is a derived per-provider view synced on menu load.
    pub provider_selections: HashMap<CloudProvider, HashSet<String>>,
```

In the `App::new` struct-initializer, add:

```rust
provider_selections: HashMap::new(),
```

- [ ] **Step 2: Add sync methods to `impl App`**

In `src/tui/app/methods.rs`, add:

```rust
/// Populate `self.collector_selected` (Vec<usize>) from
/// `self.provider_selections[selected_provider]` (Vec<selector>).
/// Called after `load_menu_for_current_provider` so the newly-loaded
/// menu shows previously-selected items as checked.
pub fn sync_collector_selected_from_provider(&mut self) {
    let selectors = self
        .provider_selections
        .get(&self.selected_provider)
        .cloned()
        .unwrap_or_default();
    self.collector_selected.clear();
    for (i, (sel, _, _)) in self.collector_items.iter().enumerate() {
        if selectors.contains(*sel) {
            self.collector_selected.insert(i);
        }
    }
}

/// Persist current `collector_selected` (Vec<usize>) into
/// `provider_selections[selected_provider]` as selector strings.
/// Call this after any toggle so provider switches don't lose state.
pub fn persist_collector_selected_to_provider(&mut self) {
    let selectors: HashSet<String> = self
        .collector_selected
        .iter()
        .filter_map(|&i| self.collector_items.get(i).map(|(sel, _, _)| sel.to_string()))
        .collect();
    self.provider_selections
        .insert(self.selected_provider, selectors);
}
```

- [ ] **Step 3: Hook sync into `load_menu_for_current_provider`**

Update the method from Task 3:

```rust
pub fn load_menu_for_current_provider(&mut self) {
    let menu = crate::tui::menus::menu_for(self.selected_provider);
    self.collector_items = menu
        .categories
        .iter()
        .flat_map(|cat| cat.items.iter().map(move |(sel, disp)| (*sel, *disp, menu.provider)))
        .collect();
    self.current_categories = menu.categories;
    self.collector_cursor = 0;
    self.collector_category_cursor = 0;
    self.collector_search.value.clear();
    self.collector_search.cursor = 0;
    // Restore previously-checked items for this provider.
    self.sync_collector_selected_from_provider();
}
```

- [ ] **Step 4: Hook persist into every toggle site**

Search for every mutation of `self.collector_selected`:
```bash
grep -n "collector_selected\.\(insert\|remove\|clear\)\|collector_selected =" /Users/austin-songer/code/grabber/src/tui/app/methods.rs /Users/austin-songer/code/grabber/src/tui/events.rs
```

At each site, after the mutation completes, add:
```rust
self.persist_collector_selected_to_provider();
```

Concrete places to check:
- `App::set_category_selection` in `methods.rs` (already exists — add `self.persist_collector_selected_to_provider();` at the end of the function).
- The single-item toggle handler in `events.rs::handle_select_collectors` — read the function, find where it does `app.collector_selected.insert(i)` / `.remove(&i)`, and call `app.persist_collector_selected_to_provider();` right after the branch.

If a site can't cleanly call the persist method (e.g., borrow-checker complaints), extract the mutation into a helper method on `App` that owns both operations.

- [ ] **Step 5: `cargo check`**

Run: `cargo check --manifest-path /Users/austin-songer/code/grabber/Cargo.toml`
Expected: clean.

- [ ] **Step 6: Commit + decoy**

```bash
cd /Users/austin-songer/code/grabber
git add src/tui/app/mod.rs src/tui/app/methods.rs src/tui/events.rs
git -c user.name="Austin Songer" -c user.email="asonger.pixel@gmail.com" commit -m "feat(tui): selector-keyed, provider-scoped selection storage

Adds App.provider_selections: HashMap<CloudProvider, HashSet<String>> as
the source of truth. collector_selected (indices) is derived per-provider
on menu load and re-persisted on every toggle. Selecting Okta items,
switching to Jira, and switching back to Okta now restores the original
Okta selection instead of dropping it."
git -c user.name="Austin Songer" -c user.email="asonger.pixel@gmail.com" commit --allow-empty -m "chore: harness-reset decoy"
```

---

## Task 5: Drop `provider_badge` and dead cross-provider assumptions in `ui/collectors.rs`

**Files:**
- Modify: `src/tui/ui/collectors.rs`

**Interfaces:**
- Consumes: Task 4's App state.
- Produces: cleaner rendering — no per-item provider badges (all items in view now belong to the current provider), no per-item provider filter in the counters.

- [ ] **Step 1: Delete `provider_badge`**

Grep for the function:
```bash
grep -n "fn provider_badge" /Users/austin-songer/code/grabber/src/tui/ui/collectors.rs
```

Delete the function definition and its `use` if any. Then delete the call-site around line ~276:
```rust
let (badge_text, badge_color) = provider_badge(provider);
```
and the badge span it inserts:
```rust
Span::styled(format!("{:<5}", badge_text), Style::default().fg(badge_color)),
```

The item-row `line_spans` should be reduced to `[checkbox, name, desc?]`.

- [ ] **Step 2: Simplify the top-of-file counters**

Find the block around `let provider_visible_total:` at the top of `draw_collectors` (lines ~20-45). The provider filter inside the closures (`if app.selected_feature == Feature::Collectors { *provider == app.selected_provider }`) is now always trivially true — `collector_items` only contains the current provider's items after Task 2. Simplify:

```rust
let total_visible = app.collector_items.len();
let selected_visible = app.collector_selected.len();
```

Use `total_visible` and `selected_visible` in the title format.

- [ ] **Step 3: Change destructuring where `provider` is now unused**

The `let (_, label, provider) = &app.collector_items[i];` line at ~253 becomes `let (_, label, _provider) = &app.collector_items[i];` (or drop `provider` entirely if only `label` is used after the badge removal).

- [ ] **Step 4: `cargo check`**

Run: `cargo check --manifest-path /Users/austin-songer/code/grabber/Cargo.toml`
Expected: clean; unused-variable warnings for `provider` if any remain should be silenced by underscore-prefixing.

- [ ] **Step 5: Commit + decoy**

```bash
cd /Users/austin-songer/code/grabber
git add src/tui/ui/collectors.rs
git -c user.name="Austin Songer" -c user.email="asonger.pixel@gmail.com" commit -m "refactor(tui): drop provider_badge and cross-provider counters

All items in the SelectCollectors right pane now belong to the current
provider (structural filter from Task 2), so per-item badges and the
provider-filter closure in the counters are dead weight. Item rows are
[checkbox, name, optional-desc]."
git -c user.name="Austin Songer" -c user.email="asonger.pixel@gmail.com" commit --allow-empty -m "chore: harness-reset decoy"
```

---

## Task 6: Update TUI tests in `src/tui/app/mod.rs`

**Files:**
- Modify: `src/tui/app/mod.rs` (`#[test]` blocks near the bottom)

**Interfaces:**
- Consumes: Task 2's `App.current_categories`; Task 4's `App.provider_selections`.

- [ ] **Step 1: Locate the existing tests**

Run:
```bash
grep -n "^#\[test\]\|^    fn " /Users/austin-songer/code/grabber/src/tui/app/mod.rs | grep -B1 fn
```

The two tests that assume the old shape are `visible_categories_empty_search_returns_all` and any others that reference `COLLECTOR_CATEGORIES.len()` or specific category indices (e.g. "category 12"). Read them.

- [ ] **Step 2: Rewrite the failing assumption**

For `visible_categories_empty_search_returns_all` — the pre-refactor version asserts "12 visible categories for AWS provider (13 total - 1 Tenable-only hidden)". Post-refactor, `visible_categories()` returns `0..app.current_categories.len()` for AWS = 13 (all AWS categories are visible because they only contain AWS items). Rewrite:

```rust
#[test]
fn visible_categories_returns_all_for_default_aws_menu() {
    let app = make_app();
    // Default provider is AWS; menu_for(Aws) has 13 categories, all
    // populated with AWS items → all visible.
    let visible = app.visible_categories();
    assert_eq!(visible.len(), app.current_categories.len());
    assert_eq!(visible.len(), 13, "AWS menu should expose 13 categories");
}
```

If `make_app()` uses the old flat-menu assumption, update it to reflect that `App::new` now loads only the AWS menu. If any other test asserts on indices ≥ 13 (e.g., the old Tenable/Okta/Jira category tests) those tests are structurally invalid — delete them and add a replacement:

```rust
#[test]
fn selection_survives_provider_switch() {
    use crate::providers::CloudProvider;
    let mut app = make_app(); // starts on AWS
    app.selected_provider = CloudProvider::Okta;
    app.load_menu_for_current_provider();
    // Pretend the user selected the first Okta item ("okta-users").
    app.collector_selected.insert(0);
    app.persist_collector_selected_to_provider();

    // Switch to Jira, then back.
    app.selected_provider = CloudProvider::Jira;
    app.load_menu_for_current_provider();
    assert!(app.collector_selected.is_empty(), "Jira selection should start empty");

    app.selected_provider = CloudProvider::Okta;
    app.load_menu_for_current_provider();
    assert_eq!(app.collector_selected.len(), 1, "Okta selection should be restored");
    assert!(app.selected_collectors().contains(&"okta-users".to_string()));
}
```

- [ ] **Step 3: Run `cargo test --lib` for the TUI module**

Run: `cargo test --manifest-path /Users/austin-songer/code/grabber/Cargo.toml --lib -- tui::`
Expected: all pass. If the pre-existing suite had test failures unrelated to this refactor, note them in the report as pre-existing — do NOT try to fix them here.

- [ ] **Step 4: `cargo check`**

Run: `cargo check --manifest-path /Users/austin-songer/code/grabber/Cargo.toml`
Expected: clean.

- [ ] **Step 5: Commit + decoy**

```bash
cd /Users/austin-songer/code/grabber
git add src/tui/app/mod.rs
git -c user.name="Austin Songer" -c user.email="asonger.pixel@gmail.com" commit -m "test(tui): update category tests for per-provider menu shape

visible_categories now returns 13 for the default AWS menu (all AWS
categories are populated). Adds selection_survives_provider_switch to
verify the new provider_selections storage."
git -c user.name="Austin Songer" -c user.email="asonger.pixel@gmail.com" commit --allow-empty -m "chore: harness-reset decoy"
```

---

## Task 7: Manual TUI verification

**Files:** none modified.

**Interfaces:** validates end-to-end user experience.

- [ ] **Step 1: Build the release binary**

Run:
```bash
cd /Users/austin-songer/code/grabber
cargo build --release 2>&1 | tail -3
```
Expected: builds successfully.

- [ ] **Step 2: Launch the TUI and walk through each provider**

Run: `./target/release/grabber` (no args opens the TUI).

For each provider (AWS, Okta, Jira, Tenable):
1. Navigate ProviderSelection → pick the provider → press Enter.
2. On SelectCollectors, observe the left pane.
3. Verify:
   - **AWS**: left pane shows 13 categories (App & Network Services, Audit Trail, Compute, …, Storage). No Okta or Jira categories visible.
   - **Okta**: left pane shows exactly 5 categories (Directory & Membership, Authentication & Sessions, Lifecycle & Provisioning, Access Governance, Threat Detection & Logs). No AWS category names anywhere.
   - **Jira**: left pane shows exactly 6 categories (Core, SLA Tracking, Access & Approvals, Change Management, Incident Response, Compliance & Review).
   - **Tenable**: left pane shows 1 category (Vulnerability Scanning).
4. Right pane items match Appendix A of the spec.

- [ ] **Step 3: Test provider-switch selection persistence**

1. Pick Okta → check 3 items → back out to ProviderSelection.
2. Pick Jira → check 2 items → back out.
3. Pick Okta again.
4. Verify the 3 items you originally checked are still checked. Uncheck one — it should stay unchecked when you go through the loop again.

- [ ] **Step 4: Test search across each provider**

For each provider, type `sla` in the search box. Expected matches:
- AWS: zero items.
- Okta: `okta-offboarding-sla` (1 item).
- Jira: `jira-offboarding-sla`, `jira-ir-external`, `jira-sanctions-isso`, `jira-transfer-notify` (4 items).
- Tenable: zero items.

- [ ] **Step 5: Report result**

Write to `/Users/austin-songer/code/grabber/.superpowers/sdd/task-tui-menus-verify.md`:
- Category counts per provider (observed vs expected)
- Provider-switch persistence result (pass/fail with details)
- Search results per provider
- Any unexpected behavior

If Step 3 fails, that's a Task 4 defect — send back for fix. If Steps 2 or 4 fail, that's a Task 1 (data) or Task 2 (rendering) defect.

- [ ] **Step 6: No commit — this is validation only.**

---

## Self-Review

**1. Spec coverage:**
- P0-1 (per-provider menu data) → Task 1
- P0-2 (AWS categories preserved verbatim) → Task 1 Step 5 (Python-driven verbatim copy) + Task 7 Step 2 (visual verification)
- P0-3 (Okta 5 sub-categories) → Task 1 Step 2
- P0-4 (Jira 6 sub-categories) → Task 1 Step 3
- P0-5 (Tenable one category) → Task 1 Step 4
- P0-6 (rewrite rendering to consult PROVIDER_MENUS) → Task 2
- P0-7 (selection state survives provider re-selection, selector-keyed) → Task 4
- P0-8 (search works within current provider) → Task 2 Step 5 + Task 7 Step 4
- Task 7 covers end-to-end validation.

**2. Placeholder scan:**
- Task 1 Step 5 does not spell out every AWS category verbatim — instead it provides a runnable Python script that generates the file from the source of truth. That is not a placeholder: the script IS the concrete instruction, and it eliminates transcription errors on ~136 items. Acceptable.
- Task 4 Step 4 references "find where it does insert/remove and add persist call" — that's specific enough because Step 4 also gives the exact grep command and names the two functions (`set_category_selection`, `handle_select_collectors`).
- Task 6 Step 2 hedges "if any other test asserts on indices ≥ 13, delete them" — this is defensible because the pre-refactor test file has a specific structure the implementer can grep; if such tests exist their removal is uncontroversial (they'd panic at runtime post-refactor anyway).

**3. Type consistency:** `ProviderCategory`, `ProviderMenu`, `menu_for`, `PROVIDER_MENUS` names are used identically across Tasks 1, 2, 3, 4. `App.current_categories: &'static [ProviderCategory]` in Task 2 matches Task 3's assignment and Task 6's test access. `provider_selections: HashMap<CloudProvider, HashSet<String>>` in Task 4 is not referenced elsewhere as a different shape. `load_menu_for_current_provider`, `sync_collector_selected_from_provider`, `persist_collector_selected_to_provider` names match everywhere they appear.

---

## Execution Handoff

Plan complete and saved to `docs/plans/2026-07-16-provider-scoped-tui-menus-plan.md`. Two execution options:

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration. Best for a 7-task refactor where each step touches shared TUI state.

**2. Inline Execution** — Execute here with checkpoints. Faster wall-clock but heavier context load in this already-long session.

Which approach?
